// SPDX-License-Identifier: GPL-2.0-or-later
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/fs.h>
#include <inttypes.h>
#include <asm/byteorder.h>
#include <sys/sysinfo.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <time.h>

#include "common.h"
#include "nvme.h"
#include "libnvme.h"
#include "plugin.h"
#include "linux/types.h"
#include "nvme-wrap.h"
#include "nvme-print.h"
#include "util/cleanup.h"
#include "util/types.h"

#define CREATE_CMD
#include "sfx-nvme.h"
#include "sfx-types.h"

#define SFX_PAGE_SHIFT	          12
#define SECTOR_SHIFT	          9

//See IDEMA LBA1-03
#define IDEMA_CAP(exp_GB)               (((__u64)exp_GB - 50ULL) * 1953504ULL + 97696368ULL)
#define IDEMA_CAP2GB(exp_sector)        (((__s64)exp_sector - 97696368LL) / 1953504LL + 50LL)
#define IDEMA_CAP2GB_LDS(exp_sector)    (((__s64)exp_sector - 12212046LL) / 244188LL + 50LL)

#define SFX_LAT_STATS_MAJOR_IDX   4
#define SFX_LAT_STATS_MINOR_IDX   1

static struct sfx_device_config g_sfx_device_config[] = {
	{ "ScaleFlux", "0xcc53", "0x0010", SFX_MYRTLE, 0x00c2, },
	{ "DIGISTOR",  "0x1dfd", "0x0010", SFX_MYRTLE, 0x00c2, },
	{ "ScaleFlux", "0xcc53", "0x0020", SFX_QUINCE, 0x00d2, },
	{ "TWSC",      "0x1f99", "0x1001", SFX_QUINCE, 0x00c3, },
	{ "TWSC",      "0x1ded", "0x3053", SFX_QUINCE, 0x00c3, },
	{ "TWSC",      "0x1ded", "0x3050", SFX_QUINCE, 0x00c3, },
	{ "ScaleFlux", "0x1ded", "0x3052", SFX_QUINCE, 0x00c3, },
	{ "TWSC",      "0x1f99", "0x1002", SFX_QUINCE, 0x00d2, },
};

static int sfx_get_ctrl_name_from_dev(struct nvme_dev *dev, char *ctrl_name, size_t size)
{
	struct stat st;
	char dev_path[48] = {};
	char sys_path[64] = {};
	char resolved[64] = {};

	snprintf(dev_path, sizeof(dev_path), "/dev/%s", dev->name);

	if (stat(dev_path, &st) < 0) {
		fprintf(stderr, "Failed to stat %s: %s\n", dev_path, strerror(errno));
		return -1;
	}

	memset(ctrl_name, 0, size);

	if (S_ISCHR(st.st_mode)) {
		strncpy(ctrl_name, dev->name, size - 1);
	} else {
		snprintf(sys_path, sizeof(sys_path), "/sys/class/block/%s", dev->name);
		if (!realpath(sys_path, resolved)) {
			switch (errno) {
			case ENOENT:
				fprintf(stderr, "Device sysfs path %s does not exist\n", sys_path);
				break;
			case EACCES:
				fprintf(stderr, "Permission denied accessing %s\n", sys_path);
				break;
			default:
				fprintf(stderr, "Failed to resolve %s: %s\n", sys_path, strerror(errno));
				break;
			}
			return -1;
		}

		char *p = strrchr(resolved, '/');
		if (p) *p = '\0';

		p = strrchr(resolved, '/');
		if (!p) return ENOTTY;

		snprintf(ctrl_name, size, "%s", p + 1);
	}

	return 0;
}

static int sfx_get_pcie_slot_from_ctrl_name(const char *ctrl_name, char* pcie_slot, size_t size)
{
	char path[128] = {};
	int len;

	memset(pcie_slot, 0, size);
	snprintf(path, sizeof(path), "/sys/class/nvme/%s/device", ctrl_name);
	len = readlink(path, pcie_slot, size - 1);
	if (len <=0) {
		fprintf(stderr, "Failed to readlink(%s): %s\n", path, strerror(errno));
		return -1;
	}

	pcie_slot[len] = '\0';
	const char *p = strrchr(pcie_slot, '/');
	if (!p) {
		fprintf(stderr, "Unexpected link format for %s: '%s'\n", path, pcie_slot);
		return -1;
	}

	memmove(pcie_slot, p + 1, strlen(p + 1) + 1);

	return 0;
}

static int sfx_read_sys_device(const char *pcie_slot, char *file_name, char *data, size_t data_len)
{
	char path[128] = {};
	int fd, len;

	snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s/%s", pcie_slot, file_name);

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Could not Open %s: %s\n\n", path, strerror(errno));
		return -1;
	}

	memset(data, 0, data_len);
	len = read(fd, data, data_len);
	close(fd);

	if (len < 1) {
		fprintf(stderr, "Could not Read %s: %s\n\n", path, strerror(errno));
		return -1;
	}

	if (len > 0 && data[len - 1] == '\n')
		data[len - 1] = '\0';

	return 0;
}

static int sfx_device_valid_check(struct nvme_dev *dev, struct sfx_device_config *dev_cfg)
{
	int i, err;

	memset(dev_cfg, 0, sizeof(*dev_cfg));

	err = sfx_get_ctrl_name_from_dev(dev, dev_cfg->ctrl_name, sizeof(dev_cfg->ctrl_name));
	if (err)
		return err;

	err = sfx_get_pcie_slot_from_ctrl_name(dev_cfg->ctrl_name, dev_cfg->pcie_slot, sizeof(dev_cfg->pcie_slot));
	if (err)
		return err;

	err = sfx_read_sys_device(dev_cfg->pcie_slot, "vendor", dev_cfg->vendor_id, sizeof(dev_cfg->vendor_id));
	if (err)
		return err;

	err = sfx_read_sys_device(dev_cfg->pcie_slot, "device", dev_cfg->device_id, sizeof(dev_cfg->device_id));
	if (err)
		return err;

	for (i=0; i < (sizeof(g_sfx_device_config) / sizeof(struct sfx_device_config)); i++) {
		if ((!strcmp(g_sfx_device_config[i].vendor_id, dev_cfg->vendor_id)) &&
			(!strcmp(g_sfx_device_config[i].device_id, dev_cfg->device_id))) {
			strcpy(dev_cfg->vendor_name, g_sfx_device_config[i].vendor_name);
			dev_cfg->product_id  = g_sfx_device_config[i].product_id;
			dev_cfg->smartlog_id = g_sfx_device_config[i].smartlog_id;
			return 0;
		}
	}

	fprintf(stderr, "Device %s VID %s DID %s not Match SFX Config\n", dev_cfg->ctrl_name, dev_cfg->vendor_id, dev_cfg->device_id);
	return -1;
}

static int nvme_exec_cust(int fd, struct nvme_cust_args *args)
{
	int err = 0;

	struct nvme_passthru_cmd cmd = {
		.opcode     = args->opcode,
		.nsid       = NVME_NSID_ALL,
		.addr       = (__u64)(uintptr_t)args->data,
		.data_len   = args->data_len,
		.cdw10      = args->data_len / 4,
		.cdw11      = args->cdw11,
		.cdw12      = args->bufid,
		.cdw13      = args->cdw13,
		.cdw14      = args->cdw14,
		.cdw15      = args->custid,
		.timeout_ms = args->timeout,
	};

	err = nvme_submit_admin_passthru(fd, &cmd, args->result);
	if (err) {
		fprintf(stderr, "Fail to exec cust opcode=0x%x custid=0x%x\n", args->opcode, args->custid);
	}

	return err;
}

static int sfx_unlock_cust(int fd)
{
	struct nvme_cust_args args = {
		.opcode = 0xc3,
		.custid = 0x0,
	};

	return nvme_exec_cust(fd, &args);
}

static int sfx_lock_cust(int fd)
{
	struct nvme_cust_args args = {
		.opcode = 0xc3,
		.custid = 0x1,
	};

	return nvme_exec_cust(fd, &args);
}

static int sfx_read_cust_data(int fd, void  *data, __u32 data_len, __u32 custid, __u32 bufid, __u32 cdw11, __u32 cdw13, __u32 cdw14)
{
	int err = 0;

	err = sfx_unlock_cust(fd);
	if (err)
		return err;

	struct nvme_cust_args args = {
		.opcode   = 0xc6,
		.data     = data,
		.data_len = data_len,
		.custid   = custid,
		.bufid    = bufid,
		.cdw11    = cdw11,
		.cdw13    = cdw13,
		.cdw14    = cdw14,
	};

	err = nvme_exec_cust(fd, &args);
	if (err)
		return err;

	return sfx_lock_cust(fd);
}

static int nvme_query_cap(int fd, __u32 nsid, __u32 data_len, void *data)
{
	int err = 0;

	struct nvme_passthru_cmd cmd = {
		.opcode		= nvme_admin_query_cap_info,
		.nsid		= nsid,
		.addr		= (__u64)(uintptr_t) data,
		.data_len	= data_len,
	};

	err = nvme_submit_admin_passthru(fd, &cmd, NULL);
	if (err) {
		fprintf(stderr, "Could not query freespace information (0xD6)\n");
	}

	return err;
}

static int nvme_change_cap(int fd, __u32 nsid, __u64 capacity)
{
	int err = 0;

	struct nvme_passthru_cmd cmd = {
		.opcode	= nvme_admin_change_cap,
		.nsid	= nsid,
		.cdw10	= (capacity & 0xffffffff),
		.cdw11	= (capacity >> 32),
	};

	err = nvme_submit_admin_passthru(fd, &cmd, NULL);
	if (err)
		fprintf(stderr, "Could not change cap (0xD4)\n");

	return err;
}

#ifdef CONFIG_JSONC
static void show_sfx_smart_log_json(struct nvme_additional_smart_log *smart,
		unsigned int nsid, const char *devname)
{
	struct json_object *root, *entry_stats, *dev_stats, *multi;

	root = json_create_object();
	json_object_add_value_string(root, "ScaleFlux Smart log", devname);

	dev_stats = json_create_object();

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->program_fail_cnt.norm);
	json_object_add_value_int(entry_stats, "raw", int48_to_long(smart->program_fail_cnt.raw));
	json_object_add_value_object(dev_stats, "program_fail_count", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->erase_fail_cnt.norm);
	json_object_add_value_int(entry_stats, "raw", int48_to_long(smart->erase_fail_cnt.raw));
	json_object_add_value_object(dev_stats, "erase_fail_count", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->wear_leveling_cnt.norm);
	multi = json_create_object();
	json_object_add_value_int(multi, "min", le16_to_cpu(smart->wear_leveling_cnt.wear_level.min));
	json_object_add_value_int(multi, "max", le16_to_cpu(smart->wear_leveling_cnt.wear_level.max));
	json_object_add_value_int(multi, "avg", le16_to_cpu(smart->wear_leveling_cnt.wear_level.avg));
	json_object_add_value_object(entry_stats, "raw", multi);
	json_object_add_value_object(dev_stats, "wear_leveling", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->e2e_err_cnt.norm);
	json_object_add_value_int(entry_stats, "raw", int48_to_long(smart->e2e_err_cnt.raw));
	json_object_add_value_object(dev_stats, "end_to_end_error_detection_count", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->crc_err_cnt.norm);
	json_object_add_value_int(entry_stats, "raw", int48_to_long(smart->crc_err_cnt.raw));
	json_object_add_value_object(dev_stats, "crc_error_count", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->timed_workload_media_wear.norm);
	json_object_add_value_float(entry_stats, "raw", ((float)int48_to_long(smart->timed_workload_media_wear.raw)) / 1024);
	json_object_add_value_object(dev_stats, "timed_workload_media_wear", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->timed_workload_host_reads.norm);
	json_object_add_value_int(entry_stats, "raw", int48_to_long(smart->timed_workload_host_reads.raw));
	json_object_add_value_object(dev_stats, "timed_workload_host_reads", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->timed_workload_timer.norm);
	json_object_add_value_int(entry_stats, "raw", int48_to_long(smart->timed_workload_timer.raw));
	json_object_add_value_object(dev_stats, "timed_workload_timer", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->thermal_throttle_status.norm);
	multi = json_create_object();
	json_object_add_value_int(multi, "pct", smart->thermal_throttle_status.thermal_throttle.pct);
	json_object_add_value_int(multi, "cnt", smart->thermal_throttle_status.thermal_throttle.count);
	json_object_add_value_object(entry_stats, "raw", multi);
	json_object_add_value_object(dev_stats, "thermal_throttle_status", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->retry_buffer_overflow_cnt.norm);
	json_object_add_value_int(entry_stats, "raw",	  int48_to_long(smart->retry_buffer_overflow_cnt.raw));
	json_object_add_value_object(dev_stats, "retry_buffer_overflow_count", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->pll_lock_loss_cnt.norm);
	json_object_add_value_int(entry_stats, "raw",	  int48_to_long(smart->pll_lock_loss_cnt.raw));
	json_object_add_value_object(dev_stats, "pll_lock_loss_count", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->nand_bytes_written.norm);
	json_object_add_value_int(entry_stats, "raw",	  int48_to_long(smart->nand_bytes_written.raw));
	json_object_add_value_object(dev_stats, "nand_bytes_written", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->host_bytes_written.norm);
	json_object_add_value_int(entry_stats, "raw",	  int48_to_long(smart->host_bytes_written.raw));
	json_object_add_value_object(dev_stats, "host_bytes_written", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->raid_recover_cnt.norm);
	json_object_add_value_int(entry_stats, "raw",	  int48_to_long(smart->raid_recover_cnt.raw));
	json_object_add_value_object(dev_stats, "raid_recover_cnt", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->prog_timeout_cnt.norm);
	json_object_add_value_int(entry_stats, "raw",	  int48_to_long(smart->prog_timeout_cnt.raw));
	json_object_add_value_object(dev_stats, "prog_timeout_cnt", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->erase_timeout_cnt.norm);
	json_object_add_value_int(entry_stats, "raw",	  int48_to_long(smart->erase_timeout_cnt.raw));
	json_object_add_value_object(dev_stats, "erase_timeout_cnt", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->read_timeout_cnt.norm);
	json_object_add_value_int(entry_stats, "raw",	  int48_to_long(smart->read_timeout_cnt.raw));
	json_object_add_value_object(dev_stats, "read_timeout_cnt", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->read_ecc_cnt.norm);
	json_object_add_value_int(entry_stats, "raw",	  int48_to_long(smart->read_ecc_cnt.raw));
	json_object_add_value_object(dev_stats, "read_ecc_cnt", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->non_media_crc_err_cnt.norm);
	json_object_add_value_int(entry_stats, "raw", int48_to_long(smart->non_media_crc_err_cnt.raw));
	json_object_add_value_object(dev_stats, "non_media_crc_err_cnt", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->compression_path_err_cnt.norm);
	json_object_add_value_int(entry_stats, "raw", int48_to_long(smart->compression_path_err_cnt.raw));
	json_object_add_value_object(dev_stats, "compression_path_err_cnt", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->out_of_space_flag.norm);
	json_object_add_value_int(entry_stats, "raw", int48_to_long(smart->out_of_space_flag.raw));
	json_object_add_value_object(dev_stats, "out_of_space_flag", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->physical_usage_ratio.norm);
	json_object_add_value_int(entry_stats, "raw", int48_to_long(smart->physical_usage_ratio.raw));
	json_object_add_value_object(dev_stats, "physical_usage_ratio", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->grown_bb_count.norm);
	json_object_add_value_int(entry_stats, "raw", int48_to_long(smart->grown_bb_count.raw));
	json_object_add_value_object(dev_stats, "grown_bb_count", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->system_area_life_remaining.norm);
	json_object_add_value_int(entry_stats, "raw", int48_to_long(smart->system_area_life_remaining.raw));
	json_object_add_value_object(dev_stats, "system_area_life_remaining", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->user_available_space_rate.norm);
	json_object_add_value_int(entry_stats, "raw", int48_to_long(smart->user_available_space_rate.raw));
	json_object_add_value_object(dev_stats, "user_available_space_rate", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->over_provisioning_rate.norm);
	json_object_add_value_int(entry_stats, "raw", int48_to_long(smart->over_provisioning_rate.raw));
	json_object_add_value_object(dev_stats, "over_provisioning_rate", entry_stats);

	json_object_add_value_object(root, "Device stats", dev_stats);

	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}
#else /* CONFIG_JSONC */
#define show_sfx_smart_log_json(smart, nsid, devname)
#endif /* CONFIG_JSONC */

static void show_sfx_smart_log(struct nvme_additional_smart_log *smart,
		unsigned int nsid, const char *devname)
{
	printf("Additional Smart Log for ScaleFlux device:%s namespace-id:%x\n",
			devname, nsid);
	printf("key                               normalized raw\n");
	printf("program_fail_count              : %3d%%       %"PRIu64"\n",
			smart->program_fail_cnt.norm,
			int48_to_long(smart->program_fail_cnt.raw));
	printf("erase_fail_count                : %3d%%       %"PRIu64"\n",
			smart->erase_fail_cnt.norm,
			int48_to_long(smart->erase_fail_cnt.raw));
	printf("wear_leveling                   : %3d%%       min: %u, max: %u, avg: %u\n",
			smart->wear_leveling_cnt.norm,
			le16_to_cpu(smart->wear_leveling_cnt.wear_level.min),
			le16_to_cpu(smart->wear_leveling_cnt.wear_level.max),
			le16_to_cpu(smart->wear_leveling_cnt.wear_level.avg));
	printf("end_to_end_error_detection_count: %3d%%       %"PRIu64"\n",
			smart->e2e_err_cnt.norm,
			int48_to_long(smart->e2e_err_cnt.raw));
	printf("crc_error_count                 : %3d%%       %"PRIu64"\n",
			smart->crc_err_cnt.norm,
			int48_to_long(smart->crc_err_cnt.raw));
	printf("timed_workload_media_wear       : %3d%%       %.3f%%\n",
			smart->timed_workload_media_wear.norm,
			((float)int48_to_long(smart->timed_workload_media_wear.raw)) / 1024);
	printf("timed_workload_host_reads       : %3d%%       %"PRIu64"%%\n",
			smart->timed_workload_host_reads.norm,
			int48_to_long(smart->timed_workload_host_reads.raw));
	printf("timed_workload_timer            : %3d%%       %"PRIu64"\n",
			smart->timed_workload_timer.norm,
			int48_to_long(smart->timed_workload_timer.raw));
	printf("thermal_throttle_status         : %3d%%       %u%%, cnt: %u\n",
			smart->thermal_throttle_status.norm,
			smart->thermal_throttle_status.thermal_throttle.pct,
			smart->thermal_throttle_status.thermal_throttle.count);
	printf("retry_buffer_overflow_count     : %3d%%       %"PRIu64"\n",
			smart->retry_buffer_overflow_cnt.norm,
			int48_to_long(smart->retry_buffer_overflow_cnt.raw));
	printf("pll_lock_loss_count             : %3d%%       %"PRIu64"\n",
			smart->pll_lock_loss_cnt.norm,
			int48_to_long(smart->pll_lock_loss_cnt.raw));
	printf("nand_bytes_written              : %3d%%       sectors: %"PRIu64"\n",
			smart->nand_bytes_written.norm,
			int48_to_long(smart->nand_bytes_written.raw));
	printf("host_bytes_written              : %3d%%       sectors: %"PRIu64"\n",
			smart->host_bytes_written.norm,
			int48_to_long(smart->host_bytes_written.raw));
	printf("raid_recover_cnt                : %3d%%       %"PRIu64"\n",
			smart->raid_recover_cnt.norm,
			int48_to_long(smart->raid_recover_cnt.raw));
	printf("read_ecc_cnt                    : %3d%%       %"PRIu64"\n",
			smart->read_ecc_cnt.norm,
			int48_to_long(smart->read_ecc_cnt.raw));
	printf("prog_timeout_cnt                : %3d%%       %"PRIu64"\n",
			smart->prog_timeout_cnt.norm,
			int48_to_long(smart->prog_timeout_cnt.raw));
	printf("erase_timeout_cnt               : %3d%%       %"PRIu64"\n",
			smart->erase_timeout_cnt.norm,
			int48_to_long(smart->erase_timeout_cnt.raw));
	printf("read_timeout_cnt                : %3d%%       %"PRIu64"\n",
			smart->read_timeout_cnt.norm,
			int48_to_long(smart->read_timeout_cnt.raw));
	printf("non_media_crc_err_cnt           : %3d%%       %" PRIu64 "\n",
		   smart->non_media_crc_err_cnt.norm,
		   int48_to_long(smart->non_media_crc_err_cnt.raw));
	printf("compression_path_err_cnt        : %3d%%       %" PRIu64 "\n",
		   smart->compression_path_err_cnt.norm,
		   int48_to_long(smart->compression_path_err_cnt.raw));
	printf("out_of_space_flag               : %3d%%       %" PRIu64 "\n",
		   smart->out_of_space_flag.norm,
		   int48_to_long(smart->out_of_space_flag.raw));
	printf("phy_capacity_used_ratio         : %3d%%       %" PRIu64 "\n",
		   smart->physical_usage_ratio.norm,
		   int48_to_long(smart->physical_usage_ratio.raw));
	printf("grown_bb_count                  : %3d%%       %" PRIu64 "\n",
		   smart->grown_bb_count.norm, int48_to_long(smart->grown_bb_count.raw));
	printf("system_area_life_remaining      : %3d%%       %" PRIu64 "\n",
		   smart->system_area_life_remaining.norm, int48_to_long(smart->system_area_life_remaining.raw));
	printf("user_available_space_rate       : %3d%%       %" PRIu64 "\n",
		   smart->user_available_space_rate.norm, int48_to_long(smart->user_available_space_rate.raw));
	printf("over_provisioning_rate          : %3d%%       %" PRIu64 "\n",
		   smart->over_provisioning_rate.norm, int48_to_long(smart->over_provisioning_rate.raw));
}

static int sfx_get_additional_smart_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	struct sfx_device_config dev_cfg;
	struct nvme_additional_smart_log smart_log;
	char *desc =
		"Get ScaleFlux vendor specific additional smart log (optionally, for the specified namespace), and show it.";
	const char *namespace = "(optional) desired namespace";
	const char *raw = "dump output in binary format";
#ifdef CONFIG_JSONC
	const char *json = "Dump output in json format";
#endif /* CONFIG_JSONC */
	struct nvme_dev *dev;
	struct config {
		__u32 namespace_id;
		bool  raw_binary;
		bool  json;
	};
	int err = 0;

	struct config cfg = {
		.namespace_id = NVME_NSID_ALL,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace),
		OPT_FLAG("raw-binary",	 'b', &cfg.raw_binary,	 raw),
		OPT_FLAG_JSON("json",	 'j', &cfg.json,	 json),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	err = sfx_device_valid_check(dev, &dev_cfg);
	if (err)
		goto close_dev;

	err = nvme_get_nsid_log(dev_fd(dev), false, 0xca, cfg.namespace_id,
				sizeof(smart_log), (void *)&smart_log);
	if (err)
		goto close_dev;

	if (cfg.json)
		show_sfx_smart_log_json(&smart_log, cfg.namespace_id, dev->name);
	else if (!cfg.raw_binary)
		show_sfx_smart_log(&smart_log, cfg.namespace_id, dev->name);
	else
		d_raw((unsigned char *)&smart_log, sizeof(smart_log));

	err = nvme_get_nsid_log(dev_fd(dev), false, 0xca, cfg.namespace_id,
				sizeof(smart_log), (void *)&smart_log);

close_dev:
	dev_close(dev);
ret:
	if (err > 0) {
		nvme_show_status(err);
	}
	return err;
}

static void show_lat_stats(struct sfx_lat_stats *stats, int write)
{
	int i;

	printf("ScaleFlux IO %s Command Latency Statistics\n", write ? "Write" : "Read");
	printf("-------------------------------------\n");
	printf("Major Revision : %u\n", stats->maj);
	printf("Minor Revision : %u\n", stats->min);

	printf("\nGroup 1: Range is 0us~63us, step 1us\n");
	for (i = 0; i < 64; i++)
		printf("Bucket %2d: %u\n", i, stats->bucket_1[i]);

	printf("\nGroup 2: Range is 63us~127us, step 1us\n");
	for (i = 0; i < 64; i++)
		printf("Bucket %2d: %u\n", i, stats->bucket_2[i]);

	printf("\nGroup 3: Range is 127us~255us, step 2us\n");
	for (i = 0; i < 64; i++)
		printf("Bucket %2d: %u\n", i, stats->bucket_3[i]);

	printf("\nGroup 4: Range is 255us~510us, step 4us\n");
	for (i = 0; i < 64; i++)
		printf("Bucket %2d: %u\n", i, stats->bucket_4[i]);

	printf("\nGroup 5: Range is 510us~1.02ms step\n");
	for (i = 0; i < 64; i++)
		printf("Bucket %2d: %u\n", i, stats->bucket_5[i]);

	printf("\nGroup 6: Range is 1.02ms~2.04ms step 16us\n");
	for (i = 0; i < 64; i++)
		printf("Bucket %2d: %u\n", i, stats->bucket_6[i]);

	printf("\nGroup 7: Range is 2.04ms~4.08ms step 32us\n");
	for (i = 0; i < 64; i++)
		printf("Bucket %2d: %u\n", i, stats->bucket_7[i]);

	printf("\nGroup 8: Range is 4.08ms~8.16ms step 64us\n");
	for (i = 0; i < 64; i++)
		printf("Bucket %2d: %u\n", i, stats->bucket_8[i]);

	printf("\nGroup 9: Range is 8.16ms~16.32ms step 128us\n");
	for (i = 0; i < 64; i++)
		printf("Bucket %2d: %u\n", i, stats->bucket_9[i]);

	printf("\nGroup 10: Range is 16.32ms~32.64ms step 256us\n");
	for (i = 0; i < 64; i++)
		printf("Bucket %2d: %u\n", i, stats->bucket_10[i]);

	printf("\nGroup 11: Range is 32.64ms~65.28ms step 512us\n");
	for (i = 0; i < 64; i++)
		printf("Bucket %2d: %u\n", i, stats->bucket_11[i]);

	printf("\nGroup 12: Range is 65.28ms~130.56ms step 1.024ms\n");
	for (i = 0; i < 64; i++)
		printf("Bucket %2d: %u\n", i, stats->bucket_12[i]);

	printf("\nGroup 13: Range is 130.56ms~261.12ms step 2.048ms\n");
	for (i = 0; i < 64; i++)
		printf("Bucket %2d: %u\n", i, stats->bucket_13[i]);

	printf("\nGroup 14: Range is 261.12ms~522.24ms step 4.096ms\n");
	for (i = 0; i < 64; i++)
		printf("Bucket %2d: %u\n", i, stats->bucket_14[i]);

	printf("\nGroup 15: Range is 522.24ms~1.04s step 8.192ms\n");
	for (i = 0; i < 64; i++)
		printf("Bucket %2d: %u\n", i, stats->bucket_15[i]);

	printf("\nGroup 16: Range is 1.04s~2.09s step 16.384ms\n");
	for (i = 0; i < 64; i++)
		printf("Bucket %2d: %u\n", i, stats->bucket_16[i]);

	printf("\nGroup 17: Range is 2.09s~4.18s step 32.768ms\n");
	for (i = 0; i < 64; i++)
		printf("Bucket %2d: %u\n", i, stats->bucket_17[i]);

	printf("\nGroup 18: Range is 4.18s~8.36s step 65.536ms\n");
	for (i = 0; i < 64; i++)
		printf("Bucket %2d: %u\n", i, stats->bucket_18[i]);

	printf("\nGroup 19: Range is 8.36s~ step 131.072ms\n");
	for (i = 0; i < 64; i++)
		printf("Bucket %2d: %u\n", i, stats->bucket_19[i]);

	printf("\nAverage latency statistics %" PRIu64 "\n",
		   (uint64_t)stats->average);
}

static int sfx_check_lat_stats_support(int fd)
{
	__u8 buf[512]  = {};
	__u8 gudid[16] = { 0x92, 0x7a, 0xc0, 0x8c, 0xd0, 0x84, 0x6c, 0x9c, 
					   0x70, 0x43, 0xe6, 0xd4, 0x58, 0x5e, 0xd4, 0x85 };
	int err = 0;

	err = nvme_get_log_simple(fd, 0xc3, sizeof(buf), (void *)&buf);
	if (err)
		return err;

	if (!memcmp(&buf[sizeof(buf)-sizeof(gudid)], gudid, sizeof(gudid))) {
		fprintf(stderr, "lat-stats cmd not support get ocp latency_monitor\n");
		err = -1;
	}

	return err;
}

static int sfx_get_lat_stats_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	struct sfx_device_config dev_cfg;
	struct sfx_lat_stats stats;
	char *desc = "Get ScaleFlux Latency Statistics log and show it.";
	const char *raw = "dump output in binary format";
	const char *write = "Get write statistics (read default)";
	struct nvme_dev *dev;
	struct config {
		bool raw_binary;
		bool write;
	};
	int err = 0;

	struct config cfg = {};

	OPT_ARGS(opts) = {
		OPT_FLAG("write",	   'w', &cfg.write,		 write),
		OPT_FLAG("raw-binary", 'b', &cfg.raw_binary, raw),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	err = sfx_device_valid_check(dev, &dev_cfg);
	if (err)
		goto close_dev;

	err = sfx_check_lat_stats_support(dev_fd(dev));
	if (err)
		goto close_dev;

	err = nvme_get_log_simple(dev_fd(dev), cfg.write ? 0xc3 : 0xc1,
				  sizeof(stats), (void *)&stats);
	if (err)
		goto close_dev;

	if ((stats.maj == SFX_LAT_STATS_MAJOR_IDX) && (stats.min == SFX_LAT_STATS_MINOR_IDX)) {
		if (!cfg.raw_binary)
			show_lat_stats(&stats, cfg.write);
		else
			d_raw((unsigned char *)&stats, sizeof(struct sfx_lat_stats));
	} else {
		printf("ScaleFlux IO %s Command Latency Statistics Invalid Version Maj %d Min %d\n",
				cfg.write ? "Write" : "Read", stats.maj, stats.min);
	}

close_dev:
	dev_close(dev);
ret:
	if (err > 0) {
		nvme_show_status(err);
	}
	return err;
}

static void show_cap_info(struct sfx_freespace_ctx *ctx)
{
	printf("logic            capacity:%5lluGB(0x%"PRIx64")\n",
			IDEMA_CAP2GB(ctx->user_space), (uint64_t)ctx->user_space);
	printf("provisioned      capacity:%5lluGB(0x%"PRIx64")\n",
			IDEMA_CAP2GB(ctx->phy_space), (uint64_t)ctx->phy_space);
	printf("free provisioned capacity:%5lluGB(0x%"PRIx64")\n",
			IDEMA_CAP2GB(ctx->free_space), (uint64_t)ctx->free_space);
	printf("used provisioned capacity:%5lluGB(0x%"PRIx64")\n",
			IDEMA_CAP2GB(ctx->phy_space) - IDEMA_CAP2GB(ctx->free_space),
			(uint64_t)(ctx->phy_space - ctx->free_space));
	printf("map_unit                 :0x%"PRIx64"K\n", (uint64_t)(ctx->map_unit * 4));
}

static int sfx_query_cap_info(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	struct sfx_device_config dev_cfg;
	struct sfx_freespace_ctx ctx = { 0 };
	char *desc = "query current capacity info";
	const char *raw = "dump output in binary format";
	struct nvme_dev *dev;
	struct config {
		bool  raw_binary;
	};
	struct config cfg = {};
	int err = 0;

	OPT_ARGS(opts) = {
		OPT_FLAG("raw-binary", 'b', &cfg.raw_binary, raw),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	err = sfx_device_valid_check(dev, &dev_cfg);
	if (err)
		goto close_dev;

	err = nvme_query_cap(dev_fd(dev), NVME_NSID_ALL, sizeof(ctx), &ctx);
	if (err)
		goto close_dev;

	if (ctx.free_space > ctx.phy_space)
		ctx.free_space = 0;

	if (!cfg.raw_binary)
		show_cap_info(&ctx);
	else
		d_raw((unsigned char *)&ctx, sizeof(ctx));

close_dev:
	dev_close(dev);
ret:
	if (err > 0) {
		nvme_show_status(err);
	}
	return err;
}

static int change_sanity_check(int fd, __u64 trg_in_4k, int *shrink)
{
	struct sfx_freespace_ctx freespace_ctx = { 0 };
	struct sysinfo s_info;
	__u64 mem_need = 0;
	__u64 cur_in_4k = 0;
	__u64 provisioned_cap_4k = 0;
	int extend = 0;

	if (nvme_query_cap(fd, NVME_NSID_ALL, sizeof(freespace_ctx), &freespace_ctx))
		return -1;

	/*
	 * capacity illegal check
	 */
	provisioned_cap_4k = freespace_ctx.phy_space >>
				(SFX_PAGE_SHIFT - SECTOR_SHIFT);
	if (trg_in_4k < provisioned_cap_4k ||
		trg_in_4k > ((__u64)provisioned_cap_4k * 4)) {
		fprintf(stderr,
			"WARNING: Only support 1.0~4.0 x provisioned capacity!\n");
		if (trg_in_4k < provisioned_cap_4k)
			fprintf(stderr,
				"WARNING: The target capacity is less than 1.0 x provisioned capacity!\n");
		else
			fprintf(stderr,
				"WARNING: The target capacity is larger than 4.0 x provisioned capacity!\n");
		return -1;
	}
	if (trg_in_4k > ((__u64)provisioned_cap_4k*4)) {
		fprintf(stderr, "WARNING: the target capacity is too large\n");
		return -1;
	}

	/*
	 * check whether mem enough if extend
	 */
	cur_in_4k = freespace_ctx.user_space >> (SFX_PAGE_SHIFT - SECTOR_SHIFT);
	extend = (cur_in_4k <= trg_in_4k);
	if (extend) {
		if (sysinfo(&s_info) < 0) {
			printf("change-cap query mem info fail\n");
			return -1;
		}
		mem_need = (trg_in_4k - cur_in_4k) * 8;
		if (s_info.freeram <= 10 || mem_need > s_info.freeram) {
			fprintf(stderr,
				"WARNING: Free memory is not enough! Please drop cache or extend more memory and retry\n"
				"WARNING: Memory needed is %"PRIu64", free memory is %"PRIu64"\n",
				(uint64_t)mem_need, (uint64_t)s_info.freeram);
			return -1;
		}
	}
	*shrink = !extend;

	return 0;
}

/**
 * @brief prompt and get user confirm input
 *
 * @param str, prompt string
 *
 * @return 0, canceled; 1 confirmed
 */
static int confirm_change(const char *str)
{
	unsigned char confirm;

	fprintf(stderr, "WARNING: %s.\n"
			"Use the force [--force] option to suppress this warning.\n", str);

	fprintf(stderr, "Confirm Y/y, Others cancel:\n");
	confirm = (unsigned char)fgetc(stdin);
	if (confirm != 'y' && confirm != 'Y') {
		fprintf(stderr, "Canceled.\n");
		return 0;
	}
	fprintf(stderr, "Sending operation ...\n");
	return 1;
}

static int sfx_change_cap(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	char *desc = "dynamic change capacity";
	const char *cap_gb = "cap size in GB";
	const char *cap_byte = "cap size in byte";
	const char *force = "The \"I know what I'm doing\" flag, skip confirmation before sending command";
	struct nvme_dev *dev;
	struct sfx_device_config dev_cfg;
	__u64 cap_in_4k = 0;
	__u64 cap_in_sec = 0;
	int shrink = 0;
	int err = 0;

	struct config {
		__u64 cap_in_byte;
		__u32 capacity_in_gb;
		bool  force;
	};

	struct config cfg = {};

	OPT_ARGS(opts) = {
		OPT_UINT("cap",			'c',	&cfg.capacity_in_gb,	cap_gb),
		OPT_SUFFIX("cap-byte",	'z',	&cfg.cap_in_byte,		cap_byte),
		OPT_FLAG("force",		'f',	&cfg.force,				force),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	err = sfx_device_valid_check(dev, &dev_cfg);
	if (err)
		goto close_dev;

	if (dev_cfg.product_id != SFX_MYRTLE) {
		printf("ScaleFlux Only Myrtle support sfx-change-cap\n");
		goto close_dev;
	}

	cap_in_sec = IDEMA_CAP(cfg.capacity_in_gb);
	cap_in_4k = cap_in_sec >> 3;
	if (cfg.cap_in_byte)
		cap_in_4k = cfg.cap_in_byte >> 12;
	printf("%dG %"PRIu64"B %"PRIu64" 4K\n",
		cfg.capacity_in_gb, (uint64_t)cfg.cap_in_byte, (uint64_t)cap_in_4k);

	if (change_sanity_check(dev_fd(dev), cap_in_4k, &shrink)) {
		printf("ScaleFlux change-capacity: fail\n");
		err = -1;
		goto close_dev;
	}

	if (!cfg.force && shrink && !confirm_change("Changing Cap may irrevocably delete this device's data")) {
		err = -1;
		goto close_dev;
	}

	err = nvme_change_cap(dev_fd(dev), NVME_NSID_ALL, cap_in_4k);
	if (err)
		goto close_dev;

	printf("ScaleFlux change-capacity: success\n");
		ioctl(dev_fd(dev), BLKRRPART);

close_dev:
	dev_close(dev);
ret:
	if (err > 0)
		nvme_show_status(err);
	return err;
}

static int nvme_parse_evtlog(void *pevent_log_info, __u32 log_len, char *output)
{
	__u32 offset = 0;
	__u32 length = log_len;
	__u16 fw_core;
	__u64 fw_time;
	__u8  code_level;
	__u8  code_type;
	char  str_buffer[512];
	__u32 str_pos;
	FILE *fd;
	int   err = 0;

	enum sfx_evtlog_level {
		sfx_evtlog_level_warning,
		sfx_evtlog_level_error,
	};

	const char *sfx_evtlog_warning[4] = {
		"RESERVED",
		"TOO_MANY_BB",
		"LOW_SPACE",
		"HIGH_TEMPERATURE"
	};

	const char *sfx_evtlog_error[14] = {
		"RESERVED",
		"HAS_ASSERT",
		"HAS_PANIC_DUMP",
		"INVALID_FORMAT_CAPACITY",
		"MAT_FAILED",
		"FREEZE_DUE_TO_RECOVERY_FAILED",
		"RFS_BROKEN",
		"MEDIA_ERR_ON_PAGE_IN",
		"MEDIA_ERR_ON_MPAGE_HEADER",
		"CAPACITOR_BROKEN",
		"READONLY_DUE_TO_RECOVERY_FAILED",
		"RD_ERR_IN_GSD_RECOVERY",
		"RD_ERR_ON_PF_RECOVERY",
		"MEDIA_ERR_ON_FULL_RECOVERY"
	};

	struct sfx_nvme_evtlog_info {
		__u16     time_stamp[4];
		__u64     magic1;
		__u8      reverse[10];
		char      evt_name[32];
		__u64     magic2;
		char      fw_ver[24];
		char      bl2_ver[32];
		__u16     code;
		__u16     assert_id;
	} __packed;

	struct sfx_nvme_evtlog_info *info = NULL;

	fd = fopen(output, "w+");
	if (!fd) {
		fprintf(stderr, "Failed to open %s file to write\n", output);
		err = ENOENT;
		goto ret;
	}

	while (length > 0) {
		info = (struct sfx_nvme_evtlog_info *)(pevent_log_info + offset);

		if ((info->magic1 == 0x474F4C545645) &&
			(info->magic2 == 0x38B0B3ABA9BA)) {

			memset(str_buffer, 0, 512);
			str_pos = 0;

			fw_core = info->time_stamp[3];
			snprintf(str_buffer + str_pos, 16, "[%d-", fw_core);
			str_pos = strlen(str_buffer);

			fw_time = ((__u64)info->time_stamp[2] << 32) + ((__u64)info->time_stamp[1] << 16) + (__u64)info->time_stamp[0];
			convert_ts(fw_time, str_buffer + str_pos);
			str_pos = strlen(str_buffer);

			strcpy(str_buffer + str_pos, "]    event-log:\n");
			str_pos = strlen(str_buffer);

			snprintf(str_buffer + str_pos, 128,
				 "  > fw_version:         %s\n  > bl2_version:        %s\n",
				 info->fw_ver, info->bl2_ver);
			str_pos = strlen(str_buffer);

			code_level = (info->code & 0x100) >> 8;
			code_type  = (info->code % 0x100);
			if (code_level == sfx_evtlog_level_warning) {
				snprintf(str_buffer + str_pos, 128,
					 "  > error_str:          [WARNING][%s]\n\n",
					 sfx_evtlog_warning[code_type]);
			} else {
				if (info->assert_id)
					snprintf(str_buffer + str_pos, 128,
						 "  > error_str:          [ERROR][%s]\n  > assert_id:          %d\n\n",
						 sfx_evtlog_error[code_type], info->assert_id);
				else
					snprintf(str_buffer + str_pos, 128,
						 "  > error_str:          [ERROR][%s]\n\n",
						 sfx_evtlog_error[code_type]);
			}
			str_pos = strlen(str_buffer);

			if (fwrite(str_buffer, 1, str_pos, fd) != str_pos) {
				fprintf(stderr, "Failed to write parse result to output file\n");
				goto close_fd;
			}
		}

		offset++;
		length--;

		if (!(offset % (log_len / 100)) || (offset == log_len))
			util_spinner("Parse", (float) (offset) / (float) (log_len));
	}

	printf("\nParse-evtlog: Success\n");

close_fd:
	fclose(fd);
ret:
	if (err > 0)
		nvme_show_status(err);
	return err;
}

static int nvme_dump_evtlog(struct nvme_dev *dev, struct sfx_device_config *dev_cfg,
				__u32 storage_medium, char *file, bool parse, char *output)
{
	struct nvme_persistent_event_log pevent;
	void *pevent_log_info;
	_cleanup_huge_ struct nvme_mem_huge mh = { 0, };
	__u8  lsp_base;
	__u64 offset = 0;
	__u64 length = 0;
	__u64 log_len;
	__u32 single_len;
	int  err = 0;
	FILE *fd = NULL;
	struct nvme_get_log_args args = {
		.args_size	= sizeof(args),
		.fd		    = dev_fd(dev),
		.lid		= NVME_LOG_LID_PERSISTENT_EVENT,
		.nsid		= NVME_NSID_ALL,
		.lpo		= NVME_LOG_LPO_NONE,
		.lsp		= NVME_LOG_LSP_NONE,
		.lsi		= NVME_LOG_LSI_NONE,
		.rae		= false,
		.uuidx		= NVME_UUID_NONE,
		.csi		= NVME_CSI_NVM,
		.ot		    = false,
		.len		= 0,
		.log		= NULL,
		.timeout	= NVME_DEFAULT_IOCTL_TIMEOUT,
		.result		= NULL,
	};

	if (!storage_medium) {
		if (dev_cfg->product_id == SFX_MYRTLE)
			lsp_base = 0;
		else
			lsp_base = 8;
		single_len = 64 * 1024 - 4;
	} else {
		lsp_base = 4;
		single_len = 32 * 1024;
	}

	args.lsp = lsp_base + NVME_PEVENT_LOG_RELEASE_CTX;
	args.log = &pevent;
	args.len = sizeof(pevent);

	err = nvme_get_log(&args);
	if (err) {
		fprintf(stderr, "Unable to get evtlog lsp=0x%x, ret = 0x%x\n", args.lsp, err);
		goto ret;
	}

	args.lsp = lsp_base + NVME_PEVENT_LOG_EST_CTX_AND_READ;
	err = nvme_get_log(&args);
	if (err) {
		fprintf(stderr, "Unable to get evtlog lsp=0x%x, ret = 0x%x\n", args.lsp, err);
		goto ret;
	}

	log_len = le64_to_cpu(pevent.tll) - sizeof(pevent);
	if (log_len % 4)
		log_len = (log_len / 4 + 1) * 4;

	pevent_log_info = nvme_alloc_huge(single_len, &mh);
	if (!pevent_log_info) {
		err = ENOMEM;
		goto ret;
	}

	fd = fopen(file, "wb+");
	if (!fd) {
		fprintf(stderr, "Failed to open %s file to write\n", file);
		err = ENOENT;
		goto free_buf;
	}

	args.lsp = lsp_base + NVME_PEVENT_LOG_READ;
	args.log = pevent_log_info;
	length = log_len;
	while (length > 0) {
		args.lpo = offset;
		if (length > single_len) {
			args.len = single_len;
		} else {
			memset(args.log, 0, args.len);
			args.len = length;
		}
		err = nvme_get_log(&args);
		if (err) {
			fprintf(stderr, "Unable to get evtlog offset=0x%llx len 0x%x ret = 0x%x\n", offset, args.len, err);
			goto close_fd;
		}

		if (fwrite(args.log, 1, args.len, fd) != args.len) {
			fprintf(stderr, "Failed to write evtlog to file\n");
			goto close_fd;
		}

		offset  += args.len;
		length  -= args.len;
		util_spinner("Dump", (float) (offset) / (float) (log_len));
	}

	printf("\nDump-evtlog: Success File:%s Size:%llu\n", file, log_len);

	nvme_free_huge(&mh);
	fclose(fd);

	if (!parse) {
		goto ret;
	}

	if (dev_cfg->product_id != SFX_MYRTLE) {
		printf("Plaintext evtlog, no parsing required\n");
		goto ret;
	}

	pevent_log_info = nvme_alloc_huge(log_len, &mh);
	if (!pevent_log_info) {
		fprintf(stderr, "Failed to alloc enough memory 0x%llx to parse evtlog\n", log_len);
		err = ENOMEM;
		goto ret;
	}

	fd = fopen(file, "rb");
	if (!fd) {
		fprintf(stderr, "Failed to open %s file to read\n", file);
		err = ENOENT;
		goto free_buf;
	}

	if (fread(pevent_log_info, 1, log_len, fd) != log_len) {
		fprintf(stderr, "Failed to read evtlog to buffer\n");
		err = EIO;
		goto close_fd;
	}

	err = nvme_parse_evtlog(pevent_log_info, log_len, output);

close_fd:
	fclose(fd);
free_buf:
	nvme_free_huge(&mh);
ret:
	if (err > 0)
		nvme_show_status(err);
	return err;
}

static int sfx_dump_evtlog(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	char *desc = "dump evtlog into file and parse";
	const char *file = "evtlog file(required)";
	const char *storage_medium = "evtlog storage medium\n"
					 "0: nand(default) 1: nor";
	const char *parse = "parse error & warning evtlog from evtlog file";
	const char *output = "parse result output file";
	struct sfx_device_config dev_cfg;
	struct nvme_dev *dev;
	int err = 0;

	struct config {
		char *file;
		__u32 storage_medium;
		bool  parse;
		char *output;
	};
	struct config cfg = {};

	OPT_ARGS(opts) = {
		OPT_FILE("file",           'f', &cfg.file,           file),
		OPT_UINT("storage_medium", 's', &cfg.storage_medium, storage_medium),
		OPT_FLAG("parse",          'p', &cfg.parse,          parse),
		OPT_FILE("output",         'o', &cfg.output,         output),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	err = sfx_device_valid_check(dev, &dev_cfg);
	if (err)
		goto close_dev;

	if (!cfg.file) {
		fprintf(stderr, "file required param\n");
		err = EINVAL;
		goto close_dev;
	}

	if (cfg.parse && !cfg.output) {
		fprintf(stderr, "output file required if evtlog need be parsed\n");
		err = EINVAL;
		goto close_dev;
	}

	err = nvme_dump_evtlog(dev, &dev_cfg, cfg.storage_medium, cfg.file, cfg.parse, cfg.output);

close_dev:
	dev_close(dev);
ret:
	if (err > 0)
		nvme_show_status(err);
	return err;
}

static int sfx_exit_write_reject(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	struct nvme_dev *dev;
	struct sfx_device_config dev_cfg;
	unsigned int status = 0;
	char *desc = "exit write reject mode";
	int err = 0;

	OPT_ARGS(opts) = {
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	err = sfx_device_valid_check(dev, &dev_cfg);
	if (err)
		goto close_dev;

	if (dev_cfg.product_id == SFX_MYRTLE) {
		printf("ScaleFlux Myrtle not support sfx-exit-write-reject\n");
		goto close_dev;
	}

	err = sfx_read_cust_data(dev_fd(dev), &status, sizeof(status), 0x89, 0, 0, 0, 0);
	if (err)
		goto close_dev;

	switch(status) {
		case 1:
			printf("The device is in normal state!\n");
			break;
		case 2:
			printf("The extended capacity has not been fully utilized!\n");
			break;
		case 3:
			printf("The number of capacity expansions has reached the limit!\n");
			break;
		default:
			printf("exit write reject mode success!\n");
			break;
	}	

close_dev:
	dev_close(dev);
ret:
	if (err > 0)
		nvme_show_status(err);
	return err;
}

static int sfx_get_pcie_status(const char *pcie_slot, char *pcie_status, size_t size)
{
	static const char *pcie_warn_list[] = {
		"UncorrErr+",
		"FatalErr+",
		"EqualizationPhase3-",
		"DLP+",
		"SDES+",
		"TLP+",
		"FCP+",
		"CmpltTO+",
		"CmpltAbrt+",
		"UnxCmplt+",
		"RxOF+",
		"MalfTLP+",
		"ECRC+",
		"ACSViol+",
		NULL
	};

	char cmd[128] = {};
	char line[128] = {};
	char line_tmp[128] = {};
	char *token;
	__u32 pcie_uncorr_err = 0, pcie_fatal_err = 0, pcie_other_err = 0;
	FILE *fp;

	snprintf(cmd, sizeof(cmd), "lspci -vvv -s %s", pcie_slot);

	fp = popen(cmd, "r");
	if (!fp) {
		fprintf(stderr, "popen %s fail!\n", cmd);
		return -1;
	}

	while (fgets(line, sizeof(line), fp)) {
		if (strstr(line, "UESta:") || strstr(line, "DevSta:")) {
			strncpy(line_tmp, line, sizeof(line_tmp) - 1);
			line_tmp[sizeof(line_tmp) - 1] = '\0';
			token = strtok(line_tmp, " \t");
			while(token) {
				for (int i=0; pcie_warn_list[i] != NULL; i++) {
					if (!strcmp(token, pcie_warn_list[i])) {
						switch(i) {
						case 0:
							pcie_uncorr_err = 1;
							break;
						case 1:
							pcie_fatal_err = 1;
							break;
						default:
							pcie_other_err = 1;
							break;
						}
					}
				}
				token = strtok(NULL, " \t");
			}
		}
	}

	memset(pcie_status, 0, size);
	snprintf(pcie_status, size, "%s", (pcie_uncorr_err != 0 || pcie_fatal_err != 0 || pcie_other_err != 0) ? "Warning":"Good");

	pclose(fp);
	return 0;
}

static int sfx_status(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Get ScaleFlux specific status information and print it";
	const char *json_desc = "Print output in JSON format, otherwise human readable";
	struct nvme_dev *dev;
	struct nvme_id_ctrl id_ctrl = { 0 };
	struct extended_health_info sfx_smart = { 0 };
	struct nvme_smart_log smart_log = { 0 };
	struct nvme_additional_smart_log add_smart_log = { 0 };
	struct sfx_device_config dev_cfg;
	struct sfx_freespace_ctx freespace_ctx = { 0 };
	int err, len, oos_extended_capacity;
	char pci_ssvid[7], link_speed[20], link_width[5], link_string[40], buffer[512];
	char numa_node[5], form_factor[15], temperature[10], io_speed[15];
	char serial_number[21], model_number[41], firmware_revision[9], pcie_status[9];
	struct json_object *root, *dev_stats, *link_stats, *crit_stats;
	double write_amp;

	struct config {
		bool json;
	};
	struct config cfg = {};

	OPT_ARGS(opts) = {
		OPT_FLAG("json-print", 'j', &cfg.json, json_desc),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	err = sfx_device_valid_check(dev, &dev_cfg);
	if (err)
		goto ret;

	err = sfx_read_sys_device(dev_cfg.pcie_slot, "subsystem_vendor", pci_ssvid, sizeof(pci_ssvid));
	if (err)
		goto close_dev;

	err = sfx_read_sys_device(dev_cfg.pcie_slot, "current_link_speed", link_speed, sizeof(link_speed));
	if (err)
		goto close_dev;

	// Ending string before "PCIe"
	for (len = 0; (len+2) < 20 && link_speed[len+2] != '\0'; ++len) {
		if (link_speed[len] == '/' && link_speed[len+1] == 's')
			link_speed[len+2] = '\0';
	}

	err = sfx_read_sys_device(dev_cfg.pcie_slot, "current_link_width", link_width, sizeof(link_width));
	if (err)
		goto close_dev;

	snprintf(link_string, 40, "Speed %s, Width x%s", link_speed, link_width);

	err = sfx_read_sys_device(dev_cfg.pcie_slot, "numa_node", numa_node, sizeof(numa_node));
	if (err)
		goto close_dev;

	err = sfx_get_pcie_status(dev_cfg.pcie_slot, pcie_status, sizeof(pcie_status));
	if (err)
		goto close_dev;

	//Populate id-ctrl
	err = nvme_identify_ctrl(dev_fd(dev), &id_ctrl);
	if (err) {
		fprintf(stderr, "Unable to read nvme_identify_ctrl() error code:%x\n", err);
		goto close_dev;
	}
	//Re-format specific fields so they can be safely treated as strings later
	serial_number[20] = '\0';
	memcpy(serial_number, id_ctrl.sn, 20);
	model_number[40] = '\0';
	memcpy(model_number, id_ctrl.mn, 40);
	firmware_revision[8] = '\0';
	memcpy(firmware_revision, id_ctrl.fr, 8);

	//Populate SMART log (0x02)
	err = nvme_cli_get_log_smart(dev, NVME_NSID_ALL, false, &smart_log);
	if (err) {
		perror("Could not read SMART log (0x02)");
		goto close_dev;
	}

	snprintf(temperature, 10, "%li", kelvin_to_celsius(smart_log.temperature[1]<<8 | smart_log.temperature[0]));

	err = nvme_get_log_simple(dev_fd(dev), dev_cfg.smartlog_id, sizeof(sfx_smart), (void *)&sfx_smart);
	if (err) {
		perror("Could not read ScaleFlux SMART log");
		goto close_dev;
	}

	switch (sfx_smart.opn[3]) {
	case 'P':
		snprintf(form_factor, 15, "%s", "AIC");
		break;
	case 'U':
		snprintf(form_factor, 15, "%s", (sfx_smart.opn[4] == '8')?"U.3":"U.2");
		break;
	case 'E':
		snprintf(form_factor, 15, "%s", "E1.S");
		break;
	case 'F':
		snprintf(form_factor, 15, "%s", "E3.S");
		break;
	default:
		snprintf(form_factor, 15, "%s", "Incorrect OPN");
	}

	//Populate Additional SMART log (0xCA)
	err = nvme_get_nsid_log(dev_fd(dev), false, 0xca, NVME_NSID_ALL, sizeof(struct nvme_additional_smart_log), (void *)&add_smart_log);
	if (err) {
		perror("Could not read Additional SMART log");
		goto close_dev;
	}

	//OK with the '-nan' if host_bytes_written is zero
	write_amp = int48_to_long(add_smart_log.nand_bytes_written.raw)/(1.0 * int48_to_long(add_smart_log.host_bytes_written.raw));

	//Get SFX freespace information
	err = nvme_query_cap(dev_fd(dev), NVME_NSID_ALL, sizeof(freespace_ctx), &freespace_ctx);
	if (err)
		goto close_dev;

	//Parse IO Speed information
	memset(&io_speed, 0, 15);
	switch (sfx_smart.io_speed) {
	case 1:
		if (dev_cfg.product_id == SFX_MYRTLE)
			strncpy(io_speed, "2.5MB/s", sizeof(io_speed) - 1);
		else
			strncpy(io_speed, "10MB/s", sizeof(io_speed) - 1);
		break;
	case 2:
		if (dev_cfg.product_id == SFX_MYRTLE)
			strncpy(io_speed, "128KB/s", sizeof(io_speed) - 1);
		else
			strncpy(io_speed, "512KB/s", sizeof(io_speed) - 1);
		break;
	case 3:
		strncpy(io_speed, "Write Reject", sizeof(io_speed) - 1);
		break;
	default:
		strncpy(io_speed, "Normal", sizeof(io_speed) - 1);
	}

	if (sfx_smart.sfx_critical_warning & SFX_CRIT_OVER_CAP) {
		err = sfx_read_cust_data(dev_fd(dev), &oos_extended_capacity, sizeof(oos_extended_capacity), 0x88, 0, 0, 0, 0);
		if (err)
			goto close_dev;
		oos_extended_capacity = oos_extended_capacity *16;
	}

	if (sfx_smart.comp_ratio < 100)
		sfx_smart.comp_ratio = 100;
	else if (sfx_smart.comp_ratio > 800)
		sfx_smart.comp_ratio = 800;

	if (cfg.json) {
		root = json_create_object();
		json_object_add_value_string(root, "ScaleFlux Status", dev->name);

		dev_stats = json_create_object();
		link_stats = json_create_object();
		crit_stats = json_create_object();

		json_object_add_value_string(dev_stats, "PCIe Vendor ID", dev_cfg.vendor_id);
		json_object_add_value_string(dev_stats, "PCIe Subsystem Vendor ID", pci_ssvid);
		json_object_add_value_string(dev_stats, "Manufacturer", dev_cfg.vendor_name);
		json_object_add_value_string(dev_stats, "Model", model_number);
		json_object_add_value_string(dev_stats, "Serial Number", serial_number);
		json_object_add_value_string(dev_stats, "OPN", (char *)sfx_smart.opn);
		json_object_add_value_string(dev_stats, "Drive Type", form_factor);
		json_object_add_value_string(dev_stats, "Firmware Revision", firmware_revision);
		json_object_add_value_string(dev_stats, "Temperature [C]", temperature);
		json_object_add_value_uint(dev_stats, "Power Consumption [mW]", sfx_smart.power_mw_consumption);
		json_object_add_value_string(dev_stats, "Atomic Write Mode", "On");
		json_object_add_value_int(dev_stats, "Percentage Used", smart_log.percent_used);
		json_object_add_value_string(dev_stats, "Data Read", uint128_t_to_si_string(le128_to_cpu(smart_log.data_units_read), 1000 * 512));
		json_object_add_value_string(dev_stats, "Data Written", uint128_t_to_si_string(le128_to_cpu(smart_log.data_units_written), 1000 * 512));
		json_object_add_value_int(dev_stats, "Correctable Error Count", sfx_smart.pcie_rx_correct_errs);
		json_object_add_value_int(dev_stats, "Uncorrectable Error Count", sfx_smart.pcie_rx_uncorrect_errs);
		json_object_add_value_string(link_stats, "PCIe Link Width", link_width);
		json_object_add_value_string(link_stats, "PCIe Link Speed", link_speed);
		json_object_add_value_string(link_stats, "PCIe Device Status", pcie_status);
		json_object_add_value_object(dev_stats, "PCIe Link Status",	link_stats);
		if (sfx_smart.friendly_changecap_support) {
			json_object_add_value_int(dev_stats, "Current Formatted Capacity [GB]", sfx_smart.cur_formatted_capability);
			json_object_add_value_int(dev_stats, "Max Formatted Capacity [GB]", sfx_smart.max_formatted_capability);
			json_object_add_value_int(dev_stats, "Extendible Capacity LBA count", sfx_smart.extendible_cap_lbacount);
		} else {
			json_object_add_value_int(dev_stats, "Formatted  Capacity [GB]", sfx_smart.max_formatted_capability);
		}
		json_object_add_value_int(dev_stats, "Provisioned Capacity [GB]", IDEMA_CAP2GB(sfx_smart.total_physical_capability));
		json_object_add_value_int(dev_stats, "Compression Ratio", sfx_smart.comp_ratio);
		json_object_add_value_int(dev_stats, "Physical Used Ratio",	sfx_smart.physical_usage_ratio);
		json_object_add_value_int(dev_stats, "Free Physical Space [GB]", IDEMA_CAP2GB(sfx_smart.free_physical_capability));
		json_object_add_value_string(dev_stats, "RSA Verify",  (sfx_smart.otp_rsa_en) ? "ON" : "OFF");
		json_object_add_value_string(dev_stats, "IO Speed",	io_speed);
		if (sfx_smart.sfx_critical_warning & SFX_CRIT_OVER_CAP) {
			json_object_add_value_int(dev_stats, "OOS Extended Capacity [GiB]", oos_extended_capacity);
		}
		json_object_add_value_string(dev_stats,	"NUMA Node", numa_node);
		json_object_add_value_int(dev_stats, "Indirection Unit [kiB]", (4*freespace_ctx.map_unit));
		json_object_add_value_double(dev_stats, "Lifetime WAF", write_amp);
		json_object_add_value_int(crit_stats, "Thermal Throttling On", (sfx_smart.temp_throttle_info));
		json_object_add_value_int(crit_stats, "Backup Capacitor Status Bad", (smart_log.critical_warning & 0x10));
		json_object_add_value_int(crit_stats, "Bad block exceeds threshold", (smart_log.critical_warning & 0x01));
		json_object_add_value_int(crit_stats, "Media Error", (smart_log.critical_warning & 0x04));
		json_object_add_value_int(crit_stats, "Read only mode", (smart_log.critical_warning & 0x08));
		json_object_add_value_int(crit_stats, "Power Failure Data Loss", (sfx_smart.sfx_critical_warning & SFX_CRIT_PWR_FAIL_DATA_LOSS));
		json_object_add_value_int(crit_stats, "Exceed physical capacity limitation", (sfx_smart.sfx_critical_warning & SFX_CRIT_OVER_CAP));
		json_object_add_value_int(crit_stats, "Read/Write lock mode", (sfx_smart.sfx_critical_warning & SFX_CRIT_RW_LOCK));

		json_object_add_value_object(dev_stats, "Critical Warning(s)", crit_stats);

		json_object_add_value_object(root, "Device stats", dev_stats);

		json_print_object(root, NULL);
		printf("\n");
		json_free_object(root);

	} else {
		// Re-using path variable to hold critical warning text
		//    order is to match sfx-status, done here to include color
		memset(buffer, 0, 512);
		len = snprintf(buffer, 512, FMT_RED "%s%s%s%s%s%s%s%s" FMT_RESET,
		(sfx_smart.temp_throttle_info)       ? " | Thermal Throttling On"                 : "",
		(smart_log.critical_warning & 0x10)  ? " | Backup Capacitor Status Bad"           : "",
		(smart_log.critical_warning & 0x01)  ? " | Bad block exceeds threshold"           : "",
		(smart_log.critical_warning & 0x04)  ? " | Media Error"                           : "",
		(smart_log.critical_warning & 0x08)  ? " | Read only mode"                        : "",
		(sfx_smart.sfx_critical_warning & SFX_CRIT_PWR_FAIL_DATA_LOSS) ? " | Power Failure Data Loss"             : "",
		(sfx_smart.sfx_critical_warning & SFX_CRIT_OVER_CAP)           ? " | Exceed physical capacity limitation" : "",
		(sfx_smart.sfx_critical_warning & SFX_CRIT_RW_LOCK)            ? " | Read/Write lock mode"                : ""
		);
		char *start = buffer + strlen(FMT_RED);
		if (!strncmp(start, " | ", 3)) {
			memmove(start, start + 3, strlen(start + 3) + 1);
		}
		if (strlen(start) <= 4)
			strcpy(buffer, "0");

		printf("%-35s%s%s\n",	"ScaleFlux Drive:",				"/dev/", dev->name);
		printf("%-35s%s\n",		"PCIe Vendor ID:",				dev_cfg.vendor_id);
		printf("%-35s%s\n",		"PCIe Subsystem Vendor ID:",	pci_ssvid);
		printf("%-35s%s\n",		"Manufacturer:",				dev_cfg.vendor_name);
		printf("%-35s%.*s\n",	"Model:", 40,					model_number);
		printf("%-35s%.*s\n",	"Serial Number:", 20,			serial_number);
		printf("%-35s%.*s\n",	"OPN:", 32,						sfx_smart.opn);
		printf("%-35s%s\n",		"Drive Type:",					form_factor);
		printf("%-35s%.*s\n",	"Firmware Revision:", 8,		firmware_revision);
		printf("%-35s%s C\n",	"Temperature:",					temperature);
		printf("%-35s%i mW\n",	"Power Consumption:",			sfx_smart.power_mw_consumption);
		printf("%-35s%s\n",		"Atomic Write mode:",			"ON");
		printf("%-35s%u%%\n",	"Percentage Used:",				smart_log.percent_used);
		printf("%-35s%s\n",		"Data Read:",				    uint128_t_to_si_string( le128_to_cpu(smart_log.data_units_read), 1000 * 512));
		printf("%-35s%s\n",		"Data Written:",			    uint128_t_to_si_string(le128_to_cpu(smart_log.data_units_written), 1000 * 512));
		printf("%-35s%i\n",		"Correctable Error Cnt:",		sfx_smart.pcie_rx_correct_errs);
		printf("%-35s%i\n",		"Uncorrectable Error Cnt:",		sfx_smart.pcie_rx_uncorrect_errs);
		printf("%-35s%s\n",		"PCIe Link Status:",			link_string);
		printf("%-35s%s\n",		"PCIe Device Status:",			pcie_status);
		if (sfx_smart.friendly_changecap_support) {
			printf("%-35s%"PRIu64" GB\n", "Current Formatted Capacity:",    (uint64_t)sfx_smart.cur_formatted_capability);
			printf("%-35s%"PRIu64" GB\n", "Max Formatted Capacity:",        (uint64_t)sfx_smart.max_formatted_capability);
			printf("%-35s%"PRIu64"\n",    "Extendible Capacity LBA count:", (uint64_t)sfx_smart.extendible_cap_lbacount);
		} else {
			printf("%-35s%"PRIu64" GB\n", "Formatted  Capacity:",           (uint64_t)sfx_smart.max_formatted_capability);
		}
		printf("%-35s%"PRIu64" GB\n", "Provisioned Capacity:",  (uint64_t)IDEMA_CAP2GB(sfx_smart.total_physical_capability));
		printf("%-35s%u%%\n",         "Compression Ratio:",	    sfx_smart.comp_ratio);
		printf("%-35s%u%%\n",         "Physical Used Ratio:",	sfx_smart.physical_usage_ratio);
		printf("%-35s%"PRIu64" GB\n", "Free Physical Space:",   (uint64_t)IDEMA_CAP2GB(sfx_smart.free_physical_capability));
		printf("%-35s%s\n",           "RSA Verify:",	        (sfx_smart.otp_rsa_en) ? "ON":"OFF");
		printf("%-35s%s\n",           "IO Speed:",				io_speed);
		if (sfx_smart.sfx_critical_warning & SFX_CRIT_OVER_CAP) {
			printf("%-35s%"PRIu64" GiB\n", "OOS Extended Capacity:", (uint64_t)oos_extended_capacity);
		}
		printf("%-35s%s\n",           "NUMA Node:",				numa_node);
		printf("%-35s%"PRIu64"K\n",   "Indirection Unit:",      (uint64_t)(4*freespace_ctx.map_unit));
		printf("%-35s%.2f\n",	      "Lifetime WAF:",			write_amp);
		printf("%-35s%s\n",           "Critical Warning(s):",	buffer);
	}

close_dev:
	dev_close(dev);
ret:
	if (err > 0)
		nvme_show_status(err);
	return err;
}

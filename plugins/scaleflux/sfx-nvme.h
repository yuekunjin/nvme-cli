/* SPDX-License-Identifier: GPL-2.0-or-later */
#undef CMD_INC_FILE
#define CMD_INC_FILE plugins/scaleflux/sfx-nvme

#if !defined(SFX_NVME) || defined(CMD_HEADER_MULTI_READ)
#define SFX_NVME

#include "cmd.h"

PLUGIN(NAME("sfx", "ScaleFlux vendor specific extensions", NVME_VERSION),
	COMMAND_LIST(
		ENTRY("smart-log-add", "Retrieve ScaleFlux SMART Log, show it", sfx_get_additional_smart_log)
		ENTRY("lat-stats", "Retrieve ScaleFlux IO Latency Statistics log, show it", sfx_get_lat_stats_log)
		ENTRY("query-cap", "Query current capacity info", sfx_query_cap_info)
		ENTRY("change-cap", "Dynamic change capacity", sfx_change_cap)
		ENTRY("dump-evtlog", "Dump evtlog into file and parse warning & error log", sfx_dump_evtlog)
		ENTRY("exit-write-reject", "Exit write reject mode", sfx_exit_write_reject)
		ENTRY("status", "Retrieve the ScaleFlux status output, show it", sfx_status)
	)
);

#endif

#include "define_cmd.h"

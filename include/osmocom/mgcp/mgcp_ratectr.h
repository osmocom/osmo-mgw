#pragma once

/* NOTE: When adding counters, also the dump_ratectr_* routines in vty.c must be updated. */

struct mgcp_ratectr_global {
	/* Rate counter group which contains stats for generic MGCP events. */
	struct rate_ctr_group *mgcp_general_ctr_group;
};

struct mgcp_ratectr_trunk {
	/* Rate counter group which contains stats for processed CRCX commands. */
	struct rate_ctr_group *mgcp_crcx_ctr_group;
	/* Rate counter group which contains stats for processed MDCX commands. */
	struct rate_ctr_group *mgcp_mdcx_ctr_group;
	/* Rate counter group which contains stats for processed DLCX commands. */
	struct rate_ctr_group *mgcp_dlcx_ctr_group;
	/* Rate counter group which aggregates stats of individual RTP connections. */
	struct rate_ctr_group *all_rtp_conn_stats;
};

int mgcp_ratectr_global_alloc(void *ctx, struct mgcp_ratectr_global *ratectr);
int mgcp_ratectr_trunk_alloc(void *ctx, struct mgcp_ratectr_trunk *ratectr);

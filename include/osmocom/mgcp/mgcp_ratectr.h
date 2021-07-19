#pragma once

/* Global MCGP general rate counters */
enum {
	MGCP_GENERAL_RX_MSGS_TOTAL,
	MGCP_GENERAL_RX_MSGS_RETRANSMITTED,
	MGCP_GENERAL_RX_MSGS_HANDLED,
	MGCP_GENERAL_RX_MSGS_UNHANDLED,
	MGCP_GENERAL_RX_FAIL_MSG_PARSE,
	MGCP_GENERAL_RX_FAIL_NO_ENDPOINT,
};

/* Trunk-global MCGP CRCX related rate counters */
enum {
	MGCP_CRCX_SUCCESS,
	MGCP_CRCX_FAIL_BAD_ACTION,
	MGCP_CRCX_FAIL_UNHANDLED_PARAM,
	MGCP_CRCX_FAIL_MISSING_CALLID,
	MGCP_CRCX_FAIL_INVALID_MODE,
	MGCP_CRCX_FAIL_LIMIT_EXCEEDED,
	MGCP_CRCX_FAIL_UNKNOWN_CALLID,
	MGCP_CRCX_FAIL_ALLOC_CONN,
	MGCP_CRCX_FAIL_NO_REMOTE_CONN_DESC,
	MGCP_CRCX_FAIL_START_RTP,
	MGCP_CRCX_FAIL_REJECTED_BY_POLICY,
	MGCP_CRCX_FAIL_NO_OSMUX,
	MGCP_CRCX_FAIL_INVALID_CONN_OPTIONS,
	MGCP_CRCX_FAIL_CODEC_NEGOTIATION,
	MGCP_CRCX_FAIL_BIND_PORT,
	MGCP_CRCX_FAIL_AVAIL,
	MGCP_CRCX_FAIL_CLAIM,
};

/* Trunk-global MCGP MDCX related rate counters */
enum {
	MGCP_MDCX_SUCCESS,
	MGCP_MDCX_FAIL_WILDCARD,
	MGCP_MDCX_FAIL_NO_CONN,
	MGCP_MDCX_FAIL_INVALID_CALLID,
	MGCP_MDCX_FAIL_INVALID_CONNID,
	MGCP_MDCX_FAIL_UNHANDLED_PARAM,
	MGCP_MDCX_FAIL_NO_CONNID,
	MGCP_MDCX_FAIL_CONN_NOT_FOUND,
	MGCP_MDCX_FAIL_INVALID_MODE,
	MGCP_MDCX_FAIL_INVALID_CONN_OPTIONS,
	MGCP_MDCX_FAIL_NO_REMOTE_CONN_DESC,
	MGCP_MDCX_FAIL_START_RTP,
	MGCP_MDCX_FAIL_REJECTED_BY_POLICY,
	MGCP_MDCX_DEFERRED_BY_POLICY,
	MGCP_MDCX_FAIL_AVAIL,
};

/* Trunk-global MCGP DLCX related rate counters */
enum {
	MGCP_DLCX_SUCCESS,
	MGCP_DLCX_FAIL_NO_CONN,
	MGCP_DLCX_FAIL_INVALID_CALLID,
	MGCP_DLCX_FAIL_INVALID_CONNID,
	MGCP_DLCX_FAIL_UNHANDLED_PARAM,
	MGCP_DLCX_FAIL_REJECTED_BY_POLICY,
	MGCP_DLCX_DEFERRED_BY_POLICY,
	MGCP_DLCX_FAIL_AVAIL,
};

/* Trunk-global E1 related counters */
enum {
        E1_I460_TRAU_RX_FAIL_CTR,
        E1_I460_TRAU_TX_FAIL_CTR,
        E1_I460_TRAU_MUX_EMPTY_CTR,
};

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
	/* Rate counter group which contains stats for E1 events (only valid for E1 trunks) */
	struct rate_ctr_group *e1_stats;
};

struct mgcp_config;
struct mgcp_trunk;

int mgcp_ratectr_global_alloc(struct mgcp_config *cfg);
int mgcp_ratectr_trunk_alloc(struct mgcp_trunk *trunk);

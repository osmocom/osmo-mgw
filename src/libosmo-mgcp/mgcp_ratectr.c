/* A Media Gateway Control Protocol Media Gateway: RFC 3435 */
/* rate-counter implementation */

/*
 * (C) 2009-2012 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009-2012 by On-Waves
 * (C) 2017-2020 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <errno.h>
#include <osmocom/core/stats.h>
#include <osmocom/core/stat_item.h>
#include <osmocom/mgcp/mgcp_conn.h>
#include <osmocom/mgcp/mgcp_trunk.h>
#include <osmocom/mgcp/mgcp_protocol.h>
#include <osmocom/mgcp/mgcp_endp.h>
#include <osmocom/mgcp/mgcp_ratectr.h>

static const struct rate_ctr_desc mgcp_general_ctr_desc[] = {
	/* rx_msgs = rx_msgs_retransmitted + rx_msgs_handled + rx_msgs_unhandled + err_rx_msg_parse + err_rx_no_endpoint */
	[MGCP_GENERAL_RX_MSGS_TOTAL] = { "mgcp:rx_msgs", "total number of MGCP messages received." },
	[MGCP_GENERAL_RX_MSGS_RETRANSMITTED] = { "mgcp:rx_msgs_retransmitted", "number of received retransmissions." },
	[MGCP_GENERAL_RX_MSGS_HANDLED] = { "mgcp:rx_msgs_handled", "number of handled MGCP messages." },
	[MGCP_GENERAL_RX_MSGS_UNHANDLED] = { "mgcp:rx_msgs_unhandled", "number of unhandled MGCP messages." },
	[MGCP_GENERAL_RX_FAIL_MSG_PARSE] = { "mgcp:err_rx_msg_parse", "error parsing MGCP message." },
	[MGCP_GENERAL_RX_FAIL_NO_ENDPOINT] =
	    { "mgcp:err_rx_no_endpoint", "can't find MGCP endpoint, probably we've used all allocated endpoints." },
};

const static struct rate_ctr_group_desc mgcp_general_ctr_group_desc = {
	.group_name_prefix = "mgcp",
	.group_description = "mgcp general statistics",
	.class_id = OSMO_STATS_CLASS_GLOBAL,
	.num_ctr = ARRAY_SIZE(mgcp_general_ctr_desc),
	.ctr_desc = mgcp_general_ctr_desc
};

static const struct rate_ctr_desc mgcp_crcx_ctr_desc[] = {
	[MGCP_CRCX_SUCCESS] = { "crcx:success", "CRCX command processed successfully." },
	[MGCP_CRCX_FAIL_BAD_ACTION] = { "crcx:bad_action", "bad action in CRCX command." },
	[MGCP_CRCX_FAIL_UNHANDLED_PARAM] = { "crcx:unhandled_param", "unhandled parameter in CRCX command." },
	[MGCP_CRCX_FAIL_MISSING_CALLID] = { "crcx:missing_callid", "missing CallId in CRCX command." },
	[MGCP_CRCX_FAIL_INVALID_MODE] = { "crcx:invalid_mode", "invalid connection mode in CRCX command." },
	[MGCP_CRCX_FAIL_LIMIT_EXCEEDED] = { "crcx:limit_exceeded", "limit of concurrent connections was reached." },
	[MGCP_CRCX_FAIL_UNKNOWN_CALLID] = { "crcx:unkown_callid", "unknown CallId in CRCX command." },
	[MGCP_CRCX_FAIL_ALLOC_CONN] = { "crcx:alloc_conn_fail", "connection allocation failure." },
	[MGCP_CRCX_FAIL_NO_REMOTE_CONN_DESC] =
	    { "crcx:no_remote_conn_desc", "no opposite end specified for connection." },
	[MGCP_CRCX_FAIL_START_RTP] = { "crcx:start_rtp_failure", "failure to start RTP processing." },
	[MGCP_CRCX_FAIL_NO_OSMUX] = { "crcx:no_osmux", "no osmux offered by peer." },
	[MGCP_CRCX_FAIL_INVALID_CONN_OPTIONS] = { "crcx:conn_opt", "connection options invalid." },
	[MGCP_CRCX_FAIL_CODEC_NEGOTIATION] = { "crcx:codec_nego", "codec negotiation failure." },
	[MGCP_CRCX_FAIL_BIND_PORT] = { "crcx:bind_port", "port bind failure." },
	[MGCP_CRCX_FAIL_AVAIL] = { "crcx:unavailable", "endpoint unavailable." },
	[MGCP_CRCX_FAIL_CLAIM] = { "crcx:claim", "endpoint can not be claimed." },
};

const static struct rate_ctr_group_desc mgcp_crcx_ctr_group_desc = {
	.group_name_prefix = "crcx",
	.group_description = "crxc statistics",
	.class_id = OSMO_STATS_CLASS_GLOBAL,
	.num_ctr = ARRAY_SIZE(mgcp_crcx_ctr_desc),
	.ctr_desc = mgcp_crcx_ctr_desc
};

static const struct rate_ctr_desc mgcp_mdcx_ctr_desc[] = {
	[MGCP_MDCX_SUCCESS] = { "mdcx:success", "MDCX command processed successfully." },
	[MGCP_MDCX_FAIL_WILDCARD] = { "mdcx:wildcard", "wildcard endpoint names in MDCX commands are unsupported." },
	[MGCP_MDCX_FAIL_NO_CONN] = { "mdcx:no_conn", "endpoint specified in MDCX command has no active connections." },
	[MGCP_MDCX_FAIL_INVALID_CALLID] = { "mdcx:callid", "invalid CallId specified in MDCX command." },
	[MGCP_MDCX_FAIL_INVALID_CONNID] = { "mdcx:connid", "invalid connection ID specified in MDCX command." },
	[MGCP_MDCX_FAIL_UNHANDLED_PARAM] = { "crcx:unhandled_param", "unhandled parameter in MDCX command." },
	[MGCP_MDCX_FAIL_NO_CONNID] = { "mdcx:no_connid", "no connection ID specified in MDCX command." },
	[MGCP_MDCX_FAIL_CONN_NOT_FOUND] =
	    { "mdcx:conn_not_found", "connection specified in MDCX command does not exist." },
	[MGCP_MDCX_FAIL_INVALID_MODE] = { "mdcx:invalid_mode", "invalid connection mode in MDCX command." },
	[MGCP_MDCX_FAIL_INVALID_CONN_OPTIONS] = { "mdcx:conn_opt", "connection options invalid." },
	[MGCP_MDCX_FAIL_NO_REMOTE_CONN_DESC] =
	    { "mdcx:no_remote_conn_desc", "no opposite end specified for connection." },
	[MGCP_MDCX_FAIL_START_RTP] = { "mdcx:start_rtp_failure", "failure to start RTP processing." },
	[MGCP_MDCX_FAIL_AVAIL] = { "mdcx:unavailable", "endpoint unavailable." },
};

const static struct rate_ctr_group_desc mgcp_mdcx_ctr_group_desc = {
	.group_name_prefix = "mdcx",
	.group_description = "mdcx statistics",
	.class_id = OSMO_STATS_CLASS_GLOBAL,
	.num_ctr = ARRAY_SIZE(mgcp_mdcx_ctr_desc),
	.ctr_desc = mgcp_mdcx_ctr_desc
};

static const struct rate_ctr_desc mgcp_dlcx_ctr_desc[] = {
	[MGCP_DLCX_SUCCESS] = { "dlcx:success", "DLCX command processed successfully." },
	[MGCP_DLCX_FAIL_NO_CONN] = { "dlcx:no_conn", "endpoint specified in DLCX command has no active connections." },
	[MGCP_DLCX_FAIL_INVALID_CALLID] =
	    { "dlcx:callid", "CallId specified in DLCX command mismatches endpoint's CallId ." },
	[MGCP_DLCX_FAIL_INVALID_CONNID] =
	    { "dlcx:connid", "connection ID specified in DLCX command does not exist on endpoint." },
	[MGCP_DLCX_FAIL_UNHANDLED_PARAM] = { "dlcx:unhandled_param", "unhandled parameter in DLCX command." },
	[MGCP_DLCX_FAIL_AVAIL] = { "dlcx:unavailable", "endpoint unavailable." },
};

const static struct rate_ctr_group_desc mgcp_dlcx_ctr_group_desc = {
	.group_name_prefix = "dlcx",
	.group_description = "dlcx statistics",
	.class_id = OSMO_STATS_CLASS_GLOBAL,
	.num_ctr = ARRAY_SIZE(mgcp_dlcx_ctr_desc),
	.ctr_desc = mgcp_dlcx_ctr_desc
};

static const struct rate_ctr_desc e1_rate_ctr_desc[] = {
	[E1_I460_TRAU_RX_FAIL_CTR] = { "e1:rx_fail", "Inbound I.460 TRAU failures." },
	[E1_I460_TRAU_TX_FAIL_CTR] = { "e1:tx_fail", "Outbound I.460 TRAU failures." },
	[E1_I460_TRAU_MUX_EMPTY_CTR] = { "e1:i460", "Outbound I.460 MUX queue empty." }
};

const static struct rate_ctr_group_desc e1_rate_ctr_group_desc = {
	.group_name_prefix = "e1",
	.group_description = "e1 statistics",
	.class_id = OSMO_STATS_CLASS_GLOBAL,
	.num_ctr = ARRAY_SIZE(e1_rate_ctr_desc),
	.ctr_desc = e1_rate_ctr_desc
};

const static struct rate_ctr_group_desc all_rtp_conn_rate_ctr_group_desc = {
	.group_name_prefix = "all_rtp_conn",
	.group_description = "aggregated statistics for all rtp connections",
	.class_id = 1,
	.num_ctr = ARRAY_SIZE(all_rtp_conn_rate_ctr_desc),
	.ctr_desc = all_rtp_conn_rate_ctr_desc
};

/*! allocate global rate counters
 *  (called once at startup).
 *  \param[in] cfg mgw configuration for which the rate counters are allocated.
 *  \returns 0 on success, -EINVAL on failure. */
int mgcp_ratectr_global_alloc(struct mgcp_config *cfg)
{
	struct mgcp_ratectr_global *ratectr = &cfg->ratectr;
	static unsigned int general_rate_ctr_index = 0;
	char ctr_name[512];

	if (ratectr->mgcp_general_ctr_group == NULL) {
		ratectr->mgcp_general_ctr_group =
		    rate_ctr_group_alloc(cfg, &mgcp_general_ctr_group_desc, general_rate_ctr_index);
		if (!ratectr->mgcp_general_ctr_group)
			return -EINVAL;
		snprintf(ctr_name, sizeof(ctr_name), "%s:general", cfg->domain);
		rate_ctr_group_set_name(ratectr->mgcp_general_ctr_group, ctr_name);
		general_rate_ctr_index++;
	}
	return 0;
}

/*! free global rate counters
 *  (called once at process shutdown).
 *  \param[in] cfg mgw configuration for which the rate counters are allocated. */
void mgcp_ratectr_global_free(struct mgcp_config *cfg)
{
	struct mgcp_ratectr_global *ratectr = &cfg->ratectr;

	if (ratectr->mgcp_general_ctr_group) {
		rate_ctr_group_free(ratectr->mgcp_general_ctr_group);
		ratectr->mgcp_general_ctr_group = NULL;
	}
}

/*! allocate trunk specific rate counters
 *  (called once on trunk initialization).
 *  \param[in] trunk mgw trunk for which the rate counters are allocated.
 *  \returns 0 on success, -EINVAL on failure */
int mgcp_ratectr_trunk_alloc(struct mgcp_trunk *trunk)
{
	struct mgcp_ratectr_trunk *ratectr = &trunk->ratectr;
	static unsigned int crcx_rate_ctr_index = 0;
	static unsigned int mdcx_rate_ctr_index = 0;
	static unsigned int dlcx_rate_ctr_index = 0;
	static unsigned int all_rtp_conn_rate_ctr_index = 0;
	char ctr_name[256];

	if (ratectr->mgcp_crcx_ctr_group == NULL) {
		ratectr->mgcp_crcx_ctr_group =
		    rate_ctr_group_alloc(trunk, &mgcp_crcx_ctr_group_desc, crcx_rate_ctr_index);
		if (!ratectr->mgcp_crcx_ctr_group)
			return -EINVAL;
		snprintf(ctr_name, sizeof(ctr_name), "%s-%u:crcx", mgcp_trunk_type_strs_str(trunk->trunk_type),
			 trunk->trunk_nr);
		rate_ctr_group_set_name(ratectr->mgcp_crcx_ctr_group, ctr_name);
		crcx_rate_ctr_index++;
	}
	if (ratectr->mgcp_mdcx_ctr_group == NULL) {
		ratectr->mgcp_mdcx_ctr_group =
		    rate_ctr_group_alloc(trunk, &mgcp_mdcx_ctr_group_desc, mdcx_rate_ctr_index);
		if (!ratectr->mgcp_mdcx_ctr_group)
			return -EINVAL;
		snprintf(ctr_name, sizeof(ctr_name), "%s-%u:mdcx", mgcp_trunk_type_strs_str(trunk->trunk_type),
			 trunk->trunk_nr);
		rate_ctr_group_set_name(ratectr->mgcp_mdcx_ctr_group, ctr_name);
		mdcx_rate_ctr_index++;
	}
	if (ratectr->mgcp_dlcx_ctr_group == NULL) {
		ratectr->mgcp_dlcx_ctr_group =
		    rate_ctr_group_alloc(trunk, &mgcp_dlcx_ctr_group_desc, dlcx_rate_ctr_index);
		if (!ratectr->mgcp_dlcx_ctr_group)
			return -EINVAL;
		snprintf(ctr_name, sizeof(ctr_name), "%s-%u:dlcx", mgcp_trunk_type_strs_str(trunk->trunk_type),
			 trunk->trunk_nr);
		rate_ctr_group_set_name(ratectr->mgcp_dlcx_ctr_group, ctr_name);
		dlcx_rate_ctr_index++;
	}
	if (ratectr->all_rtp_conn_stats == NULL) {
		ratectr->all_rtp_conn_stats = rate_ctr_group_alloc(trunk, &all_rtp_conn_rate_ctr_group_desc,
								   all_rtp_conn_rate_ctr_index);
		if (!ratectr->all_rtp_conn_stats)
			return -EINVAL;
		snprintf(ctr_name, sizeof(ctr_name), "%s-%u:rtp_conn", mgcp_trunk_type_strs_str(trunk->trunk_type),
			 trunk->trunk_nr);
		rate_ctr_group_set_name(ratectr->all_rtp_conn_stats, ctr_name);
		all_rtp_conn_rate_ctr_index++;
	}

	/* E1 specific */
	if (trunk->trunk_type == MGCP_TRUNK_E1 && ratectr->e1_stats == NULL) {
		ratectr->e1_stats = rate_ctr_group_alloc(trunk, &e1_rate_ctr_group_desc, mdcx_rate_ctr_index);
		if (!ratectr->e1_stats)
			return -EINVAL;
		snprintf(ctr_name, sizeof(ctr_name), "%s-%u:e1", mgcp_trunk_type_strs_str(trunk->trunk_type),
			 trunk->trunk_nr);
		rate_ctr_group_set_name(ratectr->e1_stats, ctr_name);
		mdcx_rate_ctr_index++;
	}
	return 0;
}

/*! free trunk specific rate counters
 *  (called once when trunk is freed).
 *  \param[in] trunk mgw trunk on which the rate counters are allocated. */
void mgcp_ratectr_trunk_free(struct mgcp_trunk *trunk)
{
	struct mgcp_ratectr_trunk *ratectr = &trunk->ratectr;

	if (ratectr->mgcp_crcx_ctr_group) {
		rate_ctr_group_free(ratectr->mgcp_crcx_ctr_group);
		ratectr->mgcp_crcx_ctr_group = NULL;
	}
	if (ratectr->mgcp_mdcx_ctr_group) {
		rate_ctr_group_free(ratectr->mgcp_mdcx_ctr_group);
		ratectr->mgcp_mdcx_ctr_group = NULL;
	}
	if (ratectr->mgcp_dlcx_ctr_group) {
		rate_ctr_group_free(ratectr->mgcp_dlcx_ctr_group);
		ratectr->mgcp_dlcx_ctr_group = NULL;
	}
	if (ratectr->all_rtp_conn_stats) {
		rate_ctr_group_free(ratectr->all_rtp_conn_stats);
		ratectr->all_rtp_conn_stats = NULL;
	}

	/* E1 specific */
	if (ratectr->e1_stats) {
		rate_ctr_group_free(ratectr->e1_stats);
		ratectr->e1_stats = NULL;
	}
}

const struct osmo_stat_item_desc trunk_stat_desc[] = {
	[TRUNK_STAT_ENDPOINTS_TOTAL] = { "endpoints:total",
					 "Number of endpoints that exist on the trunk",
					 "", 60, 0 },
	[TRUNK_STAT_ENDPOINTS_USED] = { "endpoints:used",
					"Number of endpoints in use",
					"", 60, 0 },
};

const struct osmo_stat_item_group_desc trunk_statg_desc = {
	.group_name_prefix = "trunk",
	.group_description = "mgw trunk",
	.class_id = OSMO_STATS_CLASS_GLOBAL,
	.num_items = ARRAY_SIZE(trunk_stat_desc),
	.item_desc = trunk_stat_desc,
};

/*! allocate trunk specific stat items
 *  (called once on trunk initialization).
 *  \param[in] trunk for which the stat items are allocated.
 *  \returns 0 on success, -EINVAL on failure. */
int mgcp_stat_trunk_alloc(struct mgcp_trunk *trunk)
{
	struct mgcp_stat_trunk *stats = &trunk->stats;
	static unsigned int common_stat_index = 0;
	char stat_name[256];

	stats->common = osmo_stat_item_group_alloc(trunk, &trunk_statg_desc, common_stat_index);
	if (!stats->common)
		return -EINVAL;
	snprintf(stat_name, sizeof(stat_name), "%s-%u:common", mgcp_trunk_type_strs_str(trunk->trunk_type),
		 trunk->trunk_nr);
	osmo_stat_item_group_set_name(stats->common, stat_name);
	common_stat_index++;

	return 0;
}

/*! free trunk specific stat items
 *  (called once when trunk is freed).
 *  \param[in] trunk on which the stat items are allocated. */
void mgcp_stat_trunk_free(struct mgcp_trunk *trunk)
{
	struct mgcp_stat_trunk *stats = &trunk->stats;

	if (stats->common) {
		osmo_stat_item_group_free(stats->common);
		stats->common = NULL;
	}
}

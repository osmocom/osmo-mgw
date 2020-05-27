/* Message connection list handling */

/*
 * (C) 2017 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Philipp Maier
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

#pragma once

#include <osmocom/mgcp/mgcp_internal.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/rate_ctr.h>
#include <inttypes.h>

#define LOGPCONN(conn, cat, level, fmt, args...) \
LOGPENDP((conn)->endp, cat, level, "CI:%s " fmt, \
         (conn)->id, \
         ## args)

/* RTP connection related counters */
enum {
	IN_STREAM_ERR_TSTMP_CTR,
	OUT_STREAM_ERR_TSTMP_CTR,
        RTP_PACKETS_RX_CTR,
        RTP_OCTETS_RX_CTR,
        RTP_PACKETS_TX_CTR,
        RTP_OCTETS_TX_CTR,
        RTP_DROPPED_PACKETS_CTR,
        RTP_NUM_CONNECTIONS,
};

/* RTP per-connection statistics. Instances of the corresponding rate counter group
 * exist for the lifetime of an RTP connection.
 * Must be kept in sync with all_rtp_conn_rate_ctr_desc below */
static const struct rate_ctr_desc mgcp_conn_rate_ctr_desc[] = {
	[IN_STREAM_ERR_TSTMP_CTR] = {"stream_err_tstmp:in", "Inbound rtp-stream timestamp errors."},
	[OUT_STREAM_ERR_TSTMP_CTR] = {"stream_err_tstmp:out", "Outbound rtp-stream timestamp errors."},
	[RTP_PACKETS_RX_CTR] = {"rtp:packets_rx", "Inbound rtp packets."},
	[RTP_OCTETS_RX_CTR] = {"rtp:octets_rx", "Inbound rtp octets."},
	[RTP_PACKETS_TX_CTR] = {"rtp:packets_tx", "Outbound rtp packets."},
	[RTP_OCTETS_TX_CTR] = {"rtp:octets_tx", "Outbound rtp octets."},
	[RTP_DROPPED_PACKETS_CTR] = {"rtp:dropped", "dropped rtp packets."}
};

/* Aggregated RTP connection stats. These are updated when an RTP connection is freed.
 * Must be kept in sync with mgcp_conn_rate_ctr_desc above */
static const struct rate_ctr_desc all_rtp_conn_rate_ctr_desc[] = {
	[IN_STREAM_ERR_TSTMP_CTR] = {"all_rtp:err_tstmp_in", "Total inbound rtp-stream timestamp errors."},
	[OUT_STREAM_ERR_TSTMP_CTR] = {"all_rtp:err_tstmp_out", "Total outbound rtp-stream timestamp errors."},
	[RTP_PACKETS_RX_CTR] = {"all_rtp:packets_rx", "Total inbound rtp packets."},
	[RTP_OCTETS_RX_CTR] = {"all_rtp:octets_rx", "Total inbound rtp octets."},
	[RTP_PACKETS_TX_CTR] = {"all_rtp:packets_tx", "Total outbound rtp packets."},
	[RTP_OCTETS_TX_CTR] = {"all_rtp:octets_tx", "Total outbound rtp octets."},
	[RTP_DROPPED_PACKETS_CTR] = {"all_rtp:dropped", "Total dropped rtp packets."},

	/* This last counter does not exist in per-connection stats, only here. */
	[RTP_NUM_CONNECTIONS] = {"all_rtp:num_closed_conns", "Total number of rtp connections closed."}
};

struct mgcp_conn *mgcp_conn_alloc(void *ctx, struct mgcp_endpoint *endp,
				  enum mgcp_conn_type type, char *name);
struct mgcp_conn *mgcp_conn_get(struct mgcp_endpoint *endp, const char *id);
struct mgcp_conn_rtp *mgcp_conn_get_rtp(struct mgcp_endpoint *endp,
					const char *id);
void mgcp_conn_free(struct mgcp_endpoint *endp, const char *id);
void mgcp_conn_free_oldest(struct mgcp_endpoint *endp);
void mgcp_conn_free_all(struct mgcp_endpoint *endp);
char *mgcp_conn_dump(struct mgcp_conn *conn);
struct mgcp_conn *mgcp_find_dst_conn(struct mgcp_conn *conn);

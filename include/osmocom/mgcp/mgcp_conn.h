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

#include <osmocom/mgcp/mgcp.h>
#include <osmocom/mgcp/mgcp_common.h>
#include <osmocom/mgcp/mgcp_network.h>
#include <osmocom/mgcp/osmux.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/utils.h>
#include <osmocom/gsm/iuup.h>
#include <osmocom/mgcp/mgcp_rtp_end.h>
#include <inttypes.h>

#define LOGPCONN(conn, cat, level, fmt, args...) \
LOGPENDP((conn)->endp, cat, level, "CI:%s " fmt, \
         (conn)->id, \
         ## args)

#define LOG_CONN(conn, level, fmt, args...) \
	LOGP(DRTP, level, "(%s I:%s) " fmt, \
	     (conn)->endp ? (conn)->endp->name : "none", (conn)->id, ## args)

#define LOG_CONN_RTP(conn_rtp, level, fmt, args...) \
	LOG_CONN((conn_rtp)->conn, level, fmt, ## args)

/* Specific rtp connection type (see struct mgcp_conn_rtp) */
enum mgcp_conn_rtp_type {
	MGCP_RTP_DEFAULT	= 0,
	MGCP_RTP_OSMUX,
	MGCP_RTP_IUUP,
};
extern const struct value_string mgcp_conn_rtp_type_names[];
static inline const char *mgcp_conn_rtp_type_name(enum mgcp_conn_rtp_type val)
{
	return get_value_string(mgcp_conn_rtp_type_names, val);
}

/*! Connection type, specifies which member of the union "u" in mgcp_conn
 *  contains a useful connection description (currently only RTP) */
enum mgcp_conn_type {
	MGCP_CONN_TYPE_RTP,
};

/* MGCP connection (RTP) */
struct mgcp_conn_rtp {

	/* Backpointer to conn struct */
	struct mgcp_conn *conn;

	/* Specific connection type */
	enum mgcp_conn_rtp_type type;

	/* Port status */
	struct mgcp_rtp_end end;

	/* Sequence bits */
	struct mgcp_rtp_state state;

	/* taps for the rtp connection; one per direction */
	struct mgcp_rtp_tap tap_in;
	struct mgcp_rtp_tap tap_out;

	/* Osmux states (optional) */
	struct {
		/* Osmux state: disabled, activating, active */
		enum osmux_state state;
		/* Is local_cid holding valid data? is it allocated from pool? */
		bool local_cid_allocated;
		/* Allocated local Osmux circuit ID for this conn */
		uint8_t local_cid;
		/* Is remote_cid holding valid data? was it already received from client? */
		bool remote_cid_present;
		/* Received remote Osmux circuit ID for this conn */
		uint8_t remote_cid;
		/* handle to batch messages, shared (refcounted) among several conns */
		struct osmux_in_handle *in;
		/* handle to unbatch messages, one allocated and owned per conn */
		struct osmux_out_handle *out;
		/* statistics: */
		struct rate_ctr_group *ctrg;
	} osmux;

	struct {
		struct osmo_iuup_instance *iui;
		bool active_init; /* true: Send IuUP Init */
		int rfci_id_no_data; /* RFCI Id for RFCI NO_DATA (-1 if not available) */
		bool configured;
		struct osmo_iuup_rnl_prim *init_ind;
	} iuup;

	struct rate_ctr_group *ctrg;
};

/*! MGCP connection (untyped) */
struct mgcp_conn {
	/*! list head */
	struct llist_head entry;

	/*! Backpointer to the endpoint where the conn belongs to */
	struct mgcp_endpoint *endp;

	/*! type of the connection (union) */
	enum mgcp_conn_type type;

	/*! mode of the connection */
	enum mgcp_connection_mode mode;

	/*! copy of the mode to restore the original setting (VTY) */
	enum mgcp_connection_mode mode_orig;

	/*! connection id to identify the connection */
	char id[MGCP_CONN_ID_MAXLEN];

	/*! human readable name (vty, logging) */
	char name[256];

	/*! activity tracker (for cleaning up inactive connections) */
	struct osmo_timer_list watchdog;

	/*! union with connection description */
	union {
		struct mgcp_conn_rtp rtp;
	} u;

	/*! pointer to optional private data */
	void *priv;
};

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
	[RTP_DROPPED_PACKETS_CTR] = {"rtp:dropped", "Dropped rtp packets."}
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

/* Osmux connection related counters */
enum {
	OSMUX_CHUNKS_RX_CTR,
	OSMUX_OCTETS_RX_CTR,
	OSMUX_RTP_PACKETS_TX_CTR,
	OSMUX_RTP_PACKETS_TX_DROPPED_CTR,
	OSMUX_AMR_OCTETS_TX_CTR,
	/* Only available in global stats: */
	OSMUX_NUM_CONNECTIONS,
	OSMUX_PACKETS_RX_CTR,
	OSMUX_PACKETS_TX_CTR,
	OSMUX_DROPPED_PACKETS_CTR,
};

/* RTP per-connection statistics. Instances of the corresponding rate counter group
 * exist for the lifetime of an RTP connection.
 * Must be kept in sync with all_rtp_conn_rate_ctr_desc below */
static const struct rate_ctr_desc mgcp_conn_osmux_rate_ctr_desc[] = {
	[OSMUX_CHUNKS_RX_CTR] = {"osmux:chunks_rx", "Inbound Osmux chunks."},
	[OSMUX_OCTETS_RX_CTR] = {"osmux:octets_rx", "Inbound Osmux octets."},
	[OSMUX_RTP_PACKETS_TX_CTR] = {"osmux:rtp_packets_tx", "Tx outbound RTP packets to encode as Osmux."},
	[OSMUX_RTP_PACKETS_TX_DROPPED_CTR] = {"osmux:rtp_packets_tx_dropped", "Dropped Tx outbound RTP packets to encode as Osmux."},
	[OSMUX_AMR_OCTETS_TX_CTR] = {"osmux:amr_octets_tx", "Tx outbound AMD payload octets."},
};

/* Aggregated Osmux connection stats. These are updated when an Osmux connection is freed.
 * Must be kept in sync with mgcp_conn_osmux_rate_ctr_desc above */
static const struct rate_ctr_desc all_osmux_conn_rate_ctr_desc[] = {
	[OSMUX_CHUNKS_RX_CTR] = {"all_osmux:chunks_rx", "Inbound Osmux chunks."},
	[OSMUX_OCTETS_RX_CTR] = {"all_osmux:octets_rx", "Inbound Osmux octets."},
	[OSMUX_RTP_PACKETS_TX_CTR] = {"all_osmux:rtp_packets_tx", "Tx outbound RTP packets to encode as Osmux."},
	[OSMUX_RTP_PACKETS_TX_DROPPED_CTR] = {"all_osmux:rtp_packets_tx_dropped", "Dropped Tx outbound RTP packets to encode as Osmux."},
	[OSMUX_AMR_OCTETS_TX_CTR] = {"all_osmux:amr_octets_tx", "Tx outbound AMD payload octets."},
	/* These last counters below do not exist in per-connection stats, only here: */
	[OSMUX_NUM_CONNECTIONS] = {"all_osmux:num_closed_conns", "Total number of osmux connections closed."},
	[OSMUX_PACKETS_RX_CTR] = {"all_osmux:packets_rx", "Total inbound UDP/Osmux packets."},
	[OSMUX_PACKETS_TX_CTR] = {"all_osmux:packets_tx", "Total outbound UDP/Osmux packets."},
	[OSMUX_DROPPED_PACKETS_CTR] = {"all_osmux:dropped_packets", "Dropped outbound UDP/Osmux packets."}
};

/* Was conn configured to handle Osmux? */
static inline bool mgcp_conn_rtp_is_osmux(const struct mgcp_conn_rtp *conn) {
	return conn->type == MGCP_RTP_OSMUX;
}

/* Was conn configured to handle Osmux? */
static inline bool mgcp_conn_rtp_is_iuup(const struct mgcp_conn_rtp *conn)
{
	return conn->type == MGCP_RTP_IUUP;
}

static inline struct mgcp_conn_rtp *mgcp_conn_get_conn_rtp(struct mgcp_conn *conn)
{
	OSMO_ASSERT(conn->type == MGCP_CONN_TYPE_RTP);
	return &conn->u.rtp;
}

struct mgcp_conn *mgcp_conn_alloc(void *ctx, struct mgcp_endpoint *endp,
				  enum mgcp_conn_type type, char *name);
void mgcp_conn_free(struct mgcp_conn *conn);
int mgcp_conn_set_mode(struct mgcp_conn *conn, enum mgcp_connection_mode mode);
char *mgcp_conn_dump(struct mgcp_conn *conn);
struct mgcp_conn *mgcp_find_dst_conn(struct mgcp_conn *conn);
void mgcp_conn_watchdog_kick(struct mgcp_conn *conn);

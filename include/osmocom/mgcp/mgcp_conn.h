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
#include <osmocom/mgcp/mgcp_network.h>
#include <osmocom/mgcp/osmux.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/gsm/iuup.h>
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
	MGCP_OSMUX_BSC,
	MGCP_OSMUX_BSC_NAT,
	MGCP_RTP_IUUP,
};

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
		/* Is cid holding valid data? is it allocated from pool? */
		bool cid_allocated;
		/* Allocated Osmux circuit ID for this conn */
		uint8_t cid;
		/* handle to batch messages, shared (refcounted) among several conns */
		struct osmux_in_handle *in;
		/* handle to unbatch messages, one allocated and owned per conn */
		struct osmux_out_handle *out;
		/* statistics */
		struct {
			uint32_t chunks;
			uint32_t octets;
		} stats;
	} osmux;

	struct {
		struct osmo_iuup_instance *iui;
		bool active_init; /* true: Send IuUP Init */
		int rfci_id_no_data; /* RFCI Id for RFCI NO_DATA (-1 if not available) */
		bool configured;
		struct osmo_iuup_rnl_prim *init_ind;
	} iuup;

	struct rate_ctr_group *rate_ctr_group;
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

/* Was conn configured to handle Osmux? */
static inline bool mgcp_conn_rtp_is_osmux(const struct mgcp_conn_rtp *conn) {
	return conn->type == MGCP_OSMUX_BSC || conn->type == MGCP_OSMUX_BSC_NAT;
}

/* Was conn configured to handle Osmux? */
static inline bool mgcp_conn_rtp_is_iuup(const struct mgcp_conn_rtp *conn)
{
	return conn->type == MGCP_RTP_IUUP;
}

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
struct mgcp_conn *mgcp_conn_get_oldest(struct mgcp_endpoint *endp);
void mgcp_conn_watchdog_kick(struct mgcp_conn *conn);

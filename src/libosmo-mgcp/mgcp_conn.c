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

#include <stdatomic.h>
#include <osmocom/mgcp/mgcp_conn.h>
#include <osmocom/mgcp/mgcp_network.h>
#include <osmocom/mgcp/mgcp_protocol.h>
#include <osmocom/mgcp/mgcp_common.h>
#include <osmocom/mgcp/mgcp_endp.h>
#include <osmocom/mgcp/mgcp_trunk.h>
#include <osmocom/mgcp/mgcp_sdp.h>
#include <osmocom/mgcp/mgcp_codec.h>
#include <osmocom/mgcp/mgcp_iuup.h>

#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/timer.h>
#include <ctype.h>

static const struct rate_ctr_group_desc rate_ctr_group_desc = {
	.group_name_prefix = "conn_rtp",
	.group_description = "rtp connection statistics",
	.class_id = 1,
	.num_ctr = ARRAY_SIZE(mgcp_conn_rate_ctr_desc),
	.ctr_desc = mgcp_conn_rate_ctr_desc
};


/* Allocate a new connection identifier. According to RFC3435, they must
 * be unique only within the scope of the endpoint. (Caller must provide
 * memory for id) */
static int mgcp_alloc_id(struct mgcp_endpoint *endp, char *id)
{
#define MGCP_CONN_ID_GEN_LEN 8
	int i;
	int k;
	int rc;
	uint8_t id_bin[MGCP_CONN_ID_GEN_LEN / 2];
	char *id_hex;

	/* Generate a connection id that is unique for the current endpoint.
	 * Technically a counter would be sufficient, but in order to
	 * be able to find a specific connection in large logfiles and to
	 * prevent unintentional connections we assign the connection
	 * identifiers randomly from a reasonable large number space */
	for (i = 0; i < 32; i++) {
		rc = osmo_get_rand_id(id_bin, sizeof(id_bin));
		if (rc < 0)
			return rc;

		id_hex = osmo_hexdump_nospc(id_bin, sizeof(id_bin));
		for (k = 0; k < strlen(id_hex); k++)
			id_hex[k] = toupper(id_hex[k]);

		/* ensure that the generated conn_id is unique
		 * for this endpoint */
		if (!mgcp_endp_get_conn_rtp(endp, id_hex)) {
			osmo_strlcpy(id, id_hex, MGCP_CONN_ID_MAXLEN);
			return 0;
		}
	}

	LOGPENDP(endp, DLMGCP, LOGL_ERROR, "unable to generate a unique connectionIdentifier\n");

	return -1;
}

/* Initialize rtp connection struct with default values */
static int mgcp_rtp_conn_init(struct mgcp_conn_rtp *conn_rtp, struct mgcp_conn *conn)
{
	struct mgcp_rtp_end *end = &conn_rtp->end;
	/* FIXME: Each new rate counter group requires an unique index. At the
	 * moment we generate this index using this counter, but perhaps there
	 * is a more concious way to assign the indexes. */
	static atomic_uint rate_ctr_index = 0;

	conn_rtp->type = MGCP_RTP_DEFAULT;

	/* Osmux specific defaults, only used if conn is later on Osmux-enabled: */
	conn_rtp->osmux.state = OSMUX_STATE_DISABLED;
	conn_rtp->osmux.local_cid_allocated = false;
	conn_rtp->osmux.local_cid = 0;
	conn_rtp->osmux.remote_cid_present = false;
	conn_rtp->osmux.remote_cid = 0;

	/* backpointer to the generic part of the connection */
	conn->u.rtp.conn = conn;

	end->rtp = NULL;
	end->rtcp = NULL;
	memset(&end->addr, 0, sizeof(end->addr));
	end->rtcp_port = 0;

	/* Set default values */
	end->frames_per_packet = 0;	/* unknown */
	end->packet_duration_ms = DEFAULT_RTP_AUDIO_PACKET_DURATION_MS;
	end->output_enabled = false;
	end->maximum_packet_time = -1;

	conn_rtp->ctrg = rate_ctr_group_alloc(conn, &rate_ctr_group_desc, rate_ctr_index++);
	if (!conn_rtp->ctrg)
		return -1;

	conn_rtp->state.in_stream.err_ts_ctr = rate_ctr_group_get_ctr(conn_rtp->ctrg, IN_STREAM_ERR_TSTMP_CTR);
	conn_rtp->state.out_stream.err_ts_ctr = rate_ctr_group_get_ctr(conn_rtp->ctrg, OUT_STREAM_ERR_TSTMP_CTR);

	/* Make sure codec table is reset */
	mgcp_codec_reset_all(conn_rtp);

	return 0;
}

/* Cleanup rtp connection struct */
static void mgcp_rtp_conn_cleanup(struct mgcp_conn_rtp *conn_rtp)
{
	if (mgcp_conn_rtp_is_osmux(conn_rtp))
		conn_osmux_disable(conn_rtp);
	if (mgcp_conn_rtp_is_iuup(conn_rtp))
		mgcp_conn_iuup_cleanup(conn_rtp);
	mgcp_free_rtp_port(&conn_rtp->end);
	rate_ctr_group_free(conn_rtp->ctrg);
	mgcp_codec_reset_all(conn_rtp);
}

void mgcp_conn_watchdog_cb(void *data)
{
	struct mgcp_conn *conn = data;
	LOGPCONN(conn, DLMGCP, LOGL_ERROR, "connection timed out!\n");
	mgcp_conn_free(conn);
}

void mgcp_conn_watchdog_kick(struct mgcp_conn *conn)
{
	int timeout = conn->endp->trunk->cfg->conn_timeout;
	if (!timeout)
		return;

	LOGPCONN(conn, DLMGCP, LOGL_DEBUG, "watchdog kicked\n");
	osmo_timer_schedule(&conn->watchdog, timeout, 0);
}

/*! allocate a new connection list entry.
 *  \param[in] ctx talloc context
 *  \param[in] endp associated endpoint
 *  \param[in] id identification number of the connection
 *  \param[in] type connection type (e.g. MGCP_CONN_TYPE_RTP)
 *  \returns pointer to allocated connection, NULL on error */
struct mgcp_conn *mgcp_conn_alloc(void *ctx, struct mgcp_endpoint *endp,
				  enum mgcp_conn_type type, char *name)
{
	struct mgcp_conn *conn;
	int rc;

	/* Do not allow more than the maximum number of connections */
	if (endp->type->max_conns > 0 && llist_count(&endp->conns) >= endp->type->max_conns)
		return NULL;

	/* Create new connection and add it to the list */
	conn = talloc_zero(ctx, struct mgcp_conn);
	if (!conn)
		return NULL;
	conn->endp = endp;
	conn->type = type;
	conn->mode = MGCP_CONN_NONE;
	conn->mode_orig = MGCP_CONN_NONE;
	osmo_strlcpy(conn->name, name, sizeof(conn->name));
	rc = mgcp_alloc_id(endp, conn->id);
	if (rc < 0) {
		talloc_free(conn);
		return NULL;
	}

	switch (type) {
	case MGCP_CONN_TYPE_RTP:
		if (mgcp_rtp_conn_init(&conn->u.rtp, conn) < 0) {
			talloc_free(conn);
			return NULL;
		}
		break;
	default:
		/* NOTE: This should never be called with an
		 * invalid type, its up to the programmer
		 * to ensure propery types */
		OSMO_ASSERT(false);
	}

	/* Initialize watchdog */
	osmo_timer_setup(&conn->watchdog, mgcp_conn_watchdog_cb, conn);
	mgcp_conn_watchdog_kick(conn);
	mgcp_endp_add_conn(endp, conn);

	return conn;
}

static void aggregate_rtp_conn_stats(struct mgcp_endpoint *endp, struct mgcp_conn_rtp *conn_rtp)
{
	struct rate_ctr_group *all_stats = endp->trunk->ratectr.all_rtp_conn_stats;
	struct rate_ctr_group *conn_stats = conn_rtp->ctrg;

	if (all_stats == NULL || conn_stats == NULL)
		return;

	/* Compared to per-connection RTP statistics, aggregated RTP statistics
	 * contain one additional rate couter item (RTP_NUM_CONNECTIONS).
	 * All other counters in both counter groups correspond to each other. */
	OSMO_ASSERT(conn_stats->desc->num_ctr + 1 == all_stats->desc->num_ctr);

	/* all other counters are [now] updated in real-time */
	rate_ctr_add(rate_ctr_group_get_ctr(all_stats, IN_STREAM_ERR_TSTMP_CTR),
		     rate_ctr_group_get_ctr(conn_stats, IN_STREAM_ERR_TSTMP_CTR)->current);
	rate_ctr_add(rate_ctr_group_get_ctr(all_stats, OUT_STREAM_ERR_TSTMP_CTR),
		     rate_ctr_group_get_ctr(conn_stats, OUT_STREAM_ERR_TSTMP_CTR)->current);

	rate_ctr_inc(rate_ctr_group_get_ctr(all_stats, RTP_NUM_CONNECTIONS));
}

/*! free a connection
 *  \param[in] conn the conn to free. May be NULL.
*/
void mgcp_conn_free(struct mgcp_conn *conn)
{
	struct mgcp_conn_rtp *conn_rtp;

	if (!conn)
		return;

	switch (conn->type) {
	case MGCP_CONN_TYPE_RTP:
		conn_rtp = mgcp_conn_get_conn_rtp(conn);
		aggregate_rtp_conn_stats(conn->endp, conn_rtp);
		mgcp_rtp_conn_cleanup(conn_rtp);
		break;
	default:
		/* NOTE: This should never be called with an
		 * invalid type, its up to the programmer
		 * to ensure propery types */
		OSMO_ASSERT(false);
	}

	osmo_timer_del(&conn->watchdog);
	mgcp_endp_remove_conn(conn->endp, conn);
	/* WARN: endp may have be freed after call to mgcp_endp_remove_conn */
	talloc_free(conn);
}

/*! dump basic connection information to human readable string.
 *  \param[in] conn to dump
 *  \returns human readable string */
char *mgcp_conn_dump(struct mgcp_conn *conn)
{
	static char str[sizeof(conn->name)+sizeof(conn->id)+256];
	char ipbuf[INET6_ADDRSTRLEN];
	struct osmo_strbuf sb = { .buf = str, .len = sizeof(str) };
	struct mgcp_conn_rtp *conn_rtp;

	if (!conn)
		return "NULL";

	switch (conn->type) {
	case MGCP_CONN_TYPE_RTP:
		conn_rtp = mgcp_conn_get_conn_rtp(conn);
		OSMO_STRBUF_PRINTF(sb, "(%s/%s C:%s r=%s:%u<->l=%s:%u",
				   conn->name,
				   mgcp_conn_rtp_type_name(conn->type),
				   conn->id,
				   osmo_sockaddr_ntop(&conn_rtp->end.addr.u.sa, ipbuf) ? : "NULL",
				   osmo_sockaddr_port(&conn_rtp->end.addr.u.sa),
				   conn_rtp->end.local_addr ? : "NULL",
				   conn_rtp->end.local_port);

		switch (conn_rtp->type) {
		case MGCP_RTP_OSMUX:
			OSMO_STRBUF_PRINTF(sb, " CID=%u", conn_rtp->osmux.local_cid);
			break;
		default:
			break;
		}

		OSMO_STRBUF_PRINTF(sb, ")");
		break;

	default:
		/* Should not happen, we should be able to dump
		 * every possible connection type. */
		return "(unknown connection type)";
	}

	return str;
}

/*! find destination connection on a specific endpoint.
 *  \param[in] conn to search a destination for
 *  \returns destination connection, NULL on failure */
struct mgcp_conn *mgcp_find_dst_conn(struct mgcp_conn *conn)
{
	struct mgcp_endpoint *endp;
	struct mgcp_conn *partner_conn;
	endp = conn->endp;

	/*! NOTE: This simply works by grabbing the first connection that is
	 *  not the supplied connection, which is suitable for endpoints that
	 *  do not serve more than two connections. */

	llist_for_each_entry(partner_conn, &endp->conns, entry) {
		if (conn != partner_conn) {
			return partner_conn;
		}
	}

	return NULL;
}

const struct value_string mgcp_conn_rtp_type_names[] = {
	{ MGCP_RTP_DEFAULT, "rtp" },
	{ MGCP_RTP_OSMUX, "osmux" },
	{ MGCP_RTP_IUUP, "iuup" },
	{}
};

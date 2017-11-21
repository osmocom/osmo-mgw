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

#include <osmocom/mgcp/mgcp_conn.h>
#include <osmocom/mgcp/mgcp_internal.h>
#include <osmocom/mgcp/mgcp_common.h>
#include <osmocom/mgcp/mgcp_ep.h>

/* Reset codec state and free memory */
static void mgcp_rtp_codec_reset(struct mgcp_rtp_codec *codec)
{
	codec->payload_type = -1;
	codec->subtype_name = NULL;
	codec->audio_name = NULL;
	codec->frame_duration_num = DEFAULT_RTP_AUDIO_FRAME_DUR_NUM;
	codec->frame_duration_den = DEFAULT_RTP_AUDIO_FRAME_DUR_DEN;
	codec->rate = DEFAULT_RTP_AUDIO_DEFAULT_RATE;
	codec->channels = DEFAULT_RTP_AUDIO_DEFAULT_CHANNELS;

	/* see also mgcp_sdp.c, mgcp_set_audio_info() */
	talloc_free(codec->subtype_name);
	talloc_free(codec->audio_name);
}

/* Reset states, free memory, set defaults and reset codec state */
static void mgcp_rtp_conn_reset(struct mgcp_conn_rtp *conn)
{
	struct mgcp_rtp_end *end = &conn->end;

	conn->type = MGCP_RTP_DEFAULT;
	conn->osmux.allocated_cid = -1;

	end->rtp.fd = -1;
	end->rtcp.fd = -1;
	end->local_port = 0;
	end->packets_rx = 0;
	end->octets_rx = 0;
	end->packets_tx = 0;
	end->octets_tx = 0;
	end->dropped_packets = 0;
	end->rtp_port = end->rtcp_port = 0;
	talloc_free(end->fmtp_extra);
	end->fmtp_extra = NULL;

	/* Set default values */
	end->frames_per_packet = 0;	/* unknown */
	end->packet_duration_ms = DEFAULT_RTP_AUDIO_PACKET_DURATION_MS;
	end->output_enabled = 0;

	mgcp_rtp_codec_reset(&end->codec);
	mgcp_rtp_codec_reset(&end->alt_codec);
}

/*! allocate a new connection list entry.
 *  \param[in] ctx talloc context
 *  \param[in] endp associated endpoint
 *  \param[in] id identification number of the connection
 *  \param[in] type connection type (e.g. MGCP_CONN_TYPE_RTP)
 *  \returns pointer to allocated connection, NULL on error */
struct mgcp_conn *mgcp_conn_alloc(void *ctx, struct mgcp_endpoint *endp,
				  const char *id, enum mgcp_conn_type type,
				  char *name)
{
	struct mgcp_conn *conn;
	OSMO_ASSERT(endp);
	OSMO_ASSERT(endp->conns.next != NULL && endp->conns.prev != NULL);
	OSMO_ASSERT(strlen(name) < sizeof(conn->name));

	/* Id is a mandatory parameter */
	if (!id)
		return NULL;

	/* Prevent over long id strings */
	if (strlen(id) >= MGCP_CONN_ID_LENGTH)
		return NULL;

	/* Do not allow more then two connections */
	if (llist_count(&endp->conns) >= endp->type->max_conns)
		return NULL;

	/* Prevent duplicate connection IDs */
	if (mgcp_conn_get(endp, id))
		return NULL;

	/* Create new connection and add it to the list */
	conn = talloc_zero(ctx, struct mgcp_conn);
	if (!conn)
		return NULL;
	conn->endp = endp;
	conn->type = type;
	conn->mode = MGCP_CONN_NONE;
	conn->mode_orig = MGCP_CONN_NONE;
	conn->u.rtp.conn = conn;
	strcpy(conn->name, name);
	osmo_strlcpy(conn->id, id, sizeof(conn->id));

	switch (type) {
	case MGCP_CONN_TYPE_RTP:
		mgcp_rtp_conn_reset(&conn->u.rtp);
		break;
	default:
		/* NOTE: This should never be called with an
		 * invalid type, its up to the programmer
		 * to ensure propery types */
		OSMO_ASSERT(false);
	}

	llist_add(&conn->entry, &endp->conns);

	return conn;
}

/*! find a connection by its ID.
 *  \param[in] endp associated endpoint
 *  \param[in] id identification number of the connection
 *  \returns pointer to allocated connection, NULL if not found */
struct mgcp_conn *mgcp_conn_get(struct mgcp_endpoint *endp, const char *id)
{
	OSMO_ASSERT(endp);
	OSMO_ASSERT(id);
	OSMO_ASSERT(strlen(id) < MGCP_CONN_ID_LENGTH);
	OSMO_ASSERT(endp->conns.next != NULL && endp->conns.prev != NULL);

	struct mgcp_conn *conn;

	llist_for_each_entry(conn, &endp->conns, entry) {
		if (strncmp(conn->id, id, sizeof(conn->id)) == 0)
			return conn;
	}

	return NULL;
}

/*! find an RTP connection by its ID.
 *  \param[in] endp associated endpoint
 *  \param[in] id identification number of the connection
 *  \returns pointer to allocated connection, NULL if not found */
struct mgcp_conn_rtp *mgcp_conn_get_rtp(struct mgcp_endpoint *endp,
					const char *id)
{
	OSMO_ASSERT(endp);
	OSMO_ASSERT(id);
	OSMO_ASSERT(strlen(id) < MGCP_CONN_ID_LENGTH);
	OSMO_ASSERT(endp->conns.next != NULL && endp->conns.prev != NULL);

	struct mgcp_conn *conn;

	conn = mgcp_conn_get(endp, id);
	if (!conn)
		return NULL;

	if (conn->type == MGCP_CONN_TYPE_RTP)
		return &conn->u.rtp;

	return NULL;
}

/*! free a connection by its ID.
 *  \param[in] endp associated endpoint
 *  \param[in] id identification number of the connection */
void mgcp_conn_free(struct mgcp_endpoint *endp, const char *id)
{
	OSMO_ASSERT(endp);
	OSMO_ASSERT(id);
	OSMO_ASSERT(strlen(id) < MGCP_CONN_ID_LENGTH);
	OSMO_ASSERT(endp->conns.next != NULL && endp->conns.prev != NULL);

	struct mgcp_conn *conn;

	conn = mgcp_conn_get(endp, id);
	if (!conn)
		return;

	switch (conn->type) {
	case MGCP_CONN_TYPE_RTP:
		osmux_disable_conn(&conn->u.rtp);
		osmux_release_cid(&conn->u.rtp);
		mgcp_free_rtp_port(&conn->u.rtp.end);
		break;
	default:
		/* NOTE: This should never be called with an
		 * invalid type, its up to the programmer
		 * to ensure propery types */
		OSMO_ASSERT(false);
	}

	llist_del(&conn->entry);
	talloc_free(conn);
}

/*! free oldest connection in the list.
 *  \param[in] endp associated endpoint */
void mgcp_conn_free_oldest(struct mgcp_endpoint *endp)
{
	OSMO_ASSERT(endp);
	OSMO_ASSERT(endp->conns.next != NULL && endp->conns.prev != NULL);

	struct mgcp_conn *conn;

	if (llist_empty(&endp->conns))
		return;

	conn = llist_last_entry(&endp->conns, struct mgcp_conn, entry);
	if (!conn)
		return;

	mgcp_conn_free(endp, conn->id);
}

/*! free all connections at once.
 *  \param[in] endp associated endpoint */
void mgcp_conn_free_all(struct mgcp_endpoint *endp)
{
	OSMO_ASSERT(endp);
	OSMO_ASSERT(endp->conns.next != NULL && endp->conns.prev != NULL);

	struct mgcp_conn *conn;
	struct mgcp_conn *conn_tmp;

	/* Drop all items in the list */
	llist_for_each_entry_safe(conn, conn_tmp, &endp->conns, entry) {
		mgcp_conn_free(endp, conn->id);
	}

	return;
}

/*! dump basic connection information to human readble string.
 *  \param[in] conn to dump
 *  \returns human readble string */
char *mgcp_conn_dump(struct mgcp_conn *conn)
{
	static char str[sizeof(conn->name)+sizeof(conn->id)+256];

	if (!conn) {
		snprintf(str, sizeof(str), "(null connection)");
		return str;
	}

	switch (conn->type) {
	case MGCP_CONN_TYPE_RTP:
		/* Dump RTP connection */
		snprintf(str, sizeof(str), "(%s/rtp, id:0x%s, ip:%s, "
			 "rtp:%u rtcp:%u)",
			 conn->name,
			 conn->id,
			 inet_ntoa(conn->u.rtp.end.addr),
			 ntohs(conn->u.rtp.end.rtp_port),
			 ntohs(conn->u.rtp.end.rtcp_port));
		break;

	default:
		/* Should not happen, we should be able to dump
		 * every possible connection type. */
		snprintf(str, sizeof(str), "(unknown connection type)");
		break;
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

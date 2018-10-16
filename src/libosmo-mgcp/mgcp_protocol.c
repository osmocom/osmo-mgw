/* A Media Gateway Control Protocol Media Gateway: RFC 3435 */
/* The protocol implementation */

/*
 * (C) 2009-2012 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009-2012 by On-Waves
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

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/select.h>

#include <osmocom/mgcp/mgcp.h>
#include <osmocom/mgcp/mgcp_common.h>
#include <osmocom/mgcp/mgcp_internal.h>
#include <osmocom/mgcp/mgcp_stat.h>
#include <osmocom/mgcp/mgcp_msg.h>
#include <osmocom/mgcp/mgcp_endp.h>
#include <osmocom/mgcp/mgcp_sdp.h>
#include <osmocom/mgcp/mgcp_codec.h>

struct mgcp_request {
	char *name;
	struct msgb *(*handle_request) (struct mgcp_parse_data * data);
	char *debug_name;
};

#define MGCP_REQUEST(NAME, REQ, DEBUG_NAME) \
	{ .name = NAME, .handle_request = REQ, .debug_name = DEBUG_NAME },

static struct msgb *handle_audit_endpoint(struct mgcp_parse_data *data);
static struct msgb *handle_create_con(struct mgcp_parse_data *data);
static struct msgb *handle_delete_con(struct mgcp_parse_data *data);
static struct msgb *handle_modify_con(struct mgcp_parse_data *data);
static struct msgb *handle_rsip(struct mgcp_parse_data *data);
static struct msgb *handle_noti_req(struct mgcp_parse_data *data);

/* Initalize transcoder */
static int setup_rtp_processing(struct mgcp_endpoint *endp,
				struct mgcp_conn_rtp *conn)
{
	struct mgcp_config *cfg = endp->cfg;
	struct mgcp_conn_rtp *conn_src = NULL;
	struct mgcp_conn_rtp *conn_dst = conn;
	struct mgcp_conn *_conn;

	if (conn->type != MGCP_RTP_DEFAULT) {
		LOGP(DLMGCP, LOGL_NOTICE,
		     "endpoint:%x RTP-setup: Endpoint is not configured as RTP default, stopping here!\n",
		     ENDPOINT_NUMBER(endp));
		return 0;
	}

	if (conn->conn->mode == MGCP_CONN_LOOPBACK) {
		LOGP(DLMGCP, LOGL_NOTICE,
		     "endpoint:%x RTP-setup: Endpoint is in loopback mode, stopping here!\n",
		     ENDPOINT_NUMBER(endp));
		return 0;
	}

	/* Find the "sister" connection */
	llist_for_each_entry(_conn, &endp->conns, entry) {
		if (_conn->id != conn->conn->id) {
			conn_src = &_conn->u.rtp;
			break;
		}
	}

	return cfg->setup_rtp_processing_cb(endp, conn_dst, conn_src);
}

/* array of function pointers for handling various
 * messages. In the future this might be binary sorted
 * for performance reasons. */
static const struct mgcp_request mgcp_requests[] = {
	MGCP_REQUEST("AUEP", handle_audit_endpoint, "AuditEndpoint")
	    MGCP_REQUEST("CRCX", handle_create_con, "CreateConnection")
	    MGCP_REQUEST("DLCX", handle_delete_con, "DeleteConnection")
	    MGCP_REQUEST("MDCX", handle_modify_con, "ModifiyConnection")
	    MGCP_REQUEST("RQNT", handle_noti_req, "NotificationRequest")

	    /* SPEC extension */
	    MGCP_REQUEST("RSIP", handle_rsip, "ReSetInProgress")
};

/* Helper function to allocate some memory for responses and retransmissions */
static struct msgb *mgcp_msgb_alloc(void)
{
	struct msgb *msg;
	msg = msgb_alloc_headroom(4096, 128, "MGCP msg");
	if (!msg)
		LOGP(DLMGCP, LOGL_ERROR, "Failed to msgb for MGCP data.\n");

	return msg;
}

/* Helper function for do_retransmission() and create_resp() */
static struct msgb *do_retransmission(const struct mgcp_endpoint *endp)
{
	struct msgb *msg = mgcp_msgb_alloc();
	if (!msg)
		return NULL;

	msg->l2h = msgb_put(msg, strlen(endp->last_response));
	memcpy(msg->l2h, endp->last_response, msgb_l2len(msg));
	mgcp_disp_msg(msg->l2h, msgb_l2len(msg), "Retransmitted response");
	return msg;
}

static struct msgb *create_resp(struct mgcp_endpoint *endp, int code,
				const char *txt, const char *msg,
				const char *trans, const char *param,
				const char *sdp)
{
	int len;
	struct msgb *res;

	res = mgcp_msgb_alloc();
	if (!res)
		return NULL;

	len = snprintf((char *)res->data, 2048, "%d %s%s%s\r\n%s",
		       code, trans, txt, param ? param : "", sdp ? sdp : "");
	if (len < 0) {
		LOGP(DLMGCP, LOGL_ERROR, "Failed to sprintf MGCP response.\n");
		msgb_free(res);
		return NULL;
	}

	res->l2h = msgb_put(res, len);
	LOGP(DLMGCP, LOGL_DEBUG, "Generated response: code=%d\n", code);
	mgcp_disp_msg(res->l2h, msgb_l2len(res), "Generated response");

	/*
	 * Remember the last transmission per endpoint.
	 */
	if (endp) {
		struct mgcp_trunk_config *tcfg = endp->tcfg;
		talloc_free(endp->last_response);
		talloc_free(endp->last_trans);
		endp->last_trans = talloc_strdup(tcfg->endpoints, trans);
		endp->last_response = talloc_strndup(tcfg->endpoints,
						     (const char *)res->l2h,
						     msgb_l2len(res));
	}

	return res;
}

static struct msgb *create_ok_resp_with_param(struct mgcp_endpoint *endp,
					      int code, const char *msg,
					      const char *trans,
					      const char *param)
{
	return create_resp(endp, code, " OK", msg, trans, param, NULL);
}

static struct msgb *create_ok_response(struct mgcp_endpoint *endp,
				       int code, const char *msg,
				       const char *trans)
{
	return create_ok_resp_with_param(endp, code, msg, trans, NULL);
}

static struct msgb *create_err_response(struct mgcp_endpoint *endp,
					int code, const char *msg,
					const char *trans)
{
	return create_resp(endp, code, " FAIL", msg, trans, NULL, NULL);
}

/* Add MGCP parameters to a message buffer */
static int add_params(struct msgb *msg, const struct mgcp_endpoint *endp,
		      const struct mgcp_conn_rtp *conn)
{
	int rc;

	/* NOTE: Only in the virtual trunk we allow dynamic endpoint names */
	if (endp->wildcarded_req
	    && endp->tcfg->trunk_type == MGCP_TRUNK_VIRTUAL) {
		rc = msgb_printf(msg, "Z: %s%x@%s\r\n",
				 MGCP_ENDPOINT_PREFIX_VIRTUAL_TRUNK,
				 ENDPOINT_NUMBER(endp), endp->cfg->domain);
		if (rc < 0)
			return -EINVAL;
	}

	rc = msgb_printf(msg, "I: %s\r\n", conn->conn->id);
	if (rc < 0)
		return -EINVAL;

	return 0;
}

/* Format MGCP response string (with SDP attached) */
static struct msgb *create_response_with_sdp(struct mgcp_endpoint *endp,
					     struct mgcp_conn_rtp *conn,
					     const char *msg,
					     const char *trans_id,
					     bool add_conn_params)
{
	const char *addr = endp->cfg->local_ip;
	struct msgb *sdp;
	int rc;
	struct msgb *result;
	char osmux_extension[strlen("X-Osmux: 255") + 1];
	char local_ip_addr[INET_ADDRSTRLEN];

	sdp = msgb_alloc_headroom(4096, 128, "sdp record");
	if (!sdp)
		return NULL;

	if (!addr) {
		mgcp_get_local_addr(local_ip_addr, conn);
		addr = local_ip_addr;
	}

	if (conn->osmux.state == OSMUX_STATE_NEGOTIATING) {
		sprintf(osmux_extension, "X-Osmux: %u", conn->osmux.cid);
		conn->osmux.state = OSMUX_STATE_ACTIVATING;
	} else {
		osmux_extension[0] = '\0';
	}

	/* Attach optional connection parameters */
	if (add_conn_params) {
		rc = add_params(sdp, endp, conn);
		if (rc < 0)
			goto error;
	}

	/* Attach optional OSMUX parameters */
	if (conn->osmux.state == OSMUX_STATE_NEGOTIATING) {
		rc = msgb_printf(sdp, "%s\r\n", osmux_extension);
		if (rc < 0)
			goto error;
	}

	/* Attach line break to separate the parameters from the SDP block */
	rc = msgb_printf(sdp, "\r\n");

	rc = mgcp_write_response_sdp(endp, conn, sdp, addr);
	if (rc < 0)
		goto error;
	result = create_resp(endp, 200, " OK", msg, trans_id, NULL, (char*) sdp->data);
	msgb_free(sdp);
	return result;
error:
	msgb_free(sdp);
	return NULL;
}

/* Send out dummy packet to keep the connection open, if the connection is an
 * osmux connection, send the dummy packet via OSMUX */
static void send_dummy(struct mgcp_endpoint *endp, struct mgcp_conn_rtp *conn)
{
	if (conn->osmux.state != OSMUX_STATE_DISABLED)
		osmux_send_dummy(endp, conn);
	else
		mgcp_send_dummy(endp, conn);
}

/* handle incoming messages:
 *   - this can be a command (four letters, space, transaction id)
 *   - or a response (three numbers, space, transaction id) */
struct msgb *mgcp_handle_message(struct mgcp_config *cfg, struct msgb *msg)
{
	struct mgcp_parse_data pdata;
	int rc, i, code, handled = 0;
	struct msgb *resp = NULL;
	char *data;

	if (msgb_l2len(msg) < 4) {
		LOGP(DLMGCP, LOGL_ERROR, "msg too short: %d\n", msg->len);
		return NULL;
	}

	if (mgcp_msg_terminate_nul(msg))
		return NULL;

	mgcp_disp_msg(msg->l2h, msgb_l2len(msg), "Received message");

	/* attempt to treat it as a response */
	if (sscanf((const char *)&msg->l2h[0], "%3d %*s", &code) == 1) {
		LOGP(DLMGCP, LOGL_DEBUG, "Response: Code: %d\n", code);
		return NULL;
	}

	msg->l3h = &msg->l2h[4];

	/*
	 * Check for a duplicate message and respond.
	 */
	memset(&pdata, 0, sizeof(pdata));
	pdata.cfg = cfg;
	data = mgcp_strline((char *)msg->l3h, &pdata.save);
	rc = mgcp_parse_header(&pdata, data);
	if (pdata.endp && pdata.trans
	    && pdata.endp->last_trans
	    && strcmp(pdata.endp->last_trans, pdata.trans) == 0) {
		return do_retransmission(pdata.endp);
	}

	/* check for general parser failure */
	if (rc < 0) {
		LOGP(DLMGCP, LOGL_NOTICE, "%s: failed to find the endpoint\n", msg->l2h);
		return create_err_response(NULL, -rc, (const char *) msg->l2h, pdata.trans);
	}

	for (i = 0; i < ARRAY_SIZE(mgcp_requests); ++i) {
		if (strncmp
		    (mgcp_requests[i].name, (const char *)&msg->l2h[0],
		     4) == 0) {
			handled = 1;
			resp = mgcp_requests[i].handle_request(&pdata);
			break;
		}
	}

	if (!handled)
		LOGP(DLMGCP, LOGL_NOTICE, "MSG with type: '%.4s' not handled\n",
		     &msg->l2h[0]);

	return resp;
}

/* AUEP command handler, processes the received command */
static struct msgb *handle_audit_endpoint(struct mgcp_parse_data *p)
{
	LOGP(DLMGCP, LOGL_NOTICE, "AUEP: auditing endpoint ...\n");
	return create_ok_response(p->endp, 200, "AUEP", p->trans);
}

/* Try to find a free port by attempting to bind on it. Also handle the
 * counter that points on the next free port. Since we have a pointer
 * to the next free port, binding should in work on the first attempt in
 * general. In case of failure the next port is tryed until the whole port
 * range is tryed once. */
static int allocate_port(struct mgcp_endpoint *endp, struct mgcp_conn_rtp *conn)
{
	int i;
	struct mgcp_rtp_end *end;
	struct mgcp_port_range *range;
	unsigned int tries;

	OSMO_ASSERT(conn);
	end = &conn->end;
	OSMO_ASSERT(end);

	range = &endp->cfg->net_ports;

	/* attempt to find a port */
	tries = (range->range_end - range->range_start) / 2;
	for (i = 0; i < tries; ++i) {
		int rc;

		if (range->last_port >= range->range_end)
			range->last_port = range->range_start;

		rc = mgcp_bind_net_rtp_port(endp, range->last_port, conn);

		range->last_port += 2;
		if (rc == 0) {
			return 0;
		}

	}

	LOGP(DLMGCP, LOGL_ERROR,
	     "Allocating a RTP/RTCP port failed %u times 0x%x.\n",
	     tries, ENDPOINT_NUMBER(endp));
	return -1;
}

/*! Helper function for check_local_cx_options() to get a pointer of the next
 *  lco option identifier
 *  \param[in] lco string
 *  \returns pointer to the beginning of the LCO identifier, NULL on failure */
char *get_lco_identifier(const char *options)
{
	char *ptr;
	unsigned int count = 0;

	/* Jump to the end of the lco identifier */
	ptr = strstr(options, ":");
	if (!ptr)
		return NULL;

	/* Walk backwards until the pointer points to the beginning of the
	 * lco identifier. We know that we stand at the beginning when we
	 * are either at the beginning of the memory or see a space or
	 * comma. (this is tolerant, it will accept a:10, b:11 as well as
	 * a:10,b:11) */
	while (1) {
		/* Endless loop protection */
		if (count > 10000)
			return NULL;
		else if (ptr < options || *ptr == ' ' || *ptr == ',') {
			ptr++;
			break;
		}
		ptr--;
		count++;
	}

	/* Check if we got any result */
	if (*ptr == ':')
		return NULL;

	return ptr;
}

/*! Check the LCO option. This function checks for multiple appearence of LCO
 *  options, which is illegal
 *  \param[in] ctx talloc context
 *  \param[in] lco string
 *  \returns 0 on success, -1 on failure */
int check_local_cx_options(void *ctx, const char *options)
{
	int i;
	char *options_copy;
	char *lco_identifier;
	char *lco_identifier_end;
	char *next_lco_identifier;

	char **lco_seen;
	unsigned int lco_seen_n = 0;

	if (!options)
		return -1;

	lco_seen =
	    (char **)talloc_zero_size(ctx, strlen(options) * sizeof(char *));
	options_copy = talloc_strdup(ctx, options);
	lco_identifier = options_copy;

	do {
		/* Move the lco_identifier pointer to the beginning of the
		 * current lco option identifier */
		lco_identifier = get_lco_identifier(lco_identifier);
		if (!lco_identifier)
			goto error;

		/* Look ahead to the next LCO option early, since we
		 * will parse destructively */
		next_lco_identifier = strstr(lco_identifier + 1, ",");

		/* Pinch off the end of the lco field identifier name
		 * and see if we still got something, also check if
		 * there is some value after the colon. */
		lco_identifier_end = strstr(lco_identifier, ":");
		if (!lco_identifier_end)
			goto error;
		if (*(lco_identifier_end + 1) == ' '
		    || *(lco_identifier_end + 1) == ','
		    || *(lco_identifier_end + 1) == '\0')
			goto error;
		*lco_identifier_end = '\0';
		if (strlen(lco_identifier) == 0)
			goto error;

		/* Check if we have already seen the current field identifier
		 * before. If yes, we must bail, an LCO must only appear once
		 * in the LCO string */
		for (i = 0; i < lco_seen_n; i++) {
			if (strcmp(lco_seen[i], lco_identifier) == 0)
				goto error;
		}
		lco_seen[lco_seen_n] = lco_identifier;
		lco_seen_n++;

		/* The first identifier must always be found at the beginnning
		 * of the LCO string */
		if (lco_seen[0] != options_copy)
			goto error;

		/* Go to the next lco option */
		lco_identifier = next_lco_identifier;
	} while (lco_identifier);

	talloc_free(lco_seen);
	talloc_free(options_copy);
	return 0;
error:
	talloc_free(lco_seen);
	talloc_free(options_copy);
	return -1;
}

/* Set the LCO from a string (see RFC 3435).
 * The string is stored in the 'string' field. A NULL string is handled exactly
 * like an empty string, the 'string' field is never NULL after this function
 * has been called. */
static int set_local_cx_options(void *ctx, struct mgcp_lco *lco,
				 const char *options)
{
	char *p_opt, *a_opt;
	char codec[9];

	if (!options)
		return 0;
	if (strlen(options) == 0)
		return 0;

	/* Make sure the encoding of the LCO is consistant before we proceed */
	if (check_local_cx_options(ctx, options) != 0) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "local CX options: Internal inconsistency in Local Connection Options!\n");
		return 524;
	}

	talloc_free(lco->string);
	lco->string = talloc_strdup(ctx, options);

	p_opt = strstr(lco->string, "p:");
	if (p_opt && sscanf(p_opt, "p:%d-%d",
			    &lco->pkt_period_min, &lco->pkt_period_max) == 1)
		lco->pkt_period_max = lco->pkt_period_min;

	/* FIXME: LCO also supports the negotiation of more then one codec.
	 * (e.g. a:PCMU;G726-32) But this implementation only supports a single
	 * codec only. */
	a_opt = strstr(lco->string, "a:");
	if (a_opt && sscanf(a_opt, "a:%8[^,]", codec) == 1) {
		talloc_free(lco->codec);
		lco->codec = talloc_strdup(ctx, codec);
	}

	LOGP(DLMGCP, LOGL_DEBUG,
	     "local CX options: lco->pkt_period_max: %i, lco->codec: %s\n",
	     lco->pkt_period_max, lco->codec);

	/* Check if the packetization fits the 20ms raster */
	if (lco->pkt_period_min % 20 && lco->pkt_period_max % 20) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "local CX options: packetization interval is not a multiple of 20ms!\n");
		return 535;
	}

	return 0;
}

void mgcp_rtp_end_config(struct mgcp_endpoint *endp, int expect_ssrc_change,
			 struct mgcp_rtp_end *rtp)
{
	struct mgcp_trunk_config *tcfg = endp->tcfg;

	int patch_ssrc = expect_ssrc_change && tcfg->force_constant_ssrc;

	rtp->force_aligned_timing = tcfg->force_aligned_timing;
	rtp->force_constant_ssrc = patch_ssrc ? 1 : 0;

	LOGP(DLMGCP, LOGL_DEBUG,
	     "Configuring RTP endpoint: local port %d%s%s\n",
	     ntohs(rtp->rtp_port),
	     rtp->force_aligned_timing ? ", force constant timing" : "",
	     rtp->force_constant_ssrc ? ", force constant ssrc" : "");
}

uint32_t mgcp_rtp_packet_duration(struct mgcp_endpoint *endp,
				  struct mgcp_rtp_end *rtp)
{
	int f = 0;

	/* Get the number of frames per channel and packet */
	if (rtp->frames_per_packet)
		f = rtp->frames_per_packet;
	else if (rtp->packet_duration_ms && rtp->codec->frame_duration_num) {
		int den = 1000 * rtp->codec->frame_duration_num;
		f = (rtp->packet_duration_ms * rtp->codec->frame_duration_den +
		     den / 2)
		    / den;
	}

	return rtp->codec->rate * f * rtp->codec->frame_duration_num /
	    rtp->codec->frame_duration_den;
}

static int mgcp_osmux_setup(struct mgcp_endpoint *endp, const char *line)
{
	if (!endp->cfg->osmux_init) {
		if (osmux_init(OSMUX_ROLE_BSC, endp->cfg) < 0) {
			LOGP(DLMGCP, LOGL_ERROR, "Cannot init OSMUX\n");
			return -1;
		}
		LOGP(DLMGCP, LOGL_NOTICE, "OSMUX socket has been set up\n");
	}

	return mgcp_parse_osmux_cid(line);
}

/* Process codec information contained in CRCX/MDCX */
static int handle_codec_info(struct mgcp_conn_rtp *conn,
			     struct mgcp_parse_data *p, int have_sdp, bool crcx)
{
	struct mgcp_endpoint *endp = p->endp;
	int rc;
	char *cmd;

	if (crcx)
		cmd = "CRCX";
	else
		cmd = "MDCX";

	/* Collect codec information */
	if (have_sdp) {
		/* If we have SDP, we ignore the local connection options and
		 * use only the SDP information. */
		mgcp_codec_reset_all(conn);
		rc = mgcp_parse_sdp_data(endp, conn, p);
		if (rc != 0) {
			LOGP(DLMGCP, LOGL_ERROR,
			     "%s: endpoint:%x sdp not parseable\n", cmd,
			     ENDPOINT_NUMBER(endp));

			/* See also RFC 3661: Protocol error */
			return 510;
		}
	} else if (endp->local_options.codec) {
		/* When no SDP is available, we use the codec information from
		 * the local connection options (if present) */
		mgcp_codec_reset_all(conn);
		rc = mgcp_codec_add(conn, PTYPE_UNDEFINED, endp->local_options.codec);
		if (rc != 0)
			goto error;
	}

	/* Make sure we always set a sane default codec */
	if (conn->end.codecs_assigned == 0) {
		/* When SDP and/or LCO did not supply any codec information,
		 * than it makes sense to pick a sane default: (payload-type 0,
		 * PCMU), see also: OS#2658 */
		mgcp_codec_reset_all(conn);
		rc = mgcp_codec_add(conn, 0, NULL);
		if (rc != 0)
			goto error;
	}

	/* Make codec decision */
	if (mgcp_codec_decide(conn) != 0)
		goto error;

	return 0;

error:
	LOGP(DLMGCP, LOGL_ERROR,
	     "%s: endpoint:0x%x codec negotiation failure\n", cmd,
	     ENDPOINT_NUMBER(endp));

	/* See also RFC 3661: Codec negotiation failure */
	return 534;
}

static bool parse_x_osmo_ign(struct mgcp_endpoint *endp, char *line)
{
	char *saveptr = NULL;

	if (strncmp(line, MGCP_X_OSMO_IGN_HEADER, strlen(MGCP_X_OSMO_IGN_HEADER)))
		return false;
	line += strlen(MGCP_X_OSMO_IGN_HEADER);

	while (1) {
		char *token = strtok_r(line, " ", &saveptr);
		line = NULL;
		if (!token)
			break;

		if (!strcmp(token, "C"))
			endp->x_osmo_ign |= MGCP_X_OSMO_IGN_CALLID;
		else
			LOGP(DLMGCP, LOGL_ERROR, "endpoint 0x%x: received unknown X-Osmo-IGN item '%s'\n",
			     ENDPOINT_NUMBER(endp), token);
	}

	return true;
}

/* CRCX command handler, processes the received command */
static struct msgb *handle_create_con(struct mgcp_parse_data *p)
{
	struct mgcp_trunk_config *tcfg;
	struct mgcp_endpoint *endp = p->endp;
	int error_code = 400;

	const char *local_options = NULL;
	const char *callid = NULL;
	const char *mode = NULL;
	char *line;
	int have_sdp = 0, osmux_cid = -1;
	struct mgcp_conn_rtp *conn = NULL;
	struct mgcp_conn *_conn = NULL;
	char conn_name[512];
	int rc;

	LOGP(DLMGCP, LOGL_NOTICE, "CRCX: creating new connection ...\n");

	/* parse CallID C: and LocalParameters L: */
	for_each_line(line, p->save) {
		if (!mgcp_check_param(endp, line))
			continue;

		switch (line[0]) {
		case 'L':
			local_options = (const char *)line + 3;
			break;
		case 'C':
			callid = (const char *)line + 3;
			break;
		case 'I':
			/* It is illegal to send a connection identifier
			 * together with a CRCX, the MGW will assign the
			 * connection identifier by itself on CRCX */
			return create_err_response(NULL, 523, "CRCX", p->trans);
			break;
		case 'M':
			mode = (const char *)line + 3;
			break;
		case 'X':
			if (strncmp("Osmux: ", line + 2, strlen("Osmux: ")) == 0) {
				/* If osmux is disabled, just skip setting it up */
				if (!p->endp->cfg->osmux)
					break;
				osmux_cid = mgcp_osmux_setup(endp, line);
				break;
			}

			if (parse_x_osmo_ign(endp, line))
				break;

			/* Ignore unknown X-headers */
			break;
		case '\0':
			have_sdp = 1;
			goto mgcp_header_done;
		default:
			LOGP(DLMGCP, LOGL_NOTICE,
			     "CRCX: endpoint:%x unhandled option: '%c'/%d\n",
			     ENDPOINT_NUMBER(endp), *line, *line);
			return create_err_response(NULL, 539, "CRCX", p->trans);
			break;
		}
	}

mgcp_header_done:
	tcfg = p->endp->tcfg;

	/* Check parameters */
	if (!callid) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "CRCX: endpoint:%x insufficient parameters, missing callid\n",
		     ENDPOINT_NUMBER(endp));
		return create_err_response(endp, 516, "CRCX", p->trans);
	}

	if (!mode) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "CRCX: endpoint:%x insufficient parameters, missing mode\n",
		     ENDPOINT_NUMBER(endp));
		return create_err_response(endp, 517, "CRCX", p->trans);
	}

	/* Check if we are able to accept the creation of another connection */
	if (llist_count(&endp->conns) >= endp->type->max_conns) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "CRCX: endpoint:%x endpoint full, max. %i connections allowed!\n",
		     endp->type->max_conns, ENDPOINT_NUMBER(endp));
		if (tcfg->force_realloc) {
			/* There is no more room for a connection, make some
			 * room by blindly tossing the oldest of the two two
			 * connections */
			mgcp_conn_free_oldest(endp);
		} else {
			/* There is no more room for a connection, leave
			 * everything as it is and return with an error */
			return create_err_response(endp, 540, "CRCX", p->trans);
		}
	}

	/* Check if this endpoint already serves a call, if so, check if the
	 * callids match up so that we are sure that this is our call */
	if (endp->callid && mgcp_verify_call_id(endp, callid)) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "CRCX: endpoint:0x%x allready seized by other call (%s)\n",
		     ENDPOINT_NUMBER(endp), endp->callid);
		if (tcfg->force_realloc)
			/* This is not our call, toss everything by releasing
			 * the entire endpoint. (rude!) */
			mgcp_endp_release(endp);
		else {
			/* This is not our call, leave everything as it is and
			 * return with an error. */
			return create_err_response(endp, 400, "CRCX", p->trans);
		}
	}

	/* Set the callid, creation of another connection will only be possible
	 * when the callid matches up. (Connections are distinguished by their
	 * connection ids) */
	endp->callid = talloc_strdup(tcfg->endpoints, callid);

	snprintf(conn_name, sizeof(conn_name), "%s", callid);
	_conn = mgcp_conn_alloc(NULL, endp, MGCP_CONN_TYPE_RTP, conn_name);
	if (!_conn) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "CRCX: endpoint:0x%x unable to allocate RTP connection\n",
		     ENDPOINT_NUMBER(endp));
		goto error2;

	}
	conn = mgcp_conn_get_rtp(endp, _conn->id);
	OSMO_ASSERT(conn);

	if (mgcp_parse_conn_mode(mode, endp, conn->conn) != 0) {
		error_code = 517;
		goto error2;
	}

	/* Annotate Osmux circuit ID and set it to negotiating state until this
	 * is fully set up from the dummy load. */
	conn->osmux.state = OSMUX_STATE_DISABLED;
	if (osmux_cid >= 0) {
		conn->osmux.cid = osmux_cid;
		conn->osmux.state = OSMUX_STATE_NEGOTIATING;
	} else if (endp->cfg->osmux == OSMUX_USAGE_ONLY) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "CRCX: endpoint:0x%x osmux only and no osmux offered\n",
		     ENDPOINT_NUMBER(endp));
		goto error2;
	}

	/* Set local connection options, if present */
	if (local_options) {
		rc = set_local_cx_options(endp->tcfg->endpoints,
					  &endp->local_options, local_options);
		if (rc != 0) {
			LOGP(DLMGCP, LOGL_ERROR,
			     "CRCX: endpoint:%x inavlid local connection options!\n",
			     ENDPOINT_NUMBER(endp));
			error_code = rc;
			goto error2;
		}
	}

	/* Handle codec information and decide for a suitable codec */
	rc = handle_codec_info(conn, p, have_sdp, true);
	mgcp_codec_summary(conn);
	if (rc) {
		error_code = rc;
		goto error2;
	}

	conn->end.fmtp_extra = talloc_strdup(tcfg->endpoints,
					     tcfg->audio_fmtp_extra);

	if (p->cfg->force_ptime) {
		conn->end.packet_duration_ms = p->cfg->force_ptime;
		conn->end.force_output_ptime = 1;
	}

	mgcp_rtp_end_config(endp, 0, &conn->end);

	/* check connection mode setting */
	if (conn->conn->mode != MGCP_CONN_LOOPBACK
	    && conn->conn->mode != MGCP_CONN_RECV_ONLY
	    && conn->end.rtp_port == 0) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "CRCX: endpoint:%x selected connection mode type requires an opposite end!\n",
		     ENDPOINT_NUMBER(endp));
		error_code = 527;
		goto error2;
	}

	if (allocate_port(endp, conn) != 0) {
		goto error2;
	}

	if (setup_rtp_processing(endp, conn) != 0) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "CRCX: endpoint:0x%x could not start RTP processing!\n",
		     ENDPOINT_NUMBER(endp));
		goto error2;
	}

	/* policy CB */
	if (p->cfg->policy_cb) {
		int rc;
		rc = p->cfg->policy_cb(tcfg, ENDPOINT_NUMBER(endp),
				       MGCP_ENDP_CRCX, p->trans);
		switch (rc) {
		case MGCP_POLICY_REJECT:
			LOGP(DLMGCP, LOGL_NOTICE,
			     "CRCX: endpoint:0x%x CRCX rejected by policy\n",
			     ENDPOINT_NUMBER(endp));
			mgcp_endp_release(endp);
			return create_err_response(endp, 400, "CRCX", p->trans);
			break;
		case MGCP_POLICY_DEFER:
			/* stop processing */
			return NULL;
			break;
		case MGCP_POLICY_CONT:
			/* just continue */
			break;
		}
	}

	LOGP(DLMGCP, LOGL_DEBUG,
	     "CRCX: endpoint:0x%x Creating connection: CI: %s port: %u\n",
	     ENDPOINT_NUMBER(endp), conn->conn->id, conn->end.local_port);
	if (p->cfg->change_cb)
		p->cfg->change_cb(tcfg, ENDPOINT_NUMBER(endp), MGCP_ENDP_CRCX);

	/* Send dummy packet, see also comments in mgcp_keepalive_timer_cb() */
	OSMO_ASSERT(tcfg->keepalive_interval >= MGCP_KEEPALIVE_ONCE);
	if (conn->conn->mode & MGCP_CONN_RECV_ONLY
	    && tcfg->keepalive_interval != MGCP_KEEPALIVE_NEVER)
		send_dummy(endp, conn);

	LOGP(DLMGCP, LOGL_NOTICE,
	     "CRCX: endpoint:0x%x connection successfully created\n",
	     ENDPOINT_NUMBER(endp));
	return create_response_with_sdp(endp, conn, "CRCX", p->trans, true);
error2:
	mgcp_endp_release(endp);
	LOGP(DLMGCP, LOGL_NOTICE,
	     "CRCX: endpoint:0x%x unable to create connection\n",
	     ENDPOINT_NUMBER(endp));
	return create_err_response(endp, error_code, "CRCX", p->trans);
}





/* MDCX command handler, processes the received command */
static struct msgb *handle_modify_con(struct mgcp_parse_data *p)
{
	struct mgcp_endpoint *endp = p->endp;
	int error_code = 500;
	int silent = 0;
	int have_sdp = 0;
	char *line;
	const char *local_options = NULL;
	const char *mode = NULL;
	struct mgcp_conn_rtp *conn = NULL;
        const char *conn_id = NULL;
	int rc;

	LOGP(DLMGCP, LOGL_NOTICE, "MDCX: modifying existing connection ...\n");

	/* Prohibit wildcarded requests */
	if (endp->wildcarded_req) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "MDCX: endpoint:0x%x wildcarded endpoint names not supported.\n",
		     ENDPOINT_NUMBER(endp));
		return create_err_response(endp, 507, "MDCX", p->trans);
	}

	if (llist_count(&endp->conns) <= 0) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "MDCX: endpoint:0x%x endpoint is not holding a connection.\n",
		     ENDPOINT_NUMBER(endp));
		return create_err_response(endp, 400, "MDCX", p->trans);
	}

	for_each_line(line, p->save) {
		if (!mgcp_check_param(endp, line))
			continue;

		switch (line[0]) {
		case 'C':
			if (mgcp_verify_call_id(endp, line + 3) != 0) {
				error_code = 516;
				goto error3;
			}
			break;
		case 'I':
			conn_id = (const char *)line + 3;
			if ((error_code = mgcp_verify_ci(endp, conn_id)))
				goto error3;
			break;
		case 'L':
			local_options = (const char *)line + 3;
			break;
		case 'M':
			mode = (const char *)line + 3;
			break;
		case 'Z':
			silent = strcmp("noanswer", line + 3) == 0;
			break;
		case '\0':
			have_sdp = 1;
			goto mgcp_header_done;
			break;
		default:
			LOGP(DLMGCP, LOGL_NOTICE,
			     "MDCX: endpoint:0x%x Unhandled MGCP option: '%c'/%d\n",
			     ENDPOINT_NUMBER(endp), line[0], line[0]);
			return create_err_response(NULL, 539, "MDCX", p->trans);
			break;
		}
	}

mgcp_header_done:
	if (!conn_id) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "MDCX: endpoint:0x%x insufficient parameters, missing ci (connectionIdentifier)\n",
		     ENDPOINT_NUMBER(endp));
		return create_err_response(endp, 515, "MDCX", p->trans);
	}

	conn = mgcp_conn_get_rtp(endp, conn_id);
	if (!conn)
		return create_err_response(endp, 400, "MDCX", p->trans);

	if (mode) {
		if (mgcp_parse_conn_mode(mode, endp, conn->conn) != 0) {
			error_code = 517;
			goto error3;
		}
	} else
			conn->conn->mode = conn->conn->mode_orig;

	/* Set local connection options, if present */
	if (local_options) {
		rc = set_local_cx_options(endp->tcfg->endpoints,
					  &endp->local_options, local_options);
		if (rc != 0) {
			LOGP(DLMGCP, LOGL_ERROR,
			     "MDCX: endpoint:%x inavlid local connection options!\n",
			     ENDPOINT_NUMBER(endp));
			error_code = rc;
			goto error3;
		}
	}

	/* Handle codec information and decide for a suitable codec */
	rc = handle_codec_info(conn, p, have_sdp, false);
	mgcp_codec_summary(conn);
	if (rc) {
		error_code = rc;
		goto error3;
	}

	/* check connection mode setting */
	if (conn->conn->mode != MGCP_CONN_LOOPBACK
	    && conn->conn->mode != MGCP_CONN_RECV_ONLY
	    && conn->end.rtp_port == 0) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "MDCX: endpoint:%x selected connection mode type requires an opposite end!\n",
		     ENDPOINT_NUMBER(endp));
		error_code = 527;
		goto error3;
	}


	if (setup_rtp_processing(endp, conn) != 0)
		goto error3;


	/* policy CB */
	if (p->cfg->policy_cb) {
		int rc;
		rc = p->cfg->policy_cb(endp->tcfg, ENDPOINT_NUMBER(endp),
				       MGCP_ENDP_MDCX, p->trans);
		switch (rc) {
		case MGCP_POLICY_REJECT:
			LOGP(DLMGCP, LOGL_NOTICE,
			     "MDCX: endpoint:0x%x rejected by policy\n",
			     ENDPOINT_NUMBER(endp));
			if (silent)
				goto out_silent;
			return create_err_response(endp, 400, "MDCX", p->trans);
			break;
		case MGCP_POLICY_DEFER:
			/* stop processing */
			LOGP(DLMGCP, LOGL_DEBUG,
			     "MDCX: endpoint:0x%x defered by policy\n",
			     ENDPOINT_NUMBER(endp));
			return NULL;
			break;
		case MGCP_POLICY_CONT:
			/* just continue */
			break;
		}
	}

	mgcp_rtp_end_config(endp, 1, &conn->end);

	/* modify */
	LOGP(DLMGCP, LOGL_DEBUG,
	     "MDCX: endpoint:0x%x modified conn:%s\n",
	     ENDPOINT_NUMBER(endp), mgcp_conn_dump(conn->conn));
	if (p->cfg->change_cb)
		p->cfg->change_cb(endp->tcfg, ENDPOINT_NUMBER(endp),
				  MGCP_ENDP_MDCX);

	/* Send dummy packet, see also comments in mgcp_keepalive_timer_cb() */
	OSMO_ASSERT(endp->tcfg->keepalive_interval >= MGCP_KEEPALIVE_ONCE);
	if (conn->conn->mode & MGCP_CONN_RECV_ONLY
	    && endp->tcfg->keepalive_interval != MGCP_KEEPALIVE_NEVER)
		send_dummy(endp, conn);

	if (silent)
		goto out_silent;

	LOGP(DLMGCP, LOGL_NOTICE,
	     "MDCX: endpoint:0x%x connection successfully modified\n",
	     ENDPOINT_NUMBER(endp));
	return create_response_with_sdp(endp, conn, "MDCX", p->trans, false);
error3:
	return create_err_response(endp, error_code, "MDCX", p->trans);

out_silent:
	LOGP(DLMGCP, LOGL_DEBUG, "MDCX: endpoint:0x%x silent exit\n",
	     ENDPOINT_NUMBER(endp));
	return NULL;
}

/* DLCX command handler, processes the received command */
static struct msgb *handle_delete_con(struct mgcp_parse_data *p)
{
	struct mgcp_endpoint *endp = p->endp;
	int error_code = 400;
	int silent = 0;
	char *line;
	char stats[1048];
	const char *conn_id = NULL;
	struct mgcp_conn_rtp *conn = NULL;

	LOGP(DLMGCP, LOGL_NOTICE,
	     "DLCX: endpoint:0x%x deleting connection ...\n",
	     ENDPOINT_NUMBER(endp));

	/* Prohibit wildcarded requests */
	if (endp->wildcarded_req) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "DLCX: endpoint:0x%x wildcarded endpoint names not supported.\n",
		     ENDPOINT_NUMBER(endp));
		return create_err_response(endp, 507, "DLCX", p->trans);
	}

	if (llist_count(&endp->conns) <= 0) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "DLCX: endpoint:0x%x endpoint is not holding a connection.\n",
		     ENDPOINT_NUMBER(endp));
		return create_err_response(endp, 515, "DLCX", p->trans);
	}

	for_each_line(line, p->save) {
		if (!mgcp_check_param(endp, line))
			continue;

		switch (line[0]) {
		case 'C':
			if (mgcp_verify_call_id(endp, line + 3) != 0) {
				error_code = 516;
				goto error3;
			}
			break;
		case 'I':
			conn_id = (const char *)line + 3;
			if ((error_code = mgcp_verify_ci(endp, conn_id)))
				goto error3;
			break;
		case 'Z':
			silent = strcmp("noanswer", line + 3) == 0;
			break;
		default:
			LOGP(DLMGCP, LOGL_NOTICE,
			     "DLCX: endpoint:0x%x Unhandled MGCP option: '%c'/%d\n",
			     ENDPOINT_NUMBER(endp), line[0], line[0]);
			return create_err_response(NULL, 539, "DLCX", p->trans);
			break;
		}
	}

	/* policy CB */
	if (p->cfg->policy_cb) {
		int rc;
		rc = p->cfg->policy_cb(endp->tcfg, ENDPOINT_NUMBER(endp),
				       MGCP_ENDP_DLCX, p->trans);
		switch (rc) {
		case MGCP_POLICY_REJECT:
			LOGP(DLMGCP, LOGL_NOTICE,
			     "DLCX: endpoint:0x%x rejected by policy\n",
			     ENDPOINT_NUMBER(endp));
			if (silent)
				goto out_silent;
			return create_err_response(endp, 400, "DLCX", p->trans);
			break;
		case MGCP_POLICY_DEFER:
			/* stop processing */
			return NULL;
			break;
		case MGCP_POLICY_CONT:
			/* just continue */
			break;
		}
	}

	/* When no connection id is supplied, we will interpret this as a
	 * wildcarded DLCX and drop all connections at once. (See also
	 * RFC3435 Section F.7) */
	if (!conn_id) {
		LOGP(DLMGCP, LOGL_NOTICE,
		     "DLCX: endpoint:0x%x missing ci (connectionIdentifier), will remove all connections at once\n",
		     ENDPOINT_NUMBER(endp));

		mgcp_endp_release(endp);

		/* Note: In this case we do not return any statistics,
		 * as we assume that the client is not interested in
		 * this case. */
		return create_ok_response(endp, 200, "DLCX", p->trans);
	}

	/* Find the connection */
	conn = mgcp_conn_get_rtp(endp, conn_id);
	if (!conn)
		goto error3;

	/* save the statistics of the current connection */
	mgcp_format_stats(stats, sizeof(stats), conn->conn);

	/* delete connection */
	LOGP(DLMGCP, LOGL_DEBUG, "DLCX: endpoint:0x%x deleting conn:%s\n",
	     ENDPOINT_NUMBER(endp), mgcp_conn_dump(conn->conn));
	mgcp_conn_free(endp, conn_id);
	LOGP(DLMGCP, LOGL_NOTICE,
	     "DLCX: endpoint:0x%x connection successfully deleted\n",
	     ENDPOINT_NUMBER(endp));

	/* When all connections are closed, the endpoint will be released
	 * in order to be ready to be used by another call. */
	if (llist_count(&endp->conns) <= 0) {
		mgcp_endp_release(endp);
		LOGP(DLMGCP, LOGL_DEBUG,
		     "DLCX: endpoint:0x%x endpoint released\n",
		     ENDPOINT_NUMBER(endp));
	}

	if (p->cfg->change_cb)
		p->cfg->change_cb(endp->tcfg, ENDPOINT_NUMBER(endp),
				  MGCP_ENDP_DLCX);

	if (silent)
		goto out_silent;
	return create_ok_resp_with_param(endp, 250, "DLCX", p->trans, stats);

error3:
	return create_err_response(endp, error_code, "DLCX", p->trans);

out_silent:
	LOGP(DLMGCP, LOGL_DEBUG, "DLCX: endpoint:0x%x silent exit\n",
	     ENDPOINT_NUMBER(endp));
	return NULL;
}

/* RSIP command handler, processes the received command */
static struct msgb *handle_rsip(struct mgcp_parse_data *p)
{
	/* TODO: Also implement the resetting of a specific endpoint
	 * to make mgcp_send_reset_ep() work. Currently this will call
	 * mgcp_rsip_cb() in mgw_main.c, which sets reset_endpoints=1
	 * to make read_call_agent() reset all endpoints when called
	 * next time. In order to selectively reset endpoints some
	 * mechanism to distinguish which endpoint shall be resetted
	 * is needed */

	LOGP(DLMGCP, LOGL_NOTICE, "RSIP: resetting all endpoints ...\n");

	if (p->cfg->reset_cb)
		p->cfg->reset_cb(p->endp->tcfg);
	return NULL;
}

static char extract_tone(const char *line)
{
	const char *str = strstr(line, "D/");
	if (!str)
		return CHAR_MAX;

	return str[2];
}

/* This can request like DTMF detection and forward, fax detection... it
 * can also request when the notification should be send and such. We don't
 * do this right now. */
static struct msgb *handle_noti_req(struct mgcp_parse_data *p)
{
	int res = 0;
	char *line;
	char tone = CHAR_MAX;

	LOGP(DLMGCP, LOGL_NOTICE, "RQNT: processing request for notification ...\n");

	for_each_line(line, p->save) {
		switch (line[0]) {
		case 'S':
			tone = extract_tone(line);
			break;
		}
	}

	/* we didn't see a signal request with a tone */
	if (tone == CHAR_MAX)
		return create_ok_response(p->endp, 200, "RQNT", p->trans);

	if (p->cfg->rqnt_cb)
		res = p->cfg->rqnt_cb(p->endp, tone);

	return res == 0 ?
	    create_ok_response(p->endp, 200, "RQNT", p->trans) :
	    create_err_response(p->endp, res, "RQNT", p->trans);
}

/* Connection keepalive timer, will take care that dummy packets are send
 * regularly, so that NAT connections stay open */
static void mgcp_keepalive_timer_cb(void *_tcfg)
{
	struct mgcp_trunk_config *tcfg = _tcfg;
	struct mgcp_conn *conn;
	int i;

	LOGP(DLMGCP, LOGL_DEBUG, "triggered trunk %d keepalive timer\n",
	     tcfg->trunk_nr);

	/* Do not accept invalid configuration values
	 * valid is MGCP_KEEPALIVE_NEVER, MGCP_KEEPALIVE_ONCE and
	 * values greater 0 */
	OSMO_ASSERT(tcfg->keepalive_interval >= MGCP_KEEPALIVE_ONCE);

	/* The dummy packet functionality has been disabled, we will exit
	 * immediately, no further timer is scheduled, which means we will no
	 * longer send dummy packets even when we did before */
	if (tcfg->keepalive_interval == MGCP_KEEPALIVE_NEVER)
		return;

	/* In cases where only one dummy packet is sent, we do not need
	 * the timer since the functions that handle the CRCX and MDCX are
	 * triggering the sending of the dummy packet. So we behave like in
	 * the  MGCP_KEEPALIVE_NEVER case */
	if (tcfg->keepalive_interval == MGCP_KEEPALIVE_ONCE)
		return;

	/* Send walk over all endpoints and send out dummy packets through
	 * every connection present on each endpoint */
	for (i = 1; i < tcfg->number_endpoints; ++i) {
		struct mgcp_endpoint *endp = &tcfg->endpoints[i];
		llist_for_each_entry(conn, &endp->conns, entry) {
			if (conn->mode == MGCP_CONN_RECV_ONLY)
				send_dummy(endp, &conn->u.rtp);
		}
	}

	/* Schedule the keepalive timer for the next round */
	LOGP(DLMGCP, LOGL_DEBUG, "rescheduling trunk %d keepalive timer\n",
	     tcfg->trunk_nr);
	osmo_timer_schedule(&tcfg->keepalive_timer, tcfg->keepalive_interval,
			    0);
}

void mgcp_trunk_set_keepalive(struct mgcp_trunk_config *tcfg, int interval)
{
	tcfg->keepalive_interval = interval;
	osmo_timer_setup(&tcfg->keepalive_timer, mgcp_keepalive_timer_cb, tcfg);

	if (interval <= 0)
		osmo_timer_del(&tcfg->keepalive_timer);
	else
		osmo_timer_schedule(&tcfg->keepalive_timer,
				    tcfg->keepalive_interval, 0);
}

/*! allocate configuration with default values.
 *  (called once at startup by main function) */
struct mgcp_config *mgcp_config_alloc(void)
{
	struct mgcp_config *cfg;

	cfg = talloc_zero(NULL, struct mgcp_config);
	if (!cfg) {
		LOGP(DLMGCP, LOGL_FATAL, "Failed to allocate config.\n");
		return NULL;
	}

	osmo_strlcpy(cfg->domain, "mgw", sizeof(cfg->domain));

	cfg->net_ports.range_start = RTP_PORT_DEFAULT_RANGE_START;
	cfg->net_ports.range_end = RTP_PORT_DEFAULT_RANGE_END;
	cfg->net_ports.last_port = cfg->net_ports.range_start;

	cfg->source_port = 2427;
	cfg->source_addr = talloc_strdup(cfg, "0.0.0.0");
	cfg->osmux_addr = talloc_strdup(cfg, "0.0.0.0");

	cfg->rtp_processing_cb = &mgcp_rtp_processing_default;
	cfg->setup_rtp_processing_cb = &mgcp_setup_rtp_processing_default;

	cfg->get_net_downlink_format_cb = &mgcp_get_net_downlink_format_default;

	/* default trunk handling */
	cfg->trunk.cfg = cfg;
	cfg->trunk.trunk_nr = 0;
	cfg->trunk.trunk_type = MGCP_TRUNK_VIRTUAL;
	cfg->trunk.audio_name = talloc_strdup(cfg, "AMR/8000");
	cfg->trunk.audio_payload = 126;
	cfg->trunk.audio_send_ptime = 1;
	cfg->trunk.audio_send_name = 1;
	cfg->trunk.omit_rtcp = 0;
	mgcp_trunk_set_keepalive(&cfg->trunk, MGCP_KEEPALIVE_ONCE);

	INIT_LLIST_HEAD(&cfg->trunks);

	return cfg;
}

/*! allocate configuration with default values.
 *  (called once at startup by VTY)
 *  \param[in] cfg mgcp configuration
 *  \param[in] nr trunk number
 *  \returns pointer to allocated trunk configuration */
struct mgcp_trunk_config *mgcp_trunk_alloc(struct mgcp_config *cfg, int nr)
{
	struct mgcp_trunk_config *trunk;

	trunk = talloc_zero(cfg, struct mgcp_trunk_config);
	if (!trunk) {
		LOGP(DLMGCP, LOGL_ERROR, "Failed to allocate.\n");
		return NULL;
	}

	trunk->cfg = cfg;
	trunk->trunk_type = MGCP_TRUNK_E1;
	trunk->trunk_nr = nr;
	trunk->audio_name = talloc_strdup(cfg, "AMR/8000");
	trunk->audio_payload = 126;
	trunk->audio_send_ptime = 1;
	trunk->audio_send_name = 1;
	trunk->vty_number_endpoints = 33;
	trunk->omit_rtcp = 0;
	mgcp_trunk_set_keepalive(trunk, MGCP_KEEPALIVE_ONCE);
	llist_add_tail(&trunk->entry, &cfg->trunks);
	return trunk;
}

/*! get trunk configuration by trunk number (index).
 *  \param[in] cfg mgcp configuration
 *  \param[in] index trunk number
 *  \returns pointer to trunk configuration, NULL on error */
struct mgcp_trunk_config *mgcp_trunk_num(struct mgcp_config *cfg, int index)
{
	struct mgcp_trunk_config *trunk;

	llist_for_each_entry(trunk, &cfg->trunks, entry)
	    if (trunk->trunk_nr == index)
		return trunk;

	return NULL;
}

/*! allocate endpoints and set default values.
 *  (called once at startup by VTY)
 *  \param[in] tcfg trunk configuration
 *  \returns 0 on success, -1 on failure */
int mgcp_endpoints_allocate(struct mgcp_trunk_config *tcfg)
{
	int i;

	tcfg->endpoints = _talloc_zero_array(tcfg->cfg,
					     sizeof(struct mgcp_endpoint),
					     tcfg->vty_number_endpoints,
					     "endpoints");
	if (!tcfg->endpoints)
		return -1;

	for (i = 0; i < tcfg->vty_number_endpoints; ++i) {
		INIT_LLIST_HEAD(&tcfg->endpoints[i].conns);
		tcfg->endpoints[i].cfg = tcfg->cfg;
		tcfg->endpoints[i].tcfg = tcfg;

		/* NOTE: Currently all endpoints are of type RTP, this will
		 * change when new variations are implemented */
		tcfg->endpoints[i].type = &ep_typeset.rtp;
	}

	tcfg->number_endpoints = tcfg->vty_number_endpoints;
	return 0;
}

static int send_agent(struct mgcp_config *cfg, const char *buf, int len)
{
	return write(cfg->gw_fd.bfd.fd, buf, len);
}

/*! Reset all endpoints by sending RSIP message to self.
 *  (called by VTY)
 *  \param[in] endp trunk endpoint
 *  \param[in] endpoint number
 *  \returns 0 on success, -1 on error */
int mgcp_send_reset_all(struct mgcp_config *cfg)
{
	char buf[MGCP_ENDPOINT_MAXLEN + 128];
	int len;
	int rc;

	len = snprintf(buf, sizeof(buf),
		       "RSIP 1 *@%s MGCP 1.0\r\n", cfg->domain);
	if (len < 0)
		return -1;

	rc = send_agent(cfg, buf, len);
	if (rc <= 0)
		return -1;

	return 0;
}

/*! Reset a single endpoint by sending RSIP message to self.
 *  (called by VTY)
 *  \param[in] endp trunk endpoint
 *  \param[in] endpoint number
 *  \returns 0 on success, -1 on error */
int mgcp_send_reset_ep(struct mgcp_endpoint *endp, int endpoint)
{
	char buf[MGCP_ENDPOINT_MAXLEN + 128];
	int len;
	int rc;

	len = snprintf(buf, sizeof(buf),
		       "RSIP 39 %x@%s MGCP 1.0\r\n", endpoint, endp->cfg->domain);
	if (len < 0)
		return -1;

	rc = send_agent(endp->cfg, buf, len);
	if (rc <= 0)
		return -1;

	return 0;
}

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
#include <pthread.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/select.h>

#include <osmocom/mgcp/mgcp.h>
#include <osmocom/mgcp/mgcp_common.h>
#include <osmocom/mgcp/osmux.h>
#include <osmocom/mgcp/mgcp_network.h>
#include <osmocom/mgcp/mgcp_protocol.h>
#include <osmocom/mgcp/mgcp_stat.h>
#include <osmocom/mgcp/mgcp_msg.h>
#include <osmocom/mgcp/mgcp_endp.h>
#include <osmocom/mgcp/mgcp_trunk.h>
#include <osmocom/mgcp/mgcp_sdp.h>
#include <osmocom/mgcp/mgcp_codec.h>
#include <osmocom/mgcp/mgcp_conn.h>
#include <osmocom/mgcp/mgcp_iuup.h>
#include <osmocom/mgcp/debug.h>

/* Contains the last successfully resolved endpoint name. This variable is used
 * for the unit-tests to verify that the endpoint was correctly resolved. */
static char debug_last_endpoint_name[MGCP_ENDPOINT_MAXLEN];

/* Called from unit-tests only */
char *mgcp_debug_get_last_endpoint_name(void)
{
	return debug_last_endpoint_name;
}

const struct value_string mgcp_connection_mode_strs[] = {
	{ MGCP_CONN_NONE, "none" },
	{ MGCP_CONN_RECV_SEND, "sendrecv" },
	{ MGCP_CONN_SEND_ONLY, "sendonly" },
	{ MGCP_CONN_RECV_ONLY, "recvonly" },
	{ MGCP_CONN_CONFECHO, "confecho" },
	{ MGCP_CONN_LOOPBACK, "loopback" },
	{ 0, NULL }
};

/* A combination of LOGPENDP and LOGPTRUNK that automatically falls back to
 * LOGPTRUNK when the endp parameter is NULL */
#define LOGPEPTR(endp, trunk, cat, level, fmt, args...) \
do { \
	if (endp) \
		LOGPENDP(endp, cat, level, fmt, ## args); \
	else \
		LOGPTRUNK(trunk, cat, level, fmt, ## args); \
} while (0)

/* Request data passed to the request handler */
struct mgcp_request_data {
	/* request name (e.g. "MDCX") */
	char name[4+1];

	/* parsing results from the MGCP header (trans id, endpoint name ...) */
	struct mgcp_parse_data *pdata;

	/* pointer to endpoint resource (may be NULL for wildcarded requests) */
	struct mgcp_endpoint *endp;

	/* pointer to trunk resource */
	struct mgcp_trunk *trunk;

	/* set to true when the request has been classified as wildcarded */
	bool wildcarded;

	/* Set to true when the request is targeted at the "null" endpoint */
	bool null_endp;

	/* contains cause code in case of problems during endp/trunk resolution */
	int mgcp_cause;
};

/* Request handler specification, here we specify an array with function
 * pointers to the various MGCP requests implemented below */
struct mgcp_request {
	/* request name (e.g. "MDCX") */
	char *name;

	/* function pointer to the request handler */
	struct msgb *(*handle_request)(struct mgcp_request_data *data);

	/* a human readable name that describes the request */
	char *debug_name;
};

static struct msgb *handle_audit_endpoint(struct mgcp_request_data *data);
static struct msgb *handle_create_con(struct mgcp_request_data *data);
static struct msgb *handle_delete_con(struct mgcp_request_data *data);
static struct msgb *handle_modify_con(struct mgcp_request_data *data);
static struct msgb *handle_rsip(struct mgcp_request_data *data);
static struct msgb *handle_noti_req(struct mgcp_request_data *data);
static const struct mgcp_request mgcp_requests[] = {
	{ .name = "AUEP", .handle_request = handle_audit_endpoint, .debug_name = "AuditEndpoint" },
	{
		.name = "CRCX",
		.handle_request = handle_create_con,
		.debug_name = "CreateConnection",
	},
	{
		.name = "DLCX",
		.handle_request = handle_delete_con,
		.debug_name = "DeleteConnection",
	},
	{
		.name = "MDCX",
		.handle_request = handle_modify_con,
		.debug_name = "ModifiyConnection",
	},
	{
		.name = "RQNT",
		.handle_request = handle_noti_req,
		.debug_name = "NotificationRequest",
	},

	/* SPEC extension */
	{
		.name = "RSIP",
		.handle_request = handle_rsip,
		.debug_name = "ReSetInProgress",
	},
};

/* Initalize transcoder */
static int setup_rtp_processing(struct mgcp_endpoint *endp,
				struct mgcp_conn_rtp *conn)
{
	struct mgcp_config *cfg = endp->trunk->cfg;
	struct mgcp_conn_rtp *conn_src = NULL;
	struct mgcp_conn_rtp *conn_dst = conn;
	struct mgcp_conn *_conn;

	switch (conn->type) {
	case MGCP_RTP_DEFAULT:
	case MGCP_RTP_OSMUX:
	case MGCP_RTP_IUUP:
		break;
	default:
		LOGPENDP(endp, DLMGCP, LOGL_NOTICE,
			 "RTP-setup: Endpoint is not configured as RTP default, stopping here!\n");
		return 0;
	}

	if (conn->conn->mode == MGCP_CONN_LOOPBACK) {
		LOGPENDP(endp, DLMGCP, LOGL_NOTICE,
			 "RTP-setup: Endpoint is in loopback mode, stopping here!\n");
		return 0;
	}

	/* Find the "sister" connection */
	llist_for_each_entry(_conn, &endp->conns, entry) {
		if (_conn->id != conn->conn->id) {
			conn_src = mgcp_conn_get_conn_rtp(_conn);
			break;
		}
	}

	return cfg->setup_rtp_processing_cb(endp, conn_dst, conn_src);
}

/* Helper function to allocate some memory for responses and retransmissions */
static struct msgb *mgcp_msgb_alloc(void *ctx)
{
	struct msgb *msg;
	msg = msgb_alloc_headroom_c(ctx, 4096, 128, "MGCP msg");

	if (!msg) {
		LOGP(DLMGCP, LOGL_ERROR, "Failed to msgb for MGCP data.\n");
		return NULL;
	}

	return msg;
}

/* Helper function for do_retransmission() and create_resp() */
static struct msgb *create_retransmission_response(const struct mgcp_endpoint *endp)
{
	struct msgb *msg = mgcp_msgb_alloc(endp->trunk);
	if (!msg)
		return NULL;

	msg->l2h = msgb_put(msg, strlen(endp->last_response));
	memcpy(msg->l2h, endp->last_response, msgb_l2len(msg));
	mgcp_disp_msg(msg->l2h, msgb_l2len(msg), "Retransmitted response");
	return msg;
}

static struct msgb *create_resp(void *msgctx, struct mgcp_endpoint *endp, int code, const char *txt, const char *msg,
				const char *trans, const char *param, const char *sdp)
{
	int len;
	struct msgb *res;

	OSMO_ASSERT(msgctx != 0);
	res = mgcp_msgb_alloc(msgctx);
	if (!res)
		return NULL;

	len = snprintf((char *)res->data, 2048, "%d %s%s%s\r\n%s",
		       code, trans, txt, param ? param : "", sdp ? sdp : "");
	if (len < 0) {
		LOGPENDP(endp, DLMGCP, LOGL_ERROR, "Failed to sprintf MGCP response.\n");
		msgb_free(res);
		return NULL;
	}

	res->l2h = msgb_put(res, len);
	LOGPENDP(endp, DLMGCP, LOGL_DEBUG, "Generated response: code=%d\n", code);
	mgcp_disp_msg(res->l2h, msgb_l2len(res), "Generated response");

	/*
	 * Remember the last transmission per endpoint.
	 */
	if (endp) {
		struct mgcp_trunk *trunk = endp->trunk;
		talloc_free(endp->last_response);
		talloc_free(endp->last_trans);
		endp->last_trans = talloc_strdup(trunk->endpoints, trans);
		endp->last_response = talloc_strndup(trunk->endpoints,
						     (const char *)res->l2h,
						     msgb_l2len(res));
	}

	return res;
}

static struct msgb *create_ok_resp_with_param(void *msgctx, struct mgcp_endpoint *endp, int code, const char *msg,
					      const char *trans, const char *param)
{
	return create_resp(msgctx, endp, code, " OK", msg, trans, param, NULL);
}

static struct msgb *create_ok_response(void *msgctx, struct mgcp_endpoint *endp, int code, const char *msg,
				       const char *trans)
{
	return create_ok_resp_with_param(msgctx, endp, code, msg, trans, NULL);
}

static struct msgb *create_err_response(void *msgctx, struct mgcp_endpoint *endp, int code, const char *msg,
					const char *trans)
{
	return create_resp(msgctx, endp, code, " FAIL", msg, trans, NULL, NULL);
}

/* Format MGCP response string (with SDP attached) */
static struct msgb *create_response_with_sdp(struct mgcp_endpoint *endp,
					     struct mgcp_conn_rtp *conn,
					     const char *msg,
					     const char *trans_id,
					     bool add_epname,
					     bool add_conn_id)
{
	/* cfg->local_ip allows overwritting the announced IP address with
	 * regards to the one we actually bind to. Useful in behind-NAT
	 * scenarios.
	 * TODO: we may want to define another local_ip_osmux var to
	 * us for OSMUX connections. Perhaps adding a new internal API to get it
	 * based on conn type.
	 */
	const char *addr = strlen(endp->trunk->cfg->local_ip) ? endp->trunk->cfg->local_ip : conn->end.local_addr;
	struct msgb *sdp;
	int rc;
	struct msgb *result;

	sdp = msgb_alloc_headroom_c(endp->trunk, 4096, 128, "sdp record");
	if (!sdp)
		return NULL;

	/* Attach optional endpoint name */
	if (add_epname) {
		rc = msgb_printf(sdp, "Z: %s\r\n", endp->name);
		if (rc < 0)
			goto error;
	}

	/* Attach optional connection id */
	if (add_conn_id) {
		rc = msgb_printf(sdp, "I: %s\r\n", conn->conn->id);
		if (rc < 0)
			goto error;
	}

	/* Attach optional OSMUX parameters */
	if (mgcp_conn_rtp_is_osmux(conn)) {
		rc = msgb_printf(sdp, MGCP_X_OSMO_OSMUX_HEADER " %u\r\n", conn->osmux.local_cid);
		if (rc < 0)
			goto error;
	}

	/* Attach line break to separate the parameters from the SDP block */
	rc = msgb_printf(sdp, "\r\n");

	rc = mgcp_write_response_sdp(endp, conn, sdp, addr);
	if (rc < 0)
		goto error;
	result = create_resp(endp->trunk, endp, 200, " OK", msg, trans_id, NULL, (char *)sdp->data);
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
	/* Avoid sending dummy packet if the remote address was not yet
	 * configured through CRCX/MDCX: */
	if (!mgcp_rtp_end_remote_addr_available(&conn->end))
		return;

	if (mgcp_conn_rtp_is_osmux(conn))
		osmux_send_dummy(conn);
	else
		mgcp_send_dummy(endp, conn);
}

/* handle incoming messages:
 *   - this can be a command (four letters, space, transaction id)
 *   - or a response (three numbers, space, transaction id) */
struct msgb *mgcp_handle_message(struct mgcp_config *cfg, struct msgb *msg)
{
	struct rate_ctr_group *rate_ctrs = cfg->ratectr.mgcp_general_ctr_group;
	struct mgcp_parse_data pdata;
	struct mgcp_request_data rq;
	int rc, i, code, handled = 0;
	struct msgb *resp = NULL;
	char *data;

	debug_last_endpoint_name[0] = '\0';

	/* Count all messages, even incorect ones */
	rate_ctr_inc(rate_ctr_group_get_ctr(rate_ctrs, MGCP_GENERAL_RX_MSGS_TOTAL));

	if (msgb_l2len(msg) < 4) {
		LOGP(DLMGCP, LOGL_ERROR, "msg too short: %d\n", msg->len);
		rate_ctr_inc(rate_ctr_group_get_ctr(rate_ctrs, MGCP_GENERAL_RX_FAIL_MSG_PARSE));
		return NULL;
	}

	if (mgcp_msg_terminate_nul(msg)) {
		rate_ctr_inc(rate_ctr_group_get_ctr(rate_ctrs, MGCP_GENERAL_RX_FAIL_MSG_PARSE));
		return NULL;
	}

	mgcp_disp_msg(msg->l2h, msgb_l2len(msg), "Received message");

	/* attempt to treat it as a response */
	if (sscanf((const char *)&msg->l2h[0], "%3d %*s", &code) == 1) {
		LOGP(DLMGCP, LOGL_DEBUG, "Response: Code: %d\n", code);
		rate_ctr_inc(rate_ctr_group_get_ctr(rate_ctrs, MGCP_GENERAL_RX_FAIL_MSG_PARSE));
		return NULL;
	}


	/* Parse message, extract endpoint name and transaction identifier and request name etc. */
	memset(&pdata, 0, sizeof(pdata));
	memset(&rq, 0, sizeof(rq));
	pdata.cfg = cfg;
	memcpy(rq.name, (const char *)&msg->l2h[0], sizeof(rq.name)-1);
	msg->l3h = &msg->l2h[4];
	data = mgcp_strline((char *)msg->l3h, &pdata.save);
	rc = mgcp_parse_header(&pdata, data);
	if (rc < 0) {
		LOGP(DLMGCP, LOGL_ERROR, "%s: failed to parse MCGP message\n", rq.name);
		rate_ctr_inc(rate_ctr_group_get_ctr(rate_ctrs, MGCP_GENERAL_RX_FAIL_MSG_PARSE));
		return create_err_response(cfg, NULL, -rc, rq.name, "000000");
	}

	/* Locate endpoint and trunk, if no endpoint can be located try at least to identify the trunk. */
	rq.pdata = &pdata;
	rq.wildcarded = mgcp_endp_is_wildcarded(pdata.epname);
	if (!rq.wildcarded)
		rq.null_endp = mgcp_endp_is_null(pdata.epname);
	if (!rq.null_endp)
		rq.endp = mgcp_endp_by_name(&rc, pdata.epname, pdata.cfg);
	rq.mgcp_cause = rc;
	if (!rq.endp) {
		rate_ctr_inc(rate_ctr_group_get_ctr(rate_ctrs, MGCP_GENERAL_RX_FAIL_NO_ENDPOINT));
		if (rq.wildcarded) {
			/* If we are unable to find the endpoint we still may be able to identify the trunk. Some
			 * request handlers will still be able to perform a useful action if the request refers to
			 * the whole trunk (wildcarded request). */
			LOGP(DLMGCP, LOGL_NOTICE,
			     "%s: cannot find endpoint \"%s\", cause=%d -- trying to identify trunk...\n", rq.name,
			     pdata.epname, -rq.mgcp_cause);
			rq.trunk = mgcp_trunk_by_name(pdata.cfg, pdata.epname);
			if (!rq.trunk) {
				LOGP(DLMGCP, LOGL_ERROR, "%s: failed to identify trunk for endpoint \"%s\" -- abort\n",
				     rq.name, pdata.epname);
				return create_err_response(cfg, NULL, -rq.mgcp_cause, rq.name, pdata.trans);
			}
		} else if (!rq.null_endp) {
			/* If the endpoint name suggests that the request refers to a specific endpoint, then the
			 * request cannot be handled and we must stop early. */
			LOGP(DLMGCP, LOGL_NOTICE,
			     "%s: cannot find endpoint \"%s\", cause=%d -- abort\n", rq.name,
			     pdata.epname, -rq.mgcp_cause);
			return create_err_response(cfg, NULL, -rq.mgcp_cause, rq.name, pdata.trans);
		} /* else: Handle special "null" endpoint below (with rq.endp=NULL, rq.trunk=NULL) */
	} else {
		osmo_strlcpy(debug_last_endpoint_name, rq.endp->name, sizeof(debug_last_endpoint_name));
		rq.trunk = rq.endp->trunk;
		rq.mgcp_cause = 0;

		/* Check if we have to retransmit a response from a previous transaction */
		if (pdata.trans && rq.endp->last_trans && strcmp(rq.endp->last_trans, pdata.trans) == 0) {
			rate_ctr_inc(rate_ctr_group_get_ctr(rate_ctrs, MGCP_GENERAL_RX_MSGS_RETRANSMITTED));
			return create_retransmission_response(rq.endp);
		}
	}

	/* Find an appropriate handler for the current request and execute it */
	for (i = 0; i < ARRAY_SIZE(mgcp_requests); i++) {
		if (strcmp(mgcp_requests[i].name, rq.name) == 0) {
			/* Execute request handler */
			if (rq.endp)
				LOGP(DLMGCP, LOGL_INFO,
				     "%s: executing request handler \"%s\" for endpoint resource \"%s\"\n", rq.name,
				     mgcp_requests[i].debug_name, rq.endp->name);
			else
				LOGP(DLMGCP, LOGL_INFO,
				     "%s: executing request handler \"%s\" for trunk resource of endpoint \"%s\"\n",
				     rq.name, mgcp_requests[i].debug_name, pdata.epname);
			resp = mgcp_requests[i].handle_request(&rq);
			handled = 1;
			break;
		}
	}

	/* Check if the MGCP request was handled and increment rate counters accordingly. */
	if (handled) {
		rate_ctr_inc(rate_ctr_group_get_ctr(rate_ctrs, MGCP_GENERAL_RX_MSGS_HANDLED));
	} else {
		rate_ctr_inc(rate_ctr_group_get_ctr(rate_ctrs, MGCP_GENERAL_RX_MSGS_UNHANDLED));
		LOGP(DLMGCP, LOGL_ERROR, "MSG with type: '%.4s' not handled\n", &msg->l2h[0]);
	}

	return resp;
}

/* AUEP command handler, processes the received command */
static struct msgb *handle_audit_endpoint(struct mgcp_request_data *rq)
{
	LOGPENDP(rq->endp, DLMGCP, LOGL_NOTICE, "AUEP: auditing endpoint ...\n");

	/* Auditing "null" endpoint is allowed for keepalive purposes. There's no rq->endp nor rq->trunk in this case. */
	if (rq->null_endp)
		return create_ok_response(rq->pdata->cfg, NULL, 200, "AUEP", rq->pdata->trans);

	if (!rq->endp || !mgcp_endp_avail(rq->endp)) {
		LOGPENDP(rq->endp, DLMGCP, LOGL_ERROR, "AUEP: selected endpoint not available!\n");
		return create_err_response(rq->trunk, NULL, 501, "AUEP", rq->pdata->trans);
	}

	return create_ok_response(rq->trunk, rq->endp, 200, "AUEP", rq->pdata->trans);
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
			if (strcasecmp(lco_seen[i], lco_identifier) == 0)
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
	char *lco_id;
	char codec[17];
	char nt[17];
	int len;

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

	lco_id = lco->string;
	while ((lco_id = get_lco_identifier(lco_id))) {
		switch (tolower(lco_id[0])) {
		case 'p':
			if (sscanf(lco_id + 1, ":%d-%d",
				   &lco->pkt_period_min, &lco->pkt_period_max) == 1)
				lco->pkt_period_max = lco->pkt_period_min;
			break;
		case 'a':
			/* FIXME: LCO also supports the negotiation of more than one codec.
			 * (e.g. a:PCMU;G726-32) But this implementation only supports a single
			 * codec only. Ignoring all but the first codec. */
			if (sscanf(lco_id + 1, ":%16[^,;]", codec) == 1) {
				talloc_free(lco->codec);
				/* MGCP header is case insensive, and we'll need
				   codec in uppercase when using it later: */
				len = strlen(codec);
				lco->codec = talloc_size(ctx, len + 1);
				osmo_str_toupper_buf(lco->codec, len + 1, codec);
			}
			break;
		case 'n':
			if (lco_id[1] == 't' && sscanf(lco_id + 2, ":%16[^,]", nt) == 1)
				break;
			/* else: fall throught to print notice log */
		default:
			LOGP(DLMGCP, LOGL_NOTICE,
			     "LCO: unhandled option: '%c'/%d in \"%s\"\n",
			     *lco_id, *lco_id, lco->string);
			break;
		}

		lco_id = strchr(lco_id, ',');
		if (!lco_id)
			break;
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

uint32_t mgcp_rtp_packet_duration(const struct mgcp_endpoint *endp,
				  const struct mgcp_rtp_end *rtp)
{
	int f = 0;
	struct mgcp_rtp_codec *codec = rtp->cset.codec;

	/* Get the number of frames per channel and packet */
	if (rtp->frames_per_packet)
		f = rtp->frames_per_packet;
	else if (rtp->packet_duration_ms && codec->frame_duration_num) {
		int den = 1000 * codec->frame_duration_num;
		f = (rtp->packet_duration_ms * codec->frame_duration_den +
		     den / 2)
		    / den;
	}

	return codec->rate * f * codec->frame_duration_num /
	    codec->frame_duration_den;
}

static int mgcp_trunk_osmux_init_if_needed(struct mgcp_trunk *trunk)
{
	if (trunk->cfg->osmux.initialized)
		return 0;

	if (osmux_init(trunk) < 0) {
		LOGPTRUNK(trunk, DOSMUX, LOGL_ERROR, "Cannot init OSMUX\n");
		return -3;
	}
	LOGPTRUNK(trunk, DOSMUX, LOGL_NOTICE, "OSMUX socket has been set up\n");

	return 0;
}

/* Apply parsed SDP information stored in struct mgcp_parse_sdp to conn_rtp: */
static int handle_sdp(struct mgcp_conn_rtp *conn, struct mgcp_request_data *rq)
{
	OSMO_ASSERT(conn);
	OSMO_ASSERT(rq);
	struct mgcp_parse_data *p = rq->pdata;
	OSMO_ASSERT(p);
	OSMO_ASSERT(p->hpars.have_sdp);
	struct mgcp_parse_sdp *sdp = &p->sdp;
	struct mgcp_rtp_end *rtp;

	rtp = &conn->end;

	if (sdp->ptime != MGCP_PARSE_SDP_PTIME_UNSET)
		mgcp_rtp_end_set_packet_duration_ms(rtp, sdp->ptime);

	if (sdp->maxptime != MGCP_PARSE_SDP_MAXPTIME_UNSET)
		rtp->maximum_packet_time = sdp->maxptime;

	if (sdp->rem_addr.u.sa.sa_family != AF_UNSPEC) {
		/* Keep port, only apply ip address: */
		uint16_t port = osmo_sockaddr_port(&rtp->addr.u.sa);
		memcpy(&rtp->addr, &sdp->rem_addr, sizeof(rtp->addr));
		osmo_sockaddr_set_port(&rtp->addr.u.sa, port);
	}

	if (sdp->rtp_port != MGCP_PARSE_SDP_RTP_PORT_UNSET) {
		osmo_sockaddr_set_port(&rtp->addr.u.sa, sdp->rtp_port);
		rtp->rtcp_port = htons(sdp->rtp_port + 1);
	}

	/* Copy parsed codec set to conn: */
	rtp->cset = sdp->cset;

	return 0;
}

/* Process codec information contained in CRCX/MDCX */
static int handle_codec_info(struct mgcp_conn_rtp *conn, struct mgcp_request_data *rq)
{
	struct mgcp_endpoint *endp = rq->endp;
	struct mgcp_conn *conn_dst;
	struct mgcp_conn_rtp *conn_dst_rtp;
	struct mgcp_rtp_codecset *cset = &conn->end.cset;
	int rc;

	/* Collect codec information */
	if (rq->pdata->hpars.have_sdp) {
		/* If we have SDP, we ignore the local connection options and
		 * use only the SDP information. */
		rc = handle_sdp(conn, rq);
		if (rc != 0)
			goto error;
	} else if (endp->local_options.codec) {
		/* When no SDP is available, we use the codec information from
		 * the local connection options (if present) */
		mgcp_codecset_reset(cset);
		rc = mgcp_codecset_add_codec(cset, PTYPE_UNDEFINED, endp->local_options.codec, NULL);
		if (rc != 0)
			goto error;
	}

	/* Make sure we always set a sane default codec */
	if (cset->codecs_assigned == 0) {
		/* When SDP and/or LCO did not supply any codec information,
		 * than it makes sense to pick a sane default: (payload-type 0,
		 * PCMU), see also: OS#2658 */
		mgcp_codecset_reset(cset);
		rc = mgcp_codecset_add_codec(cset, 0, NULL, NULL);
		if (rc != 0)
			goto error;
	}

	/* Try to find an destination RTP connection that we can include in the codec decision. */
	conn_dst = mgcp_find_dst_conn(conn->conn);
	if (conn_dst && conn_dst->type == MGCP_CONN_TYPE_RTP)
		conn_dst_rtp = mgcp_conn_get_conn_rtp(conn_dst);
	else
		conn_dst_rtp = NULL;

	/* Make codec decision */
	if (mgcp_codecset_decide(&conn->end.cset, conn_dst_rtp ? &conn_dst_rtp->end.cset : NULL) != 0)
		goto error;

	return 0;

error:
	LOGPCONN(conn->conn, DLMGCP, LOGL_ERROR, "%s: codec negotiation failure\n", rq->name);
	/* See also RFC 3661: Codec negotiation failure */
	return 534;
}

/* CRCX command handler, processes the received command */
static struct msgb *handle_create_con(struct mgcp_request_data *rq)
{
	struct mgcp_parse_data *pdata = rq->pdata;
	struct mgcp_trunk *trunk = rq->trunk;
	struct mgcp_endpoint *endp = rq->endp;
	struct mgcp_parse_hdr_pars *hpars = &pdata->hpars;
	struct rate_ctr_group *rate_ctrs;
	int error_code = 400;
	struct mgcp_conn *conn = NULL;
	struct mgcp_conn_rtp *conn_rtp = NULL;
	char conn_name[512];
	int rc;

	LOGPENDP(endp, DLMGCP, LOGL_NOTICE, "CRCX: creating new connection ...\n");

	if (rq->null_endp) {
		/* trunk not available so rate_ctr aren't available either. */
		LOGP(DLMGCP, LOGL_ERROR, "CRCX: Not allowed in 'null' endpoint!\n");
		return create_err_response(pdata->cfg, NULL, 502, "CRCX", pdata->trans);
	}

	rate_ctrs = trunk->ratectr.mgcp_crcx_ctr_group;

	/* we must have a free ep */
	if (!endp) {
		rate_ctr_inc(rate_ctr_group_get_ctr(rate_ctrs, MGCP_CRCX_FAIL_AVAIL));
		LOGPENDP(endp, DLMGCP, LOGL_ERROR, "CRCX: no free endpoints available!\n");
		return create_err_response(rq->trunk, NULL, 403, "CRCX", pdata->trans);
	}

	if (!mgcp_endp_avail(endp)) {
		rate_ctr_inc(rate_ctr_group_get_ctr(rate_ctrs, MGCP_CRCX_FAIL_AVAIL));
		LOGPENDP(endp, DLMGCP, LOGL_ERROR,
			 "CRCX: selected endpoint not available!\n");
		return create_err_response(rq->trunk, NULL, 501, "CRCX", pdata->trans);
	}

	/* parse CallID C: and LocalParameters L: */
	rc = mgcp_parse_hdr_pars(pdata);
	switch (rc) {
	case 0:
		break; /* all good, continue below */
	case -539:
		rate_ctr_inc(rate_ctr_group_get_ctr(rate_ctrs, MGCP_CRCX_FAIL_UNHANDLED_PARAM));
		return create_err_response(rq->trunk, NULL, -rc, "CRCX", pdata->trans);
	default:
		return create_err_response(rq->trunk, NULL, -rc, "CRCX", pdata->trans);
	}

	/* Check parameters */
	if (!hpars->callid) {
		LOGPENDP(endp, DLMGCP, LOGL_ERROR,
			 "CRCX: insufficient parameters, missing callid\n");
		rate_ctr_inc(rate_ctr_group_get_ctr(rate_ctrs, MGCP_CRCX_FAIL_MISSING_CALLID));
		return create_err_response(endp, endp, 516, "CRCX", pdata->trans);
	}

	if (hpars->mode == MGCP_CONN_NONE) {
		LOGPENDP(endp, DLMGCP, LOGL_ERROR,
			 "CRCX: insufficient parameters, invalid mode\n");
		rate_ctr_inc(rate_ctr_group_get_ctr(rate_ctrs, MGCP_CRCX_FAIL_INVALID_MODE));
		return create_err_response(endp, endp, 517, "CRCX", pdata->trans);
	}

	/* It is illegal to send a connection identifier
	 * together with a CRCX, the MGW will assign the
	 * connection identifier by itself on CRCX */
	if (hpars->connid) {
		LOGPENDP(endp, DLMGCP, LOGL_ERROR, "CRCX: 'I: %s' not expected!\n", hpars->connid);
		rate_ctr_inc(rate_ctr_group_get_ctr(rate_ctrs, MGCP_CRCX_FAIL_BAD_ACTION));
		return create_err_response(endp, endp, 523, "CRCX", pdata->trans);
	}

	/* Parse SDP if found: */
	if (hpars->have_sdp) {
		rc = mgcp_parse_sdp_data(pdata);
		if (rc < 0) { /* See also RFC 3661: Protocol error */
			LOGPENDP(endp, DLMGCP,  LOGL_ERROR, "CRCX: sdp not parseable\n");
			return create_err_response(endp, endp, 510, "CRCX", pdata->trans);
		}
	}

	/* Reject osmux if disabled by config */
	if (trunk->cfg->osmux.usage == OSMUX_USAGE_OFF &&
	    hpars->remote_osmux_cid != MGCP_PARSE_HDR_PARS_OSMUX_CID_UNSET) {
		LOGPENDP(endp, DLMGCP, LOGL_ERROR, "CRCX: Request with Osmux but it is disabled by config!\n");
		rate_ctr_inc(rate_ctr_group_get_ctr(rate_ctrs, MGCP_CRCX_FAIL_NO_OSMUX));
		return create_err_response(endp, endp, 511, "CRCX", pdata->trans);
	}
	/* Reject non-osmux if required by config */
	if (trunk->cfg->osmux.usage == OSMUX_USAGE_ONLY &&
	    hpars->remote_osmux_cid == MGCP_PARSE_HDR_PARS_OSMUX_CID_UNSET) {
		LOGPENDP(endp, DLMGCP, LOGL_ERROR, "CRCX: Request without Osmux but it is required by config!\n");
		return create_err_response(endp, endp, 517, "CRCX", pdata->trans);
	}

	/* Make sure osmux is setup: */
	if (hpars->remote_osmux_cid != MGCP_PARSE_HDR_PARS_OSMUX_CID_UNSET)
		mgcp_trunk_osmux_init_if_needed(trunk);

	/* Check if we are able to accept the creation of another connection */
	if (mgcp_endp_is_full(endp)) {
		LOGPENDP(endp, DLMGCP, LOGL_ERROR,
			"CRCX: endpoint full, max. %i connections allowed!\n",
			endp->type->max_conns);
		if (trunk->force_realloc) {
			/* There is no more room for a connection, make some
			 * room by blindly tossing the oldest of the two two
			 * connections */
			mgcp_endp_free_conn_oldest(endp);
			OSMO_ASSERT(!mgcp_endp_is_full(endp));
		} else {
			/* There is no more room for a connection, leave
			 * everything as it is and return with an error */
			rate_ctr_inc(rate_ctr_group_get_ctr(rate_ctrs, MGCP_CRCX_FAIL_LIMIT_EXCEEDED));
			return create_err_response(endp, endp, 540, "CRCX", pdata->trans);
		}
	}

	/* Update endp->x_osmo_ign: */
	endp->x_osmo_ign |= hpars->x_osmo_ign;

	/* Check if this endpoint already serves a call, if so, check if the
	 * callids match up so that we are sure that this is our call */
	if (endp->callid && mgcp_verify_call_id(endp, hpars->callid)) {
		LOGPENDP(endp, DLMGCP, LOGL_ERROR,
			 "CRCX: already seized by other call (%s)\n",
			 endp->callid);
		if (trunk->force_realloc)
			/* This is not our call, toss everything by releasing
			 * the entire endpoint. (rude!) */
			mgcp_endp_release(endp);
		else {
			/* This is not our call, leave everything as it is and
			 * return with an error. */
			rate_ctr_inc(rate_ctr_group_get_ctr(rate_ctrs, MGCP_CRCX_FAIL_UNKNOWN_CALLID));
			return create_err_response(endp, endp, 400, "CRCX", pdata->trans);
		}
	}

	if (!endp->callid) {
		/* Claim endpoint resources. This will also set the callid,
		 * creating additional connections will only be possible if
		 * the callid matches up (see above). */
		rc = mgcp_endp_claim(endp, hpars->callid);
		if (rc != 0) {
			rate_ctr_inc(rate_ctr_group_get_ctr(rate_ctrs, MGCP_CRCX_FAIL_CLAIM));
			return create_err_response(endp, endp, 502, "CRCX", pdata->trans);
		}
	}

	snprintf(conn_name, sizeof(conn_name), "%s", hpars->callid);
	conn = mgcp_conn_alloc(trunk->endpoints, endp, MGCP_CONN_TYPE_RTP, conn_name);
	if (!conn) {
		LOGPENDP(endp, DLMGCP, LOGL_ERROR,
			 "CRCX: unable to allocate RTP connection\n");
		rate_ctr_inc(rate_ctr_group_get_ctr(rate_ctrs, MGCP_CRCX_FAIL_ALLOC_CONN));
		goto error2;
	}

	if (mgcp_conn_set_mode(conn, hpars->mode) < 0) {
		error_code = 517;
		rate_ctr_inc(rate_ctr_group_get_ctr(rate_ctrs, MGCP_CRCX_FAIL_INVALID_MODE));
		goto error2;
	}

	conn_rtp = mgcp_conn_get_conn_rtp(conn);
	OSMO_ASSERT(conn_rtp);

	/* If X-Osmux (remote CID) was received, alloc next avail CID as local CID */
	if (hpars->remote_osmux_cid != MGCP_PARSE_HDR_PARS_OSMUX_CID_UNSET) {
		if (osmux_init_conn(conn_rtp) < 0) {
			rate_ctr_inc(rate_ctr_group_get_ctr(rate_ctrs, MGCP_CRCX_FAIL_NO_OSMUX));
			goto error2;
		}
		if (hpars->remote_osmux_cid >= 0) {
			conn_rtp->osmux.remote_cid_present = true;
			conn_rtp->osmux.remote_cid = hpars->remote_osmux_cid;
		} /* else: -1 (wildcard) */
	}

	/* Set local connection options, if present */
	if (hpars->local_options) {
		rc = set_local_cx_options(trunk->endpoints,
					  &endp->local_options, hpars->local_options);
		if (rc != 0) {
			LOGPCONN(conn, DLMGCP, LOGL_ERROR,
				 "CRCX: invalid local connection options!\n");
			error_code = rc;
			rate_ctr_inc(rate_ctr_group_get_ctr(rate_ctrs, MGCP_CRCX_FAIL_INVALID_CONN_OPTIONS));
			goto error2;
		}
	}

	/* Handle codec information and decide for a suitable codec */
	rc = handle_codec_info(conn_rtp, rq);
	mgcp_codecset_summary(&conn_rtp->end.cset, mgcp_conn_dump(conn));
	if (rc) {
		error_code = rc;
		rate_ctr_inc(rate_ctr_group_get_ctr(rate_ctrs, MGCP_CRCX_FAIL_CODEC_NEGOTIATION));
		goto error2;
	}
	/* Upgrade the conn type RTP_DEFAULT->RTP_IUUP if needed based on requested codec: */
	if (conn_rtp->type == MGCP_RTP_DEFAULT &&
	    strcmp(conn_rtp->end.cset.codec->subtype_name, "VND.3GPP.IUFP") == 0) {
		rc = mgcp_conn_iuup_init(conn_rtp);
	}

	/* Find a local address for conn based on policy and initial SDP remote
	   information, then find a free port for it */
	if (mgcp_get_local_addr(conn_rtp->end.local_addr, conn_rtp) < 0) {
		rate_ctr_inc(rate_ctr_group_get_ctr(rate_ctrs, MGCP_CRCX_FAIL_BIND_PORT));
		goto error2;
	}
	if (mgcp_trunk_allocate_conn_rtp_ports(trunk, conn_rtp) != 0) {
		rate_ctr_inc(rate_ctr_group_get_ctr(rate_ctrs, MGCP_CRCX_FAIL_BIND_PORT));
		goto error2;
	}

	if (setup_rtp_processing(endp, conn_rtp) != 0) {
		LOGPCONN(conn, DLMGCP, LOGL_ERROR,
			 "CRCX: could not start RTP processing!\n");
		rate_ctr_inc(rate_ctr_group_get_ctr(rate_ctrs, MGCP_CRCX_FAIL_START_RTP));
		goto error2;
	}

	/* Notify Osmux conn that CRCX was received */
	if (mgcp_conn_rtp_is_osmux(conn_rtp)) {
		if (conn_osmux_event_rx_crcx_mdcx(conn_rtp) < 0) {
			LOGPCONN(conn, DLMGCP, LOGL_ERROR, "CRCX: Osmux handling failed!\n");
			goto error2;
		}
	}

	LOGPCONN(conn, DLMGCP, LOGL_DEBUG,
		 "CRCX: Creating connection: port: %u\n", conn_rtp->end.local_port);

	/* Send dummy packet, see also comments in mgcp_keepalive_timer_cb() */
	OSMO_ASSERT(trunk->keepalive_interval >= MGCP_KEEPALIVE_ONCE);
	if (conn->mode & MGCP_CONN_RECV_ONLY &&
	    trunk->keepalive_interval != MGCP_KEEPALIVE_NEVER)
		send_dummy(endp, conn_rtp);

	LOGPCONN(conn, DLMGCP, LOGL_NOTICE,
		 "CRCX: connection successfully created\n");
	rate_ctr_inc(rate_ctr_group_get_ctr(rate_ctrs, MGCP_CRCX_SUCCESS));
	mgcp_endp_update(endp);

	/* NOTE: Only in the virtual trunk we allow dynamic endpoint names */
	bool add_epname = rq->wildcarded && trunk->trunk_type == MGCP_TRUNK_VIRTUAL;
	return create_response_with_sdp(endp, conn_rtp, "CRCX", pdata->trans, add_epname, true);
error2:
	mgcp_endp_release(endp);
	LOGPENDP(endp, DLMGCP, LOGL_NOTICE,
		 "CRCX: unable to create connection\n");
	return create_err_response(endp, endp, error_code, "CRCX", pdata->trans);
}

/* MDCX command handler, processes the received command */
static struct msgb *handle_modify_con(struct mgcp_request_data *rq)
{
	struct mgcp_parse_data *pdata = rq->pdata;
	struct mgcp_trunk *trunk = rq->trunk;
	struct mgcp_endpoint *endp = rq->endp;
	struct mgcp_parse_hdr_pars *hpars = &pdata->hpars;
	struct rate_ctr_group *rate_ctrs;
	char new_local_addr[INET6_ADDRSTRLEN];
	int error_code = 500;
	struct mgcp_conn *conn = NULL;
	struct mgcp_conn_rtp *conn_rtp = NULL;
	int rc;

	LOGPENDP(endp, DLMGCP, LOGL_NOTICE, "MDCX: modifying existing connection ...\n");

	if (rq->null_endp) {
		/* trunk not available so rate_ctr aren't available either. */
		LOGP(DLMGCP, LOGL_ERROR, "MDCX: Not allowed in 'null' endpoint!\n");
		return create_err_response(pdata->cfg, NULL, 502, "MDCX", pdata->trans);
	}

	rate_ctrs = trunk->ratectr.mgcp_mdcx_ctr_group;

	/* Prohibit wildcarded requests */
	if (rq->wildcarded) {
		LOGPENDP(endp, DLMGCP, LOGL_ERROR,
			 "MDCX: wildcarded endpoint names not supported.\n");
		rate_ctr_inc(rate_ctr_group_get_ctr(rate_ctrs, MGCP_MDCX_FAIL_WILDCARD));
		return create_err_response(rq->trunk, endp, 507, "MDCX", pdata->trans);
	}

	if (!endp || !mgcp_endp_avail(endp)) {
		rate_ctr_inc(rate_ctr_group_get_ctr(rate_ctrs, MGCP_MDCX_FAIL_AVAIL));
		LOGPENDP(endp, DLMGCP, LOGL_ERROR, "MDCX: selected endpoint not available!\n");
		return create_err_response(rq->trunk, NULL, 501, "MDCX", pdata->trans);
	}
	if (mgcp_endp_num_conns(endp) <= 0) {
		LOGPENDP(endp, DLMGCP, LOGL_ERROR,
			 "MDCX: endpoint is not holding a connection.\n");
		rate_ctr_inc(rate_ctr_group_get_ctr(rate_ctrs, MGCP_MDCX_FAIL_NO_CONN));
		return create_err_response(endp, endp, 400, "MDCX", pdata->trans);
	}

	rc = mgcp_parse_hdr_pars(pdata);
	switch (rc) {
	case 0:
		break; /* all good, continue below */
	case -539:
		rate_ctr_inc(rate_ctr_group_get_ctr(rate_ctrs, MGCP_MDCX_FAIL_UNHANDLED_PARAM));
		return create_err_response(rq->trunk, NULL, -rc, "MDCX", pdata->trans);
	default:
		return create_err_response(rq->trunk, NULL, -rc, "MDCX", pdata->trans);
	}

	if (hpars->callid && mgcp_verify_call_id(endp, hpars->callid) < 0) {
		rate_ctr_inc(rate_ctr_group_get_ctr(rate_ctrs, MGCP_MDCX_FAIL_INVALID_CALLID));
		return create_err_response(endp, endp, 516, "MDCX", pdata->trans);
	}

	if (!hpars->connid) {
		LOGPENDP(endp, DLMGCP, LOGL_ERROR,
			 "MDCX: insufficient parameters, missing ci (connectionIdentifier)\n");
		rate_ctr_inc(rate_ctr_group_get_ctr(rate_ctrs, MGCP_MDCX_FAIL_NO_CONNID));
		return create_err_response(endp, endp, 515, "MDCX", pdata->trans);
	} else if ((error_code = mgcp_verify_ci(endp, hpars->connid)) != 0) {
		rate_ctr_inc(rate_ctr_group_get_ctr(rate_ctrs, MGCP_MDCX_FAIL_INVALID_CONNID));
		return create_err_response(endp, endp, error_code, "MDCX", pdata->trans);
	}

	/* Parse SDP if found: */
	if (hpars->have_sdp) {
		rc = mgcp_parse_sdp_data(pdata);
		if (rc < 0) {
			/* See also RFC 3661: Protocol error */
			LOGPENDP(endp, DLMGCP,  LOGL_ERROR, "MDCX: sdp not parseable\n");
			return create_err_response(endp, endp, 510, "MDCX", pdata->trans);
		}
	}

	conn = mgcp_endp_get_conn(endp, hpars->connid);
	if (!conn) {
		rate_ctr_inc(rate_ctr_group_get_ctr(rate_ctrs, MGCP_MDCX_FAIL_CONN_NOT_FOUND));
		return create_err_response(endp, endp, 400, "MDCX", pdata->trans);
	}

	mgcp_conn_watchdog_kick(conn);

	if (hpars->mode == MGCP_CONN_NONE) {
		/* Reset conn mode in case it was tweaked through VTY: */
		conn->mode = conn->mode_orig;
	} else if (mgcp_conn_set_mode(conn, hpars->mode) < 0) {
		rate_ctr_inc(rate_ctr_group_get_ctr(rate_ctrs, MGCP_MDCX_FAIL_INVALID_MODE));
		return create_err_response(endp, endp, 517, "MDCX", pdata->trans);
	}

	/* Set local connection options, if present */
	if (hpars->local_options) {
		rc = set_local_cx_options(trunk->endpoints,
					  &endp->local_options, hpars->local_options);
		if (rc != 0) {
			LOGPCONN(conn, DLMGCP, LOGL_ERROR,
				 "MDCX: invalid local connection options!\n");
			error_code = rc;
			rate_ctr_inc(rate_ctr_group_get_ctr(rate_ctrs, MGCP_MDCX_FAIL_INVALID_CONN_OPTIONS));
			goto error3;
		}
	}

	conn_rtp = mgcp_conn_get_conn_rtp(conn);
	OSMO_ASSERT(conn_rtp);

	/* Handle codec information and decide for a suitable codec */
	rc = handle_codec_info(conn_rtp, rq);
	mgcp_codecset_summary(&conn_rtp->end.cset, mgcp_conn_dump(conn));
	if (rc) {
		error_code = rc;
		goto error3;
	}
	/* Upgrade the conn type RTP_DEFAULT->RTP_IUUP if needed based on requested codec: */
	if (conn_rtp->type == MGCP_RTP_DEFAULT &&
	    strcmp(conn_rtp->end.cset.codec->subtype_name, "VND.3GPP.IUFP") == 0)
		rc = mgcp_conn_iuup_init(conn_rtp);

	if (mgcp_conn_rtp_is_osmux(conn_rtp)) {
		OSMO_ASSERT(conn_rtp->osmux.local_cid_allocated);
		if (hpars->remote_osmux_cid < -1) {
			LOGPCONN(conn, DLMGCP, LOGL_ERROR, "MDCX: Failed to parse Osmux CID!\n");
			goto error3;
		}
		if (hpars->remote_osmux_cid == -1) {
			LOGPCONN(conn, DLMGCP, LOGL_ERROR, "MDCX: wilcard in MDCX is not supported!\n");
			goto error3;
		}
		if (conn_rtp->osmux.remote_cid_present &&
		    hpars->remote_osmux_cid != conn_rtp->osmux.remote_cid) {
			LOGPCONN(conn, DLMGCP, LOGL_ERROR, "MDCX: changing already allocated CID is not supported!\n");
			goto error3;
		}
		conn_rtp->osmux.remote_cid_present = true;
		conn_rtp->osmux.remote_cid = hpars->remote_osmux_cid;
		if (conn_osmux_event_rx_crcx_mdcx(conn_rtp) < 0) {
			LOGPCONN(conn, DLMGCP, LOGL_ERROR, "MDCX: Osmux handling failed!\n");
			goto error3;
		}
	}

	/* MDCX may have provided a new remote address, which means we may need
	   to update our announced IP addr and re-bind our local end. This can
	   happen for instance if MGW initially provided an IPv4 during CRCX
	   ACK, and now MDCX tells us the remote has an IPv6 address. */
	if (mgcp_get_local_addr(new_local_addr, conn_rtp) < 0) {
		rate_ctr_inc(rate_ctr_group_get_ctr(rate_ctrs, MGCP_CRCX_FAIL_BIND_PORT));
		goto error3;
	}
	if (strcmp(new_local_addr, conn_rtp->end.local_addr)) {
		osmo_strlcpy(conn_rtp->end.local_addr, new_local_addr, sizeof(conn_rtp->end.local_addr));
		mgcp_rtp_end_free_port(&conn_rtp->end);
		if (mgcp_trunk_allocate_conn_rtp_ports(trunk, conn_rtp) != 0) {
			rate_ctr_inc(rate_ctr_group_get_ctr(rate_ctrs, MGCP_CRCX_FAIL_BIND_PORT));
			goto error3;
		}
	}

	if (setup_rtp_processing(endp, conn_rtp) != 0) {
		rate_ctr_inc(rate_ctr_group_get_ctr(rate_ctrs, MGCP_MDCX_FAIL_START_RTP));
		goto error3;
	}

	/* modify */
	LOGPCONN(conn, DLMGCP, LOGL_DEBUG,
		 "MDCX: modified conn:%s\n", mgcp_conn_dump(conn));

	/* Send dummy packet, see also comments in mgcp_keepalive_timer_cb() */
	OSMO_ASSERT(trunk->keepalive_interval >= MGCP_KEEPALIVE_ONCE);
	if (conn->mode & MGCP_CONN_RECV_ONLY &&
	    trunk->keepalive_interval != MGCP_KEEPALIVE_NEVER)
		send_dummy(endp, conn_rtp);

	rate_ctr_inc(rate_ctr_group_get_ctr(rate_ctrs, MGCP_MDCX_SUCCESS));

	LOGPCONN(conn, DLMGCP, LOGL_NOTICE,
		 "MDCX: connection successfully modified\n");
	mgcp_endp_update(endp);
	return create_response_with_sdp(endp, conn_rtp, "MDCX", pdata->trans, false, false);
error3:
	return create_err_response(endp, endp, error_code, "MDCX", pdata->trans);
}

/* DLCX command handler, processes the received command */
static struct msgb *handle_delete_con(struct mgcp_request_data *rq)
{
	struct mgcp_parse_data *pdata = rq->pdata;
	struct mgcp_trunk *trunk = rq->trunk;
	struct mgcp_endpoint *endp = rq->endp;
	struct mgcp_parse_hdr_pars *hpars = &pdata->hpars;
	struct rate_ctr_group *rate_ctrs;
	char stats[1048];
	struct mgcp_conn *conn = NULL;
	unsigned int i;
	int rc;

	/* NOTE: In this handler we can not take it for granted that the endp
	 * pointer will be populated, however a trunk is always guaranteed (except for 'null' endp).
	 */

	LOGPEPTR(endp, trunk, DLMGCP, LOGL_NOTICE, "DLCX: deleting connection(s) ...\n");

	if (rq->null_endp) {
		/* trunk not available so rate_ctr aren't available either. */
		LOGP(DLMGCP, LOGL_ERROR, "DLCX: Not allowed in 'null' endpoint!\n");
		return create_err_response(pdata->cfg, NULL, 502, "DLCX", pdata->trans);
	}

	rate_ctrs = trunk->ratectr.mgcp_dlcx_ctr_group;
	if (endp && !mgcp_endp_avail(endp)) {
		rate_ctr_inc(rate_ctr_group_get_ctr(rate_ctrs, MGCP_DLCX_FAIL_AVAIL));
		LOGPENDP(endp, DLMGCP, LOGL_ERROR,
			 "DLCX: selected endpoint not available!\n");
		return create_err_response(rq->trunk, NULL, 501, "DLCX", pdata->trans);
	}

	if (endp && !rq->wildcarded && llist_empty(&endp->conns)) {
		LOGPENDP(endp, DLMGCP, LOGL_ERROR,
			 "DLCX: endpoint is not holding a connection.\n");
		rate_ctr_inc(rate_ctr_group_get_ctr(rate_ctrs, MGCP_DLCX_FAIL_NO_CONN));
		return create_err_response(endp, endp, 515, "DLCX", pdata->trans);
	}

	/* Handle wildcarded DLCX that refers to the whole trunk. This means
	 * that we walk over all endpoints on the trunk in order to drop all
	 * connections on the trunk. (see also RFC3435 Annex F.7) */
	if (rq->wildcarded) {
		int num_conns = 0;
		for (i = 0; i < trunk->number_endpoints; i++) {
			num_conns += mgcp_endp_num_conns(trunk->endpoints[i]);
			mgcp_endp_release(trunk->endpoints[i]);
		}
		rate_ctr_add(rate_ctr_group_get_ctr(rate_ctrs, MGCP_DLCX_SUCCESS), num_conns);
		return create_ok_response(trunk, NULL, 200, "DLCX", pdata->trans);
	}

	rc = mgcp_parse_hdr_pars(pdata);
	switch (rc) {
	case 0:
		break; /* all good, continue below */
	case -539:
		rate_ctr_inc(rate_ctr_group_get_ctr(rate_ctrs, MGCP_DLCX_FAIL_UNHANDLED_PARAM));
		return create_err_response(rq->trunk, NULL, -rc, "DLCX", pdata->trans);
	default:
		return create_err_response(rq->trunk, NULL, -rc, "DLCX", pdata->trans);
	}

	if (hpars->callid) {
		/* If we have no endpoint, but a call id in the request, then this request cannot be handled */
		if (!endp) {
			LOGPTRUNK(trunk, DLMGCP, LOGL_NOTICE,
				"cannot handle requests with call-id (C) without endpoint -- abort!");
			rate_ctr_inc(rate_ctr_group_get_ctr(rate_ctrs, MGCP_DLCX_FAIL_UNHANDLED_PARAM));
			return create_err_response(rq->trunk, NULL, 539, "DLCX", pdata->trans);
		}
		if (mgcp_verify_call_id(endp, hpars->callid) != 0) {
			rate_ctr_inc(rate_ctr_group_get_ctr(rate_ctrs, MGCP_DLCX_FAIL_INVALID_CALLID));
			return create_err_response(endp, endp, 516, "DLCX", pdata->trans);
		}
	}

	if (hpars->connid) {
		/* If we have no endpoint, but a connection id in the request, then this request cannot be handled */
		if (!endp) {
			LOGPTRUNK(trunk, DLMGCP, LOGL_NOTICE,
				  "cannot handle requests with conn-id (I) without endpoint -- abort!");
			rate_ctr_inc(rate_ctr_group_get_ctr(rate_ctrs, MGCP_DLCX_FAIL_UNHANDLED_PARAM));
			return create_err_response(rq->trunk, NULL, 539, "DLCX", pdata->trans);
		}
		if ((rc = mgcp_verify_ci(endp, hpars->connid)) != 0) {
			rate_ctr_inc(rate_ctr_group_get_ctr(rate_ctrs, MGCP_DLCX_FAIL_INVALID_CONNID));
			return create_err_response(endp, endp, rc, "DLCX", pdata->trans);
		}
	}

	/* The logic does not permit to go past this point without having the
	 * the endp pointer populated. */
	OSMO_ASSERT(endp);

	/* When no connection id is supplied, we will interpret this as a
	 * wildcarded DLCX that refers to the selected endpoint. This means
	 * that we drop all connections on that specific endpoint at once.
	 * (See also RFC3435 Section F.7) */
	if (!hpars->connid) {
		int num_conns = mgcp_endp_num_conns(endp);
		LOGPENDP(endp, DLMGCP, LOGL_NOTICE,
			 "DLCX: missing ci (connectionIdentifier), will remove all connections (%d total) at once\n",
			 num_conns);

		if (num_conns > 0)
			rate_ctr_add(rate_ctr_group_get_ctr(rate_ctrs, MGCP_DLCX_SUCCESS), num_conns);

		mgcp_endp_release(endp);

		/* Note: In this case we do not return any statistics,
		 * as we assume that the client is not interested in
		 * this case. */
		return create_ok_response(endp, endp, 200, "DLCX", pdata->trans);
	}

	/* Find the connection */
	conn = mgcp_endp_get_conn(endp, hpars->connid);
	if (!conn) {
		rate_ctr_inc(rate_ctr_group_get_ctr(rate_ctrs, MGCP_DLCX_FAIL_INVALID_CONNID));
		return create_err_response(endp, endp, 400, "DLCX", pdata->trans);
	}
	/* save the statistics of the current connection */
	mgcp_format_stats(stats, sizeof(stats), conn);

	/* delete connection */
	LOGPCONN(conn, DLMGCP, LOGL_DEBUG, "DLCX: deleting conn:%s\n",
		 mgcp_conn_dump(conn));
	mgcp_conn_free(conn);
	LOGPENDP(endp, DLMGCP, LOGL_NOTICE,
		 "DLCX: connection successfully deleted\n");

	/* When all connections are closed, the endpoint will be released
	 * in order to be ready to be used by another call. */
	if (mgcp_endp_num_conns(endp) <= 0) {
		mgcp_endp_release(endp);
		LOGPENDP(endp, DLMGCP, LOGL_DEBUG, "DLCX: endpoint released\n");
	}

	rate_ctr_inc(rate_ctr_group_get_ctr(rate_ctrs, MGCP_DLCX_SUCCESS));
	return create_ok_resp_with_param(endp, endp, 250, "DLCX", pdata->trans, stats);
}

/* RSIP command handler, processes the received command */
static struct msgb *handle_rsip(struct mgcp_request_data *rq)
{
	/* TODO: Also implement the resetting of a specific endpoint
	 * to make mgcp_send_reset_ep() work. Currently this will call
	 * mgcp_rsip_cb() in mgw_main.c, which sets reset_endpoints=1
	 * to make read_call_agent() reset all endpoints when called
	 * next time. In order to selectively reset endpoints some
	 * mechanism to distinguish which endpoint shall be resetted
	 * is needed */

	LOGP(DLMGCP, LOGL_NOTICE, "RSIP: resetting all endpoints ...\n");

	if (rq->null_endp) {
		/* trunk not available so rate_ctr aren't available either. */
		LOGP(DLMGCP, LOGL_ERROR, "RSIP: Not allowed in 'null' endpoint!\n");
		return create_err_response(rq->pdata->cfg, NULL, 502, "RSIP", rq->pdata->trans);
	}

	if (rq->pdata->cfg->reset_cb)
		rq->pdata->cfg->reset_cb(rq->endp->trunk);
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
static struct msgb *handle_noti_req(struct mgcp_request_data *rq)
{
	int res = 0;
	char *line;
	char tone = CHAR_MAX;

	LOGP(DLMGCP, LOGL_NOTICE, "RQNT: processing request for notification ...\n");

	if (rq->null_endp) {
		/* trunk not available so rate_ctr aren't available either. */
		LOGP(DLMGCP, LOGL_ERROR, "RQNT: Not allowed in 'null' endpoint!\n");
		return create_err_response(rq->pdata->cfg, NULL, 502, "RQNT", rq->pdata->trans);
	}

	for_each_line(line, rq->pdata->save) {
		switch (toupper(line[0])) {
		case 'S':
			tone = extract_tone(line);
			break;
		}
	}

	/* we didn't see a signal request with a tone */
	if (tone == CHAR_MAX)
		return create_ok_response(rq->endp, rq->endp, 200, "RQNT", rq->pdata->trans);

	if (rq->pdata->cfg->rqnt_cb)
		res = rq->pdata->cfg->rqnt_cb(rq->endp, tone);

	return res == 0 ? create_ok_response(rq->endp, rq->endp, 200, "RQNT", rq->pdata->trans) :
				create_err_response(rq->endp, rq->endp, res, "RQNT", rq->pdata->trans);
}

/* Connection keepalive timer, will take care that dummy packets are send
 * regularly, so that NAT connections stay open */
static void mgcp_keepalive_timer_cb(void *_trunk)
{
	struct mgcp_trunk *trunk = _trunk;
	struct mgcp_conn *conn;
	int i;

	LOGP(DLMGCP, LOGL_DEBUG, "triggered trunk %d keepalive timer\n",
	     trunk->trunk_nr);

	/* Do not accept invalid configuration values
	 * valid is MGCP_KEEPALIVE_NEVER, MGCP_KEEPALIVE_ONCE and
	 * values greater 0 */
	OSMO_ASSERT(trunk->keepalive_interval >= MGCP_KEEPALIVE_ONCE);

	/* The dummy packet functionality has been disabled, we will exit
	 * immediately, no further timer is scheduled, which means we will no
	 * longer send dummy packets even when we did before */
	if (trunk->keepalive_interval == MGCP_KEEPALIVE_NEVER)
		return;

	/* In cases where only one dummy packet is sent, we do not need
	 * the timer since the functions that handle the CRCX and MDCX are
	 * triggering the sending of the dummy packet. So we behave like in
	 * the  MGCP_KEEPALIVE_NEVER case */
	if (trunk->keepalive_interval == MGCP_KEEPALIVE_ONCE)
		return;

	/* Send walk over all endpoints and send out dummy packets through
	 * every connection present on each endpoint */
	for (i = 0; i < trunk->number_endpoints; ++i) {
		struct mgcp_endpoint *endp = trunk->endpoints[i];
		llist_for_each_entry(conn, &endp->conns, entry) {
			if (conn->type == MGCP_CONN_TYPE_RTP &&
			    conn->mode == MGCP_CONN_RECV_ONLY)
				send_dummy(endp, mgcp_conn_get_conn_rtp(conn));
		}
	}

	/* Schedule the keepalive timer for the next round */
	LOGP(DLMGCP, LOGL_DEBUG, "rescheduling trunk %d keepalive timer\n",
	     trunk->trunk_nr);
	osmo_timer_schedule(&trunk->keepalive_timer, trunk->keepalive_interval,
			    0);
}

void mgcp_trunk_set_keepalive(struct mgcp_trunk *trunk, int interval)
{
	trunk->keepalive_interval = interval;
	osmo_timer_setup(&trunk->keepalive_timer, mgcp_keepalive_timer_cb, trunk);

	if (interval <= 0)
		osmo_timer_del(&trunk->keepalive_timer);
	else
		osmo_timer_schedule(&trunk->keepalive_timer,
				    trunk->keepalive_interval, 0);
}

/* Free config, this function is automatically called by talloc_free when the configuration is freed. */
static int config_free_talloc_destructor(struct mgcp_config *cfg)
{
	mgcp_ratectr_global_free(cfg);
	return 0;
}

/*! allocate configuration with default values.
 *  (called once at startup by main function) */
struct mgcp_config *mgcp_config_alloc(void)
{
	/* FIXME: This is unrelated to the protocol, put this in some
	 * appropiate place! */
	struct mgcp_config *cfg;

	cfg = talloc_zero(NULL, struct mgcp_config);
	if (!cfg) {
		LOGP(DLMGCP, LOGL_FATAL, "Failed to allocate config.\n");
		return NULL;
	}

	osmo_strlcpy(cfg->domain, "mgw", sizeof(cfg->domain));

	cfg->net_ports.lock = (pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;
	cfg->net_ports.range_start = RTP_PORT_DEFAULT_RANGE_START;
	cfg->net_ports.range_end = RTP_PORT_DEFAULT_RANGE_END;
	cfg->net_ports.last_port = cfg->net_ports.range_start;

	cfg->source_port = 2427;
	osmo_strlcpy(cfg->source_addr, "0.0.0.0", sizeof(cfg->source_addr));

	cfg->rtp_processing_cb = &mgcp_rtp_processing_default;
	cfg->setup_rtp_processing_cb = &mgcp_setup_rtp_processing_default;

	INIT_LLIST_HEAD(&cfg->trunks);

	/* Allocate virtual trunk */
	if (!mgcp_trunk_alloc(cfg, MGCP_TRUNK_VIRTUAL, MGCP_VIRT_TRUNK_ID)) {
		talloc_free(cfg);
		return NULL;
	}

	mgcp_ratectr_global_alloc(cfg);
	talloc_set_destructor(cfg, config_free_talloc_destructor);

	return cfg;
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
 *  \param[in] endp to reset
 *  \returns 0 on success, -1 on error */
int mgcp_send_reset_ep(struct mgcp_endpoint *endp)
{
	char buf[MGCP_ENDPOINT_MAXLEN + 128];
	int len;
	int rc;

	len = snprintf(buf, sizeof(buf),
		       "RSIP 39 %s MGCP 1.0\r\n", endp->name);
	if (len < 0)
		return -1;

	rc = send_agent(endp->trunk->cfg, buf, len);
	if (rc <= 0)
		return -1;

	return 0;
}

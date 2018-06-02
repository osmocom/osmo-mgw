/* (C) 2018 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Philipp Maier
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <osmocom/mgcp_client/mgcp_client.h>
#include <osmocom/mgcp_client/mgcp_client_fsm.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/fsm.h>
#include <osmocom/core/byteswap.h>
#include <arpa/inet.h>
#include <osmocom/core/logging.h>

/* Context information, this is attached to the priv pointer of the FSM and
 * is also handed back when dispatcheing events to the parent FSM. This is
 * purly intened and not meant to be accessible for the API user */
struct mgcp_ctx {
	/* MGCP client instance that is used to interact with the MGW */
	struct mgcp_client *mgcp;

	/* The ID of the last pending transaction. This is used internally
	 * to cancel the transaction in case of an error */
	mgcp_trans_id_t mgw_pending_trans;

	/* Flag to mark that there is a pending transaction */
	bool mgw_trans_pending;

	/* Connection ID which has been assigned by he MGW */
	char conn_id[MGCP_CONN_ID_LENGTH];

	/* Local RTP connection info, the MGW will send outgoing traffic to the
	 * ip/port specified here. The Address does not have to be choosen right
	 * on the creation of a connection. It can always be modified later by
	 * the user. */
	struct mgcp_conn_peer conn_peer_local;

	/* Remote RTP connection info, the ip/port specified here is the address
	 * where the MGW expects the RTP data to be sent. This address is
	 * defined by soly by the MGW and can not be influenced by the user. */
	struct mgcp_conn_peer conn_peer_remote;

	/* The terminate flag is a way to handle cornercase sitations that
	 * might occur when the user runs into an error situation and sends
	 * a DLCX command while the FSM is waiting for a response. In this
	 * case the DLCX command is not executed immediately. Instead the
	 * terminate flag is set. When the response to from the previous
	 * operation is received, we know that there is a DLCX event is
	 * pending. The FSM then generates the EV_DLCX by itsself before
	 * it enters ST_READY to cause the immediate execution of the
	 * DLCX procedure. (If normal operations are executed too fast,
	 * the API functions will return an error. In general, the user
	 * should synchronize using the callback events) */
	bool terminate;

	/* Event that is sent when the current operation is completed (except
	 * for DLCX, there the specified parent_term_evt is sent instead) */
	uint32_t parent_evt;
};

#define S(x)	(1 << (x))

#define MGCP_MGW_TIMEOUT 4	/* in seconds */
#define MGCP_MGW_TIMEOUT_TIMER_NR 1

enum fsm_mgcp_client_states {
	ST_CRCX,
	ST_CRCX_RESP,
	ST_READY,
	ST_MDCX_RESP,
	ST_DLCX_RESP,
};

enum fsm_mgcp_client_evt {
	EV_CRCX,
	EV_CRCX_RESP,
	EV_MDCX,
	EV_MDCX_RESP,
	EV_DLCX,
	EV_DLCX_RESP,
};

static const struct value_string fsm_mgcp_client_evt_names[] = {
	OSMO_VALUE_STRING(EV_CRCX),
	OSMO_VALUE_STRING(EV_CRCX_RESP),
	OSMO_VALUE_STRING(EV_MDCX),
	OSMO_VALUE_STRING(EV_MDCX_RESP),
	OSMO_VALUE_STRING(EV_DLCX),
	OSMO_VALUE_STRING(EV_DLCX_RESP),
	{0, NULL}
};

static struct msgb *make_crcx_msg_bind(struct mgcp_ctx *mgcp_ctx)
{
	struct mgcp_msg mgcp_msg;

	mgcp_msg = (struct mgcp_msg) {
		.verb = MGCP_VERB_CRCX,
		.presence = (MGCP_MSG_PRESENCE_ENDPOINT | MGCP_MSG_PRESENCE_CALL_ID | MGCP_MSG_PRESENCE_CONN_MODE),
		.call_id = mgcp_ctx->conn_peer_local.call_id,
		.conn_mode = MGCP_CONN_RECV_ONLY,
	};
	osmo_strlcpy(mgcp_msg.endpoint, mgcp_ctx->conn_peer_local.endpoint, MGCP_ENDPOINT_MAXLEN);

	return mgcp_msg_gen(mgcp_ctx->mgcp, &mgcp_msg);
}

static struct msgb *make_crcx_msg_bind_connect(struct mgcp_ctx *mgcp_ctx)
{
	struct mgcp_msg mgcp_msg;

	mgcp_msg = (struct mgcp_msg) {
		.verb = MGCP_VERB_CRCX,.presence = (MGCP_MSG_PRESENCE_ENDPOINT | MGCP_MSG_PRESENCE_CALL_ID |
						    MGCP_MSG_PRESENCE_CONN_MODE | MGCP_MSG_PRESENCE_AUDIO_IP |
						    MGCP_MSG_PRESENCE_AUDIO_PORT),
		.call_id = mgcp_ctx->conn_peer_local.call_id,
		.conn_mode = MGCP_CONN_RECV_SEND,
		.audio_ip = mgcp_ctx->conn_peer_local.addr,
		.audio_port = mgcp_ctx->conn_peer_local.port,
	};
	osmo_strlcpy(mgcp_msg.endpoint, mgcp_ctx->conn_peer_local.endpoint, MGCP_ENDPOINT_MAXLEN);

	return mgcp_msg_gen(mgcp_ctx->mgcp, &mgcp_msg);
}

static struct msgb *make_mdcx_msg(struct mgcp_ctx *mgcp_ctx)
{
	struct mgcp_msg mgcp_msg;

	mgcp_msg = (struct mgcp_msg) {
		.verb = MGCP_VERB_MDCX,
		.presence = (MGCP_MSG_PRESENCE_ENDPOINT | MGCP_MSG_PRESENCE_CALL_ID | MGCP_MSG_PRESENCE_CONN_ID |
			     MGCP_MSG_PRESENCE_CONN_MODE | MGCP_MSG_PRESENCE_AUDIO_IP | MGCP_MSG_PRESENCE_AUDIO_PORT),
		.call_id =  mgcp_ctx->conn_peer_remote.call_id,
		.conn_id = mgcp_ctx->conn_id,
		.conn_mode = MGCP_CONN_RECV_SEND,
		.audio_ip = mgcp_ctx->conn_peer_local.addr,
		.audio_port = mgcp_ctx->conn_peer_local.port,
	};
	osmo_strlcpy(mgcp_msg.endpoint, mgcp_ctx->conn_peer_remote.endpoint, MGCP_ENDPOINT_MAXLEN);

	/* Note: We take the endpoint and the call_id from the remote
	 * connection info, because we can be confident that the
	 * information there is valid. For the local info, we explicitly
	 * allow endpoint and call_id to be optional */
	return mgcp_msg_gen(mgcp_ctx->mgcp, &mgcp_msg);
}

struct msgb *make_dlcx_msg(struct mgcp_ctx *mgcp_ctx)
{
	struct mgcp_msg mgcp_msg;

	mgcp_msg = (struct mgcp_msg) {
		.verb = MGCP_VERB_DLCX,
		.presence = (MGCP_MSG_PRESENCE_ENDPOINT | MGCP_MSG_PRESENCE_CALL_ID | MGCP_MSG_PRESENCE_CONN_ID),
		.call_id = mgcp_ctx->conn_peer_remote.call_id,
		.conn_id = mgcp_ctx->conn_id,
	};
	osmo_strlcpy(mgcp_msg.endpoint, mgcp_ctx->conn_peer_remote.endpoint, MGCP_ENDPOINT_MAXLEN);

	return mgcp_msg_gen(mgcp_ctx->mgcp, &mgcp_msg);
}

static void mgw_crcx_resp_cb(struct mgcp_response *r, void *priv);

static void fsm_crcx_cb(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct mgcp_ctx *mgcp_ctx = data;
	struct mgcp_client *mgcp;
	struct msgb *msg;
	int rc;

	OSMO_ASSERT(mgcp_ctx);
	mgcp = mgcp_ctx->mgcp;
	OSMO_ASSERT(mgcp);

	switch (event) {
	case EV_CRCX:
		LOGPFSML(fi, LOGL_DEBUG, "MGW/CRCX: creating connection on MGW endpoint:%s...\n",
			 mgcp_ctx->conn_peer_local.endpoint);

		if (mgcp_ctx->conn_peer_local.port)
			msg = make_crcx_msg_bind_connect(mgcp_ctx);
		else
			msg = make_crcx_msg_bind(mgcp_ctx);
		OSMO_ASSERT(msg);

		mgcp_ctx->mgw_pending_trans = mgcp_msg_trans_id(msg);
		mgcp_ctx->mgw_trans_pending = true;
		rc = mgcp_client_tx(mgcp, msg, mgw_crcx_resp_cb, fi);
		if (rc < 0) {
			osmo_fsm_inst_term(fi, OSMO_FSM_TERM_ERROR, NULL);
			return;
		}

		osmo_fsm_inst_state_chg(fi, ST_CRCX_RESP, MGCP_MGW_TIMEOUT, MGCP_MGW_TIMEOUT_TIMER_NR);
		break;
	default:
		OSMO_ASSERT(false);
		break;
	}
}

static void mgw_crcx_resp_cb(struct mgcp_response *r, void *priv)
{
	struct osmo_fsm_inst *fi = priv;
	struct mgcp_ctx *mgcp_ctx;
	int rc;

	OSMO_ASSERT(fi);
	mgcp_ctx = fi->priv;
	OSMO_ASSERT(mgcp_ctx);

	mgcp_ctx->mgw_trans_pending = false;

	if (r->head.response_code != 200) {
		LOGPFSML(fi, LOGL_ERROR,
			 "MGW/CRCX: response yields error: %d %s\n", r->head.response_code, r->head.comment);
		osmo_fsm_inst_term(fi, OSMO_FSM_TERM_ERROR, NULL);
		return;
	}

	osmo_strlcpy(mgcp_ctx->conn_id, r->head.conn_id, sizeof(mgcp_ctx->conn_id));
	LOGPFSML(fi, LOGL_DEBUG, "MGW/CRCX: MGW responded with CI: %s\n", mgcp_ctx->conn_id);

	rc = mgcp_response_parse_params(r);
	if (rc) {
		LOGPFSML(fi, LOGL_ERROR, "MGW/CRCX: Cannot parse CRCX response\n");
		osmo_fsm_inst_term(fi, OSMO_FSM_TERM_ERROR, NULL);
		return;
	}
	LOGPFSML(fi, LOGL_DEBUG, "MGW/CRCX: MGW responded with address %s:%u\n", r->audio_ip, r->audio_port);

	osmo_strlcpy(mgcp_ctx->conn_peer_remote.addr, r->audio_ip, sizeof(mgcp_ctx->conn_peer_remote.addr));
	mgcp_ctx->conn_peer_remote.port = r->audio_port;

	if (strlen(r->head.endpoint) > 0) {
		/* If we get an endpoint identifier back from the MGW, take it */
		osmo_strlcpy(mgcp_ctx->conn_peer_remote.endpoint, r->head.endpoint,
			     sizeof(mgcp_ctx->conn_peer_remote.endpoint));
	} else if (strstr(mgcp_ctx->conn_peer_local.endpoint, "*") == NULL) {
		/* If we do not get an endpoint identifier back and the
		 * identifier we used to create the connection is not a
		 * wildcarded one, we take the local endpoint identifier
		 * instead */
		osmo_strlcpy(mgcp_ctx->conn_peer_remote.endpoint, mgcp_ctx->conn_peer_local.endpoint,
			     sizeof(mgcp_ctx->conn_peer_local.endpoint));
	} else {
		LOGPFSML(fi, LOGL_ERROR, "MGW/CRCX: CRCX yielded not suitable endpoint identifier\n");
		osmo_fsm_inst_term(fi, OSMO_FSM_TERM_ERROR, NULL);
		return;
	}

	mgcp_ctx->conn_peer_remote.call_id = mgcp_ctx->conn_peer_local.call_id;

	osmo_fsm_inst_dispatch(fi, EV_CRCX_RESP, mgcp_ctx);
}

static void fsm_crcx_resp_cb(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct mgcp_ctx *mgcp_ctx = data;
	OSMO_ASSERT(mgcp_ctx);

	switch (event) {
	case EV_CRCX_RESP:
		osmo_fsm_inst_state_chg(fi, ST_READY, 0, 0);
		if (mgcp_ctx->terminate) {
			/* Trigger immediate DLCX if DLCX was requested while the FSM was
			 * busy with the previous operation */
			LOGPFSML(fi, LOGL_ERROR, "MGW/CRCX: FSM was busy while DLCX was requested, executing now...\n");
			osmo_fsm_inst_dispatch(fi, EV_DLCX, mgcp_ctx);
		} else
			osmo_fsm_inst_dispatch(fi->proc.parent, mgcp_ctx->parent_evt, &mgcp_ctx->conn_peer_remote);
		break;
	default:
		OSMO_ASSERT(false);
		break;
	}
}

static void mgw_mdcx_resp_cb(struct mgcp_response *r, void *priv);
static void mgw_dlcx_resp_cb(struct mgcp_response *r, void *priv);

static void fsm_ready_cb(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct mgcp_ctx *mgcp_ctx = data;
	struct msgb *msg;
	struct mgcp_client *mgcp;
	uint32_t new_state;
	int rc;

	OSMO_ASSERT(mgcp_ctx);
	mgcp = mgcp_ctx->mgcp;
	OSMO_ASSERT(mgcp);

	switch (event) {
	case EV_MDCX:
		msg = make_mdcx_msg(mgcp_ctx);
		OSMO_ASSERT(msg);
		rc = mgcp_client_tx(mgcp, msg, mgw_mdcx_resp_cb, fi);
		new_state = ST_MDCX_RESP;
		break;
	case EV_DLCX:
		msg = make_dlcx_msg(mgcp_ctx);
		OSMO_ASSERT(msg);
		rc = mgcp_client_tx(mgcp, msg, mgw_dlcx_resp_cb, fi);
		new_state = ST_DLCX_RESP;
		break;
	default:
		OSMO_ASSERT(false);
		break;
	}

	mgcp_ctx->mgw_pending_trans = mgcp_msg_trans_id(msg);
	mgcp_ctx->mgw_trans_pending = true;

	if (rc < 0) {
		osmo_fsm_inst_term(fi, OSMO_FSM_TERM_ERROR, NULL);
		return;
	}

	osmo_fsm_inst_state_chg(fi, new_state, MGCP_MGW_TIMEOUT, MGCP_MGW_TIMEOUT_TIMER_NR);
}

static void mgw_mdcx_resp_cb(struct mgcp_response *r, void *priv)
{
	struct osmo_fsm_inst *fi = priv;
	struct mgcp_ctx *mgcp_ctx;
	int rc;

	OSMO_ASSERT(fi);
	mgcp_ctx = fi->priv;
	OSMO_ASSERT(mgcp_ctx);

	mgcp_ctx->mgw_trans_pending = false;

	if (r->head.response_code != 200) {
		LOGPFSML(fi, LOGL_ERROR, "MGW/MDCX: response yields error: %d %s\n", r->head.response_code,
			 r->head.comment);
		osmo_fsm_inst_term(fi, OSMO_FSM_TERM_ERROR, NULL);
		return;
	}

	rc = mgcp_response_parse_params(r);
	if (rc) {
		LOGPFSML(fi, LOGL_ERROR, "MGW/MDCX: Cannot parse MDCX response\n");
		osmo_fsm_inst_term(fi, OSMO_FSM_TERM_ERROR, NULL);
		return;
	}
	LOGPFSML(fi, LOGL_DEBUG, "MGW/MDCX: MGW responded with address %s:%u\n", r->audio_ip, r->audio_port);

	osmo_strlcpy(mgcp_ctx->conn_peer_remote.addr, r->audio_ip, sizeof(mgcp_ctx->conn_peer_remote.addr));
	mgcp_ctx->conn_peer_remote.port = r->audio_port;

	osmo_fsm_inst_dispatch(fi, EV_MDCX_RESP, mgcp_ctx);
}

static void fsm_mdcx_resp_cb(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct mgcp_ctx *mgcp_ctx = data;
	OSMO_ASSERT(mgcp_ctx);

	switch (event) {
	case EV_MDCX_RESP:
		osmo_fsm_inst_state_chg(fi, ST_READY, 0, 0);
		if (mgcp_ctx->terminate) {
			/* Trigger immediate DLCX if DLCX was requested while the FSM was
			 * busy with the previous operation */
			LOGPFSML(fi, LOGL_ERROR, "MGW/MDCX: FSM was busy while DLCX was requested, executing now...\n");
			osmo_fsm_inst_dispatch(fi, EV_DLCX, mgcp_ctx);
		} else
			osmo_fsm_inst_dispatch(fi->proc.parent, mgcp_ctx->parent_evt, &mgcp_ctx->conn_peer_remote);
		break;
	default:
		OSMO_ASSERT(false);
		break;
	}
}

static void mgw_dlcx_resp_cb(struct mgcp_response *r, void *priv)
{
	struct osmo_fsm_inst *fi = priv;
	struct mgcp_ctx *mgcp_ctx;

	OSMO_ASSERT(fi);
	mgcp_ctx = fi->priv;
	OSMO_ASSERT(mgcp_ctx);

	mgcp_ctx->mgw_trans_pending = false;

	if (r->head.response_code != 250) {
		LOGPFSML(fi, LOGL_ERROR,
			 "MGW/DLCX: response yields error: %d %s\n", r->head.response_code, r->head.comment);
		osmo_fsm_inst_term(fi, OSMO_FSM_TERM_ERROR, NULL);
		return;
	}

	osmo_fsm_inst_dispatch(fi, EV_DLCX_RESP, mgcp_ctx);
}

static void fsm_dlcx_resp_cb(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct mgcp_ctx *mgcp_ctx = data;
	OSMO_ASSERT(mgcp_ctx);

	switch (event) {
	case EV_DLCX_RESP:
		/* Rub out the connection identifier, since the connection
		 * is no longer present and we will use the connection id
		 * to know in error cases if the connection is still present
		 * or not */
		memset(mgcp_ctx->conn_id, 0, sizeof(mgcp_ctx->conn_id));

		osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REGULAR, NULL);
		break;
	default:
		OSMO_ASSERT(false);
		break;
	}
}

static int fsm_timeout_cb(struct osmo_fsm_inst *fi)
{
	struct mgcp_ctx *mgcp_ctx = fi->priv;
	struct mgcp_client *mgcp;

	OSMO_ASSERT(mgcp_ctx);
	mgcp = mgcp_ctx->mgcp;
	OSMO_ASSERT(mgcp);

	if (fi->T == MGCP_MGW_TIMEOUT_TIMER_NR) {
		/* Note: We were unable to communicate with the MGW,
		 * unfortunately there is no meaningful action we can take
		 * now other than giving up. */
		osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REGULAR, NULL);
	} else {
		/* Note: Ther must not be any unsolicited timers
		 * in this FSM. If so, we have serious problem. */
		OSMO_ASSERT(false);
	}

	return 0;
}

static void fsm_cleanup_cb(struct osmo_fsm_inst *fi, enum osmo_fsm_term_cause cause)
{
	struct mgcp_ctx *mgcp_ctx = fi->priv;
	struct mgcp_client *mgcp;
	struct msgb *msg;

	OSMO_ASSERT(mgcp_ctx);
	mgcp = mgcp_ctx->mgcp;
	OSMO_ASSERT(mgcp);

	/* If there is still a transaction pending, cancel it now. */
	if (mgcp_ctx->mgw_trans_pending)
		mgcp_client_cancel(mgcp, mgcp_ctx->mgw_pending_trans);

	/* Should the FSM be terminated while there are still open connections
	 * on the MGW, we send an unconditional DLCX to terminate the
	 * connection. This is not the normal case. The user should always use
	 * mgcp_conn_delete() to instruct the FSM to perform a graceful exit */
	if (strlen(mgcp_ctx->conn_id)) {
		LOGPFSML(fi, LOGL_ERROR,
			 "MGW/DLCX: abrupt FSM termination with connections still present, sending unconditional DLCX...\n");
		msg = make_dlcx_msg(mgcp_ctx);
		OSMO_ASSERT(msg);
		mgcp_client_tx(mgcp, msg, NULL, NULL);
	}

	talloc_free(mgcp_ctx);
}

static struct osmo_fsm_state fsm_mgcp_client_states[] = {

	/* Initial CRCX state. This state is immediately entered and executed
	 * when the FSM is started. The rationale is that we first have to
	 * create a connectin before we can execute other operations on that
	 * connection. */
	[ST_CRCX] = {
		     .in_event_mask = S(EV_CRCX),
		     .out_state_mask = S(ST_CRCX_RESP),
		     .name = OSMO_STRINGIFY(ST_CRCX),
		     .action = fsm_crcx_cb,
		     },

	/* Wait for the response to a CRCX operation, check and process the
	 * results, change to ST_READY afterwards. */
	[ST_CRCX_RESP] = {
			  .in_event_mask = S(EV_CRCX_RESP),
			  .out_state_mask = S(ST_READY),
			  .name = OSMO_STRINGIFY(ST_CRCX_RESP),
			  .action = fsm_crcx_resp_cb,
			  },

	/* In this idle state we wait for further operations (e.g. MDCX) that
	 * can be executed by the user using the API. There is no timeout in
	 * this state. The connection lives on until the user decides to
	 * terminate it (DLCX). */
	[ST_READY] = {
		      .in_event_mask = S(EV_MDCX) | S(EV_DLCX),
		      .out_state_mask = S(ST_MDCX_RESP) | S(ST_DLCX_RESP),
		      .name = OSMO_STRINGIFY(ST_READY),
		      .action = fsm_ready_cb,
		      },

	/* Wait for the response of a MDCX operation, check and process the
	 * results, change to ST_READY afterwards. */
	[ST_MDCX_RESP] = {
			  .in_event_mask = S(EV_MDCX_RESP),
			  .out_state_mask = S(ST_READY),
			  .name = OSMO_STRINGIFY(ST_MDCX_RESP),
			  .action = fsm_mdcx_resp_cb,
			  },

	/* Wait for the response of a DLCX operation and terminate the FSM
	 * normally. */
	[ST_DLCX_RESP] = {
			  .in_event_mask = S(EV_DLCX_RESP),
			  .out_state_mask = 0,
			  .name = OSMO_STRINGIFY(ST_DLCX_RESP),
			  .action = fsm_dlcx_resp_cb,
			  },
};

static struct osmo_fsm fsm_mgcp_client = {
	.name = "MGCP_CONN",
	.states = fsm_mgcp_client_states,
	.num_states = ARRAY_SIZE(fsm_mgcp_client_states),
	.timer_cb = fsm_timeout_cb,
	.cleanup = fsm_cleanup_cb,
	.event_names = fsm_mgcp_client_evt_names,
};

/*! allocate FSM, and create a new connection on the MGW.
 *  \param[in] mgcp MGCP client descriptor.
 *  \param[in] parent_fi Parent FSM instance.
 *  \param[in] parent_term_evt Event to be sent to parent when terminating.
 *  \param[in] parent_evt Event to be sent to parent when operation is done.
 *  \param[in] conn_peer Connection parameters (ip, port...).
 *  \returns newly-allocated, initialized and registered FSM instance, NULL on error. */
struct osmo_fsm_inst *mgcp_conn_create(struct mgcp_client *mgcp, struct osmo_fsm_inst *parent_fi,
				       uint32_t parent_term_evt, uint32_t parent_evt, struct mgcp_conn_peer *conn_peer)
{
	struct mgcp_ctx *mgcp_ctx;
	static bool fsm_registered = false;
	struct osmo_fsm_inst *fi;
	struct in_addr ip_test;

	OSMO_ASSERT(parent_fi);
	OSMO_ASSERT(mgcp);
	OSMO_ASSERT(conn_peer);

	/* Check if IP/Port informstaion in conn info makes sense */
	if (conn_peer->port && inet_aton(conn_peer->addr, &ip_test) == 0)
		return NULL;

	/* Register the fsm description (if not already done) */
	if (fsm_registered == false) {
		osmo_fsm_register(&fsm_mgcp_client);
		fsm_registered = true;
	}

	/* Allocate and configure a new fsm instance */
	fi = osmo_fsm_inst_alloc_child(&fsm_mgcp_client, parent_fi, parent_term_evt);
	OSMO_ASSERT(fi);
	mgcp_ctx = talloc_zero(fi, struct mgcp_ctx);
	OSMO_ASSERT(mgcp_ctx);
	mgcp_ctx->mgcp = mgcp;
	mgcp_ctx->parent_evt = parent_evt;

	memcpy(&mgcp_ctx->conn_peer_local, conn_peer, sizeof(mgcp_ctx->conn_peer_local));
	fi->priv = mgcp_ctx;

	/* start state machine */
	OSMO_ASSERT(fi->state == ST_CRCX);
	osmo_fsm_inst_dispatch(fi, EV_CRCX, mgcp_ctx);

	return fi;
}

/*! modify an existing connection on the MGW.
 *  \param[in] fi FSM instance.
 *  \param[in] parent_evt Event to be sent to parent when operation is done.
 *  \param[in] conn_peer New connection information (ip, port...).
 *  \returns 0 on success, -EINVAL on error. */
int mgcp_conn_modify(struct osmo_fsm_inst *fi, uint32_t parent_evt, struct mgcp_conn_peer *conn_peer)
{
	OSMO_ASSERT(fi);
	struct mgcp_ctx *mgcp_ctx = fi->priv;
	struct in_addr ip_test;

	OSMO_ASSERT(mgcp_ctx);
	OSMO_ASSERT(conn_peer);

	/* The user must not issue an MDCX before the CRCX has completed,
	 * if this happens, it means that the parent FSM has overhead the
	 * parent_evt (mandatory!) and executed the MDCX without even
	 * waiting for the results. Another reason could be that the
	 * parent FSM got messed up */
	OSMO_ASSERT(fi->state != ST_CRCX_RESP);

	/* If the user tries to issue an MDCX while an DLCX operation is
	 * pending, there must be a serious problem with the paren FSM.
	 * Eeither the parent_term_evt (mandatory!) has been overheard,
	 * or the parant FSM got messed so badly that it still assumes
	 * a live connection although it as killed it. */
	OSMO_ASSERT(fi->state != ST_DLCX_RESP);

	/* Check if IP/Port parameters make sense */
	if (conn_peer->port == 0)
		return -EINVAL;
	if (inet_aton(conn_peer->addr, &ip_test) == 0)
		return -EINVAL;

	/*! The user may supply an endpoint identifier in conn_peer. The
	 *  identifier is then checked. This check is optional. Later steps do
	 *  not depend on the endpoint identifier supplied here because it is
	 *  already implicitly known from the CRCX phase. */
	if (strlen(conn_peer->endpoint) && strcmp(conn_peer->endpoint, mgcp_ctx->conn_peer_remote.endpoint))
		return -EINVAL;

	/*! Note: The call-id is implicitly known from the previous CRCX and
	 *  will not be checked even when it is set in conn_peer. */

	mgcp_ctx->parent_evt = parent_evt;
	memcpy(&mgcp_ctx->conn_peer_local, conn_peer, sizeof(mgcp_ctx->conn_peer_local));
	osmo_fsm_inst_dispatch(fi, EV_MDCX, mgcp_ctx);
	return 0;
}

/*! delete existing connection on the MGW, destroy FSM afterwards.
 *  \param[in] fi FSM instance. */
void mgcp_conn_delete(struct osmo_fsm_inst *fi)
{
	OSMO_ASSERT(fi);
	struct mgcp_ctx *mgcp_ctx = fi->priv;

	OSMO_ASSERT(mgcp_ctx);

	/* Unlink FSM from parent */
	osmo_fsm_inst_unlink_parent(fi, NULL);

	/* An error situation where the parent FSM must be killed immediately
	 * may lead into a situation where the DLCX can not be executed right
	 * at that moment because the FSM is still busy with another operation.
	 * In those cases we postpone the DLCX so that the FSM and the
	 * connections on the MGW get cleaned up gracefully. */
	if (fi->state != ST_READY) {
		LOGPFSML(fi, LOGL_ERROR, "MGW: operation still pending, DLCX will be postponed.\n");
		mgcp_ctx->terminate = true;
		return;
	}
	osmo_fsm_inst_dispatch(fi, EV_DLCX, mgcp_ctx);
}

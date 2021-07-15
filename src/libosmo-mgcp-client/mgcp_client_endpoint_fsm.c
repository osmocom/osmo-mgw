/* FSM to manage multiple connections of an MGW endpoint
 *
 * (C) 2018-2019 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Neels Hofmeyr <neels@hofmeyr.de>
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

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <osmocom/core/fsm.h>
#include <osmocom/core/byteswap.h>
#include <osmocom/core/tdef.h>
#include <osmocom/core/sockaddr_str.h>

#include <osmocom/mgcp_client/mgcp_client_endpoint_fsm.h>

#define LOG_CI(ci, level, fmt, args...) do { \
	if (!ci || !ci->ep) \
		LOGP(DLMGCP, level, "(unknown MGW endpoint) " fmt, ## args); \
	else \
		LOG_MGCPC_EP(ci->ep, level, "CI[%d] %s%s%s: " fmt, \
			(int)(ci - ci->ep->ci), \
			ci->label ? : "-", \
			ci->mgcp_ci_str[0] ? " CI=" : "", \
			ci->mgcp_ci_str[0] ? ci->mgcp_ci_str : "", \
			## args); \
	} while(0)

#define LOG_CI_VERB(ci, level, fmt, args...) do { \
	if (ci->verb_info.addr[0]) \
		LOG_CI(ci, level, "%s %s:%u: " fmt, \
			osmo_mgcp_verb_name(ci->verb), ci->verb_info.addr, ci->verb_info.port, \
			## args); \
	else \
		LOG_CI(ci, level, "%s: " fmt, \
			osmo_mgcp_verb_name(ci->verb), \
			## args); \
	} while(0)

enum osmo_mgcpc_ep_fsm_state {
	OSMO_MGCPC_EP_ST_UNUSED = 0,
	OSMO_MGCPC_EP_ST_WAIT_MGW_RESPONSE,
	OSMO_MGCPC_EP_ST_IN_USE,
};

enum osmo_mgcpc_ep_fsm_event {
	_OSMO_MGCPC_EP_EV_LAST = 0,
	/* and MGW response events are allocated dynamically */
};

#define FIRST_CI_EVENT (_OSMO_MGCPC_EP_EV_LAST + (_OSMO_MGCPC_EP_EV_LAST & 1)) /* rounded up to even nr */
#define USABLE_CI ((32 - FIRST_CI_EVENT)/2)
#define EV_TO_CI_IDX(event) ((event - FIRST_CI_EVENT) / 2)

#define CI_EV_SUCCESS(ci) (FIRST_CI_EVENT + (((ci) - ci->ep->ci) * 2))
#define CI_EV_FAILURE(ci) (CI_EV_SUCCESS(ci) + 1)

static struct osmo_fsm osmo_mgcpc_ep_fsm;

struct fsm_notify {
	struct llist_head entry;
	struct osmo_fsm_inst *fi;
	uint32_t success;
	uint32_t failure;
	void *data;
};

/*! One connection on an endpoint, corresponding to a connection identifier (CI) as returned by the MGW.
 * An endpoint has a fixed number of slots of these, which may or may not be in use.
 */
struct osmo_mgcpc_ep_ci {
	struct osmo_mgcpc_ep *ep;

	bool occupied;
	char label[64];
	struct osmo_fsm_inst *mgcp_client_fi;

	bool pending;
	bool sent;
	enum mgcp_verb verb;
	struct mgcp_conn_peer verb_info;
	struct fsm_notify notify;

	bool got_port_info;
	struct mgcp_conn_peer rtp_info;
	char mgcp_ci_str[MGCP_CONN_ID_LENGTH];
};

/*! An MGW endpoint with N connections, like "rtpbridge/23@mgw". */
struct osmo_mgcpc_ep {
	/*! MGCP client connection to the MGW. */
	struct mgcp_client *mgcp_client;
	struct osmo_fsm_inst *fi;

	/*! Endpoint string; at first this might be a wildcard, and upon the first CRCX OK response, this will reflect
	 * the endpoint name returned by the MGW. */
	char endpoint[MGCP_ENDPOINT_MAXLEN];

	/*! Timeout definitions used for this endpoint, see osmo_mgcpc_ep_fsm_timeouts. */
	const struct osmo_tdef *T_defs;

	/*! True as soon as the first CRCX OK is received. The endpoint name may be determined by the first CRCX
	 * response, so to dispatch any other messages, the FSM instance *must* wait for the first CRCX OK to arrive
	 * first. Once the endpoint name is pinpointed, any amount of operations may be dispatched concurrently. */
	bool first_crcx_complete;

	/*! Endpoint connection slots. Note that each connection has its own set of FSM event numbers to signal success
	 * and failure, depending on its index within this array. See CI_EV_SUCCESS and CI_EV_FAILURE. */
	struct osmo_mgcpc_ep_ci ci[USABLE_CI];

	/*! Internal use: if a function keeps an fsm_notify for later dispatch while already clearing or re-using the
	 * ci[], the fsm_notify should be kept here to also get canceled by osmo_mgcpc_ep_cancel_notify(). */
	struct llist_head background_notify;
};

const struct value_string osmo_mgcp_verb_names[] = {
	{ MGCP_VERB_CRCX, "CRCX" },
	{ MGCP_VERB_MDCX, "MDCX" },
	{ MGCP_VERB_DLCX, "DLCX" },
	{ MGCP_VERB_AUEP, "AUEP" },
	{ MGCP_VERB_RSIP, "RSIP" },
	{}
};

static void osmo_mgcpc_ep_count(struct osmo_mgcpc_ep *ep, int *occupied, int *pending_not_sent,
				int *waiting_for_response);

static struct osmo_mgcpc_ep_ci *osmo_mgcpc_ep_check_ci(struct osmo_mgcpc_ep_ci *ci)
{
	if (!ci)
		return NULL;
	if (!ci->ep)
		return NULL;
	if (ci < ci->ep->ci || ci >= &ci->ep->ci[USABLE_CI])
		return NULL;
	return ci;
}

static struct osmo_mgcpc_ep_ci *osmo_mgcpc_ep_ci_for_event(struct osmo_mgcpc_ep *ep, uint32_t event)
{
	int idx;
	if (event < FIRST_CI_EVENT)
		return NULL;
	idx = EV_TO_CI_IDX(event);
	if (idx >= sizeof(ep->ci))
		return NULL;
	return osmo_mgcpc_ep_check_ci(&ep->ci[idx]);
}

const char *osmo_mgcpc_ep_name(const struct osmo_mgcpc_ep *ep)
{
	if (!ep)
		return "NULL";
	if (ep->endpoint[0])
		return ep->endpoint;
	return osmo_fsm_inst_name(ep->fi);
}

const char *mgcp_conn_peer_name(const struct mgcp_conn_peer *info)
{
	/* I'd be fine with a smaller buffer and accept truncation, but gcc possibly refuses to build if
	 * this buffer is too small. */
	static char buf[1024];

	if (!info)
		return "NULL";

	if (info->endpoint[0]
	    && info->addr[0])
		snprintf(buf, sizeof(buf), "%s:%s:%u",
			 info->endpoint, info->addr, info->port);
	else if (info->endpoint[0])
		snprintf(buf, sizeof(buf), "%s", info->endpoint);
	else if (info->addr[0])
		snprintf(buf, sizeof(buf), "%s:%u", info->addr, info->port);
	else
		return "empty";
	return buf;
}

const char *osmo_mgcpc_ep_ci_name(const struct osmo_mgcpc_ep_ci *ci)
{
	const struct mgcp_conn_peer *rtp_info;

	if (!ci)
		return "NULL";

	rtp_info = osmo_mgcpc_ep_ci_get_rtp_info(ci);

	if (rtp_info)
		return mgcp_conn_peer_name(rtp_info);
	return osmo_mgcpc_ep_name(ci->ep);
}

const char *osmo_mgcpc_ep_ci_id(const struct osmo_mgcpc_ep_ci *ci)
{
	if (!ci || !ci->mgcp_ci_str[0])
		return NULL;
	return ci->mgcp_ci_str;
}

static struct value_string osmo_mgcpc_ep_fsm_event_names[33] = {};

static char osmo_mgcpc_ep_fsm_event_name_bufs[32][32] = {};

static void fill_event_names()
{
	int i;
	for (i = 0; i < (ARRAY_SIZE(osmo_mgcpc_ep_fsm_event_names) - 1); i++) {
		if (i < _OSMO_MGCPC_EP_EV_LAST)
			continue;
		if (i < FIRST_CI_EVENT || EV_TO_CI_IDX(i) > USABLE_CI) {
			osmo_mgcpc_ep_fsm_event_names[i] = (struct value_string){i, "Unused"};
			continue;
		}
		snprintf(osmo_mgcpc_ep_fsm_event_name_bufs[i], sizeof(osmo_mgcpc_ep_fsm_event_name_bufs[i]),
			 "MGW Response for CI #%d", EV_TO_CI_IDX(i));
		osmo_mgcpc_ep_fsm_event_names[i] = (struct value_string){i, osmo_mgcpc_ep_fsm_event_name_bufs[i]};
	}
}

static __attribute__((constructor)) void osmo_mgcpc_ep_fsm_init()
{
	OSMO_ASSERT(osmo_fsm_register(&osmo_mgcpc_ep_fsm) == 0);
	fill_event_names();
}

struct osmo_mgcpc_ep *osmo_mgcpc_ep_fi_mgwep(struct osmo_fsm_inst *fi)
{
	OSMO_ASSERT(fi);
	OSMO_ASSERT(fi->fsm == &osmo_mgcpc_ep_fsm);
	OSMO_ASSERT(fi->priv);
	return fi->priv;
}

/*! Allocate an osmo_mgcpc_ep FSM.
 * MGCP messages to set up the endpoint will be sent on the given mgcp_client, as soon as the first
 * osmo_mgcpc_ep_ci_request() is invoked.
 *
 * IMPORTANT: To avoid use-after-free problems, using this FSM requires use of deferred FSM deallocation using
 * osmo_fsm_set_dealloc_ctx(), e.g. using osmo_select_main_ctx(OTC_SELECT) with osmo_select_main_ctx() as main loop.
 *
 * A typical sequence of events would be:
 *
 *    ep = osmo_mgcpc_ep_alloc(..., mgcp_client_rtpbridge_wildcard(client));
 *    ci_to_ran = osmo_mgcpc_ep_ci_add(ep);
 *    osmo_mgcpc_ep_ci_request(ci_to_ran, MGCP_VERB_CRCX, verb_info,
 *                             my_call_fsm, MY_EVENT_MGCP_OK, MY_EVENT_MGCP_FAIL);
 *    ci_to_cn = osmo_mgcpc_ep_ci_add(ep);
 *    osmo_mgcpc_ep_ci_request(ci_to_cn, MGCP_VERB_CRCX, verb_info,
 *                             my_call_fsm, MY_EVENT_MGCP_OK, MY_EVENT_MGCP_FAIL);
 *    ...
 *    osmo_mgcpc_ep_ci_request(ci_to_ran, MGCP_VERB_MDCX, ...);
 *    ...
 *    osmo_mgcpc_ep_clear(ep);
 *    ep = NULL;
 *
 * \param parent  Parent FSM.
 * \param parent_term_event  Event to dispatch to the parent on termination of this FSM instance.
 * \param mgcp_client  Connection to the MGW.
 * \param T_defs  Timeout definitions to be used for FSM states, see osmo_mgcpc_ep_fsm_timeouts.
 * \param fsm_id  FSM instance ID.
 * \param endpoint_str_fmt  The endpoint string format to send to the MGW upon the first CRCX.
 *                          See mgcp_client_rtpbridge_wildcard() for "rtpbridge" endpoints.
 */
struct osmo_mgcpc_ep *osmo_mgcpc_ep_alloc(struct osmo_fsm_inst *parent, uint32_t parent_term_event,
					  struct mgcp_client *mgcp_client,
					  const struct osmo_tdef *T_defs,
					  const char *fsm_id,
					  const char *endpoint_str_fmt, ...)
{
	va_list ap;
	struct osmo_fsm_inst *fi;
	struct osmo_mgcpc_ep *ep;
	int rc;

	if (!mgcp_client)
		return NULL;

	fi = osmo_fsm_inst_alloc_child(&osmo_mgcpc_ep_fsm, parent, parent_term_event);
	OSMO_ASSERT(fi);

	osmo_fsm_inst_update_id(fi, fsm_id);

	ep = talloc_zero(fi, struct osmo_mgcpc_ep);
	OSMO_ASSERT(ep);

	*ep = (struct osmo_mgcpc_ep){
		.mgcp_client = mgcp_client,
		.fi = fi,
		.T_defs = T_defs,
	};
	INIT_LLIST_HEAD(&ep->background_notify);
	fi->priv = ep;

	va_start(ap, endpoint_str_fmt);
	rc = vsnprintf(ep->endpoint, sizeof(ep->endpoint), endpoint_str_fmt ? : "", ap);
	va_end(ap);

	if (rc <= 0 || rc >= sizeof(ep->endpoint)) {
		LOG_MGCPC_EP(ep, LOGL_ERROR, "Endpoint name too long or too short: %s\n",
			  ep->endpoint);
		osmo_fsm_inst_term(ep->fi, OSMO_FSM_TERM_ERROR, 0);
		return NULL;
	}

	return ep;
}

/*! Add a connection to an endpoint.
 * Allocate a connection identifier slot in the osmo_mgcpc_ep instance, do not yet dispatch a CRCX.
 * The CRCX is dispatched only upon the first osmo_mgcpc_ep_ci_request().
 * \param ep  Parent endpoint instance.
 * \param label_fmt  Label for logging.
 */
struct osmo_mgcpc_ep_ci *osmo_mgcpc_ep_ci_add(struct osmo_mgcpc_ep *ep,
					      const char *label_fmt, ...)
{
	va_list ap;
	int i;
	struct osmo_mgcpc_ep_ci *ci;

	for (i = 0; i < USABLE_CI; i++) {
		ci = &ep->ci[i];

		if (ci->occupied || ci->mgcp_client_fi)
			continue;

		*ci = (struct osmo_mgcpc_ep_ci){
			.ep = ep,
			.occupied = true,
		};
		if (label_fmt) {
			va_start(ap, label_fmt);
			vsnprintf(ci->label, sizeof(ci->label), label_fmt, ap);
			va_end(ap);
		}
		return ci;
	}

	LOG_MGCPC_EP(ep, LOGL_ERROR,
		  "Cannot allocate another endpoint, all "
		  OSMO_STRINGIFY_VAL(USABLE_CI) " are in use\n");

	return NULL;
}

static bool osmo_mgcpc_ep_fsm_check_state_chg_after_response(struct osmo_fsm_inst *fi);

static void on_failure(struct osmo_mgcpc_ep_ci *ci)
{
	struct osmo_mgcpc_ep *ep = ci->ep;
	struct fsm_notify notify;
	int i;

	if (!ci->occupied)
		return;

	/* When dispatching an event for this CI, the user may decide to trigger the next request for this conn right
	 * away. So we must be ready with a cleared *ci. Store the notify separately and clear before dispatching. */
	notify = ci->notify;
	/* Register the planned notification in ep->background_notify so we also catch any osmo_mgcpc_ep_cancel_notify()
	 * that might be triggered between clearing the ci and actually dispatching the event. */
	llist_add(&notify.entry, &ep->background_notify);

	*ci = (struct osmo_mgcpc_ep_ci){
		.ep = ci->ep,
	};

	/* An MGCP failure typically means the endpoint becomes unusable, cancel all pending request (except DLCX).
	 * Particularly, if two CRCX were scheduled and the first fails, we must no longer dispatch the second CRCX. */
	for (i = 0; i < ARRAY_SIZE(ep->ci); i++) {
		struct osmo_mgcpc_ep_ci *other_ci = &ep->ci[i];
		if (other_ci == ci)
			continue;
		if (!other_ci->occupied)
			continue;
		if (!other_ci->pending)
			continue;
		if (other_ci->sent)
			continue;
		if (other_ci->verb == MGCP_VERB_DLCX)
			continue;
		/* Just clear the pending request, don't fire more events than below. */
		other_ci->pending = false;
	}

	/* If this check has terminated the FSM instance, don't fire any more events to prevent use-after-free problems.
	 * The endpoint FSM does dispatch a term event to its parent, and everything should be cleaned like that. */
	if (!osmo_mgcpc_ep_fsm_check_state_chg_after_response(ep->fi)) {
		/* The ep has deallocated, no need to llist_del(&notify.entry) here. */
		return;
	}

	if (notify.fi)
		osmo_fsm_inst_dispatch(notify.fi, notify.failure, notify.data);

	llist_del(&notify.entry);
}

static int update_endpoint_name(struct osmo_mgcpc_ep_ci *ci, const char *new_endpoint_name)
{
	struct osmo_mgcpc_ep *ep = ci->ep;
	int rc;
	int i;

	if (!strcmp(ep->endpoint, new_endpoint_name)) {
		/* Same endpoint name, nothing to do. */
		return 0;
	}

	/* The endpoint name should only change on the very first CRCX response. */
	if (ep->first_crcx_complete) {
		LOG_CI(ci, LOGL_ERROR, "Reponse returned mismatching endpoint name."
		       " This is endpoint %s, instead received %s\n",
		       ep->endpoint, new_endpoint_name);
		on_failure(ci);
		return -EINVAL;
	}

	/* This is the first CRCX response, update endpoint name. */
	rc = OSMO_STRLCPY_ARRAY(ep->endpoint, new_endpoint_name);
	if (rc <= 0 || rc >= sizeof(ep->endpoint)) {
		LOG_CI(ci, LOGL_ERROR, "Unable to copy endpoint name %s\n", osmo_quote_str(new_endpoint_name, -1));
		osmo_mgcpc_ep_ci_dlcx(ci);
		on_failure(ci);
		return -ENOSPC;
	}

	/* Make sure already pending requests use this updated endpoint name. */
	for (i = 0; i < ARRAY_SIZE(ep->ci); i++) {
		struct osmo_mgcpc_ep_ci *other_ci = &ep->ci[i];
		if (!other_ci->occupied)
			continue;
		if (!other_ci->pending)
			continue;
		if (other_ci->sent)
			continue;
		OSMO_STRLCPY_ARRAY(other_ci->verb_info.endpoint, ep->endpoint);
	}
	return 0;
}

static void on_success(struct osmo_mgcpc_ep_ci *ci, void *data)
{
	struct mgcp_conn_peer *rtp_info;

	if (!ci->occupied)
		return;

	ci->pending = false;

	rtp_info = data;

	switch (ci->verb) {
	case MGCP_VERB_CRCX:
		/* If we sent a wildcarded endpoint name on CRCX, we need to store the resulting endpoint
		 * name here. Also, we receive the MGW's RTP port information. */
		osmo_strlcpy(ci->mgcp_ci_str, mgcp_conn_get_ci(ci->mgcp_client_fi),
			sizeof(ci->mgcp_ci_str));
		if (rtp_info->endpoint[0]) {
			/* On errors, this instance might already be deallocated. Make sure to not access anything after
			 * error. */
			if (update_endpoint_name(ci, rtp_info->endpoint))
				return;
		}
		ci->ep->first_crcx_complete = true;
		OSMO_ASSERT(rtp_info);
		/* fall through */
	case MGCP_VERB_MDCX:
		/* Always update the received RTP ip/port information, since MGW
		 * may provide new one after remote end params changed */
		if (rtp_info) {
			ci->got_port_info = true;
			ci->rtp_info = *rtp_info;
		}
		break;

	default:
		break;
	}

	LOG_CI(ci, LOGL_DEBUG, "received successful response to %s: RTP=%s%s\n",
	       osmo_mgcp_verb_name(ci->verb),
	       mgcp_conn_peer_name(ci->got_port_info? &ci->rtp_info : NULL),
	       ci->notify.fi ? "" : " (not sending a notification)");

	if (ci->notify.fi)
		osmo_fsm_inst_dispatch(ci->notify.fi, ci->notify.success, ci->notify.data);

	osmo_mgcpc_ep_fsm_check_state_chg_after_response(ci->ep->fi);
}

/*! Return the MGW's local RTP port information for this connection, i.e. the local port that MGW is receiving on, as
 * returned by the last CRCX-OK / MDCX-OK message. */
const struct mgcp_conn_peer *osmo_mgcpc_ep_ci_get_rtp_info(const struct osmo_mgcpc_ep_ci *ci)
{
	ci = osmo_mgcpc_ep_check_ci((struct osmo_mgcpc_ep_ci*)ci);
	if (!ci)
		return NULL;
	if (!ci->got_port_info)
		return NULL;
	return &ci->rtp_info;
}

/*! Return the MGW's remote RTP port information for this connection, i.e. the remote RTP port that the MGW is sending
 * to, as sent to the MGW by the last CRCX / MDCX message. */
const struct mgcp_conn_peer *osmo_mgcpc_ep_ci_get_remote_rtp_info(const struct osmo_mgcpc_ep_ci *ci)
{
	ci = osmo_mgcpc_ep_check_ci((struct osmo_mgcpc_ep_ci*)ci);
	if (!ci)
		return NULL;
	return &ci->verb_info;
}

/*! Return the MGW's RTP port information for this connection, as returned by the last CRCX/MDCX OK message. */
bool osmo_mgcpc_ep_ci_get_crcx_info_to_sockaddr(const struct osmo_mgcpc_ep_ci *ci, struct sockaddr_storage *dest)
{
	const struct mgcp_conn_peer *rtp_info;
	int family;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;

	rtp_info = osmo_mgcpc_ep_ci_get_rtp_info(ci);
	if (!rtp_info)
		return false;

	family = osmo_ip_str_type(rtp_info->addr);
	switch (family) {
	case AF_INET:
		sin = (struct sockaddr_in *)dest;
		sin->sin_family = AF_INET;
		sin->sin_port = osmo_ntohs(rtp_info->port);
		if (inet_pton(AF_INET, rtp_info->addr, &sin->sin_addr) != 1)
			return false;
		break;
	case AF_INET6:
		sin6 = (struct sockaddr_in6 *)dest;
		sin6->sin6_family = AF_INET6;
		sin6->sin6_port = osmo_ntohs(rtp_info->port);
		if (inet_pton(AF_INET6, rtp_info->addr, &sin6->sin6_addr) != 1)
			return false;
		break;
	default:
		return false;
	}
	return true;
}

bool osmo_mgcpc_ep_ci_get_crcx_info_to_osmux_cid(const struct osmo_mgcpc_ep_ci *ci, uint8_t* cid)
{
	const struct mgcp_conn_peer *rtp_info;

	rtp_info = osmo_mgcpc_ep_ci_get_rtp_info(ci);
	if (!rtp_info)
		return false;

	if (!rtp_info->x_osmo_osmux_use)
		return false;

	*cid = rtp_info->x_osmo_osmux_cid;
	return true;
}

static const struct osmo_tdef_state_timeout osmo_mgcpc_ep_fsm_timeouts[32] = {
	[OSMO_MGCPC_EP_ST_WAIT_MGW_RESPONSE] = { .T=-2427 },
};

/* Transition to a state, using the T timer defined in assignment_fsm_timeouts.
 * The actual timeout value is in turn obtained from osmo_mgcpc_ep.T_defs.
 * Assumes local variable fi exists. */
#define osmo_mgcpc_ep_fsm_state_chg(state) \
	osmo_tdef_fsm_inst_state_chg(fi, state, osmo_mgcpc_ep_fsm_timeouts, \
				     ((struct osmo_mgcpc_ep*)fi->priv)->T_defs, 5)

/*! Dispatch an actual CRCX/MDCX/DLCX message for this connection.
 *
 * If the 'notify' instance deallocates before it received a notification of event_success or event_failure,
 * osmo_mgcpc_ep_ci_cancel_notify() or osmo_mgcpc_ep_cancel_notify() must be called. It is not harmful to cancel
 * notification after an event has been received.
 *
 * \param ci  Connection identifier as obtained from osmo_mgcpc_ep_ci_add().
 * \param verb  MGCP operation to dispatch.
 * \param verb_info  Parameters for the MGCP operation.
 * \param notify  Peer FSM instance to notify of completed/failed operation.
 * \param event_success  Which event to dispatch to 'notify' upon OK response.
 * \param event_failure  Which event to dispatch to 'notify' upon failure response.
 * \param notify_data  Data pointer to pass to the event dispatch for both success and failure.
 */
void osmo_mgcpc_ep_ci_request(struct osmo_mgcpc_ep_ci *ci,
			      enum mgcp_verb verb, const struct mgcp_conn_peer *verb_info,
			      struct osmo_fsm_inst *notify,
			      uint32_t event_success, uint32_t event_failure,
			      void *notify_data)
{
	struct osmo_mgcpc_ep *ep;
	struct osmo_fsm_inst *fi;
	struct osmo_mgcpc_ep_ci cleared_ci;
	ci = osmo_mgcpc_ep_check_ci(ci);

	if (!ci) {
		LOGP(DLMGCP, LOGL_ERROR, "Invalid MGW endpoint request: no ci\n");
		goto dispatch_error;
	}
	if (!verb_info && verb != MGCP_VERB_DLCX) {
		LOG_CI(ci, LOGL_ERROR, "Invalid MGW endpoint request: missing verb details for %s\n",
		       osmo_mgcp_verb_name(verb));
		goto dispatch_error;
	}
	if ((verb < 0) || (verb > MGCP_VERB_RSIP)) {
		LOG_CI(ci, LOGL_ERROR, "Invalid MGW endpoint request: unknown verb: %s\n",
		       osmo_mgcp_verb_name(verb));
		goto dispatch_error;
	}

	ep = ci->ep;
	fi = ep->fi;

	/* Clear volatile state by explicitly keeping those that should remain. Because we can't assign
	 * the char[] directly, dance through cleared_ci and copy back. */
	cleared_ci = (struct osmo_mgcpc_ep_ci){
		.ep = ep,
		.mgcp_client_fi = ci->mgcp_client_fi,
		.got_port_info = ci->got_port_info,
		.rtp_info = ci->rtp_info,

		.occupied = true,
		/* .pending = true follows below */
		.verb = verb,
		.notify = {
			.fi = notify,
			.success = event_success,
			.failure = event_failure,
			.data = notify_data,
		}
	};
	osmo_strlcpy(cleared_ci.label, ci->label, sizeof(cleared_ci.label));
	osmo_strlcpy(cleared_ci.mgcp_ci_str, ci->mgcp_ci_str, sizeof(cleared_ci.mgcp_ci_str));
	*ci = cleared_ci;

	LOG_CI_VERB(ci, LOGL_DEBUG, "notify=%s\n", osmo_fsm_inst_name(ci->notify.fi));

	if (verb_info)
		ci->verb_info = *verb_info;

	if (ep->endpoint[0]) {
		if (ci->verb_info.endpoint[0] && strcmp(ci->verb_info.endpoint, ep->endpoint))
			LOG_CI(ci, LOGL_ERROR,
			       "Warning: Requested %s on endpoint %s, but this CI is on endpoint %s."
			       " Using the proper endpoint instead.\n",
			       osmo_mgcp_verb_name(verb), ci->verb_info.endpoint, ep->endpoint);
		osmo_strlcpy(ci->verb_info.endpoint, ep->endpoint, sizeof(ci->verb_info.endpoint));
	}

	switch (ci->verb) {
	case MGCP_VERB_CRCX:
		if (ci->mgcp_client_fi) {
			LOG_CI(ci, LOGL_ERROR, "CRCX can be called only once per MGW endpoint CI\n");
			on_failure(ci);
			return;
		}
		break;

	case MGCP_VERB_MDCX:
		if (!ci->mgcp_client_fi) {
			LOG_CI_VERB(ci, LOGL_ERROR, "The first verb on an unused MGW endpoint CI must be CRCX, not %s\n",
				    osmo_mgcp_verb_name(ci->verb));
			on_failure(ci);
			return;
		}
		break;

	case MGCP_VERB_DLCX:
		if (!ci->mgcp_client_fi) {
			LOG_CI_VERB(ci, LOGL_DEBUG, "Ignoring DLCX on unused MGW endpoint CI\n");
			return;
		}
		break;

	default:
		LOG_CI(ci, LOGL_ERROR, "This verb is not supported: %s\n", osmo_mgcp_verb_name(ci->verb));
		on_failure(ci);
		return;
	}

	ci->pending = true;

	LOG_CI_VERB(ci, LOGL_DEBUG, "Scheduling\n");

	if (ep->fi->state != OSMO_MGCPC_EP_ST_WAIT_MGW_RESPONSE)
		osmo_mgcpc_ep_fsm_state_chg(OSMO_MGCPC_EP_ST_WAIT_MGW_RESPONSE);

	return;
dispatch_error:
	if (notify)
		osmo_fsm_inst_dispatch(notify, event_failure, notify_data);
}

/*! No longer notify for any state changes for any conns of this endpoint.
 * Useful if the notify instance passed to osmo_mgcpc_ep_ci_request() is about to deallocate.
 * \param ep  The endpoint FSM instance.
 * \param notify  Which target to cancel notification for, if NULL cancel all notifications. */
void osmo_mgcpc_ep_cancel_notify(struct osmo_mgcpc_ep *ep, struct osmo_fsm_inst *notify)
{
	struct fsm_notify *n;
	int i;
	for (i = 0; i < ARRAY_SIZE(ep->ci); i++) {
		struct osmo_mgcpc_ep_ci *ci = &ep->ci[i];
		if (!notify || ci->notify.fi == notify)
			ci->notify.fi = NULL;
	}
	llist_for_each_entry(n, &ep->background_notify, entry) {
		if (!notify || n->fi == notify)
			n->fi = NULL;
	}

}

/* Return the osmo_mgcpc_ep that this conn belongs to. */
struct osmo_mgcpc_ep *osmo_mgcpc_ep_ci_ep(struct osmo_mgcpc_ep_ci *conn)
{
	if (!conn)
		return NULL;
	return conn->ep;
}

static int send_verb(struct osmo_mgcpc_ep_ci *ci)
{
	int rc;
	struct osmo_mgcpc_ep *ep = ci->ep;
	struct fsm_notify notify;

	if (!ci->occupied || !ci->pending || ci->sent)
		return 0;

	switch (ci->verb) {

	case MGCP_VERB_CRCX:
		OSMO_ASSERT(!ci->mgcp_client_fi);
		LOG_CI_VERB(ci, LOGL_DEBUG, "Sending\n");
		ci->mgcp_client_fi = mgcp_conn_create(ep->mgcp_client, ep->fi,
						      CI_EV_FAILURE(ci), CI_EV_SUCCESS(ci),
						      &ci->verb_info);
		ci->sent = true;
		if (!ci->mgcp_client_fi){
			LOG_CI_VERB(ci, LOGL_ERROR, "Cannot send\n");
			on_failure(ci);
			return -EINVAL;
		}
		osmo_fsm_inst_update_id(ci->mgcp_client_fi, ci->label);
		break;

	case MGCP_VERB_MDCX:
		OSMO_ASSERT(ci->mgcp_client_fi);
		LOG_CI_VERB(ci, LOGL_DEBUG, "Sending\n");
		rc = mgcp_conn_modify(ci->mgcp_client_fi, CI_EV_SUCCESS(ci), &ci->verb_info);
		ci->sent = true;
		if (rc) {
			LOG_CI_VERB(ci, LOGL_ERROR, "Cannot send (rc=%d %s)\n", rc, strerror(-rc));
			on_failure(ci);
			return -EINVAL;
		}
		break;

	case MGCP_VERB_DLCX:
		LOG_CI(ci, LOGL_DEBUG, "Sending MGCP: %s %s\n",
		       osmo_mgcp_verb_name(ci->verb), ci->mgcp_ci_str);
		/* The way this is designed, we actually need to forget all about the ci right away. */
		mgcp_conn_delete(ci->mgcp_client_fi);
		notify = ci->notify;
		*ci = (struct osmo_mgcpc_ep_ci){
			.ep = ep,
		};
		/* When dispatching an event for this CI, the user may decide to trigger the next request for this conn
		 * right away. So we must be ready with a cleared *ci. */
		if (notify.fi)
			osmo_fsm_inst_dispatch(notify.fi, notify.success, notify.data);
		break;

	default:
		OSMO_ASSERT(false);
	}

	return 1;
}

/*! DLCX all connections, terminate the endpoint FSM and free. */
void osmo_mgcpc_ep_clear(struct osmo_mgcpc_ep *ep)
{
	if (!ep)
		return;
	osmo_mgcpc_ep_cancel_notify(ep, NULL);
	osmo_fsm_inst_term(ep->fi, OSMO_FSM_TERM_REGULAR, 0);
}

static void osmo_mgcpc_ep_count(struct osmo_mgcpc_ep *ep, int *occupied, int *pending_not_sent,
				int *waiting_for_response)
{
	int i;

	if (occupied)
		*occupied = 0;

	if (pending_not_sent)
		*pending_not_sent = 0;

	if (waiting_for_response)
		*waiting_for_response = 0;

	for (i = 0; i < ARRAY_SIZE(ep->ci); i++) {
		struct osmo_mgcpc_ep_ci *ci = &ep->ci[i];
		if (ci->occupied) {
			if (occupied)
				(*occupied)++;
		} else
			continue;

		if (ci->pending)
			LOG_CI_VERB(ci, LOGL_DEBUG, "%s\n",
				    ci->sent ? "waiting for response" : "waiting to be sent");
		else
			LOG_CI_VERB(ci, LOGL_DEBUG, "done (%s)\n", mgcp_conn_peer_name(osmo_mgcpc_ep_ci_get_rtp_info(ci)));

		if (ci->pending && ci->sent)
			if (waiting_for_response)
				(*waiting_for_response)++;
		if (ci->pending && !ci->sent)
			if (pending_not_sent)
				(*pending_not_sent)++;
	}
}

static bool osmo_mgcpc_ep_fsm_check_state_chg_after_response(struct osmo_fsm_inst *fi)
{
	int waiting_for_response;
	int occupied;
	struct osmo_mgcpc_ep *ep = osmo_mgcpc_ep_fi_mgwep(fi);

	osmo_mgcpc_ep_count(ep, &occupied, NULL, &waiting_for_response);
	LOG_MGCPC_EP(ep, LOGL_DEBUG, "CI in use: %d, waiting for response: %d\n", occupied, waiting_for_response);

	if (!occupied)  {
		/* All CI have been released. The endpoint no longer exists. Notify the parent FSM, by
		 * terminating. */
		osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REGULAR, 0);
		return false;
	}

	if (!waiting_for_response) {
		if (fi->state != OSMO_MGCPC_EP_ST_IN_USE)
			osmo_mgcpc_ep_fsm_state_chg(OSMO_MGCPC_EP_ST_IN_USE);
	}

	return true;
}

static void osmo_mgcpc_ep_fsm_wait_mgw_response_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	static int re_enter = 0;
	int rc;
	int count = 0;
	int i;
	struct osmo_mgcpc_ep *ep = osmo_mgcpc_ep_fi_mgwep(fi);

	re_enter++;
	OSMO_ASSERT(re_enter < 10);

	/* The first CRCX gives us the endpoint name in the CRCX response. So we must wait for the first CRCX endpoint
	 * response to come in before sending any other MGCP requests -- otherwise we might end up creating new
	 * endpoints instead of acting on the same. This FSM always sends out N requests and waits for all of them to
	 * complete before sending out new requests. Hence we're safe when the very first time at most one request is
	 * sent (which needs to be a CRCX). */

	for (i = 0; i < ARRAY_SIZE(ep->ci); i++) {
		struct osmo_mgcpc_ep_ci *ci = &ep->ci[i];

		/* Make sure that only CRCX get dispatched if no CRCX were sent yet. */
		if (!ep->first_crcx_complete) {
			if (ci->occupied && ci->verb != MGCP_VERB_CRCX)
				continue;
		}

		rc = send_verb(&ep->ci[i]);
		/* Need to be careful not to access the instance after failure. Event chains may already have
		 * deallocated this memory. */
		if (rc < 0)
			return;
		if (!rc)
			continue;
		count++;
		/* Make sure that we wait for the first CRCX response before dispatching more requests. */
		if (!ep->first_crcx_complete)
			break;
	}

	LOG_MGCPC_EP(ep, LOGL_DEBUG, "Sent messages: %d\n", count);
	if (ep->first_crcx_complete)
		osmo_mgcpc_ep_fsm_check_state_chg_after_response(fi);
	re_enter--;
}

static void osmo_mgcpc_ep_fsm_handle_ci_events(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct osmo_mgcpc_ep_ci *ci;
	struct osmo_mgcpc_ep *ep = osmo_mgcpc_ep_fi_mgwep(fi);
	ci = osmo_mgcpc_ep_ci_for_event(ep, event);
	if (ci) {
		if (event == CI_EV_SUCCESS(ci))
			on_success(ci, data);
		else
			on_failure(ci);
	}
}

static void osmo_mgcpc_ep_fsm_in_use_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	int pending_not_sent;
	struct osmo_mgcpc_ep *ep = osmo_mgcpc_ep_fi_mgwep(fi);

	osmo_mgcpc_ep_count(ep, NULL, &pending_not_sent, NULL);
	if (pending_not_sent)
		osmo_mgcpc_ep_fsm_state_chg(OSMO_MGCPC_EP_ST_WAIT_MGW_RESPONSE);
}

#define S(x)	(1 << (x))

static const struct osmo_fsm_state osmo_mgcpc_ep_fsm_states[] = {
	[OSMO_MGCPC_EP_ST_UNUSED] = {
		.name = "UNUSED",
		.in_event_mask = 0,
		.out_state_mask = 0
			| S(OSMO_MGCPC_EP_ST_WAIT_MGW_RESPONSE)
			,
	},
	[OSMO_MGCPC_EP_ST_WAIT_MGW_RESPONSE] = {
		.name = "WAIT_MGW_RESPONSE",
		.onenter = osmo_mgcpc_ep_fsm_wait_mgw_response_onenter,
		.action = osmo_mgcpc_ep_fsm_handle_ci_events,
		.in_event_mask = 0xffffffff,
		.out_state_mask = 0
			| S(OSMO_MGCPC_EP_ST_IN_USE)
			,
	},
	[OSMO_MGCPC_EP_ST_IN_USE] = {
		.name = "IN_USE",
		.onenter = osmo_mgcpc_ep_fsm_in_use_onenter,
		.action = osmo_mgcpc_ep_fsm_handle_ci_events,
		.in_event_mask = 0xffffffff, /* mgcp_client_fsm may send parent term anytime */
		.out_state_mask = 0
			| S(OSMO_MGCPC_EP_ST_WAIT_MGW_RESPONSE)
			,
	},
};

static int osmo_mgcpc_ep_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	int i;
	struct osmo_mgcpc_ep *ep = osmo_mgcpc_ep_fi_mgwep(fi);

	switch (fi->T) {
	default:
		for (i = 0; i < ARRAY_SIZE(ep->ci); i++) {
			struct osmo_mgcpc_ep_ci *ci = &ep->ci[i];
			if (!ci->occupied)
				continue;
			if (!(ci->pending && ci->sent))
				continue;
			on_failure(ci);
		}
		return 0;
	}

	return 0;
}

void osmo_mgcpc_ep_fsm_pre_term(struct osmo_fsm_inst *fi, enum osmo_fsm_term_cause cause)
{
	int i;
	struct osmo_mgcpc_ep *ep = osmo_mgcpc_ep_fi_mgwep(fi);

	/* We want the mgcp_client_fsm to still stick around until it received the DLCX "OK" responses from the MGW. So
	 * it should not dealloc along with this ep_fsm instance. Instead, signal DLCX for each conn on the endpoint,
	 * and detach the mgcp_client_fsm from being a child-fsm.
	 *
	 * After mgcp_conn_delete(), an mgcp_client_fsm instance goes into ST_DLCX_RESP, which waits up to 4 seconds for
	 * a DLCX OK. If none is received in that time, the instance terminates. So cleanup of the instance is
	 * guaranteed. */

	for (i = 0; i < ARRAY_SIZE(ep->ci); i++) {
		struct osmo_mgcpc_ep_ci *ci = &ep->ci[i];

		if (!ci->occupied || !ci->mgcp_client_fi)
			continue;

		/* mgcp_conn_delete() unlinks itself from this parent FSM implicitly and waits for the DLCX OK. */
		mgcp_conn_delete(ci->mgcp_client_fi);
		/* Forget all about this ci */
		*ci = (struct osmo_mgcpc_ep_ci){
			.ep = ep,
		};
	}
}

static struct osmo_fsm osmo_mgcpc_ep_fsm = {
	.name = "mgw-endp",
	.states = osmo_mgcpc_ep_fsm_states,
	.num_states = ARRAY_SIZE(osmo_mgcpc_ep_fsm_states),
	.log_subsys = DLMGCP,
	.event_names = osmo_mgcpc_ep_fsm_event_names,
	.timer_cb = osmo_mgcpc_ep_fsm_timer_cb,
	.pre_term = osmo_mgcpc_ep_fsm_pre_term,
};

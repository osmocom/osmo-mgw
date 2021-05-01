/* FSM to manage multiple connections of an MGW endpoint */
#pragma once

#include <osmocom/mgcp_client/mgcp_client_fsm.h>

#define LOG_MGCPC_EP(ep, level, fmt, args...) do { \
	LOGPFSML(ep->fi, level, "%s " fmt, \
		 osmo_mgcpc_ep_name(ep), ## args); \
	} while(0)

struct osmo_mgcpc_ep;
struct osmo_mgcpc_ep_ci;
struct osmo_tdef;

struct osmo_mgcpc_ep *osmo_mgcpc_ep_alloc(struct osmo_fsm_inst *parent, uint32_t parent_term_event,
					  struct mgcp_client *mgcp_client,
					  const struct osmo_tdef *T_defs,
					  const char *fsm_id,
					  const char *endpoint_str_fmt, ...);

struct osmo_mgcpc_ep_ci *osmo_mgcpc_ep_ci_add(struct osmo_mgcpc_ep *ep, const char *label_fmt, ...);
const struct mgcp_conn_peer *osmo_mgcpc_ep_ci_get_rtp_info(const struct osmo_mgcpc_ep_ci *ci);
bool osmo_mgcpc_ep_ci_get_crcx_info_to_sockaddr(const struct osmo_mgcpc_ep_ci *ci, struct sockaddr_storage *dest);
bool osmo_mgcpc_ep_ci_get_crcx_info_to_osmux_cid(const struct osmo_mgcpc_ep_ci *ci, uint8_t* cid);

const struct mgcp_conn_peer *osmo_mgcpc_ep_ci_get_remote_rtp_info(const struct osmo_mgcpc_ep_ci *ci);

void osmo_mgcpc_ep_ci_request(struct osmo_mgcpc_ep_ci *ci,
			      enum mgcp_verb verb, const struct mgcp_conn_peer *verb_info,
			      struct osmo_fsm_inst *notify,
			      uint32_t event_success, uint32_t event_failure,
			      void *notify_data);

void osmo_mgcpc_ep_cancel_notify(struct osmo_mgcpc_ep *ep, struct osmo_fsm_inst *notify);
struct osmo_mgcpc_ep *osmo_mgcpc_ep_ci_ep(struct osmo_mgcpc_ep_ci *ci);

/*! Dispatch a DLCX for the given connection.
 * \param ci  Connection identifier as obtained from osmo_mgcpc_ep_ci_add().
 */
static inline void osmo_mgcpc_ep_ci_dlcx(struct osmo_mgcpc_ep_ci *ci)
{
	osmo_mgcpc_ep_ci_request(ci, MGCP_VERB_DLCX, NULL, NULL, 0, 0, NULL);
}

void osmo_mgcpc_ep_clear(struct osmo_mgcpc_ep *ep);

const char *osmo_mgcpc_ep_name(const struct osmo_mgcpc_ep *ep);
const char *osmo_mgcpc_ep_ci_name(const struct osmo_mgcpc_ep_ci *ci);
const char *osmo_mgcpc_ep_ci_id(const struct osmo_mgcpc_ep_ci *ci);

extern const struct value_string osmo_mgcp_verb_names[];
static inline const char *osmo_mgcp_verb_name(enum mgcp_verb val)
{ return get_value_string(osmo_mgcp_verb_names, val); }

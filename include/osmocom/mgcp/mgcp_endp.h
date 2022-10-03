/* Endpoint types */

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

#include <osmocom/core/msgb.h>
#include <osmocom/gsm/i460_mux.h>
#include <osmocom/mgcp/mgcp_protocol.h>

struct sockaddr;
struct mgcp_conn;
struct mgcp_conn_rtp;
struct mgcp_endpoint;

/* Number of E1 subslots (different variants, not all useable at the same time) */
#define MGCP_ENDP_E1_SUBSLOTS 15

#define LOGPENDP(endp, cat, level, fmt, args...) \
LOGP(cat, level, "endpoint:%s " fmt, \
     endp ? endp->name : "none", \
     ## args)

enum rtp_proto {
	MGCP_PROTO_RTP,
	MGCP_PROTO_RTCP,
};

struct osmo_rtp_msg_ctx {
	enum rtp_proto proto;
	struct mgcp_conn_rtp *conn_src;
	struct osmo_sockaddr *from_addr;
};

#define OSMO_RTP_MSG_CTX(MSGB) ((struct osmo_rtp_msg_ctx*)(MSGB)->cb)

osmo_static_assert(sizeof(((struct msgb*)0)->cb) >= sizeof(struct osmo_rtp_msg_ctx), osmo_rtp_msg_ctx_fits_in_msgb_cb);

/* Callback type for RTP dispatcher functions (e.g mgcp_dispatch_rtp_bridge_cb, see below).
 * The OSMO_RTP_MSG_CTX() should be set appropriately on the msg. */
typedef int (*mgcp_dispatch_rtp_cb) (struct msgb *msg);

/* Callback type for endpoint specific cleanup actions. This function
 * is automatically executed when a connection is freed (see mgcp_conn_free()
 * in mgcp_conn.c). Depending on the type of the endpoint there may be endpoint
 * specific things to take care of once a connection has been removed. */
typedef void (*mgcp_cleanup_cp) (struct mgcp_endpoint *endp,
				 struct mgcp_conn *conn);

/*! MGCP endpoint properties */
struct mgcp_endpoint_type {
	/*! maximum number of connections */
	int max_conns;

	/*! callback that defines how to dispatch incoming RTP data */
	mgcp_dispatch_rtp_cb dispatch_rtp_cb;

	/*! callback that implements endpoint specific cleanup actions */
	mgcp_cleanup_cp cleanup_cb;
};

/*! MGCP endpoint typeset */
struct mgcp_endpoint_typeset {
	struct mgcp_endpoint_type rtp;
	struct mgcp_endpoint_type e1;
};

/*! static MGCP endpoint typeset (pre-initalized, read-only) */
extern const struct mgcp_endpoint_typeset ep_typeset;

/*! MGCP endpoint model */
struct mgcp_endpoint {

	/*! Unique endpoint name, used for addressing via MGCP */
	char *name;

	/*! Call identifier string (as supplied by the call agant) */
	char *callid;

	/*! Local connection options (see mgcp_internal.h) */
	struct mgcp_lco local_options;

	/*! List of struct mgcp_conn, of the connections active on this endpoint */
	struct llist_head conns;

	/*! Backpointer to the trunk this endpoint belongs to */
	struct mgcp_trunk *trunk;

	/*! Endpoint properties (see above) */
	const struct mgcp_endpoint_type *type;

	/*! Last MGCP transmission (in case re-transmission is required) */
	char *last_trans;

	/*! Last MGCP response (in case re-transmission is required) */
	char *last_response;

	/*! MGCP_X_OSMO_IGN_* flags from 'X-Osmo-IGN:' header */
	uint32_t x_osmo_ign;

	/* E1 specific */
	struct {
		struct osmo_i460_schan_desc scd;
		struct osmo_i460_subchan *schan;
		struct osmo_fsm_inst *trau_sync_fi;
		struct osmo_trau2rtp_state *trau_rtp_st;
		uint8_t last_amr_ft;
		struct mgcp_rtp_codec *last_codec;
	} e1;

};

struct mgcp_endpoint *mgcp_endp_alloc(struct mgcp_trunk *trunk, unsigned int index);
void mgcp_endp_release(struct mgcp_endpoint *endp);
int mgcp_endp_claim(struct mgcp_endpoint *endp, const char *callid);
void mgcp_endp_update(struct mgcp_endpoint *endp);
bool mgcp_endp_is_wildcarded(const char *epname);
struct mgcp_endpoint *mgcp_endp_by_name_trunk(int *cause, const char *epname,
					      const struct mgcp_trunk *trunk);
struct mgcp_endpoint *mgcp_endp_by_name(int *cause, const char *epname,
					struct mgcp_config *cfg);
bool mgcp_endp_avail(struct mgcp_endpoint *endp);
void mgcp_endp_add_conn(struct mgcp_endpoint *endp, struct mgcp_conn *conn);
void mgcp_endp_remove_conn(struct mgcp_endpoint *endp, struct mgcp_conn *conn);
void mgcp_endp_strip_name(char *epname_stripped, const char *epname,
			 const struct mgcp_trunk *trunk);
struct mgcp_endpoint *mgcp_endp_find_specific(const char *epname,
			const struct mgcp_trunk *trunk);

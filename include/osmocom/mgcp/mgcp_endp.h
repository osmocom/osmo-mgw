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

struct sockaddr_in;
struct mgcp_conn;
struct mgcp_endpoint;

/* Callback type for RTP dispatcher functions
   (e.g mgcp_dispatch_rtp_bridge_cb, see below) */
typedef int (*mgcp_dispatch_rtp_cb) (int proto, struct sockaddr_in *addr,
				     char *buf, unsigned int buf_size,
				     struct mgcp_conn *conn);

/* Callback type for endpoint specific cleanup actions. This function
 * is automatically executed when a connection is freed (see mgcp_conn_free()
 * in mgcp_conn.c). Depending on the type of the endpoint there may be endpoint
 * specific things to take care of once a connection has been removed. */
typedef void (*mgcp_cleanup_cp) (struct mgcp_endpoint *endp,
				 struct mgcp_conn *conn);

/*! MGCP endpoint properties */
struct mgcp_endpoint_type {
	/*!< maximum number of connections */
	int max_conns;

	/*!< callback that defines how to dispatch incoming RTP data */
	mgcp_dispatch_rtp_cb dispatch_rtp_cb;

	/*!< callback that implements endpoint specific cleanup actions */
	mgcp_cleanup_cp cleanup_cb;
};

/*! MGCP endpoint typeset */
struct mgcp_endpoint_typeset {
	struct mgcp_endpoint_type rtp;
};

/*! static MGCP endpoint typeset (pre-initalized, read-only) */
extern const struct mgcp_endpoint_typeset ep_typeset;

/*! MGCP endpoint model */
struct mgcp_endpoint {

	/*!< Call identifier string (as supplied by the call agant) */
	char *callid;

	/*!< Local connection options (see mgcp_intermal.h) */
	struct mgcp_lco local_options;

	/*!< List with connections active on this endpoint */
	struct llist_head conns;

	/*!< Backpointer to the MGW configuration */
	struct mgcp_config *cfg;

	/*!< Backpointer to the Trunk specific configuration */
	struct mgcp_trunk_config *tcfg;

	/*!< Endpoint properties (see above) */
	const struct mgcp_endpoint_type *type;

	/*!< Last MGCP transmission (in case re-transmission is required) */
	char *last_trans;

	/*!< Last MGCP response (in case re-transmission is required) */
	char *last_response;

	/*!< Memorize if this endpoint was choosen by the MGW (wildcarded, true)
	 *   or if the user has choosen the particular endpoint explicitly. */
	bool wildcarded_req;
};

/*! Extract endpoint number for a given endpoint */
#define ENDPOINT_NUMBER(endp) abs((int)(endp - endp->tcfg->endpoints))

void mgcp_endp_release(struct mgcp_endpoint *endp);


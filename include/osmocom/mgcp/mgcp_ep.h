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

/* Callback type for RTP dispatcher functions
   (e.g mgcp_dispatch_rtp_bridge_cb, see below) */
typedef int (*mgcp_dispatch_rtp_cb) (int proto, struct sockaddr_in *addr,
				     char *buf, unsigned int buf_size,
				     struct mgcp_conn *conn);

/*! MGCP endpoint properties */
struct mgcp_endpoint_type {
	/*!< maximum number of connections */
	int max_conns;

	/*!< callback that defines how to dispatch incoming RTP data */
	mgcp_dispatch_rtp_cb dispatch_rtp_cb;
};

/*! MGCP endpoint typeset */
struct mgcp_endpoint_typeset {
	struct mgcp_endpoint_type rtp;
};

/*! static MGCP endpoint typeset (pre-initalized, read-only) */
extern const struct mgcp_endpoint_typeset ep_typeset;

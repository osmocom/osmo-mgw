/* MGCP common implementations.
 * These are used in libosmo-mgcp as well as libosmo-mgcp-client.
 * To avoid interdependency, these are implemented in .h file only. */

/*
 * (C) 2017 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
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

/* Two copies of this file are kept in osmocom/mgcp/ and osmocom/mgcp_client/.
 * Since both are by definition identical, use the old header exclusion ifdefs
 * instead of '#pragma once' to avoid including both of these files.
 * Though at the time of writing there are no such users, this allows including
 * both libosmo-mgcp and libosmo-mgcp-client headers in the same file. */
#ifndef OSMO_MGCP_COMMON_H
#define OSMO_MGCP_COMMON_H

#include <string.h>
#include <errno.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>

#define for_each_non_empty_line(line, save)			\
	for (line = strtok_r(NULL, "\r\n", &save); line;	\
	     line = strtok_r(NULL, "\r\n", &save))

enum mgcp_connection_mode {
	MGCP_CONN_NONE = 0,
	MGCP_CONN_RECV_ONLY = 1,
	MGCP_CONN_SEND_ONLY = 2,
	MGCP_CONN_RECV_SEND = MGCP_CONN_RECV_ONLY | MGCP_CONN_SEND_ONLY,
	MGCP_CONN_LOOPBACK  = 4 | MGCP_CONN_RECV_SEND,
};

/* Ensure that the msg->l2h is NUL terminated. */
static inline int mgcp_msg_terminate_nul(struct msgb *msg)
{
	unsigned char *tail = msg->l2h + msgb_l2len(msg); /* char after l2 data */
	if (tail[-1] == '\0')
		/* nothing to do */;
	else if (msgb_tailroom(msg) > 0)
		tail[0] = '\0';
	else if (tail[-1] == '\r' || tail[-1] == '\n')
		tail[-1] = '\0';
	else {
		LOGP(DLMGCP, LOGL_ERROR, "Cannot NUL terminate MGCP message: "
		     "Length: %d, Buffer size: %d\n",
		     msgb_l2len(msg), msg->data_len);
		return -ENOTSUP;
	}
	return 0;
}

#endif

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
	MGCP_CONN_CONFECHO  = 8 | MGCP_CONN_RECV_SEND,
};

#define MGCP_X_OSMO_IGN_HEADER "X-Osmo-IGN:"
#define MGCP_X_OSMO_OSMUX_HEADER "X-Osmux:"

/* Values should be bitwise-OR-able */
enum mgcp_x_osmo_ign {
	MGCP_X_OSMO_IGN_NONE = 0,
	MGCP_X_OSMO_IGN_CALLID = 1,
};

/* Codec parameters (communicated via SDP/fmtp) */
struct mgcp_codec_param {
	bool amr_octet_aligned_present;
	bool amr_octet_aligned;
	bool fr_efr_twts001_present;
	bool fr_efr_twts001;
	bool hr_twts002_present;
	bool hr_twts002;
};

/* Ensure that the msg->l2h is NUL terminated. */
static inline int mgcp_msg_terminate_nul(struct msgb *msg)
{
	unsigned char *tail = msg->tail; /* char after l2 data */
	if (tail[-1] == '\0')
		/* nothing to do */;
	else if (msgb_tailroom(msg) > 0)
		msgb_put_u8(msg, (uint8_t)'\0');
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

/* Maximum length of the comment field */
#define MGCP_COMMENT_MAXLEN 256

/* Maximum allowed String length of Connection Identifiers as per spec
 * (see also RFC3435 2.1.3.2 Names of Connections), plus one for '\0'. */
#define MGCP_CONN_ID_MAXLEN 32+1

/* Deprecated: old name of MGCP_CONN_ID_MAXLEN. */
#define MGCP_CONN_ID_LENGTH MGCP_CONN_ID_MAXLEN

/* String length of Endpoint Identifiers.
/  (see also RFC3435 section 3.2.1.3) */
#define MGCP_ENDPOINT_MAXLEN (255*2+1+1)

/* A prefix to denote the virtual trunk (RTP on both ends) */
#define MGCP_ENDPOINT_PREFIX_VIRTUAL_TRUNK "rtpbridge/"

/* A prefix to denote the e1 trunk
 * (see also RFC3435 section E.2) */
#define MGCP_ENDPOINT_PREFIX_E1_TRUNK "ds/e1-"

/* Maximal number of payload types / codecs that can be negotiated via SDP at
 * at once. */
#define MGCP_MAX_CODECS 10

/* Maximum length of SignalRequests string (RFC 3435 section 3.2.2.21)
 * including the terminating NUL. */
#define MGCP_SIGNAL_REQ_MAXLEN 32

/* Themyscira Wireless MGW implementations are asymmetric, e.g., one side
 * must always be Ater-IP while the other side is PCMoIP, and not any other
 * combination.  These MGWs require a non-standard X-Side parameter line
 * to be included in CRCX command, e.g., "X-Side: Ater" or "X-Side: PCM".
 * Define the maximum allowed length of side ID string, including
 * the terminating NUL. */
#define MGCP_SIDE_ID_MAXLEN 16

#endif

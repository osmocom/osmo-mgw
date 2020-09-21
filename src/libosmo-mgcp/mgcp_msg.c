/* A Media Gateway Control Protocol Media Gateway: RFC 3435 */
/* Message parser/generator utilities */

/*
 * (C) 2009-2012 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009-2012 by On-Waves
 * (C) 2017 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
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

#include <limits.h>

#include <osmocom/mgcp/mgcp.h>
#include <osmocom/mgcp/osmux.h>
#include <osmocom/mgcp/mgcp_protocol.h>
#include <osmocom/mgcp/mgcp_common.h>
#include <osmocom/mgcp/mgcp_msg.h>
#include <osmocom/mgcp/mgcp_conn.h>
#include <osmocom/mgcp/mgcp_endp.h>

/*! Display an mgcp message on the log output.
 *  \param[in] message mgcp message string
 *  \param[in] len message mgcp message string length
 *  \param[in] preamble string to display in logtext in front of each line */
void mgcp_disp_msg(unsigned char *message, unsigned int len, char *preamble)
{
	unsigned char line[80];
	unsigned char *ptr;
	unsigned int consumed = 0;
	unsigned int consumed_line = 0;
	unsigned int line_count = 0;

	if (!log_check_level(DLMGCP, LOGL_DEBUG))
		return;

	while (1) {
		memset(line, 0, sizeof(line));
		ptr = line;
		consumed_line = 0;
		do {
			if (*message != '\n' && *message != '\r') {
				*ptr = *message;
				ptr++;
			}
			message++;
			consumed++;
			consumed_line++;
		} while (*message != '\n' && consumed < len
			 && consumed_line < sizeof(line));

		if (strlen((const char *)line)) {
			LOGP(DLMGCP, LOGL_DEBUG, "%s: line #%02u: %s\n",
			     preamble, line_count, line);
			line_count++;
		}

		if (consumed >= len)
			return;
	}
}

/*! Parse connection mode.
 *  \param[in] mode as string (recvonly, sendrecv, sendonly or loopback)
 *  \param[in] endp pointer to endpoint (only used for log output)
 *  \param[out] associated connection to be modified accordingly
 *  \returns 0 on success, -1 on error */
int mgcp_parse_conn_mode(const char *mode, struct mgcp_endpoint *endp,
			 struct mgcp_conn *conn)
{
	int ret = 0;

	if (!mode) {
		LOGPCONN(conn, DLMGCP, LOGL_ERROR,
			 "missing connection mode\n");
		return -1;
	}
	if (!conn)
		return -1;
	if (!endp)
		return -1;

	if (strcasecmp(mode, "recvonly") == 0)
		conn->mode = MGCP_CONN_RECV_ONLY;
	else if (strcasecmp(mode, "sendrecv") == 0)
		conn->mode = MGCP_CONN_RECV_SEND;
	else if (strcasecmp(mode, "sendonly") == 0)
		conn->mode = MGCP_CONN_SEND_ONLY;
	else if (strcasecmp(mode, "loopback") == 0)
		conn->mode = MGCP_CONN_LOOPBACK;
	else {
		LOGPCONN(conn, DLMGCP, LOGL_ERROR,
			 "unknown connection mode: '%s'\n", mode);
		ret = -1;
	}

	/* Special handling for RTP connections */
	if (conn->type == MGCP_CONN_TYPE_RTP) {
		conn->u.rtp.end.output_enabled =
		    conn->mode & MGCP_CONN_SEND_ONLY ? 1 : 0;
	}

	LOGPENDP(endp, DLMGCP, LOGL_DEBUG, "conn:%s\n", mgcp_conn_dump(conn));

	LOGPCONN(conn, DLMGCP, LOGL_DEBUG, "connection mode '%s' %d\n",
		 mode, conn->mode);

	/* Special handling für RTP connections */
	if (conn->type == MGCP_CONN_TYPE_RTP) {
		LOGPCONN(conn, DLMGCP, LOGL_DEBUG, "output_enabled %d\n",
			 conn->u.rtp.end.output_enabled);
	}

	/* The VTY might change the connection mode at any time, so we have
	 * to hold a copy of the original connection mode */
	conn->mode_orig = conn->mode;

	return ret;
}

/*! Analyze and parse the the hader of an MGCP messeage string.
 *  \param[out] pdata caller provided memory to store the parsing results
 *  \param[in] data mgcp message string
 *  \returns when the status line was complete and transaction_id and
 *  endp out parameters are set, -1 on error */
int mgcp_parse_header(struct mgcp_parse_data *pdata, char *data)
{
	int i = 0;
	char *elem, *save = NULL;
	int cause;

	/*! This function will parse the header part of the received
	 *  MGCP message. The parsing results are stored in pdata.
	 *  The function will also automatically search the pool with
	 *  available endpoints in order to find an endpoint that matches
	 *  the endpoint string in in the header */

	OSMO_ASSERT(data);
	pdata->trans = "000000";

	for (elem = strtok_r(data, " ", &save); elem;
	     elem = strtok_r(NULL, " ", &save)) {
		switch (i) {
		case 0:
			pdata->trans = elem;
			break;
		case 1:
			pdata->endp = mgcp_endp_by_name(&cause, elem, pdata->cfg);
			if (!pdata->endp) {
				LOGP(DLMGCP, LOGL_ERROR,
				     "Unable to find Endpoint `%s'\n", elem);
				OSMO_ASSERT(cause < 0);
				return cause;
			}
			break;
		case 2:
			if (strcasecmp("MGCP", elem)) {
				LOGP(DLMGCP, LOGL_ERROR,
				     "MGCP header parsing error\n");
				return -510;
			}
			break;
		case 3:
			if (strcmp("1.0", elem)) {
				LOGP(DLMGCP, LOGL_ERROR, "MGCP version `%s' "
				     "not supported\n", elem);
				return -528;
			}
			break;
		}
		i++;
	}

	if (i != 4) {
		LOGP(DLMGCP, LOGL_ERROR, "MGCP status line too short.\n");
		pdata->trans = "000000";
		pdata->endp = NULL;
		return -510;
	}

	return 0;
}

/*! Extract OSMUX CID from an MGCP parameter line (string).
 *  \param[in] line single parameter line from the MGCP message
 *  \returns OSMUX CID, -1 wildcard, -2 on error */
int mgcp_parse_osmux_cid(const char *line)
{
	int osmux_cid;


	if (strcasecmp(line + 2, "Osmux: *") == 0) {
		LOGP(DLMGCP, LOGL_DEBUG, "Parsed wilcard Osmux CID\n");
		return -1;
	}

	if (sscanf(line + 2 + 7, "%u", &osmux_cid) != 1) {
		LOGP(DLMGCP, LOGL_ERROR, "Failed parsing Osmux in MGCP msg line: %s\n",
		     line);
		return -2;
	}

	if (osmux_cid > OSMUX_CID_MAX) {
		LOGP(DLMGCP, LOGL_ERROR, "Osmux ID too large: %u > %u\n",
		     osmux_cid, OSMUX_CID_MAX);
		return -2;
	}
	LOGP(DLMGCP, LOGL_DEBUG, "bsc-nat offered Osmux CID %u\n", osmux_cid);

	return osmux_cid;
}

/*! Check MGCP parameter line (string) for plausibility.
 *  \param[in] endp pointer to endpoint (only used for log output)
 *  \param[in] line single parameter line from the MGCP message
 *  \returns 1 when line seems plausible, 0 on error */
int mgcp_check_param(const struct mgcp_endpoint *endp, const char *line)
{
	const size_t line_len = strlen(line);
	if (line[0] != '\0' && line_len < 2) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "Wrong MGCP option format: '%s' on %s\n",
		     line, endp->name);
		return 0;
	}

	/* FIXME: A couple more checks wouldn't hurt... */

	return 1;
}

/*! Check if the specified callid seems plausible.
  * \param[in] endp pointer to endpoint
  * \param{in] callid to verify
  * \returns 0 when callid seems plausible, -1 on error */
int mgcp_verify_call_id(struct mgcp_endpoint *endp, const char *callid)
{
	/*! This function compares the supplied callid with the called that is
	 *  stored in the endpoint structure. */

	if (!endp)
		return -1;

	/* Accept any CallID for "X-Osmo-IGN: C" */
	if (endp->x_osmo_ign & MGCP_X_OSMO_IGN_CALLID)
		return 0;

	if (!callid)
		return -1;
	if (!endp->callid)
		return -1;

	if (strcmp(endp->callid, callid) != 0) {
		LOGPENDP(endp, DLMGCP, LOGL_ERROR,
			 "CallIDs mismatch: '%s' != '%s'\n",
			 endp->callid, callid);
		return -1;
	}

	return 0;
}

/*! Check if the specified connection id seems plausible.
  * \param[in] endp pointer to endpoint
  * \param{in] connection id to verify
  * \returns 0 when connection id is valid and exists, an RFC3435 error code on error.
  */
int mgcp_verify_ci(struct mgcp_endpoint *endp, const char *conn_id)
{
	/* For invalid conn_ids, return 510 "The transaction could not be executed, because some
	 * unspecified protocol error was detected." */

	/* Check for null identifiers */
	if (!conn_id) {
		LOGPENDP(endp, DLMGCP, LOGL_ERROR,
			 "invalid ConnectionIdentifier (missing)\n");
		return 510;
	}

	/* Check for empty connection identifiers */
	if (strlen(conn_id) == 0) {
		LOGPENDP(endp, DLMGCP, LOGL_ERROR,
			 "invalid ConnectionIdentifier (empty)\n");
		return 510;
	}

	/* Check for over long connection identifiers */
	if (strlen(conn_id) > (MGCP_CONN_ID_MAXLEN-1)) {
		LOGPENDP(endp, DLMGCP, LOGL_ERROR,
			"invalid ConnectionIdentifier (too long: %zu > %d) 0x%s\n",
			 strlen(conn_id), MGCP_CONN_ID_MAXLEN-1, conn_id);
		return 510;
	}

	/* Check if connection exists */
	if (mgcp_conn_get(endp, conn_id))
		return 0;

	LOGPENDP(endp, DLMGCP, LOGL_ERROR,
	     "no connection found under ConnectionIdentifier 0x%s\n", conn_id);

	/* When the conn_id was not found, return error code 515 "The transaction refers to an incorrect
	 * connection-id (may have been already deleted)." */
	return 515;
}

/*! Extract individual lines from MCGP message.
  * \param[in] str MGCP message string, consisting of multiple lines
  * \param{in] saveptr pointer to next line in str
  * \returns line, NULL when done */
char *mgcp_strline(char *str, char **saveptr)
{
	char *result;

	/*! The function must be called with *str set to the input string
	 *  for the first line. After that saveptr will be initalized.
	 *  all consecutive lines are extracted by calling the function
	 *  with str set to NULL. When done, the function will return NULL
	 *  to indicate that all lines have been parsed. */

	if (str)
		*saveptr = str;

	result = *saveptr;

	if (*saveptr != NULL) {
		*saveptr = strpbrk(*saveptr, "\r\n");

		if (*saveptr != NULL) {
			char *eos = *saveptr;

			if ((*saveptr)[0] == '\r' && (*saveptr)[1] == '\n')
				(*saveptr)++;
			(*saveptr)++;
			if ((*saveptr)[0] == '\0')
				*saveptr = NULL;

			*eos = '\0';
		}
	}

	return result;
}

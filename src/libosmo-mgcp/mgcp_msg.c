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

#include <osmocom/mgcp/mgcp_internal.h>
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
		LOGP(DLMGCP, LOGL_ERROR,
		     "endpoint:0x%x missing connection mode\n",
		     ENDPOINT_NUMBER(endp));
		return -1;
	}
	if (!conn)
		return -1;
	if (!endp)
		return -1;

	if (strcmp(mode, "recvonly") == 0)
		conn->mode = MGCP_CONN_RECV_ONLY;
	else if (strcmp(mode, "sendrecv") == 0)
		conn->mode = MGCP_CONN_RECV_SEND;
	else if (strcmp(mode, "sendonly") == 0)
		conn->mode = MGCP_CONN_SEND_ONLY;
	else if (strcmp(mode, "loopback") == 0)
		conn->mode = MGCP_CONN_LOOPBACK;
	else {
		LOGP(DLMGCP, LOGL_ERROR,
		     "endpoint:0x%x unknown connection mode: '%s'\n",
		     ENDPOINT_NUMBER(endp), mode);
		ret = -1;
	}

	/* Special handling für RTP connections */
	if (conn->type == MGCP_CONN_TYPE_RTP) {
		conn->u.rtp.end.output_enabled =
		    conn->mode & MGCP_CONN_SEND_ONLY ? 1 : 0;
	}

	LOGP(DLMGCP, LOGL_DEBUG,
	     "endpoint:0x%x conn:%s\n",
	     ENDPOINT_NUMBER(endp), mgcp_conn_dump(conn));

	LOGP(DLMGCP, LOGL_DEBUG,
	     "endpoint:0x%x connection mode '%s' %d\n",
	     ENDPOINT_NUMBER(endp), mode, conn->mode);

	/* Special handling für RTP connections */
	if (conn->type == MGCP_CONN_TYPE_RTP) {
		LOGP(DLMGCP, LOGL_DEBUG, "endpoint:0x%x output_enabled %d\n",
		     ENDPOINT_NUMBER(endp), conn->u.rtp.end.output_enabled);
	}

	/* The VTY might change the connection mode at any time, so we have
	 * to hold a copy of the original connection mode */
	conn->mode_orig = conn->mode;

	return ret;
}

/* We have a null terminated string with the endpoint name here. We only
 * support two kinds. Simple ones as seen on the BSC level and the ones
 * seen on the trunk side. (helper function for find_endpoint()) */
static struct mgcp_endpoint *find_e1_endpoint(struct mgcp_config *cfg,
					      const char *mgcp)
{
	char *rest = NULL;
	struct mgcp_trunk_config *tcfg;
	int trunk, endp;
	struct mgcp_endpoint *endp_ptr;

	trunk = strtoul(mgcp + 6, &rest, 10);
	if (rest == NULL || rest[0] != '/' || trunk < 1) {
		LOGP(DLMGCP, LOGL_ERROR, "Wrong trunk name '%s'\n", mgcp);
		return NULL;
	}

	endp = strtoul(rest + 1, &rest, 10);
	if (rest == NULL || rest[0] != '@') {
		LOGP(DLMGCP, LOGL_ERROR, "Wrong endpoint name '%s'\n", mgcp);
		return NULL;
	}

	/* signalling is on timeslot 1 */
	if (endp == 1)
		return NULL;

	tcfg = mgcp_trunk_num(cfg, trunk);
	if (!tcfg) {
		LOGP(DLMGCP, LOGL_ERROR, "The trunk %d is not declared.\n",
		     trunk);
		return NULL;
	}

	if (!tcfg->endpoints) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "Endpoints of trunk %d not allocated.\n", trunk);
		return NULL;
	}

	if (endp < 1 || endp >= tcfg->number_endpoints) {
		LOGP(DLMGCP, LOGL_ERROR, "Failed to find endpoint '%s'\n",
		     mgcp);
		return NULL;
	}

	endp_ptr = &tcfg->endpoints[endp];
	endp_ptr->wildcarded_req = false;
	return endp_ptr;
}

/* Find an endpoint that is not in use. Do this by going through the endpoint
 * array, check the callid. A callid nullpointer indicates that the endpoint
 * is free */
static struct mgcp_endpoint *find_free_endpoint(struct mgcp_endpoint *endpoints,
						unsigned int number_endpoints)
{
	struct mgcp_endpoint *endp;
	unsigned int i;

	for (i = 0; i < number_endpoints; i++) {
		if (endpoints[i].callid == NULL) {
			endp = &endpoints[i];
			LOGP(DLMGCP, LOGL_DEBUG,
			     "endpoint:0x%x found free endpoint\n",
			     ENDPOINT_NUMBER(endp));
			endp->wildcarded_req = true;
			return endp;
		}
	}

	LOGP(DLMGCP, LOGL_ERROR, "Not able to find a free endpoint\n");
	return NULL;
}

/* Check if the domain name, which is supplied with the endpoint name
 * matches the configuration. */
static int check_domain_name(struct mgcp_config *cfg, const char *mgcp)
{
	char *domain_to_check;

	domain_to_check = strstr(mgcp, "@");
	if (!domain_to_check)
		return -EINVAL;

	if (strcmp(domain_to_check+1, cfg->domain) != 0)
		return -EINVAL;

	return 0;
}

/* Search the endpoint pool for the endpoint that had been selected via the
 * MGCP message (helper function for mgcp_analyze_header()) */
static struct mgcp_endpoint *find_endpoint(struct mgcp_config *cfg,
					   const char *mgcp,
					   int *cause)
{
	char *endptr = NULL;
	unsigned int gw = INT_MAX;
	const char *endpoint_number_str;
	struct mgcp_endpoint *endp;

	*cause = 0;

	/* Check if the domainname in the request is correct */
	if (check_domain_name(cfg, mgcp)) {
		LOGP(DLMGCP, LOGL_ERROR, "Wrong domain name '%s'\n", mgcp);
		*cause = -500;
		return NULL;
	}

	/* Check if the E1 trunk is requested */
	if (strncmp(mgcp, "ds/e1", 5) == 0) {
		endp = find_e1_endpoint(cfg, mgcp);
		if (!endp)
			*cause = -500;
		return endp;
	}

	/* Check if the virtual trunk is addressed (new, correct way with prefix) */
	if (strncmp
	    (mgcp, MGCP_ENDPOINT_PREFIX_VIRTUAL_TRUNK,
	     strlen(MGCP_ENDPOINT_PREFIX_VIRTUAL_TRUNK)) == 0) {
		endpoint_number_str =
		    mgcp + strlen(MGCP_ENDPOINT_PREFIX_VIRTUAL_TRUNK);
		if (endpoint_number_str[0] == '*') {
			endp = find_free_endpoint(cfg->trunk.endpoints,
						  cfg->trunk.number_endpoints);
			if (!endp)
				*cause = -403;
			return endp;
		}
		gw = strtoul(endpoint_number_str, &endptr, 16);
		if (gw < cfg->trunk.number_endpoints && endptr[0] == '@') {
			endp = &cfg->trunk.endpoints[gw];
			endp->wildcarded_req = false;
			return endp;
		}
	}

	/* Deprecated method without prefix */
	LOGP(DLMGCP, LOGL_NOTICE,
	     "Addressing virtual trunk without prefix (deprecated), please use %s: '%s'\n",
	     MGCP_ENDPOINT_PREFIX_VIRTUAL_TRUNK, mgcp);
	gw = strtoul(mgcp, &endptr, 16);
	if (gw < cfg->trunk.number_endpoints && endptr[0] == '@') {
		endp = &cfg->trunk.endpoints[gw];
		endp->wildcarded_req = false;
		return endp;
	}

	LOGP(DLMGCP, LOGL_ERROR, "Not able to find the endpoint: '%s'\n", mgcp);
	*cause = -500;
	return NULL;
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
			pdata->endp = find_endpoint(pdata->cfg, elem, &cause);
			if (!pdata->endp) {
				LOGP(DLMGCP, LOGL_ERROR,
				     "Unable to find Endpoint `%s'\n", elem);
				OSMO_ASSERT(cause < 0);
				return cause;
			}
			break;
		case 2:
			if (strcmp("MGCP", elem)) {
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
 *  \returns OSMUX CID, -1 on error */
int mgcp_parse_osmux_cid(const char *line)
{
	int osmux_cid;

	if (sscanf(line + 2, "Osmux: %u", &osmux_cid) != 1)
		return -1;

	if (osmux_cid > OSMUX_CID_MAX) {
		LOGP(DLMGCP, LOGL_ERROR, "Osmux ID too large: %u > %u\n",
		     osmux_cid, OSMUX_CID_MAX);
		return -1;
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
		     "Wrong MGCP option format: '%s' on 0x%x\n",
		     line, ENDPOINT_NUMBER(endp));
		return 0;
	}

	/* FIXME: A couple more checks wouldn't hurt... */

	return 1;
}

/*! Check if the specified callid seems plausible.
  * \param[in] endp pointer to endpoint
  * \param{in] callid to verify
  * \returns 1 when callid seems plausible, 0 on error */
int mgcp_verify_call_id(struct mgcp_endpoint *endp, const char *callid)
{
	/*! This function compares the supplied callid with the called that is
	 *  stored in the endpoint structure. */

	if (!endp)
		return -1;
	if (!callid)
		return -1;
	if (!endp->callid)
		return -1;

	if (strcmp(endp->callid, callid) != 0) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "endpoint:0x%x CallIDs does not match '%s' != '%s'\n",
		     ENDPOINT_NUMBER(endp), endp->callid, callid);
		return -1;
	}

	return 0;
}

/*! Check if the specified connection id seems plausible.
  * \param[in] endp pointer to endpoint
  * \param{in] connection id to verify
  * \returns 1 when connection id seems plausible, 0 on error */
int mgcp_verify_ci(struct mgcp_endpoint *endp, const char *conn_id)
{
	/* Check for null identifiers */
	if (!conn_id) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "endpoint:0x%x invalid ConnectionIdentifier (missing)\n",
		     ENDPOINT_NUMBER(endp));
		return -1;
	}

	/* Check for empty connection identifiers */
	if (strlen(conn_id) == 0) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "endpoint:0x%x invalid ConnectionIdentifier (empty)\n",
		     ENDPOINT_NUMBER(endp));
		return -1;
	}

	/* Check for over long connection identifiers */
	if (strlen(conn_id) > MGCP_CONN_ID_LENGTH) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "endpoint:0x%x invalid ConnectionIdentifier (too long) 0x%s\n",
		     ENDPOINT_NUMBER(endp), conn_id);
		return -1;
	}

	/* Check if connection exists */
	if (mgcp_conn_get(endp, conn_id))
		return 0;

	LOGP(DLMGCP, LOGL_ERROR,
	     "endpoint:0x%x no connection found under ConnectionIdentifier 0x%s\n",
	     ENDPOINT_NUMBER(endp), conn_id);

	return -1;
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

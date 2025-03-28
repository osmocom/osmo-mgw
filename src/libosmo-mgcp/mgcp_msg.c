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
#include <ctype.h>

#include <osmocom/mgcp/mgcp.h>
#include <osmocom/mgcp/osmux.h>
#include <osmocom/mgcp/mgcp_protocol.h>
#include <osmocom/mgcp/mgcp_common.h>
#include <osmocom/mgcp/mgcp_msg.h>
#include <osmocom/mgcp/mgcp_conn.h>
#include <osmocom/mgcp/mgcp_endp.h>
#include <osmocom/mgcp/mgcp_trunk.h>

/* (same fmt as LOGPENDP()) */
#define LOG_MGCP_PDATA(PDATA, LEVEL, FMT, ARGS...) \
	LOGP(DLMGCP, LEVEL, "%s: endpoint(%s) " FMT, (PDATA)->rq->name, (PDATA)->epname ? : "null-epname", ##ARGS)

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
 *  \param[in] mode as string (recvonly, sendrecv, sendonly confecho or loopback)
 *  \returns MGCP_CONN_* on success, MGCP_CONN_NONE on error */
enum mgcp_connection_mode mgcp_parse_conn_mode(const char *mode)
{

	if (!mode)
		return MGCP_CONN_NONE;

	if (strcasecmp(mode, "recvonly") == 0)
		return MGCP_CONN_RECV_ONLY;
	if (strcasecmp(mode, "sendrecv") == 0)
		return MGCP_CONN_RECV_SEND;
	if (strcasecmp(mode, "sendonly") == 0)
		return MGCP_CONN_SEND_ONLY;
	if (strcasecmp(mode, "confecho") == 0)
		return MGCP_CONN_CONFECHO;
	if (strcasecmp(mode, "loopback") == 0)
		return MGCP_CONN_LOOPBACK;
	return MGCP_CONN_NONE;
}

/*! Helper function for check_local_cx_options() to get a pointer of the next
 *  lco option identifier
 *  \param[in] lco string
 *  \returns pointer to the beginning of the LCO identifier, NULL on failure */
char *get_lco_identifier(const char *options)
{
	char *ptr;
	unsigned int count = 0;

	/* Jump to the end of the lco identifier */
	ptr = strstr(options, ":");
	if (!ptr)
		return NULL;

	/* Walk backwards until the pointer points to the beginning of the
	* lco identifier. We know that we stand at the beginning when we
	* are either at the beginning of the memory or see a space or
	* comma. (this is tolerant, it will accept a:10, b:11 as well as
	* a:10,b:11) */
	while (1) {
		/* Endless loop protection */
		if (count > 10000)
			return NULL;
		else if (ptr < options || *ptr == ' ' || *ptr == ',') {
			ptr++;
			break;
		}
		ptr--;
		count++;
	}

	/* Check if we got any result */
	if (*ptr == ':')
		return NULL;

	return ptr;
}

/*! Check the LCO option. This function checks for multiple appearance of LCO
*  options, which is illegal
*  \param[in] ctx talloc context
*  \param[in] lco string
*  \returns 0 on success, -1 on failure */
int check_local_cx_options(void *ctx, const char *options)
{
	int i;
	char *options_copy;
	char *lco_identifier;
	char *lco_identifier_end;
	char *next_lco_identifier;

	char **lco_seen;
	unsigned int lco_seen_n = 0;

	if (!options)
		return -1;

	lco_seen =
	(char **)talloc_zero_size(ctx, strlen(options) * sizeof(char *));
	options_copy = talloc_strdup(ctx, options);
	lco_identifier = options_copy;

	do {
		/* Move the lco_identifier pointer to the beginning of the
		* current lco option identifier */
		lco_identifier = get_lco_identifier(lco_identifier);
		if (!lco_identifier)
			goto error;

		/* Look ahead to the next LCO option early, since we
		* will parse destructively */
		next_lco_identifier = strstr(lco_identifier + 1, ",");

		/* Pinch off the end of the lco field identifier name
		* and see if we still got something, also check if
		* there is some value after the colon. */
		lco_identifier_end = strstr(lco_identifier, ":");
		if (!lco_identifier_end)
			goto error;
		if (*(lco_identifier_end + 1) == ' '
		|| *(lco_identifier_end + 1) == ','
		|| *(lco_identifier_end + 1) == '\0')
			goto error;
		*lco_identifier_end = '\0';
		if (strlen(lco_identifier) == 0)
			goto error;

		/* Check if we have already seen the current field identifier
		* before. If yes, we must bail, an LCO must only appear once
		* in the LCO string */
		for (i = 0; i < lco_seen_n; i++) {
			if (strcasecmp(lco_seen[i], lco_identifier) == 0)
				goto error;
		}
		lco_seen[lco_seen_n] = lco_identifier;
		lco_seen_n++;

		/* The first identifier must always be found at the beginnning
		* of the LCO string */
		if (lco_seen[0] != options_copy)
			goto error;

		/* Go to the next lco option */
		lco_identifier = next_lco_identifier;
	} while (lco_identifier);

	talloc_free(lco_seen);
	talloc_free(options_copy);
	return 0;
error:
	talloc_free(lco_seen);
	talloc_free(options_copy);
	return -1;
}

/* Set the LCO from a string (see RFC 3435).
* The string is stored in the 'string' field. A NULL string is handled exactly
* like an empty string, the 'string' field is never NULL after this function
* has been called. */
static int mgcp_parse_lco(void *ctx, struct mgcp_lco *lco, const char *options)
{
	const char *lco_id;
	char codec[17];
	char nt[17];
	int len;

	if (!options)
		return 0;
	if (strlen(options) == 0)
		return 0;

	lco->present = true;

	/* Make sure the encoding of the LCO is consistent before we proceed */
	if (check_local_cx_options(ctx, options) != 0) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "local CX options: Internal inconsistency in Local Connection Options!\n");
		return -524;
	}

	lco_id = options;
	while ((lco_id = get_lco_identifier(lco_id))) {
		switch (tolower(lco_id[0])) {
		case 'p':
			if (sscanf(lco_id + 1, ":%d-%d",
				&lco->pkt_period_min, &lco->pkt_period_max) == 1)
				lco->pkt_period_max = lco->pkt_period_min;
			break;
		case 'a':
			/* FIXME: LCO also supports the negotiation of more than one codec.
			* (e.g. a:PCMU;G726-32) But this implementation only supports a single
			* codec only. Ignoring all but the first codec. */
			if (sscanf(lco_id + 1, ":%16[^,;]", codec) == 1) {
				talloc_free(lco->codec);
				/* MGCP header is case insensive, and we'll need
				codec in uppercase when using it later: */
				len = strlen(codec);
				lco->codec = talloc_size(ctx, len + 1);
				osmo_str_toupper_buf(lco->codec, len + 1, codec);
			}
			break;
		case 'n':
			if (lco_id[1] == 't' && sscanf(lco_id + 2, ":%16[^,]", nt) == 1)
				break;
			/* else: fall through to print notice log */
		default:
			LOGP(DLMGCP, LOGL_NOTICE,
			     "LCO: unhandled option: '%c'/%d in \"%s\"\n",
			     *lco_id, *lco_id, options);
			break;
		}

		lco_id = strchr(lco_id, ',');
		if (!lco_id)
			break;
	}

	LOGP(DLMGCP, LOGL_DEBUG,
	     "local CX options: lco->pkt_period_max: %d, lco->codec: %s\n",
	     lco->pkt_period_max, lco->codec);

	/* Check if the packetization fits the 20ms raster */
	if (lco->pkt_period_min % 20 && lco->pkt_period_max % 20) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "local CX options: packetization interval is not a multiple of 20ms!\n");
		return -535;
	}

	return 0;
}

/*! Analyze and parse the the hader of an MGCP messeage string.
 *  \param[out] pdata caller provided memory to store the parsing results.
 *  \param[in] data mgcp message string.
 *  \returns 0 when the status line was complete and parseable, negative (MGCP
 *  cause code) on error. */
int mgcp_parse_header(struct mgcp_parse_data *pdata, char *data)
{
	int i = 0;
	char *elem, *save = NULL;

	/*! This function will parse the header part of the received
	 *  MGCP message. The parsing results are stored in pdata. */

	OSMO_ASSERT(data);

	for (elem = strtok_r(data, " ", &save); elem;
	     elem = strtok_r(NULL, " ", &save)) {
		switch (i) {
		case 0:
			pdata->trans = elem;
			break;
		case 1:
			pdata->epname = elem;
			break;
		case 2:
			if (strcasecmp("MGCP", elem)) {
				LOG_MGCP_PDATA(pdata, LOGL_ERROR, "MGCP header parsing error\n");
				return -510;
			}
			break;
		case 3:
			if (strcmp("1.0", elem))
				return -528;
			break;
		}
		i++;
	}

	if (i != 4) {
		LOG_MGCP_PDATA(pdata, LOGL_ERROR, "MGCP status line too short.\n");
		return -510;
	}

	return 0;
}

static bool parse_x_osmo_ign(struct mgcp_parse_data *pdata, char *line)
{
	char *saveptr = NULL;

	if (strncasecmp(line, MGCP_X_OSMO_IGN_HEADER, strlen(MGCP_X_OSMO_IGN_HEADER)))
		return false;
	line += strlen(MGCP_X_OSMO_IGN_HEADER);

	while (1) {
		char *token = strtok_r(line, " ", &saveptr);
		line = NULL;
		if (!token)
			break;

		if (!strcasecmp(token, "C"))
			pdata->hpars.x_osmo_ign |= MGCP_X_OSMO_IGN_CALLID;
		else
			LOG_MGCP_PDATA(pdata, LOGL_ERROR, "received unknown X-Osmo-IGN item '%s'\n", token);
	}

	return true;
}

/*! Analyze and parse the the header of an MGCP message string.
 *  \param[inout] pdata caller provided memory to store the parsing results.
 *  \returns 0 when parsing was successful, negative (MGCP cause code) on error. */
int mgcp_parse_hdr_pars(struct mgcp_parse_data *pdata)
{
	struct mgcp_parse_hdr_pars *hp = &pdata->hpars;
	char *line;
	int rc;

	mgcp_parse_hdr_pars_init(hp);

	for_each_line(line, pdata->save) {
		if (!mgcp_check_param(line)) {
			LOG_MGCP_PDATA(pdata, LOGL_NOTICE, "wrong MGCP option format: '%s'\n", line);
			continue;
		}

		switch (toupper(line[0])) {
		case 'L':
			hp->lco_string = (const char *)line + 3;
			rc = mgcp_parse_lco(pdata, &hp->lco, hp->lco_string);
			if (rc < 0) {
				LOG_MGCP_PDATA(pdata, LOGL_NOTICE, "Invalid LocalConnectionOptions line: '%s'", line);
				switch (pdata->rq->verb) {
				case MGCP_VERB_CRCX:
					rate_ctr_inc(rate_ctr_group_get_ctr(pdata->rq->trunk->ratectr.mgcp_crcx_ctr_group,
									    MGCP_CRCX_FAIL_INVALID_CONN_OPTIONS));
					break;
				case MGCP_VERB_MDCX:
					rate_ctr_inc(rate_ctr_group_get_ctr(pdata->rq->trunk->ratectr.mgcp_mdcx_ctr_group,
									    MGCP_MDCX_FAIL_INVALID_CONN_OPTIONS));
					break;
				default:
					break;
				}
				return rc;
			}
			break;
		case 'C':
			hp->callid = (const char *)line + 3;
			break;
		case 'I':
			hp->connid = (const char *)line + 3;
			break;
		case 'M':
			hp->mode = mgcp_parse_conn_mode((const char *)line + 3);
			break;
		case 'X':
			if (strncasecmp("Osmux: ", line + 2, strlen("Osmux: ")) == 0) {
				hp->remote_osmux_cid = mgcp_parse_osmux_cid(line);
				break;
			}
			if (parse_x_osmo_ign(pdata, line))
				break;
			/* Ignore unknown X-headers */
			break;
		case '\0':
			hp->have_sdp = true;
			goto mgcp_header_done;
		default:
			LOG_MGCP_PDATA(pdata, LOGL_NOTICE, "unhandled option: '%c'/%d\n", *line, *line);
			switch (pdata->rq->verb) {
			case MGCP_VERB_CRCX:
				rate_ctr_inc(rate_ctr_group_get_ctr(pdata->rq->trunk->ratectr.mgcp_crcx_ctr_group,
								    MGCP_CRCX_FAIL_UNHANDLED_PARAM));
				break;
			case MGCP_VERB_MDCX:
				rate_ctr_inc(rate_ctr_group_get_ctr(pdata->rq->trunk->ratectr.mgcp_mdcx_ctr_group,
								    MGCP_MDCX_FAIL_UNHANDLED_PARAM));
				break;
			case MGCP_VERB_DLCX:
				rate_ctr_inc(rate_ctr_group_get_ctr(pdata->rq->trunk->ratectr.mgcp_dlcx_ctr_group,
								    MGCP_DLCX_FAIL_UNHANDLED_PARAM));
				break;
			default:
				break;
			}
			return -539;
		}
	}

mgcp_header_done:
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
		return MGCP_PARSE_HDR_PARS_OSMUX_CID_WILDCARD;
	}

	if (sscanf(line + 2 + 7, "%u", &osmux_cid) != 1) {
		LOGP(DLMGCP, LOGL_ERROR, "Failed parsing Osmux in MGCP msg line: %s\n",
		     line);
		return MGCP_PARSE_HDR_PARS_OSMUX_CID_UNSET;
	}

	if (osmux_cid > OSMUX_CID_MAX) {
		LOGP(DLMGCP, LOGL_ERROR, "Osmux ID too large: %u > %u\n",
		     osmux_cid, OSMUX_CID_MAX);
		return MGCP_PARSE_HDR_PARS_OSMUX_CID_UNSET;
	}
	LOGP(DLMGCP, LOGL_DEBUG, "MGCP client offered Osmux CID %u\n", osmux_cid);

	return osmux_cid;
}

/*! Check MGCP parameter line (string) for plausibility.
 *  \param[in] line single parameter line from the MGCP message
 *  \returns true when line seems plausible, false on error */
bool mgcp_check_param(const char *line)
{
	const size_t line_len = strlen(line);
	if (line[0] != '\0' && line_len < 2)
		return false;

	/* FIXME: A couple more checks wouldn't hurt... */

	return true;
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
	if (mgcp_endp_get_conn(endp, conn_id))
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

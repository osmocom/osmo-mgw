/* mgcp_utils - common functions to setup an MGCP connection
 */
/* (C) 2016 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/select.h>
#include <osmocom/core/write_queue.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/byteswap.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/sockaddr_str.h>

#include <osmocom/mgcp_client/mgcp_client.h>
#include <osmocom/mgcp_client/mgcp_client_internal.h>

#include <osmocom/abis/e1_input.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <limits.h>

#ifndef OSMUX_CID_MAX
#define OSMUX_CID_MAX 255 /* FIXME: use OSMUX_CID_MAX from libosmo-netif? */
#endif

#define LOGPMGW(mgcp, level, fmt, args...) \
LOGP(DLMGCP, level, "MGW(%s) " fmt, mgcp_client_name(mgcp), ## args)

/* Codec descripton for dynamic payload types (SDP) */
const struct value_string osmo_mgcpc_codec_names[] = {
	{ CODEC_PCMU_8000_1, "PCMU/8000/1" },
	{ CODEC_GSM_8000_1, "GSM/8000/1" },
	{ CODEC_PCMA_8000_1, "PCMA/8000/1" },
	{ CODEC_G729_8000_1, "G729/8000/1" },
	{ CODEC_GSMEFR_8000_1, "GSM-EFR/8000/1" },
	{ CODEC_GSMHR_8000_1, "GSM-HR-08/8000/1" },
	{ CODEC_AMR_8000_1, "AMR/8000/1" },
	{ CODEC_AMRWB_16000_1, "AMR-WB/16000/1" },
	{ CODEC_IUFP, "VND.3GPP.IUFP/16000" },
	{ CODEC_CLEARMODE, "CLEARMODE/8000" },
	{ 0, NULL },
};

/* Get encoding name from a full codec string e,g.
 * ("CODEC/8000/2" => returns "CODEC") */
static char *extract_codec_name(const char *str)
{
	static char buf[64];
	unsigned int i;

	if (!str)
		return NULL;

	osmo_strlcpy(buf, str, sizeof(buf));

	for (i = 0; i < strlen(buf); i++) {
		if (buf[i] == '/')
			buf[i] = '\0';
	}

	return buf;
}

/*! Map a string to a codec.
 *  \ptmap[in] str input string (e.g "GSM/8000/1", "GSM/8000" or "GSM")
 *  \returns codec that corresponds to the given string representation. */
enum mgcp_codecs map_str_to_codec(const char *str)
{
	unsigned int i;
	char *codec_name;
	char str_buf[64];

	osmo_strlcpy(str_buf, extract_codec_name(str), sizeof(str_buf));

	for (i = 0; i < ARRAY_SIZE(osmo_mgcpc_codec_names); i++) {
		codec_name = extract_codec_name(osmo_mgcpc_codec_names[i].str);
		if (!codec_name)
			continue;
		if (strcmp(codec_name, str_buf) == 0)
			return osmo_mgcpc_codec_names[i].value;
	}

	return -1;
}

/* Check the ptmap for illegal mappings */
static int check_ptmap(const struct ptmap *ptmap)
{
	/* Check if there are mappings that leave the IANA assigned dynamic
	 * payload type range. Under normal conditions such mappings should
	 * not occur */

	/* Its ok to have a 1:1 mapping in the statically defined
	 * range, this won't hurt */
	if (ptmap->codec == ptmap->pt)
		return 0;

	if (ptmap->codec < 96 || ptmap->codec > 127)
		goto error;
	if (ptmap->pt < 96 || ptmap->pt > 127)
		goto error;

	return 0;
error:
	LOGP(DLMGCP, LOGL_ERROR,
	     "ptmap contains illegal mapping: codec=%u maps to pt=%u\n",
	     ptmap->codec, ptmap->pt);
	return -1;
}

/*! Map a codec to a payload type.
 *  \ptmap[in] payload pointer to payload type map with specified payload types.
 *  \ptmap[in] ptmap_len length of the payload type map.
 *  \ptmap[in] codec the codec for which the payload type should be looked up.
 *  \returns assigned payload type */
unsigned int map_codec_to_pt(const struct ptmap *ptmap, unsigned int ptmap_len,
			     enum mgcp_codecs codec)
{
	unsigned int i;

	/*! Note: If the payload type map is empty or the codec is not found
	 *  in the map, then a 1:1 mapping is performed. If the codec falls
	 *  into the statically defined range or if the mapping table isself
	 *  tries to map to the statically defined range, then the mapping
	 *  is also ignored and a 1:1 mapping is performed instead. */

	/* we may return the codec directly since enum mgcp_codecs directly
	 * corresponds to the statically assigned payload types */
	if (codec < 96 || codec > 127)
		return codec;

	for (i = 0; i < ptmap_len; i++) {
		/* Skip illegal map entries */
		if (check_ptmap(ptmap) == 0 && ptmap->codec == codec)
			return ptmap->pt;
		ptmap++;
	}

	/* If nothing is found, do not perform any mapping */
	return codec;
}

/*! Map a payload type to a codec.
 *  \ptmap[in] payload pointer to payload type map with specified payload types.
 *  \ptmap[in] ptmap_len length of the payload type map.
 *  \ptmap[in] payload type for which the codec should be looked up.
 *  \returns codec that corresponds to the specified payload type */
enum mgcp_codecs map_pt_to_codec(struct ptmap *ptmap, unsigned int ptmap_len,
				 unsigned int pt)
{
	unsigned int i;

	/*! Note: If the payload type map is empty or the payload type is not
	 *  found in the map, then a 1:1 mapping is performed. If the payload
	 *  type falls into the statically defined range or if the mapping
	 *  table isself tries to map to the statically defined range, then
	 *  the mapping is also ignored and a 1:1 mapping is performed
	 *  instead. */

	/* See also note in map_codec_to_pt() */
	if (pt < 96 || pt > 127)
		return pt;

	for (i = 0; i < ptmap_len; i++) {
		if (check_ptmap(ptmap) == 0 && ptmap->pt == pt)
			return ptmap->codec;
		ptmap++;
	}

	/* If nothing is found, do not perform any mapping */
	return pt;
}

static void _mgcp_client_conf_init(struct mgcp_client_conf *conf)
{
	/* NULL and -1 default to MGCP_CLIENT_*_DEFAULT values */
	*conf = (struct mgcp_client_conf){
		.local_addr = NULL,
		.local_port = -1,
		.remote_addr = NULL,
		.remote_port = -1,
		.keepalive = {
			.timeout_sec = 0, /* disabled */
			.req_interval_sec = 0, /* disabled */
			.req_endpoint_name = MGCP_CLIENT_KEEPALIVE_DEFAULT_ENDP,
		},
	};

	INIT_LLIST_HEAD(&conf->reset_epnames);
}

/*! Allocate and initialize MGCP client configuration struct with default values.
 *  \param[in] ctx talloc context to use as a parent during allocation.
 *
 * The returned struct can be freed using talloc_free().
 */
struct mgcp_client_conf *mgcp_client_conf_alloc(void *ctx)
{
	struct mgcp_client_conf *conf = talloc(ctx, struct mgcp_client_conf);
	_mgcp_client_conf_init(conf);
	return conf;
}

/*! Initialize MGCP client configuration struct with default values.
 *  \param[out] conf Client configuration.
 *
 * This function is deprecated and should not be used, as it may break if size
 * of struct mgcp_client_conf changes in the future!
 */
void mgcp_client_conf_init(struct mgcp_client_conf *conf)
{
	_mgcp_client_conf_init(conf);
}

static void mgcp_client_handle_response(struct mgcp_client *mgcp,
					struct mgcp_response_pending *pending,
					struct mgcp_response *response)
{
	if (!pending) {
		LOGPMGW(mgcp, LOGL_ERROR, "Cannot handle NULL response\n");
		return;
	}
	if (pending->response_cb)
		pending->response_cb(response, pending->priv);
	else
		LOGPMGW(mgcp, LOGL_DEBUG, "MGCP response ignored (NULL cb)\n");
	talloc_free(pending);
}

static int mgcp_response_parse_head(struct mgcp_response *r, struct msgb *msg)
{
	int comment_pos;
	char *end;

	if (mgcp_msg_terminate_nul(msg))
		goto response_parse_failure;

	r->body = (char *)msg->data;

	if (sscanf(r->body, "%3d %u %n",
		   &r->head.response_code, &r->head.trans_id,
		   &comment_pos) != 2)
		goto response_parse_failure;

	osmo_strlcpy(r->head.comment, r->body + comment_pos, sizeof(r->head.comment));
	end = strchr(r->head.comment, '\r');
	if (!end)
		goto response_parse_failure;
	/* Mark the end of the comment */
	*end = '\0';
	return 0;

response_parse_failure:
	LOGP(DLMGCP, LOGL_ERROR,
	     "Failed to parse MGCP response header\n");
	return -EINVAL;
}

/* TODO undup against mgcp_protocol.c:mgcp_check_param() */
static bool mgcp_line_is_valid(const char *line)
{
	const size_t line_len = strlen(line);
	if (line[0] == '\0')
		return true;

	if (line_len < 2
	    || line[1] != '=') {
		LOGP(DLMGCP, LOGL_ERROR,
		     "Wrong MGCP option format: '%s'\n",
		     line);
		return false;
	}

	return true;
}

/* Parse a line like "m=audio 16002 RTP/AVP 98", extract port and payload types */
static int mgcp_parse_audio_port_pt(struct mgcp_response *r, char *line)
{
	char *pt_str;
	char *pt_end;
	unsigned long int pt;
	unsigned int count = 0;
	unsigned int i;

	/* Extract port information */
	if (sscanf(line, "m=audio %hu", &r->audio_port) != 1)
		goto response_parse_failure_port;
	if (r->audio_port == 0)
		goto response_parse_failure_port;

	/* Extract payload types */
	line = strstr(line, "RTP/AVP ");
	if (!line)
		goto exit;

	pt_str = strtok(line, " ");
	while (1) {
		/* Do not allow excessive payload types */
		if (count > ARRAY_SIZE(r->codecs))
			goto response_parse_failure_pt;

		pt_str = strtok(NULL, " ");
		if (!pt_str)
			break;
		errno = 0;
		pt = strtoul(pt_str, &pt_end, 0);
		if ((errno == ERANGE && pt == ULONG_MAX) || (errno && !pt) ||
		    pt_str == pt_end)
			goto response_parse_failure_pt;

		if (pt >> 7) /* PT is 7 bit field, higher values not allowed */
			goto response_parse_failure_pt;

		/* Do not allow duplicate payload types */
		for (i = 0; i < count; i++)
			if (r->codecs[i] == pt)
				goto response_parse_failure_pt;

		/* Note: The payload type we store may not necessarly match
		 * the codec types we have defined in enum mgcp_codecs. To
		 * ensure that the end result only contains codec types which
		 * match enum mgcp_codecs, we will go through afterwards and
		 * remap the affected entries with the inrofmation we learn
		 * from rtpmap */
		r->codecs[count] = pt;
		count++;
	}

	r->codecs_len = count;

exit:
	return 0;

response_parse_failure_port:
	LOGP(DLMGCP, LOGL_ERROR,
	     "Failed to parse SDP parameter port (%s)\n", line);
	return -EINVAL;

response_parse_failure_pt:
	LOGP(DLMGCP, LOGL_ERROR,
	     "Failed to parse SDP parameter payload types (%s)\n", line);
	return -EINVAL;
}

/* Parse a line like "m=audio 16002 RTP/AVP 98", extract port and payload types */
static int mgcp_parse_audio_ptime_rtpmap(struct mgcp_response *r, const char *line)
{
	unsigned int pt;
	char codec_resp[64];
	enum mgcp_codecs codec;

#define A_PTIME "a=ptime:"
#define A_RTPMAP "a=rtpmap:"

	if (osmo_str_startswith(line, A_PTIME)) {
		if (sscanf(line, A_PTIME "%u", &r->ptime) != 1) {
			LOGP(DLMGCP, LOGL_ERROR,
			     "Failed to parse SDP parameter, invalid ptime (%s)\n", line);
			return -EINVAL;
		}
	} else if (osmo_str_startswith(line, A_RTPMAP)) {
		if (sscanf(line, A_RTPMAP "%d %63s", &pt, codec_resp) != 2) {
			LOGP(DLMGCP, LOGL_ERROR,
			     "Failed to parse SDP parameter, invalid rtpmap: %s\n", osmo_quote_str(line, -1));
			return -EINVAL;
		}
		if (r->ptmap_len >= ARRAY_SIZE(r->ptmap)) {
			LOGP(DLMGCP, LOGL_ERROR, "No more space in ptmap array (len=%u)\n", r->ptmap_len);
			return -ENOSPC;
		}
		codec = map_str_to_codec(codec_resp);
		r->ptmap[r->ptmap_len].pt = pt;
		r->ptmap[r->ptmap_len].codec = codec;
		r->ptmap_len++;
	}

	return 0;
}

/* Parse a line like "c=IN IP4 10.11.12.13" */
static int mgcp_parse_audio_ip(struct mgcp_response *r, const char *line)
{
	struct in6_addr ip_test;
	bool is_ipv6;

	if (strncmp("c=IN IP", line, 7) != 0)
		goto response_parse_failure;
	line += 7;
	if (*line == '6')
		is_ipv6 = true;
	else if (*line == '4')
		is_ipv6 = false;
	else
		goto response_parse_failure;
	line++;
	if (*line != ' ')
		goto response_parse_failure;
	line++;

	/* Extract and check IP-Address */
	if (is_ipv6) {
		/* 45 = INET6_ADDRSTRLEN -1 */
		if (sscanf(line, "%45s", r->audio_ip) != 1)
			goto response_parse_failure;
		if (inet_pton(AF_INET6, r->audio_ip, &ip_test) != 1)
			goto response_parse_failure;
	} else {
		/* 15 = INET_ADDRSTRLEN -1 */
		if (sscanf(line, "%15s", r->audio_ip) != 1)
			goto response_parse_failure;
		if (inet_pton(AF_INET, r->audio_ip, &ip_test) != 1)
			goto response_parse_failure;
	}
	return 0;

response_parse_failure:
	LOGP(DLMGCP, LOGL_ERROR,
	     "Failed to parse MGCP response header (audio ip)\n");
	return -EINVAL;
}

/*! Extract OSMUX CID from an MGCP parameter line (string).
 *  \param[in] line single parameter line from the MGCP message
 *  \returns OSMUX CID, -1 wildcard, -2 on error
 * FIXME: This is a copy of function in mgcp_msg.c. Have some common.c file between both libs?
 */
static int mgcp_parse_osmux_cid(const char *line)
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

	if (osmux_cid > OSMUX_CID_MAX) { /* OSMUX_CID_MAX from libosmo-netif */
		LOGP(DLMGCP, LOGL_ERROR, "Osmux ID too large: %u > %u\n",
		     osmux_cid, OSMUX_CID_MAX);
		return -2;
	}
	LOGP(DLMGCP, LOGL_DEBUG, "MGW offered Osmux CID %u\n", osmux_cid);

	return osmux_cid;
}

/* A new section is marked by a double line break, check a few more
 * patterns as there may be variants */
static char *mgcp_find_section_end(char *string)
{
	char *rc;

	rc = strstr(string, "\n\n");
	if (rc)
		return rc + 2;

	rc = strstr(string, "\n\r\n\r");
	if (rc)
		return rc + 4;

	rc = strstr(string, "\r\n\r\n");
	if (rc)
		return rc + 4;

	return NULL;
}

/*! Parse body (SDP) parameters of the MGCP response
 *  \param[in,out] r Response data
 *  \returns 0 on success, -EINVAL on error. */
int mgcp_response_parse_params(struct mgcp_response *r)
{
	char *line;
	int rc;
	char *data;
	char *data_ptr;
	int i;

	/* Since this functions performs a destructive parsing, we create a
	 * local copy of the body data */
	OSMO_ASSERT(r->body);
	data = talloc_strdup(r, r->body);
	OSMO_ASSERT(data);

	/* Find beginning of the parameter (SDP) section */
	data_ptr = mgcp_find_section_end(data);
	if (!data_ptr) {
		LOGP(DLMGCP, LOGL_DEBUG, "MGCP response contains no SDP parameters\n");
		rc = 0;
		goto exit;
	}

	/* data_ptr now points to the beginning of the section-end-marker; for_each_non_empty_line()
	 * skips any \r and \n characters for free, so we don't need to skip the marker. */

	for_each_non_empty_line(line, data_ptr) {
		if (!mgcp_line_is_valid(line))
			return -EINVAL;

		switch (line[0]) {
		case 'a':
			rc = mgcp_parse_audio_ptime_rtpmap(r, line);
			if (rc)
				goto exit;
			break;
		case 'm':
			rc = mgcp_parse_audio_port_pt(r, line);
			if (rc)
				goto exit;
			break;
		case 'c':
			rc = mgcp_parse_audio_ip(r, line);
			if (rc)
				goto exit;
			break;
		default:
			/* skip unhandled parameters */
			break;
		}
	}

	/* See also note in mgcp_parse_audio_port_pt() */
	for (i = 0; i < r->codecs_len; i++)
	        r->codecs[i] =  map_pt_to_codec(r->ptmap, r->ptmap_len, r->codecs[i]);

	rc = 0;
exit:
	talloc_free(data);
	return rc;
}

/* Parse a line like "X: something" */
static int mgcp_parse_head_param(char *result, unsigned int result_len,
				 char label, const char *line)
{
	char label_string[4];
	size_t rc;

	/* Detect empty parameters */
	if (strlen(line) < 4)
		goto response_parse_failure;

	/* Check if the label matches */
	snprintf(label_string, sizeof(label_string), "%c: ", label);
	if (memcmp(label_string, line, 3) != 0)
		goto response_parse_failure;

	/* Copy payload part of the string to destinations (the label string
	 * is always 3 chars long) */
	rc = osmo_strlcpy(result, line + 3, result_len);
	if (rc >= result_len) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "Failed to parse MGCP response (parameter label: %c):"
		     " the received conn ID is too long: %zu, maximum is %u characters\n",
		     label, rc, result_len - 1);
		return -ENOSPC;
	}
	return 0;

response_parse_failure:
	LOGP(DLMGCP, LOGL_ERROR,
	     "Failed to parse MGCP response (parameter label: %c)\n", label);
	return -EINVAL;
}

/* Parse MGCP parameters of the response */
static int parse_head_params(struct mgcp_response *r)
{
	char *line;
	int rc = 0;
	OSMO_ASSERT(r->body);
	char *data;
	char *data_ptr;
	char *data_end;

	/* Since this functions performs a destructive parsing, we create a
	 * local copy of the body data */
	data = talloc_zero_size(r, strlen(r->body)+1);
	OSMO_ASSERT(data);
	data_ptr = data;
	osmo_strlcpy(data, r->body, strlen(r->body));

	/* If there is an SDP body attached, prevent for_each_non_empty_line()
	 * into running in there, we are not yet interested in the parameters
	 * stored there. */
	data_end = mgcp_find_section_end(data);
	if (data_end)
		*data_end = '\0';

	for_each_non_empty_line(line, data_ptr) {
		switch (toupper(line[0])) {
		case 'Z':
			rc = mgcp_parse_head_param(r->head.endpoint,
						   sizeof(r->head.endpoint),
						   'Z', line);
			if (rc)
				goto exit;

			/* A specific endpoint identifier returned by the MGW
			 * must not contain any wildcard characters */
			if (strstr(r->head.endpoint, "*") != NULL) {
				rc = -EINVAL;
				goto exit;
			}

			/* A specific endpoint identifier returned by the MGW
			 * must contain an @ character */
			if (strstr(r->head.endpoint, "@") == NULL) {
				rc = -EINVAL;
				goto exit;
			}
			break;
		case 'I':
			rc = mgcp_parse_head_param(r->head.conn_id,
						   sizeof(r->head.conn_id),
						   'I', line);
			if (rc)
				goto exit;
			break;
		case 'X':
			if (strncasecmp("Osmux: ", line + 2, strlen("Osmux: ")) == 0) {
				rc = mgcp_parse_osmux_cid(line);
				if (rc < 0) {
					/* -1: we don't want wildcards in response. -2: error */
					rc = -EINVAL;
					goto exit;
				}
				r->head.x_osmo_osmux_use = true;
				r->head.x_osmo_osmux_cid = (uint8_t) rc;
				rc = 0;
				break;
			}
			/* Ignore unknown X-headers */
			break;
		default:
			/* skip unhandled parameters */
			break;
		}
	}
exit:
	talloc_free(data);
	return rc;
}

static struct mgcp_response_pending *mgcp_client_response_pending_get(
					 struct mgcp_client *mgcp,
					 mgcp_trans_id_t trans_id)
{
	struct mgcp_response_pending *pending;
	llist_for_each_entry(pending, &mgcp->responses_pending, entry) {
		if (pending->trans_id == trans_id) {
			llist_del(&pending->entry);
			return pending;
		}
	}
	return NULL;
}

/* Feed an MGCP message into the receive processing.
 * Parse the head and call any callback registered for the transaction id found
 * in the MGCP message. This is normally called directly from the internal
 * mgcp_do_read that reads from the socket connected to the MGCP gateway. This
 * function is published mainly to be able to feed data from the test suite.
 */
int mgcp_client_rx(struct mgcp_client *mgcp, struct msgb *msg)
{
	struct mgcp_response *r;
	struct mgcp_response_pending *pending;
	int rc;

	r = talloc_zero(mgcp, struct mgcp_response);
	OSMO_ASSERT(r);

	/* Re-arm keepalive timer if enabled */
	if (OSMO_UNLIKELY(mgcp->conn_up == false)) {
		LOGPMGW(mgcp, LOGL_NOTICE, "MGCP link to MGW now considered UP\n");
		mgcp->conn_up = true;
	}
	if (mgcp->actual.keepalive.timeout_sec > 0)
		osmo_timer_schedule(&mgcp->keepalive_rx_timer, mgcp->actual.keepalive.timeout_sec, 0);

	rc = mgcp_response_parse_head(r, msg);
	if (rc) {
		LOGPMGW(mgcp, LOGL_ERROR, "Cannot parse MGCP response (head)\n");
		rc = 1;
		goto error;
	}

	LOGPMGW(mgcp, LOGL_DEBUG, "MGCP client: Rx %d %u %s\n",
	     r->head.response_code, r->head.trans_id, r->head.comment);

	rc = parse_head_params(r);
	if (rc) {
		LOGPMGW(mgcp, LOGL_ERROR, "Cannot parse MGCP response (head parameters)\n");
		rc = 1;
		goto error;
	}

	pending = mgcp_client_response_pending_get(mgcp, r->head.trans_id);
	if (!pending) {
		LOGPMGW(mgcp, LOGL_ERROR, "Cannot find matching MGCP transaction for trans_id %d\n",
			r->head.trans_id);
		rc = -ENOENT;
		goto error;
	}

	mgcp_client_handle_response(mgcp, pending, r);
	rc = 0;

error:
	talloc_free(r);
	return rc;
}

static int mgcp_do_read(struct osmo_fd *fd)
{
	struct mgcp_client *mgcp = fd->data;
	struct msgb *msg;
	int ret;

	msg = msgb_alloc_headroom(4096, 128, "mgcp_from_gw");
	if (!msg) {
		LOGPMGW(mgcp, LOGL_ERROR, "Failed to allocate MGCP message.\n");
		return -1;
	}

	ret = read(fd->fd, msg->data, 4096 - 128);
	if (ret <= 0) {
		LOGPMGW(mgcp, LOGL_ERROR, "Failed to read: %s: %d='%s'\n",
		     osmo_sock_get_name2(fd->fd), errno, strerror(errno));

		msgb_free(msg);
		return -1;
	}

	msg->l2h = msgb_put(msg, ret);
	ret = mgcp_client_rx(mgcp, msg);
	talloc_free(msg);
	return ret;
}

static int mgcp_do_write(struct osmo_fd *fd, struct msgb *msg)
{
	int ret;
	struct mgcp_client *mgcp = fd->data;

	LOGPMGW(mgcp, LOGL_DEBUG, "Tx MGCP: %s: len=%u '%s'...\n",
		osmo_sock_get_name2(fd->fd), msg->len,
		osmo_escape_str((const char *)msg->data, OSMO_MIN(42, msg->len)));

	ret = write(fd->fd, msg->data, msg->len);
	if (OSMO_UNLIKELY(ret != msg->len))
		LOGPMGW(mgcp, LOGL_ERROR, "Failed to Tx MGCP: %s: %d='%s'; msg: len=%u '%s'...\n",
			osmo_sock_get_name2(fd->fd), errno, strerror(errno),
			msg->len, osmo_escape_str((const char *)msg->data, OSMO_MIN(42, msg->len)));

	/* Re-arm the keepalive Tx timer: */
	if (mgcp->actual.keepalive.req_interval_sec > 0)
		osmo_timer_schedule(&mgcp->keepalive_tx_timer, mgcp->actual.keepalive.req_interval_sec, 0);
	return ret;
}

static const char *_mgcp_client_name_append_domain(const struct mgcp_client *mgcp, const char *name)
{
	static char endpoint[MGCP_ENDPOINT_MAXLEN];
	int rc;

	rc = snprintf(endpoint, sizeof(endpoint), "%s@%s", name, mgcp_client_endpoint_domain(mgcp));
	if (rc > sizeof(endpoint) - 1) {
		LOGPMGW(mgcp, LOGL_ERROR, "MGCP endpoint exceeds maximum length of %zu: '%s@%s'\n",
			sizeof(endpoint) - 1, name, mgcp_client_endpoint_domain(mgcp));
		return NULL;
	}
	if (rc < 1) {
		LOGPMGW(mgcp, LOGL_ERROR, "Cannot compose MGCP endpoint name\n");
		return NULL;
	}
	return endpoint;
}

/* Safely ignore the MGCP response to the DLCX sent via _mgcp_client_send_dlcx() */
static void _ignore_mgcp_response(struct mgcp_response *response, void *priv) { }

/* Format DLCX message (fire and forget) and send it off to the MGW */
static void _mgcp_client_send_dlcx(struct mgcp_client *mgcp, const char *epname)
{
	struct msgb *msgb_dlcx;
	struct mgcp_msg mgcp_msg_dlcx = {
		.verb = MGCP_VERB_DLCX,
		.presence = MGCP_MSG_PRESENCE_ENDPOINT,
	};
	osmo_strlcpy(mgcp_msg_dlcx.endpoint, epname, sizeof(mgcp_msg_dlcx.endpoint));
	msgb_dlcx = mgcp_msg_gen(mgcp, &mgcp_msg_dlcx);
	mgcp_client_tx(mgcp, msgb_dlcx, &_ignore_mgcp_response, NULL);
}

/* Format AuditEndpoint message (fire and forget) and send it off to the MGW */
static void _mgcp_client_send_auep(struct mgcp_client *mgcp, const char *epname)
{
	struct msgb *msgb_auep;
	struct mgcp_msg mgcp_msg_auep = {
		.verb = MGCP_VERB_AUEP,
		.presence = MGCP_MSG_PRESENCE_ENDPOINT,
	};
	OSMO_STRLCPY_ARRAY(mgcp_msg_auep.endpoint, epname);
	msgb_auep = mgcp_msg_gen(mgcp, &mgcp_msg_auep);
	mgcp_client_tx(mgcp, msgb_auep, &_ignore_mgcp_response, NULL);
}

static void mgcp_client_keepalive_tx_timer_cb(void *data)
{
	struct mgcp_client *mgcp = (struct mgcp_client *)data;
	LOGPMGW(mgcp, LOGL_INFO, "Triggering keepalive MGCP request\n");
	const char *epname = _mgcp_client_name_append_domain(mgcp, mgcp->actual.keepalive.req_endpoint_name);
	_mgcp_client_send_auep(mgcp, epname);

	/* Re-arm the timer: */
	osmo_timer_schedule(&mgcp->keepalive_tx_timer, mgcp->actual.keepalive.req_interval_sec, 0);
}

static void mgcp_client_keepalive_rx_timer_cb(void *data)
{
	struct mgcp_client *mgcp = (struct mgcp_client *)data;
	LOGPMGW(mgcp, LOGL_ERROR, "MGCP link to MGW now considered DOWN (keepalive timeout, more than %u seconds with no answer from MGW)\n",
		mgcp->actual.keepalive.timeout_sec);
	mgcp->conn_up = false;
	/* TODO: Potentially time out all ongoing transactions for that MGW. Maybe based on VTY cfg? */
}

struct mgcp_client *mgcp_client_init(void *ctx,
				     struct mgcp_client_conf *conf)
{
	struct mgcp_client *mgcp;
	struct reset_ep *reset_ep;
	struct reset_ep *actual_reset_ep;

	mgcp = talloc_zero(ctx, struct mgcp_client);
	if (!mgcp)
		return NULL;

	INIT_LLIST_HEAD(&mgcp->responses_pending);

	mgcp->next_trans_id = 1;

	mgcp->actual.local_addr = conf->local_addr ? conf->local_addr :
		MGCP_CLIENT_LOCAL_ADDR_DEFAULT;
	mgcp->actual.local_port = conf->local_port > 0 ? (uint16_t)conf->local_port :
		MGCP_CLIENT_LOCAL_PORT_DEFAULT;

	mgcp->actual.remote_addr = conf->remote_addr ? conf->remote_addr :
		MGCP_CLIENT_REMOTE_ADDR_DEFAULT;
	mgcp->actual.remote_port = conf->remote_port >= 0 ? (uint16_t)conf->remote_port :
		MGCP_CLIENT_REMOTE_PORT_DEFAULT;

	if (osmo_strlcpy(mgcp->actual.endpoint_domain_name, conf->endpoint_domain_name,
			 sizeof(mgcp->actual.endpoint_domain_name))
	    >= sizeof(mgcp->actual.endpoint_domain_name)) {
		LOGPMGW(mgcp, LOGL_ERROR, "MGCP client: endpoint domain name is too long, max length is %zu: '%s'\n",
			sizeof(mgcp->actual.endpoint_domain_name) - 1, conf->endpoint_domain_name);
		talloc_free(mgcp);
		return NULL;
	}
	LOGPMGW(mgcp, LOGL_NOTICE, "MGCP client: using endpoint domain '@%s'\n", mgcp_client_endpoint_domain(mgcp));

	INIT_LLIST_HEAD(&mgcp->actual.reset_epnames);
	llist_for_each_entry(reset_ep, &conf->reset_epnames, list) {
		actual_reset_ep = talloc_memdup(mgcp, reset_ep, sizeof(*reset_ep));
		llist_add_tail(&actual_reset_ep->list, &mgcp->actual.reset_epnames);
	}

	if (conf->description)
		mgcp->actual.description = talloc_strdup(mgcp, conf->description);

	osmo_wqueue_init(&mgcp->wq, 1024);
	mgcp->wq.read_cb = mgcp_do_read;
	mgcp->wq.write_cb = mgcp_do_write;
	osmo_fd_setup(&mgcp->wq.bfd, -1, OSMO_FD_READ, osmo_wqueue_bfd_cb, mgcp, 0);

	memcpy(&mgcp->actual.keepalive, &conf->keepalive, sizeof(conf->keepalive));
	osmo_timer_setup(&mgcp->keepalive_tx_timer, mgcp_client_keepalive_tx_timer_cb, mgcp);
	osmo_timer_setup(&mgcp->keepalive_rx_timer, mgcp_client_keepalive_rx_timer_cb, mgcp);

	return mgcp;
}

/*! Initialize client connection (opens socket)
 *  \param[in,out] mgcp MGCP client descriptor.
 *  \returns 0 on success, -EINVAL on error. */
int mgcp_client_connect(struct mgcp_client *mgcp)
{
	int rc;
	struct reset_ep *reset_ep;
	const char *epname;
	bool some_dlcx_sent = false;

	if (!mgcp) {
		LOGPMGW(mgcp, LOGL_FATAL, "Client not initialized properly\n");
		return -EINVAL;
	}

	rc = osmo_sock_init2_ofd(&mgcp->wq.bfd, AF_UNSPEC, SOCK_DGRAM, IPPROTO_UDP, mgcp->actual.local_addr,
				 mgcp->actual.local_port, mgcp->actual.remote_addr, mgcp->actual.remote_port,
				 OSMO_SOCK_F_BIND | OSMO_SOCK_F_CONNECT);
	if (rc < 0) {
		LOGPMGW(mgcp, LOGL_FATAL,
		     "Failed to initialize socket %s:%u -> %s:%u for MGW: %s\n",
		     mgcp->actual.local_addr ? mgcp->actual.local_addr : "(any)", mgcp->actual.local_port,
		     mgcp->actual.remote_addr ? mgcp->actual.local_addr : "(any)", mgcp->actual.remote_port,
		     strerror(errno));
		goto error_close_fd;
	}

	LOGPMGW(mgcp, LOGL_INFO, "MGW connection: %s\n", osmo_sock_get_name2(mgcp->wq.bfd.fd));

	/* If configured, send a DLCX message to the endpoints that are configured to
	 * be reset on startup. Usually this is a wildcarded endpoint. */
	llist_for_each_entry(reset_ep, &mgcp->actual.reset_epnames, list) {
		epname = _mgcp_client_name_append_domain(mgcp, reset_ep->name);
		LOGPMGW(mgcp, LOGL_INFO, "Sending DLCX to: %s\n", epname);
		_mgcp_client_send_dlcx(mgcp, epname);
		some_dlcx_sent = true;
	}

	if (mgcp->actual.keepalive.req_interval_sec > 0) {
		if (!some_dlcx_sent) {
			/* Attempt an immediate probe to find out if link is UP or DOWN: */
			osmo_timer_schedule(&mgcp->keepalive_tx_timer, 0, 0);
		}
		/* else: keepalive_tx_timer was already scheduled (if needed) down in the stack during Tx DLCX above */
	} else {
		/* Assume link is UP by default, so that this MGW can be selected: */
		mgcp->conn_up = true;
	}

	if (mgcp->actual.keepalive.timeout_sec > 0)
		osmo_timer_schedule(&mgcp->keepalive_rx_timer, mgcp->actual.keepalive.timeout_sec, 0);

	return 0;
error_close_fd:
	close(mgcp->wq.bfd.fd);
	mgcp->wq.bfd.fd = -1;
	return rc;
}

/*! DEPRECATED: Initialize client connection (opens socket)
 *  \param[in,out] mgcp MGCP client descriptor.
 *  \returns 0 on success, -EINVAL on error. */
int mgcp_client_connect2(struct mgcp_client *mgcp, unsigned int retry_n_ports)
{
	return mgcp_client_connect(mgcp);
}

/*! Terminate client connection
 *  \param[in,out] mgcp MGCP client descriptor.
 *  \returns 0 on success, -EINVAL on error. */
void mgcp_client_disconnect(struct mgcp_client *mgcp)
{
	struct osmo_wqueue *wq;

	if (!mgcp) {
		LOGP(DLMGCP, LOGL_FATAL, "MGCP client not initialized properly\n");
		return;
	}

	/* Disarm keepalive Tx/Rx timer until next connect() */
	osmo_timer_del(&mgcp->keepalive_rx_timer);
	osmo_timer_del(&mgcp->keepalive_tx_timer);
	mgcp->conn_up = false;

	wq = &mgcp->wq;
	osmo_wqueue_clear(wq);
	LOGPMGW(mgcp, LOGL_INFO, "MGCP association: %s -- closed!\n", osmo_sock_get_name2(wq->bfd.fd));
	if (osmo_fd_is_registered(&wq->bfd))
		osmo_fd_unregister(&wq->bfd);
	close(wq->bfd.fd);
	wq->bfd.fd = -1;
}

/*! Get the IP-Aaddress of the associated MGW as string.
 *  \param[in] mgcp MGCP client descriptor.
 *  \returns a pointer to the address string. */
const char *mgcp_client_remote_addr_str(struct mgcp_client *mgcp)
{
	return mgcp->actual.remote_addr;
}

/*! Get the IP-Port of the associated MGW.
 *  \param[in] mgcp MGCP client descriptor.
 *  \returns port number. */
uint16_t mgcp_client_remote_port(struct mgcp_client *mgcp)
{
	return mgcp->actual.remote_port;
}

/*! Get the IP-Address of the associated MGW as its numeric representation.
 *  DEPRECATED, DON'T USE.
 *  \param[in] mgcp MGCP client descriptor.
 *  \returns IP-Address as 32 bit integer (network byte order) */
uint32_t mgcp_client_remote_addr_n(struct mgcp_client *mgcp)
{
	return 0;
}

/* To compose endpoint names, usually for CRCX, use this as domain name.
 * For example, snprintf("rtpbridge\*@%s", mgcp_client_endpoint_domain(mgcp)). */
const char *mgcp_client_endpoint_domain(const struct mgcp_client *mgcp)
{
	return mgcp->actual.endpoint_domain_name[0] ? mgcp->actual.endpoint_domain_name : "mgw";
}

/*! Compose endpoint name for a wildcarded request to the virtual trunk
 *  \param[in] mgcp MGCP client descriptor.
 *  \returns string containing the endpoint name (e.g. rtpbridge\*@mgw) */
const char *mgcp_client_rtpbridge_wildcard(const struct mgcp_client *mgcp)
{
	return _mgcp_client_name_append_domain(mgcp, "rtpbridge/*");
}

/*! Compose endpoint name for an E1 endpoint.
 *  \param[in] ctx talloc context.
 *  \param[in] mgcp MGCP client descriptor.
 *  \param[in] trunk_id id number of the E1 trunk (1-64).
 *  \param[in] ts timeslot on the E1 trunk (1-31).
 *  \param[in] rate bitrate used on the E1 trunk (e.g 16 for 16kbit).
 *  \param[in] offset bit offset of the E1 subslot (e.g. 4 for the third 16k subslot).
 *  \returns string containing the endpoint name (e.g. ds/e1-1/s-1/su16-4). */
const char *mgcp_client_e1_epname(void *ctx, const struct mgcp_client *mgcp, uint8_t trunk_id, uint8_t ts,
				  uint8_t rate, uint8_t offset)
{
	/* See also comment in libosmo-mgcp, mgcp_client.c, gen_e1_epname() */
	const uint8_t valid_rates[] = { 64, 32, 32, 16, 16, 16, 16, 8, 8, 8, 8, 8, 8, 8, 8 };
	const uint8_t valid_offsets[] = { 0, 0, 4, 0, 2, 4, 6, 0, 1, 2, 3, 4, 5, 6, 7 };

	uint8_t i;
	bool rate_offs_valid = false;
	char *epname;

	epname =
	    talloc_asprintf(ctx, "ds/e1-%u/s-%u/su%u-%u@%s", trunk_id, ts, rate, offset,
			    mgcp_client_endpoint_domain(mgcp));
	if (!epname) {
		LOGPMGW(mgcp, LOGL_ERROR, "Cannot compose MGCP e1-endpoint name!\n");
		return NULL;
	}

	/* Check if the supplied rate/offset pair resembles a valid combination */
	for (i = 0; i < sizeof(valid_rates); i++) {
		if (valid_rates[i] == rate && valid_offsets[i] == offset)
			rate_offs_valid = true;
	}
	if (!rate_offs_valid) {
		LOGPMGW(mgcp, LOGL_ERROR,
			"Cannot compose MGCP e1-endpoint name (%s), rate(%u)/offset(%u) combination is invalid!\n",
			epname, rate, offset);
		talloc_free(epname);
		return NULL;
	}

	/* An E1 line has a maximum of 32 timeslots, while the first (ts=0) is
	 * reserverd for framing and alignment, so we can not use it here. */
	if (ts == 0 || ts > NUM_E1_TS-1) {
		LOGPMGW(mgcp, LOGL_ERROR,
			"Cannot compose MGCP e1-endpoint name (%s), E1-timeslot number (%u) is invalid!\n",
			epname, ts);
		talloc_free(epname);
		return NULL;
	}

	return epname;
}

struct mgcp_response_pending *mgcp_client_pending_add(struct mgcp_client *mgcp, mgcp_trans_id_t trans_id,
						      mgcp_response_cb_t response_cb, void *priv)
{
	struct mgcp_response_pending *pending;

	pending = talloc_zero(mgcp, struct mgcp_response_pending);
	if (!pending)
		return NULL;

	pending->trans_id = trans_id;
	pending->response_cb = response_cb;
	pending->priv = priv;
	llist_add_tail(&pending->entry, &mgcp->responses_pending);

	return pending;
}

/* Send the MGCP message in msg to the MGW and handle a response with
 * response_cb. NOTE: the response_cb still needs to call
 * mgcp_response_parse_params(response) to get the parsed parameters -- to
 * potentially save some CPU cycles, only the head line has been parsed when
 * the response_cb is invoked.
 * Before the priv pointer becomes invalid, e.g. due to transaction timeout,
 * mgcp_client_cancel() needs to be called for this transaction.
 */
int mgcp_client_tx(struct mgcp_client *mgcp, struct msgb *msg,
		   mgcp_response_cb_t response_cb, void *priv)
{
	struct mgcp_response_pending *pending = NULL;
	mgcp_trans_id_t trans_id;
	int rc;

	trans_id = msg->cb[MSGB_CB_MGCP_TRANS_ID];
	if (!trans_id) {
		LOGPMGW(mgcp, LOGL_ERROR,
			"Unset transaction id in mgcp send request\n");
		talloc_free(msg);
		return -EINVAL;
	}

	/* Do not allocate a dummy 'mgcp_response_pending' entry */
	if (response_cb != NULL) {
		pending = mgcp_client_pending_add(mgcp, trans_id, response_cb, priv);
		if (!pending) {
			talloc_free(msg);
			return -ENOMEM;
		}
	}

	if (msgb_l2len(msg) > 4096) {
		LOGPMGW(mgcp, LOGL_ERROR,
			"Cannot send, MGCP message too large: %u\n",
			msgb_l2len(msg));
		msgb_free(msg);
		rc = -EINVAL;
		goto mgcp_tx_error;
	}

	rc = osmo_wqueue_enqueue(&mgcp->wq, msg);
	if (rc) {
		LOGPMGW(mgcp, LOGL_FATAL, "Could not queue message to MGW\n");
		msgb_free(msg);
		goto mgcp_tx_error;
	} else
		LOGPMGW(mgcp, LOGL_DEBUG, "Queued %u bytes for MGW\n",
			msgb_l2len(msg));
	return 0;

mgcp_tx_error:
	if (!pending)
		return rc;
	/* Dequeue pending response, it's going to be free()d */
	llist_del(&pending->entry);
	/* Pass NULL to response cb to indicate an error */
	mgcp_client_handle_response(mgcp, pending, NULL);
	return rc;
}

/*! Cancel a pending transaction.
 *  \param[in] mgcp MGCP client descriptor.
 *  \param[in,out] trans_id Transaction id.
 *  \returns 0 on success, -ENOENT on error.
 *
 * Should a priv pointer passed to mgcp_client_tx() become invalid, this function must be called. In
 * practical terms, if the caller of mgcp_client_tx() wishes to tear down a transaction without having
 * received a response this function must be called. The trans_id can be obtained by calling
 * mgcp_msg_trans_id() on the msgb produced by mgcp_msg_gen(). */
int mgcp_client_cancel(struct mgcp_client *mgcp, mgcp_trans_id_t trans_id)
{
	struct mgcp_response_pending *pending = mgcp_client_response_pending_get(mgcp, trans_id);
	if (!pending) {
		/*! Note: it is not harmful to cancel a transaction twice. */
		LOGPMGW(mgcp, LOGL_ERROR, "Cannot cancel, no such transaction: %u\n", trans_id);
		return -ENOENT;
	}
	LOGPMGW(mgcp, LOGL_DEBUG, "Canceled transaction %u\n", trans_id);
	talloc_free(pending);
	return 0;
	/*! We don't really need to clean up the wqueue: In all sane cases, the msgb has already been sent
	 *  out and is no longer in the wqueue. If it still is in the wqueue, then sending MGCP messages
	 *  per se is broken and the program should notice so by a full wqueue. Even if this was called
	 *  before we had a chance to send out the message and it is still going to be sent, we will just
	 *  ignore the reply to it later. Removing a msgb from the wqueue here would just introduce more
	 *  bug surface in terms of failing to update wqueue API's counters or some such.
	 */
}

static mgcp_trans_id_t mgcp_client_next_trans_id(struct mgcp_client *mgcp)
{
	/* avoid zero trans_id to distinguish from unset trans_id */
	if (!mgcp->next_trans_id)
		mgcp->next_trans_id ++;
	return mgcp->next_trans_id ++;
}

#define MGCP_CRCX_MANDATORY (MGCP_MSG_PRESENCE_ENDPOINT | \
			     MGCP_MSG_PRESENCE_CALL_ID | \
			     MGCP_MSG_PRESENCE_CONN_MODE)
#define MGCP_MDCX_MANDATORY (MGCP_MSG_PRESENCE_ENDPOINT | \
			     MGCP_MSG_PRESENCE_CALL_ID |  \
			     MGCP_MSG_PRESENCE_CONN_ID)
#define MGCP_DLCX_MANDATORY (MGCP_MSG_PRESENCE_ENDPOINT)
#define MGCP_AUEP_MANDATORY (MGCP_MSG_PRESENCE_ENDPOINT)
#define MGCP_RSIP_MANDATORY 0	/* none */

/* Helper function for mgcp_msg_gen(): Add LCO information to MGCP message */
static int add_lco(struct msgb *msg, struct mgcp_msg *mgcp_msg)
{
	unsigned int i;
	const char *codec;
	unsigned int pt;

#define MSGB_PRINTF_OR_RET(FMT, ARGS...) do { \
		if (msgb_printf(msg, FMT, ##ARGS) != 0) { \
			LOGP(DLMGCP, LOGL_ERROR, "Message buffer too small, can not generate MGCP/SDP message\n"); \
			return -ENOBUFS; \
		} \
	} while (0)

	MSGB_PRINTF_OR_RET("L:");

	if (mgcp_msg->ptime)
		MSGB_PRINTF_OR_RET(" p:%u,", mgcp_msg->ptime);

	if (mgcp_msg->codecs_len) {
		MSGB_PRINTF_OR_RET(" a:");
		for (i = 0; i < mgcp_msg->codecs_len; i++) {
			pt = mgcp_msg->codecs[i];
			codec = get_value_string_or_null(osmo_mgcpc_codec_names, pt);

			/* Note: Use codec descriptors from enum mgcp_codecs
			 * in mgcp_client only! */
			if (!codec)
				return -EINVAL;

			MSGB_PRINTF_OR_RET("%s", extract_codec_name(codec));
			if (i < mgcp_msg->codecs_len - 1)
				MSGB_PRINTF_OR_RET(";");
		}
		MSGB_PRINTF_OR_RET(",");
	}

	MSGB_PRINTF_OR_RET(" nt:IN\r\n");
	return 0;

#undef MSGB_PRINTF_OR_RET
}

/* Helper function for mgcp_msg_gen(): Add SDP information to MGCP message */
static int add_sdp(struct msgb *msg, struct mgcp_msg *mgcp_msg, struct mgcp_client *mgcp)
{
	unsigned int i;
	char local_ip[INET6_ADDRSTRLEN];
	int local_ip_family, audio_ip_family;
	const char *codec;
	unsigned int pt;

#define MSGB_PRINTF_OR_RET(FMT, ARGS...) do { \
		if (msgb_printf(msg, FMT, ##ARGS) != 0) { \
			LOGPMGW(mgcp, LOGL_ERROR, "Message buffer too small, can not generate MGCP message (SDP)\n"); \
			return -ENOBUFS; \
		} \
	} while (0)

	/* Add separator to mark the beginning of the SDP block */
	MSGB_PRINTF_OR_RET("\r\n");

	/* Add SDP protocol version */
	MSGB_PRINTF_OR_RET("v=0\r\n");

	/* Determine local IP-Address */
	if (osmo_sock_local_ip(local_ip, mgcp->actual.remote_addr) < 0) {
		LOGPMGW(mgcp, LOGL_ERROR,
			"Could not determine local IP-Address!\n");
		return -EINVAL;
	}
	local_ip_family = osmo_ip_str_type(local_ip);
	if (local_ip_family == AF_UNSPEC)
		return -EINVAL;
	audio_ip_family = osmo_ip_str_type(mgcp_msg->audio_ip);
	if (audio_ip_family == AF_UNSPEC)
		return -EINVAL;

	/* Add owner/creator (SDP) */
	MSGB_PRINTF_OR_RET("o=- %x 23 IN IP%c %s\r\n", mgcp_msg->call_id,
			  local_ip_family == AF_INET6 ? '6' : '4',
			  local_ip);

	/* Add session name (none) */
	MSGB_PRINTF_OR_RET("s=-\r\n");

	/* Add RTP address and port */
	if (mgcp_msg->audio_port == 0) {
		LOGPMGW(mgcp, LOGL_ERROR,
			"Invalid port number, can not generate MGCP message\n");
		msgb_free(msg);
		return -EINVAL;
	}
	if (strlen(mgcp_msg->audio_ip) <= 0) {
		LOGPMGW(mgcp, LOGL_ERROR,
			"Empty ip address, can not generate MGCP message\n");
		msgb_free(msg);
		return -EINVAL;
	}
	MSGB_PRINTF_OR_RET("c=IN IP%c %s\r\n",
			  audio_ip_family == AF_INET6 ? '6' : '4',
			  mgcp_msg->audio_ip);

	/* Add time description, active time (SDP) */
	MSGB_PRINTF_OR_RET("t=0 0\r\n");

	MSGB_PRINTF_OR_RET("m=audio %u RTP/AVP", mgcp_msg->audio_port);
	for (i = 0; i < mgcp_msg->codecs_len; i++) {
		pt = map_codec_to_pt(mgcp_msg->ptmap, mgcp_msg->ptmap_len, mgcp_msg->codecs[i]);
		MSGB_PRINTF_OR_RET(" %u", pt);

	}
	MSGB_PRINTF_OR_RET("\r\n");

	/* Add optional codec parameters (fmtp) */
	if (mgcp_msg->param_present) {
		for (i = 0; i < mgcp_msg->codecs_len; i++) {
			/* The following is only applicable for AMR */
			if (mgcp_msg->codecs[i] != CODEC_AMR_8000_1 && mgcp_msg->codecs[i] != CODEC_AMRWB_16000_1)
				   continue;
			pt = map_codec_to_pt(mgcp_msg->ptmap, mgcp_msg->ptmap_len, mgcp_msg->codecs[i]);
			if (mgcp_msg->param.amr_octet_aligned_present && mgcp_msg->param.amr_octet_aligned)
				MSGB_PRINTF_OR_RET("a=fmtp:%u octet-align=1\r\n", pt);
			else if (mgcp_msg->param.amr_octet_aligned_present && !mgcp_msg->param.amr_octet_aligned)
				MSGB_PRINTF_OR_RET("a=fmtp:%u octet-align=0\r\n", pt);
		}
	}

	for (i = 0; i < mgcp_msg->codecs_len; i++) {
		pt = map_codec_to_pt(mgcp_msg->ptmap, mgcp_msg->ptmap_len, mgcp_msg->codecs[i]);

		/* Note: Only dynamic payload type from the range 96-127
		 * require to be explained further via rtpmap. All others
		 * are implcitly definedby the number in m=audio */
		if (pt >= 96 && pt <= 127) {
			codec = get_value_string_or_null(osmo_mgcpc_codec_names, mgcp_msg->codecs[i]);

			/* Note: Use codec descriptors from enum mgcp_codecs
			 * in mgcp_client only! */
			if (!codec)
				return -EINVAL;

			MSGB_PRINTF_OR_RET("a=rtpmap:%u %s\r\n", pt, codec);
		}
	}

	if (mgcp_msg->ptime)
		MSGB_PRINTF_OR_RET("a=ptime:%u\r\n", mgcp_msg->ptime);

	return 0;
#undef MSGB_PRINTF_OR_RET
}

/*! Generate an MGCP message
 *  \param[in] mgcp MGCP client descriptor.
 *  \param[in] mgcp_msg Message description
 *  \returns message buffer on success, NULL on error. */
struct msgb *mgcp_msg_gen(struct mgcp_client *mgcp, struct mgcp_msg *mgcp_msg)
{
	mgcp_trans_id_t trans_id = mgcp_client_next_trans_id(mgcp);
	uint32_t mandatory_mask;
	struct msgb *msg = msgb_alloc_headroom(4096, 128, "MGCP tx");
	bool use_sdp = false;
	char buf[32];

#define MSGB_PRINTF_OR_RET(FMT, ARGS...) do { \
		if (msgb_printf(msg, FMT, ##ARGS) != 0) { \
			LOGPMGW(mgcp, LOGL_ERROR, "Message buffer too small, can not generate MGCP/SDP message\n"); \
			goto exit_error; \
		} \
	} while (0)

	msg->l2h = msg->data;
	msg->cb[MSGB_CB_MGCP_TRANS_ID] = trans_id;

	/* Add command verb */
	switch (mgcp_msg->verb) {
	case MGCP_VERB_CRCX:
		mandatory_mask = MGCP_CRCX_MANDATORY;
		MSGB_PRINTF_OR_RET("CRCX %u", trans_id);
		break;
	case MGCP_VERB_MDCX:
		mandatory_mask = MGCP_MDCX_MANDATORY;
		MSGB_PRINTF_OR_RET("MDCX %u", trans_id);
		break;
	case MGCP_VERB_DLCX:
		mandatory_mask = MGCP_DLCX_MANDATORY;
		MSGB_PRINTF_OR_RET("DLCX %u", trans_id);
		break;
	case MGCP_VERB_AUEP:
		mandatory_mask = MGCP_AUEP_MANDATORY;
		MSGB_PRINTF_OR_RET("AUEP %u", trans_id);
		break;
	case MGCP_VERB_RSIP:
		mandatory_mask = MGCP_RSIP_MANDATORY;
		MSGB_PRINTF_OR_RET("RSIP %u", trans_id);
		break;
	default:
		LOGPMGW(mgcp, LOGL_ERROR, "Invalid command verb, can not generate MGCP message\n");
		goto exit_error;
	}

	/* Check if mandatory fields are missing */
	if (!((mgcp_msg->presence & mandatory_mask) == mandatory_mask)) {
		LOGPMGW(mgcp, LOGL_ERROR,
			"One or more missing mandatory fields, can not generate MGCP message\n");
		goto exit_error;
	}

	/* Add endpoint name */
	if (mgcp_msg->presence & MGCP_MSG_PRESENCE_ENDPOINT) {
		if (strlen(mgcp_msg->endpoint) <= 0) {
			LOGPMGW(mgcp, LOGL_ERROR, "Empty endpoint name, can not generate MGCP message\n");
			goto exit_error;
		}

		if (strstr(mgcp_msg->endpoint, "@") == NULL) {
			LOGPMGW(mgcp, LOGL_ERROR,
				"Endpoint name (%s) lacks separator (@), can not generate MGCP message\n",
				mgcp_msg->endpoint);
			goto exit_error;
		}

		MSGB_PRINTF_OR_RET(" %s", mgcp_msg->endpoint);
	}

	/* Add protocol version */
	MSGB_PRINTF_OR_RET(" MGCP 1.0\r\n");

	/* Add call id */
	if (mgcp_msg->presence & MGCP_MSG_PRESENCE_CALL_ID)
		MSGB_PRINTF_OR_RET("C: %x\r\n", mgcp_msg->call_id);

	/* Add connection id */
	if (mgcp_msg->presence & MGCP_MSG_PRESENCE_CONN_ID) {
		if (strlen(mgcp_msg->conn_id) <= 0) {
			LOGPMGW(mgcp, LOGL_ERROR, "Empty connection id, can not generate MGCP message\n");
			goto exit_error;
		}
		MSGB_PRINTF_OR_RET("I: %s\r\n", mgcp_msg->conn_id);
	}

	/* Using SDP makes sense when a valid IP/Port combination is specified,
	 * if we do not know this information yet, we fall back to LCO */
	if (mgcp_msg->presence & MGCP_MSG_PRESENCE_AUDIO_IP
	    && mgcp_msg->presence & MGCP_MSG_PRESENCE_AUDIO_PORT)
		use_sdp = true;

	/* Add local connection options (LCO) */
	if (!use_sdp
	    && (mgcp_msg->verb == MGCP_VERB_CRCX
		|| mgcp_msg->verb == MGCP_VERB_MDCX)) {
		if (add_lco(msg, mgcp_msg) < 0) {
			LOGPMGW(mgcp, LOGL_ERROR, "Failed to add LCO, can not generate MGCP message\n");
			goto exit_error;
		}
	}

	/* Add mode */
	if (mgcp_msg->presence & MGCP_MSG_PRESENCE_CONN_MODE)
		MSGB_PRINTF_OR_RET("M: %s\r\n", mgcp_client_cmode_name(mgcp_msg->conn_mode));

	/* Add X-Osmo-IGN */
	if ((mgcp_msg->presence & MGCP_MSG_PRESENCE_X_OSMO_IGN)
	    && (mgcp_msg->x_osmo_ign != 0))
		MSGB_PRINTF_OR_RET(MGCP_X_OSMO_IGN_HEADER "%s\r\n",
				   mgcp_msg->x_osmo_ign & MGCP_X_OSMO_IGN_CALLID ? " C" : "");

	/* Add X-Osmo-Osmux */
	if ((mgcp_msg->presence & MGCP_MSG_PRESENCE_X_OSMO_OSMUX_CID)) {
		if (mgcp_msg->x_osmo_osmux_cid < -1 || mgcp_msg->x_osmo_osmux_cid > OSMUX_CID_MAX) {
			LOGPMGW(mgcp, LOGL_ERROR, "Wrong Osmux CID %d, can not generate MGCP message\n",
				mgcp_msg->x_osmo_osmux_cid);
			goto exit_error;
		}
		snprintf(buf, sizeof(buf), " %d", mgcp_msg->x_osmo_osmux_cid);
		MSGB_PRINTF_OR_RET(MGCP_X_OSMO_OSMUX_HEADER "%s\r\n",
				   mgcp_msg->x_osmo_osmux_cid == -1 ? " *" : buf);
	}


	/* Add session description protocol (SDP) */
	if (use_sdp
	    && (mgcp_msg->verb == MGCP_VERB_CRCX
		|| mgcp_msg->verb == MGCP_VERB_MDCX)) {
		if (add_sdp(msg, mgcp_msg, mgcp) < 0) {
			LOGPMGW(mgcp, LOGL_ERROR, "Failed to add SDP, can not generate MGCP message\n");
			goto exit_error;
		}
	}

	return msg;

exit_error:
	msgb_free(msg);
	return NULL;
#undef MSGB_PRINTF_OR_RET
}

/*! Retrieve the MGCP transaction ID from a msgb generated by mgcp_msg_gen()
 *  \param[in] msg message buffer
 *  \returns Transaction id. */
mgcp_trans_id_t mgcp_msg_trans_id(struct msgb *msg)
{
	return (mgcp_trans_id_t)msg->cb[MSGB_CB_MGCP_TRANS_ID];
}

/*! Get the configuration parameters for a given MGCP client instance
 *  \param[in] mgcp MGCP client descriptor.
 *  \returns configuration */
struct mgcp_client_conf *mgcp_client_conf_actual(struct mgcp_client *mgcp)
{
	return &mgcp->actual;
}

const struct value_string mgcp_client_connection_mode_strs[] = {
	{ MGCP_CONN_NONE, "none" },
	{ MGCP_CONN_RECV_SEND, "sendrecv" },
	{ MGCP_CONN_SEND_ONLY, "sendonly" },
	{ MGCP_CONN_RECV_ONLY, "recvonly" },
	{ MGCP_CONN_LOOPBACK, "loopback" },
	{ 0, NULL }
};

/*! Get MGCP client instance name (VTY).
 *  \param[in] mgcp MGCP client descriptor.
 *  \returns MGCP client name.
 *
 *  The user can only modify the name of an MGCP client instance when it is
 *  part of a pool. For single MGCP client instances and MGCP client instance
 *  where no description is set via the VTY, the MGW domain name will be used
 *  as name. */
const char *mgcp_client_name(const struct mgcp_client *mgcp)
{
	if (!mgcp)
		return "(null)";

	if (mgcp->actual.description)
		return mgcp->actual.description;
	else
		return mgcp_client_endpoint_domain(mgcp);
}

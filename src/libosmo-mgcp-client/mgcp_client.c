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

#include <osmocom/mgcp_client/mgcp_client.h>
#include <osmocom/mgcp_client/mgcp_client_internal.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <unistd.h>
#include <string.h>

#ifndef OSMUX_CID_MAX
#define OSMUX_CID_MAX 255 /* FIXME: use OSMUX_CID_MAX from libosmo-netif? */
#endif

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

	/* FIXME osmo_strlcpy */
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
	 * corresponds to the statićally assigned payload types */
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

/*! Initalize MGCP client configuration struct with default values.
 *  \param[out] conf Client configuration.*/
void mgcp_client_conf_init(struct mgcp_client_conf *conf)
{
	/* NULL and -1 default to MGCP_CLIENT_*_DEFAULT values */
	*conf = (struct mgcp_client_conf){
		.local_addr = NULL,
		.local_port = -1,
		.remote_addr = NULL,
		.remote_port = -1,
	};
}

static void mgcp_client_handle_response(struct mgcp_client *mgcp,
					struct mgcp_response_pending *pending,
					struct mgcp_response *response)
{
	if (!pending) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "Cannot handle NULL response\n");
		return;
	}
	if (pending->response_cb)
		pending->response_cb(response, pending->priv);
	else
		LOGP(DLMGCP, LOGL_DEBUG, "MGCP response ignored (NULL cb)\n");
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
	unsigned int pt;
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
		pt = atoi(pt_str);

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
	unsigned int codec;


	if (strstr(line, "ptime")) {
		if (sscanf(line, "a=ptime:%u", &r->ptime) != 1)
			goto response_parse_failure_ptime;
	} else if (strstr(line, "rtpmap")) {
		if (sscanf(line, "a=rtpmap:%d %63s", &pt, codec_resp) == 2) {
			/* The MGW may assign an own payload type in the
			 * response if the choosen codec falls into the IANA
			 * assigned dynamic payload type range (96-127).
			 * Normally the MGW should obey the 3gpp payload type
			 * assignments, which are fixed, so we likely wont see
			 * anything unexpected here. In order to be sure that
			 * we will now check the codec string and if the result
			 * does not match to what is IANA / 3gpp assigned, we
			 * will create an entry in the ptmap table so we can
			 * lookup later what has been assigned. */
			codec = map_str_to_codec(codec_resp);
			if (codec != pt) {
				if (r->ptmap_len < ARRAY_SIZE(r->ptmap)) {
					r->ptmap[r->ptmap_len].pt = pt;
					r->ptmap[r->ptmap_len].codec = codec;
					r->ptmap_len++;
				} else
					goto response_parse_failure_rtpmap;
			}

		} else
			goto response_parse_failure_rtpmap;
	}

	return 0;

response_parse_failure_ptime:
	LOGP(DLMGCP, LOGL_ERROR,
	     "Failed to parse SDP parameter, invalid ptime (%s)\n", line);
	return -EINVAL;
response_parse_failure_rtpmap:
	LOGP(DLMGCP, LOGL_ERROR,
	     "Failed to parse SDP parameter, invalid rtpmap (%s)\n", line);
	return -EINVAL;
}

/* Parse a line like "c=IN IP4 10.11.12.13" */
static int mgcp_parse_audio_ip(struct mgcp_response *r, const char *line)
{
	struct in_addr ip_test;

	if (strlen(line) < 16)
		goto response_parse_failure;

	/* The current implementation strictly supports IPV4 only ! */
	if (memcmp("c=IN IP4 ", line, 9) != 0)
		goto response_parse_failure;

	/* Extract IP-Address */
	osmo_strlcpy(r->audio_ip, line + 9, sizeof(r->audio_ip));

	/* Check IP-Address */
	if (inet_aton(r->audio_ip, &ip_test) == 0)
		goto response_parse_failure;

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
	LOGP(DLMGCP, LOGL_DEBUG, "bsc-nat offered Osmux CID %u\n", osmux_cid);

	return osmux_cid;
}

/* A new section is marked by a double line break, check a few more
 * patterns as there may be variants */
static char *mgcp_find_section_end(char *string)
{
	char *rc;

	rc = strstr(string, "\n\n");
	if (rc)
		return rc;

	rc = strstr(string, "\n\r\n\r");
	if (rc)
		return rc;

	rc = strstr(string, "\r\n\r\n");
	if (rc)
		return rc;

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
		LOGP(DLMGCP, LOGL_ERROR,
		     "MGCP response: cannot find start of SDP parameters\n");
		rc = -EINVAL;
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
		switch (line[0]) {
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
		case 'x':
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

	rc = mgcp_response_parse_head(r, msg);
	if (rc) {
		LOGP(DLMGCP, LOGL_ERROR, "Cannot parse MGCP response (head)\n");
		rc = 1;
		goto error;
	}

	rc = parse_head_params(r);
	if (rc) {
		LOGP(DLMGCP, LOGL_ERROR, "Cannot parse MGCP response (head parameters)\n");
		rc = 1;
		goto error;
	}

	pending = mgcp_client_response_pending_get(mgcp, r->head.trans_id);
	if (!pending) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "Cannot find matching MGCP transaction for trans_id %d\n",
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
		LOGP(DLMGCP, LOGL_ERROR, "Failed to allocate MGCP message.\n");
		return -1;
	}

	ret = read(fd->fd, msg->data, 4096 - 128);
	if (ret <= 0) {
		LOGP(DLMGCP, LOGL_ERROR, "Failed to read: %s: %d='%s'\n", osmo_sock_get_name2(fd->fd),
		     errno, strerror(errno));

		msgb_free(msg);
		return -1;
	} else if (ret > 4096 - 128) {
		LOGP(DLMGCP, LOGL_ERROR, "Too much data: %s: %d\n", osmo_sock_get_name2(fd->fd), ret);
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

	LOGP(DLMGCP, LOGL_DEBUG, "Tx MGCP: %s: len=%u '%s'...\n",
	     osmo_sock_get_name2(fd->fd), msg->len, osmo_escape_str((const char*)msg->data, OSMO_MIN(42, msg->len)));

	ret = write(fd->fd, msg->data, msg->len);
	if (ret != msg->len)
		LOGP(DLMGCP, LOGL_ERROR, "Failed to Tx MGCP: %s: %d='%s'; msg: len=%u '%s'...\n",
		     osmo_sock_get_name2(fd->fd), errno, strerror(errno),
		     msg->len, osmo_escape_str((const char*)msg->data, OSMO_MIN(42, msg->len)));
	return ret;
}

struct mgcp_client *mgcp_client_init(void *ctx,
				     struct mgcp_client_conf *conf)
{
	struct mgcp_client *mgcp;

	mgcp = talloc_zero(ctx, struct mgcp_client);

	INIT_LLIST_HEAD(&mgcp->responses_pending);
	INIT_LLIST_HEAD(&mgcp->inuse_endpoints);

	mgcp->next_trans_id = 1;

	mgcp->actual.local_addr = conf->local_addr ? conf->local_addr :
		MGCP_CLIENT_LOCAL_ADDR_DEFAULT;
	mgcp->actual.local_port = conf->local_port >= 0 ? (uint16_t)conf->local_port :
		MGCP_CLIENT_LOCAL_PORT_DEFAULT;

	mgcp->actual.remote_addr = conf->remote_addr ? conf->remote_addr :
		MGCP_CLIENT_REMOTE_ADDR_DEFAULT;
	mgcp->actual.remote_port = conf->remote_port >= 0 ? (uint16_t)conf->remote_port :
		MGCP_CLIENT_REMOTE_PORT_DEFAULT;

	if (osmo_strlcpy(mgcp->actual.endpoint_domain_name, conf->endpoint_domain_name,
			 sizeof(mgcp->actual.endpoint_domain_name))
	    >= sizeof(mgcp->actual.endpoint_domain_name)) {
		LOGP(DLMGCP, LOGL_ERROR, "MGCP client: endpoint domain name is too long, max length is %zu: '%s'\n",
		     sizeof(mgcp->actual.endpoint_domain_name) - 1, conf->endpoint_domain_name);
		talloc_free(mgcp);
		return NULL;
	}
	LOGP(DLMGCP, LOGL_NOTICE, "MGCP client: using endpoint domain '@%s'\n", mgcp_client_endpoint_domain(mgcp));

	return mgcp;
}

static int init_socket(struct mgcp_client *mgcp)
{
	int rc;
	struct osmo_wqueue *wq;
	int i;

	wq = &mgcp->wq;

	for (i = 0; i < 100; i++) {

		/* Initalize socket with the currently configured port
		 * number */
		rc = osmo_sock_init2_ofd(&wq->bfd, AF_INET, SOCK_DGRAM, IPPROTO_UDP, mgcp->actual.local_addr,
					 mgcp->actual.local_port, mgcp->actual.remote_addr, mgcp->actual.remote_port,
					 OSMO_SOCK_F_BIND | OSMO_SOCK_F_CONNECT);
		if (rc > 0)
			return rc;

		/* If there is a different port than the default port
		 * configured then we assume that the user has choosen
		 * that port conciously and we will not try to resolve
		 * this by silently choosing a different port. */
		if (mgcp->actual.local_port != MGCP_CLIENT_LOCAL_PORT_DEFAULT && i == 0)
			return -EINVAL;

		/* Choose a new port number to try next */
		LOGP(DLMGCP, LOGL_NOTICE,
		     "MGCPGW failed to bind to %s:%u, retrying with port %u\n",
		     mgcp->actual.local_addr, mgcp->actual.local_port, mgcp->actual.local_port + 1);
		mgcp->actual.local_port++;
	}

	LOGP(DLMGCP, LOGL_FATAL, "MGCPGW failed to find a port to bind on %i times.\n", i);
	return -EINVAL;
}

/*! Initalize client connection (opens socket only, no request is sent yet)
 *  \param[in,out] mgcp MGCP client descriptor.
 *  \returns 0 on success, -EINVAL on error. */
int mgcp_client_connect(struct mgcp_client *mgcp)
{
	struct sockaddr_in addr;
	struct osmo_wqueue *wq;
	int rc;

	if (!mgcp) {
		LOGP(DLMGCP, LOGL_FATAL, "MGCPGW client not initialized properly\n");
		return -EINVAL;
	}

	wq = &mgcp->wq;

	rc = init_socket(mgcp);
	if (rc < 0) {
		LOGP(DLMGCP, LOGL_FATAL,
		     "Failed to initialize socket %s:%u -> %s:%u for MGCP GW: %s\n",
		     mgcp->actual.local_addr, mgcp->actual.local_port,
		     mgcp->actual.remote_addr, mgcp->actual.remote_port, strerror(errno));
		goto error_close_fd;
	}

	inet_aton(mgcp->actual.remote_addr, &addr.sin_addr);
	mgcp->remote_addr = htonl(addr.sin_addr.s_addr);

	osmo_wqueue_init(wq, 10);
	wq->bfd.when = BSC_FD_READ;
	wq->bfd.data = mgcp;
	wq->read_cb = mgcp_do_read;
	wq->write_cb = mgcp_do_write;

	LOGP(DLMGCP, LOGL_INFO, "MGCP GW connection: %s\n", osmo_sock_get_name2(wq->bfd.fd));

	return 0;
error_close_fd:
	close(wq->bfd.fd);
	wq->bfd.fd = -1;
	return rc;
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

/*! Get the IP-Aaddress of the associated MGW as its numeric representation.
 *  \param[in] mgcp MGCP client descriptor.
 *  \returns IP-Address as 32 bit integer (network byte order) */
uint32_t mgcp_client_remote_addr_n(struct mgcp_client *mgcp)
{
	return mgcp->remote_addr;
}

/* To compose endpoint names, usually for CRCX, use this as domain name.
 * For example, snprintf("rtpbridge\*@%s", mgcp_client_endpoint_domain(mgcp)). */
const char *mgcp_client_endpoint_domain(const struct mgcp_client *mgcp)
{
	return mgcp->actual.endpoint_domain_name[0] ? mgcp->actual.endpoint_domain_name : "mgw";
}

static const char *_mgcp_client_name_append_domain(const struct mgcp_client *mgcp, char *name)
{
	static char endpoint[MGCP_ENDPOINT_MAXLEN];
	int rc;

	rc = snprintf(endpoint, sizeof(endpoint), "%s@%s", name, mgcp_client_endpoint_domain(mgcp));
	if (rc > sizeof(endpoint) - 1) {
		LOGP(DLMGCP, LOGL_ERROR, "MGCP endpoint exceeds maximum length of %zu: '%s@%s'\n",
		     sizeof(endpoint) - 1, name, mgcp_client_endpoint_domain(mgcp));
		return NULL;
	}
	if (rc < 1) {
		LOGP(DLMGCP, LOGL_ERROR, "Cannot compose MGCP endpoint name\n");
		return NULL;
	}
	return endpoint;
}

const char *mgcp_client_rtpbridge_wildcard(const struct mgcp_client *mgcp)
{
	return _mgcp_client_name_append_domain(mgcp, "rtpbridge/*");
}

struct mgcp_response_pending * mgcp_client_pending_add(
					struct mgcp_client *mgcp,
					mgcp_trans_id_t trans_id,
					mgcp_response_cb_t response_cb,
					void *priv)
{
	struct mgcp_response_pending *pending;

	pending = talloc_zero(mgcp, struct mgcp_response_pending);
	pending->trans_id = trans_id;
	pending->response_cb = response_cb;
	pending->priv = priv;
	llist_add_tail(&pending->entry, &mgcp->responses_pending);

	return pending;
}

/* Send the MGCP message in msg to the MGCP GW and handle a response with
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
	struct mgcp_response_pending *pending;
	mgcp_trans_id_t trans_id;
	int rc;

	trans_id = msg->cb[MSGB_CB_MGCP_TRANS_ID];
	if (!trans_id) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "Unset transaction id in mgcp send request\n");
		talloc_free(msg);
		return -EINVAL;
	}

	pending = mgcp_client_pending_add(mgcp, trans_id, response_cb, priv);

	if (msgb_l2len(msg) > 4096) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "Cannot send, MGCP message too large: %u\n",
		     msgb_l2len(msg));
		msgb_free(msg);
		rc = -EINVAL;
		goto mgcp_tx_error;
	}

	rc = osmo_wqueue_enqueue(&mgcp->wq, msg);
	if (rc) {
		LOGP(DLMGCP, LOGL_FATAL, "Could not queue message to MGCP GW\n");
		msgb_free(msg);
		goto mgcp_tx_error;
	} else
		LOGP(DLMGCP, LOGL_DEBUG, "Queued %u bytes for MGCP GW\n",
		     msgb_l2len(msg));
	return 0;

mgcp_tx_error:
	/* Pass NULL to response cb to indicate an error */
	mgcp_client_handle_response(mgcp, pending, NULL);
	return -1;
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
		LOGP(DLMGCP, LOGL_ERROR, "Cannot cancel, no such transaction: %u\n", trans_id);
		return -ENOENT;
	}
	LOGP(DLMGCP, LOGL_DEBUG, "Canceled transaction %u\n", trans_id);
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
	int rc = 0;
	const char *codec;
	unsigned int pt;

	rc += msgb_printf(msg, "L:");

	if (mgcp_msg->ptime)
		rc += msgb_printf(msg, " p:%u,", mgcp_msg->ptime);

	if (mgcp_msg->codecs_len) {
		rc += msgb_printf(msg, " a:");
		for (i = 0; i < mgcp_msg->codecs_len; i++) {
			pt = mgcp_msg->codecs[i];
			codec = get_value_string_or_null(osmo_mgcpc_codec_names, pt);

			/* Note: Use codec descriptors from enum mgcp_codecs
			 * in mgcp_client only! */
			OSMO_ASSERT(codec);
			rc += msgb_printf(msg, "%s", extract_codec_name(codec));
			if (i < mgcp_msg->codecs_len - 1)
				rc += msgb_printf(msg, ";");
		}
		rc += msgb_printf(msg, ",");
	}

	rc += msgb_printf(msg, " nt:IN\r\n");

	return rc;
}

/* Helper function for mgcp_msg_gen(): Add SDP information to MGCP message */
static int add_sdp(struct msgb *msg, struct mgcp_msg *mgcp_msg, struct mgcp_client *mgcp)
{
	unsigned int i;
	int rc = 0;
	char local_ip[INET_ADDRSTRLEN];
	const char *codec;
	unsigned int pt;

	/* Add separator to mark the beginning of the SDP block */
	rc += msgb_printf(msg, "\r\n");

	/* Add SDP protocol version */
	rc += msgb_printf(msg, "v=0\r\n");

	/* Determine local IP-Address */
	if (osmo_sock_local_ip(local_ip, mgcp->actual.remote_addr) < 0) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "Could not determine local IP-Address!\n");
		msgb_free(msg);
		return -2;
	}

	/* Add owner/creator (SDP) */
	rc += msgb_printf(msg, "o=- %x 23 IN IP4 %s\r\n",
			  mgcp_msg->call_id, local_ip);

	/* Add session name (none) */
	rc += msgb_printf(msg, "s=-\r\n");

	/* Add RTP address and port */
	if (mgcp_msg->audio_port == 0) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "Invalid port number, can not generate MGCP message\n");
		msgb_free(msg);
		return -2;
	}
	if (strlen(mgcp_msg->audio_ip) <= 0) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "Empty ip address, can not generate MGCP message\n");
		msgb_free(msg);
		return -2;
	}
	rc += msgb_printf(msg, "c=IN IP4 %s\r\n", mgcp_msg->audio_ip);

	/* Add time description, active time (SDP) */
	rc += msgb_printf(msg, "t=0 0\r\n");

	rc += msgb_printf(msg, "m=audio %u RTP/AVP", mgcp_msg->audio_port);
	for (i = 0; i < mgcp_msg->codecs_len; i++) {
		pt = map_codec_to_pt(mgcp_msg->ptmap, mgcp_msg->ptmap_len, mgcp_msg->codecs[i]);
		rc += msgb_printf(msg, " %u", pt);

	}
	rc += msgb_printf(msg, "\r\n");

	/* Add optional codec parameters (fmtp) */
	if (mgcp_msg->param_present) {
		for (i = 0; i < mgcp_msg->codecs_len; i++) {
			/* The following is only applicable for AMR */
			if (mgcp_msg->codecs[i] != CODEC_AMR_8000_1 && mgcp_msg->codecs[i] != CODEC_AMRWB_16000_1)
				   continue;
			pt = map_codec_to_pt(mgcp_msg->ptmap, mgcp_msg->ptmap_len, mgcp_msg->codecs[i]);
			if (mgcp_msg->param.amr_octet_aligned_present && mgcp_msg->param.amr_octet_aligned)
				rc += msgb_printf(msg, "a=fmtp:%u octet-align=1\r\n", pt);
			else if (mgcp_msg->param.amr_octet_aligned_present && !mgcp_msg->param.amr_octet_aligned)
				rc += msgb_printf(msg, "a=fmtp:%u octet-align=0\r\n", pt);
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
			OSMO_ASSERT(codec);

			rc += msgb_printf(msg, "a=rtpmap:%u %s\r\n", pt, codec);
		}
	}

	if (mgcp_msg->ptime)
		rc += msgb_printf(msg, "a=ptime:%u\r\n", mgcp_msg->ptime);

	return rc;
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
	int rc = 0;
	int rc_sdp;
	bool use_sdp = false;
	char buf[32];

	msg->l2h = msg->data;
	msg->cb[MSGB_CB_MGCP_TRANS_ID] = trans_id;

	/* Add command verb */
	switch (mgcp_msg->verb) {
	case MGCP_VERB_CRCX:
		mandatory_mask = MGCP_CRCX_MANDATORY;
		rc += msgb_printf(msg, "CRCX %u", trans_id);
		break;
	case MGCP_VERB_MDCX:
		mandatory_mask = MGCP_MDCX_MANDATORY;
		rc += msgb_printf(msg, "MDCX %u", trans_id);
		break;
	case MGCP_VERB_DLCX:
		mandatory_mask = MGCP_DLCX_MANDATORY;
		rc += msgb_printf(msg, "DLCX %u", trans_id);
		break;
	case MGCP_VERB_AUEP:
		mandatory_mask = MGCP_AUEP_MANDATORY;
		rc += msgb_printf(msg, "AUEP %u", trans_id);
		break;
	case MGCP_VERB_RSIP:
		mandatory_mask = MGCP_RSIP_MANDATORY;
		rc += msgb_printf(msg, "RSIP %u", trans_id);
		break;
	default:
		LOGP(DLMGCP, LOGL_ERROR,
		     "Invalid command verb, can not generate MGCP message\n");
		msgb_free(msg);
		return NULL;
	}

	/* Check if mandatory fields are missing */
	if (!((mgcp_msg->presence & mandatory_mask) == mandatory_mask)) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "One or more missing mandatory fields, can not generate MGCP message\n");
		msgb_free(msg);
		return NULL;
	}

	/* Add endpoint name */
	if (mgcp_msg->presence & MGCP_MSG_PRESENCE_ENDPOINT) {
		if (strlen(mgcp_msg->endpoint) <= 0) {
			LOGP(DLMGCP, LOGL_ERROR,
			     "Empty endpoint name, can not generate MGCP message\n");
			msgb_free(msg);
			return NULL;
		}

		if (strstr(mgcp_msg->endpoint, "@") == NULL) {
			LOGP(DLMGCP, LOGL_ERROR,
			     "Endpoint name (%s) lacks separator (@), can not generate MGCP message\n",
			     mgcp_msg->endpoint);
			msgb_free(msg);
		}

		rc += msgb_printf(msg, " %s", mgcp_msg->endpoint);
	}

	/* Add protocol version */
	rc += msgb_printf(msg, " MGCP 1.0\r\n");

	/* Add call id */
	if (mgcp_msg->presence & MGCP_MSG_PRESENCE_CALL_ID)
		rc += msgb_printf(msg, "C: %x\r\n", mgcp_msg->call_id);

	/* Add connection id */
	if (mgcp_msg->presence & MGCP_MSG_PRESENCE_CONN_ID) {
		if (strlen(mgcp_msg->conn_id) <= 0) {
			LOGP(DLMGCP, LOGL_ERROR,
			     "Empty connection id, can not generate MGCP message\n");
			msgb_free(msg);
			return NULL;
		}
		rc += msgb_printf(msg, "I: %s\r\n", mgcp_msg->conn_id);
	}

	/* Using SDP makes sense when a valid IP/Port combination is specifiec,
	 * if we do not know this information yet, we fall back to LCO */
	if (mgcp_msg->presence & MGCP_MSG_PRESENCE_AUDIO_IP
	    && mgcp_msg->presence & MGCP_MSG_PRESENCE_AUDIO_PORT)
		use_sdp = true;

	/* Add local connection options (LCO) */
	if (!use_sdp
	    && (mgcp_msg->verb == MGCP_VERB_CRCX
		|| mgcp_msg->verb == MGCP_VERB_MDCX))
		rc += add_lco(msg, mgcp_msg);

	/* Add mode */
	if (mgcp_msg->presence & MGCP_MSG_PRESENCE_CONN_MODE)
		rc +=
		    msgb_printf(msg, "M: %s\r\n",
				mgcp_client_cmode_name(mgcp_msg->conn_mode));

	/* Add X-Osmo-IGN */
	if ((mgcp_msg->presence & MGCP_MSG_PRESENCE_X_OSMO_IGN)
	    && (mgcp_msg->x_osmo_ign != 0))
		rc +=
		    msgb_printf(msg, MGCP_X_OSMO_IGN_HEADER "%s\r\n",
				mgcp_msg->x_osmo_ign & MGCP_X_OSMO_IGN_CALLID ? " C": "");

	/* Add X-Osmo-Osmux */
	if ((mgcp_msg->presence & MGCP_MSG_PRESENCE_X_OSMO_OSMUX_CID)) {
		if (mgcp_msg->x_osmo_osmux_cid < -1 || mgcp_msg->x_osmo_osmux_cid > OSMUX_CID_MAX) {
			LOGP(DLMGCP, LOGL_ERROR,
			     "Wrong Osmux CID %d, can not generate MGCP message\n",
			     mgcp_msg->x_osmo_osmux_cid);
			msgb_free(msg);
			return NULL;
		}
		snprintf(buf, sizeof(buf), " %d", mgcp_msg->x_osmo_osmux_cid);
		rc +=
		    msgb_printf(msg, MGCP_X_OSMO_OSMUX_HEADER "%s\r\n",
				mgcp_msg->x_osmo_osmux_cid == -1 ? " *": buf);
	}


	/* Add session description protocol (SDP) */
	if (use_sdp
	    && (mgcp_msg->verb == MGCP_VERB_CRCX
		|| mgcp_msg->verb == MGCP_VERB_MDCX)) {
		rc_sdp = add_sdp(msg, mgcp_msg, mgcp);
		if (rc_sdp == -2)
			return NULL;
		else
			rc += rc_sdp;
	}

	if (rc != 0) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "message buffer to small, can not generate MGCP message\n");
		msgb_free(msg);
		msg = NULL;
	}

	return msg;
}

/*! Retrieve the MGCP transaction ID from a msgb generated by mgcp_msg_gen()
 *  \param[in] msg message buffer
 *  \returns Transaction id. */
mgcp_trans_id_t mgcp_msg_trans_id(struct msgb *msg)
{
	return (mgcp_trans_id_t)msg->cb[MSGB_CB_MGCP_TRANS_ID];
}

/*! Get the configuration parameters a given MGCP client instance
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

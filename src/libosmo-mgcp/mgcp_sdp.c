/*
 * Some SDP file parsing...
 *
 * (C) 2009-2015 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009-2014 by On-Waves
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

#include <osmocom/core/msgb.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/sockaddr_str.h>

#include <osmocom/mgcp/mgcp.h>
#include <osmocom/mgcp/osmux.h>
#include <osmocom/mgcp/mgcp_conn.h>
#include <osmocom/mgcp/mgcp_protocol.h>
#include <osmocom/mgcp/mgcp_msg.h>
#include <osmocom/mgcp/mgcp_endp.h>
#include <osmocom/mgcp/mgcp_trunk.h>
#include <osmocom/mgcp/mgcp_codec.h>
#include <osmocom/mgcp/mgcp_sdp.h>
#include <osmocom/mgcp/mgcp_protocol.h>
#include <osmocom/mgcp_client/fmtp.h>

#include <errno.h>
#include <stdlib.h>
#include <limits.h>

/* Two structs to store intermediate parsing results. The function
 * mgcp_parse_sdp_data() is using the following two structs as temporary
 * storage for parsing the SDP codec information. */
struct sdp_rtp_map {
	/* the type */
	int payload_type;
	/* null, static or later dynamic codec name */
	char *codec_name;
	/* A pointer to the original line for later parsing */
	char *map_line;

	int rate;
	int channels;
};
struct sdp_fmtp_param {
	int payload_type;
	const char *fmtp;
};


/* Helper function to extrapolate missing codec parameters in a codec mao from
 * an already filled in payload_type, called from: mgcp_parse_sdp_data() */
static void codecs_initialize(void *ctx, struct sdp_rtp_map *codecs, int used)
{
	int i;

	for (i = 0; i < used; ++i) {
		switch (codecs[i].payload_type) {
		case 0:
			codecs[i].codec_name = "PCMU";
			codecs[i].rate = 8000;
			codecs[i].channels = 1;
			break;
		case 3:
			codecs[i].codec_name = "GSM";
			codecs[i].rate = 8000;
			codecs[i].channels = 1;
			break;
		case 8:
			codecs[i].codec_name = "PCMA";
			codecs[i].rate = 8000;
			codecs[i].channels = 1;
			break;
		case 18:
			codecs[i].codec_name = "G729";
			codecs[i].rate = 8000;
			codecs[i].channels = 1;
			break;
		default:
			codecs[i].codec_name = NULL;
			codecs[i].rate = 0;
			codecs[i].channels = 0;
		}
	}
}

/* Helper function to update codec map information with additional data from
 * SDP, called from: mgcp_parse_sdp_data() */
static void codecs_update(void *ctx, struct sdp_rtp_map *codecs, int used,
			  int payload_type, const char *audio_name)
{
	int i;

	for (i = 0; i < used; ++i) {
		char audio_codec[64];
		int rate = -1;
		int channels = -1;

		/* Note: We can only update payload codecs that already exist
		 * in our codec list. If we get an unexpected payload type,
		 * we just drop it */
		if (codecs[i].payload_type != payload_type)
			continue;

		if (sscanf(audio_name, "%63[^/]/%d/%d",
			   audio_codec, &rate, &channels) < 1) {
			LOGP(DLMGCP, LOGL_ERROR, "Failed to parse '%s'\n",
			     audio_name);
			continue;
		}

		codecs[i].map_line = talloc_strdup(ctx, audio_name);
		codecs[i].codec_name = talloc_strdup(ctx, audio_codec);
		codecs[i].rate = rate;
		codecs[i].channels = channels;
		return;
	}

	LOGP(DLMGCP, LOGL_ERROR, "Unconfigured PT(%d) with %s\n", payload_type,
	     audio_name);
}

/* Extract payload types from SDP, also check for duplicates */
static int pt_from_sdp(void *ctx, struct sdp_rtp_map *codecs,
		       unsigned int codecs_len, char *sdp)
{
	char *str;
	char *str_ptr;
	char *pt_str;
	char *pt_end;
	unsigned long int pt;
	unsigned int count = 0;
	unsigned int i;

	str = talloc_zero_size(ctx, strlen(sdp) + 1);
	str_ptr = str;
	strcpy(str_ptr, sdp);

	str_ptr = strstr(str_ptr, "RTP/AVP ");
	if (!str_ptr)
		goto exit;

	pt_str = strtok(str_ptr, " ");
	if (!pt_str)
		goto exit;

	while (1) {
		/* Do not allow excessive payload types */
		if (count > codecs_len)
			goto error;

		pt_str = strtok(NULL, " ");
		if (!pt_str)
			break;

		errno = 0;
		pt = strtoul(pt_str, &pt_end, 0);
		if ((errno == ERANGE && pt == ULONG_MAX) || (errno && !pt) ||
		    pt_str == pt_end)
			goto error;

		if (pt >> 7) /* PT is 7 bit field, higher values not allowed */
			goto error;

		/* Do not allow duplicate payload types */
		for (i = 0; i < count; i++)
			if (codecs[i].payload_type == pt)
				goto error;

		codecs[count].payload_type = pt;
		count++;
	}

exit:
	talloc_free(str);
	return count;
error:
	talloc_free(str);
	return -EINVAL;
}

/* Extract fmtp parameters from SDP, called from: mgcp_parse_sdp_data() */
static int fmtp_from_sdp(void *ctx, struct sdp_fmtp_param *fmtp_param, char *sdp)
{
	char *str;
	char *str_ptr;
	unsigned int pt;

	memset(fmtp_param, 0, sizeof(*fmtp_param));

	str = talloc_zero_size(ctx, strlen(sdp) + 1);
	str_ptr = str;
	strcpy(str_ptr, sdp);

	/* Check if the input string begins with an fmtp token */
	str_ptr = strstr(str_ptr, "fmtp:");
	if (!str_ptr)
		goto exit;
	str_ptr += 5;

	/* Extract payload type */
	if (sscanf(str_ptr, "%u ", &pt) != 1)
		goto error;
	fmtp_param->payload_type = pt;

	/* Advance pointer to the beginning of the parameter section */
	str_ptr = strstr(str_ptr, " ");
	if (!str_ptr)
		goto error;
	str_ptr++;

	fmtp_param->fmtp = talloc_strdup(ctx, str_ptr);

exit:
	talloc_free(str);
	return 0;
error:
	talloc_free(str);
	return -EINVAL;
}


static int audio_ip_from_sdp(struct osmo_sockaddr *dst_addr, char *sdp)
{
	bool is_ipv6;
	char ipbuf[INET6_ADDRSTRLEN];
	if (strncmp("c=IN IP", sdp, 7) != 0)
		return -1;
	sdp += 7;
	if (*sdp == '6')
	       is_ipv6 = true;
	else if (*sdp == '4')
	       is_ipv6 = false;
	else
	       return -1;
	sdp++;
	if (*sdp != ' ')
		return -1;
	sdp++;
	if (is_ipv6) {
		/* 45 = INET6_ADDRSTRLEN -1 */
		if (sscanf(sdp, "%45s", ipbuf) != 1)
			return -1;
		if (inet_pton(AF_INET6, ipbuf, &dst_addr->u.sin6.sin6_addr) != 1)
			return -1;
		dst_addr->u.sa.sa_family = AF_INET6;
	} else {
		/* 15 = INET_ADDRSTRLEN -1 */
		if (sscanf(sdp, "%15s", ipbuf) != 1)
			return -1;
		if (inet_pton(AF_INET, ipbuf, &dst_addr->u.sin.sin_addr) != 1)
			return -1;
		dst_addr->u.sa.sa_family = AF_INET;
	}
	return 0;
}

/* Pick optional fmtp parameters by payload type, if there are no fmtp
 * parameters, a nullpointer is returned */
static const char *param_by_pt(int pt, struct sdp_fmtp_param *fmtp_params, unsigned int fmtp_params_len)
{
	unsigned int i;

	for (i = 0; i < fmtp_params_len; i++) {
		if (fmtp_params[i].payload_type == pt)
			return fmtp_params[i].fmtp;
	}

	return NULL;
}

/*! Analyze SDP input string.
 *  \param[in] endp trunk endpoint.
 *  \param[out] conn associated rtp connection.
 *  \param[out] caller provided memory to store the parsing results.
 *
 *  Note: In conn (conn->end) the function returns the packet duration,
 *  rtp port, rtcp port and the codec information.
 *  \returns 0 on success, -1 on failure. */
int mgcp_parse_sdp_data(const struct mgcp_endpoint *endp,
			struct mgcp_conn_rtp *conn, struct mgcp_parse_data *p)
{
	struct sdp_rtp_map codecs[MGCP_MAX_CODECS];
	unsigned int codecs_used = 0;
	struct sdp_fmtp_param fmtp_params[MGCP_MAX_CODECS];
	unsigned int fmtp_used = 0;
	char ipbuf[INET6_ADDRSTRLEN];
	char *line;
	unsigned int i;
	void *tmp_ctx = talloc_new(NULL);
	struct mgcp_rtp_end *rtp;

	int payload_type;
	int ptime, ptime2 = 0;
	char audio_name[64];
	int port, rc;

	OSMO_ASSERT(endp);
	OSMO_ASSERT(conn);
	OSMO_ASSERT(p);

	rtp = &conn->end;
	memset(&codecs, 0, sizeof(codecs));

	for_each_line(line, p->save) {
		switch (line[0]) {
		case 'o':
		case 's':
		case 't':
		case 'v':
			/* skip these SDP attributes */
			break;
		case 'a':
			if (sscanf(line, "a=rtpmap:%d %63s", &payload_type, audio_name) == 2) {
				codecs_update(tmp_ctx, codecs, codecs_used, payload_type, audio_name);
				break;
			}

			if (sscanf(line, "a=ptime:%d-%d", &ptime, &ptime2) >= 1) {
				if (ptime2 > 0 && ptime2 != ptime)
					rtp->packet_duration_ms = 0;
				else
					rtp->packet_duration_ms = ptime;
				break;
			}

			if (sscanf(line, "a=maxptime:%d", &ptime2) == 1) {
				rtp->maximum_packet_time = ptime2;
				break;
			}

			if (strncmp("a=fmtp:", line, 6) == 0) {
				rc = fmtp_from_sdp(conn->conn, &fmtp_params[fmtp_used], line);
				if (rc >= 0)
					fmtp_used++;
				break;
			}

			break;
		case 'm':
			rc = sscanf(line, "m=audio %d RTP/AVP", &port);
			if (rc == 1) {
				osmo_sockaddr_set_port(&rtp->addr.u.sa, port);
				rtp->rtcp_port = htons(port + 1);
			}

			rc = pt_from_sdp(conn->conn, codecs,
					 ARRAY_SIZE(codecs), line);
			if (rc > 0)
				codecs_used = rc;
			break;
		case 'c':
			if (audio_ip_from_sdp(&rtp->addr, line) < 0) {
				talloc_free(tmp_ctx);
				return -1;
			}
			break;
		default:
			if (endp)
				/* TODO: Check spec: We used the bare endpoint number before,
				 * now we use the endpoint name as a whole? Is this allowed? */
				LOGP(DLMGCP, LOGL_NOTICE,
				     "Unhandled SDP option: '%c'/%d on %s\n",
				     line[0], line[0], endp->name);
			else
				LOGP(DLMGCP, LOGL_NOTICE,
				     "Unhandled SDP option: '%c'/%d\n",
				     line[0], line[0]);
			break;
		}
	}
	OSMO_ASSERT(codecs_used <= MGCP_MAX_CODECS);

	/* So far we have only set the payload type in the codec struct. Now we
	 * fill up the remaining fields of the codec description with some default
	 * information */
	codecs_initialize(tmp_ctx, codecs, codecs_used);

	/* Store parsed codec information */
	for (i = 0; i < codecs_used; i++) {
		const char *fmtp = param_by_pt(codecs[i].payload_type, fmtp_params, fmtp_used);
		rc = mgcp_codec_add2(conn, codecs[i].payload_type, codecs[i].map_line, fmtp);
		if (rc < 0)
			LOGPENDP(endp, DLMGCP, LOGL_NOTICE, "failed to add codec\n");
	}

	talloc_free(tmp_ctx);

	LOGPCONN(conn->conn, DLMGCP, LOGL_NOTICE,
	     "Got media info via SDP: port:%d, addr:%s, duration:%d, payload-types:",
	     osmo_sockaddr_port(&rtp->addr.u.sa), osmo_sockaddr_ntop(&rtp->addr.u.sa, ipbuf),
	     rtp->packet_duration_ms);
	if (codecs_used == 0)
		LOGPC(DLMGCP, LOGL_NOTICE, "none");
	for (i = 0; i < codecs_used; i++) {
		LOGPC(DLMGCP, LOGL_NOTICE, " %d=%s%s%s%s",
		      rtp->codecs[i].payload_type,
		      strlen(rtp->codecs[i].subtype_name) ? rtp->codecs[i].subtype_name : "unknown",
		      rtp->codecs[i].fmtp[0] ? ",fmtp='" : "",
		      rtp->codecs[i].fmtp,
		      rtp->codecs[i].fmtp[0] ? "'" : "");
	}
	LOGPC(DLMGCP, LOGL_NOTICE, "\n");

	return 0;
}


/* Add all codecs related lines to SDP payload */
static int add_codecs(struct msgb *sdp, const struct mgcp_conn_rtp *conn)
{
	int rc;
	unsigned int i;
	int local_port;
	struct mgcp_trunk *trunk = conn->conn->endp->trunk;

	if (!conn->end.codecs_assigned)
		return 0;

	/* Compose 'm=audio 1234 RTP/AVP 112 96 3' line, with
	 * - local RTP port
	 * - a list of all assigned payload type numbers
	 */

	if (mgcp_conn_rtp_is_osmux(conn))
		local_port = trunk->cfg->osmux.local_port;
	else
		local_port = conn->end.local_port;

	rc = msgb_printf(sdp, "m=audio %d RTP/AVP", local_port);
	if (rc < 0)
		return -EINVAL;

	for (i = 0; i < conn->end.codecs_assigned; i++) {
		const struct mgcp_rtp_codec *c = &conn->end.codecs[i];
		rc = msgb_printf(sdp, " %d", c->payload_type);
		if (rc < 0)
			return -EINVAL;
	}

	rc = msgb_printf(sdp, "\r\n");
	if (rc < 0)
		return -EINVAL;

	/* Compose 'a=rtpmap:N FOO' lines for codecs in above list that require it.
	 * e.g. GSM-FR is implicitly defined by payload type number 3, so it is enough to list 3 above;
	 * AMR needs a line like 'a=rtpmap:112 AMR/8000/1' in addition to listing 112 above.
	 */
	for (i = 0; i < conn->end.codecs_assigned; i++) {
		const struct mgcp_rtp_codec *c = &conn->end.codecs[i];
		if (!c->audio_name[0])
			continue;

		/* Dynamic payload type numbers need explicit rtpmap defining the codec by "subtype name" like "AMR" or
		 * "GSM-HR-08". Others are defined implicitly, like GSM-FR by payload type number 3.
		 *
		 * Also, if the trunk is configured as "no sdp audio-payload send-name", omit all rtpmap lines.
		 */
		if (c->payload_type >= 96 && c->payload_type <= 127
		    && trunk->audio_send_name) {
			if (msgb_printf(sdp, "a=rtpmap:%d %s\r\n", c->payload_type, c->audio_name) < 0)
				return -EINVAL;
		}

		/* Compose 'a=fmtp:N foo=bar' line if fmtp is defined for this codec.
		 * e.g. AMR has fmtp like 'octet-align=1', 'mode-set=0,2,4,7'.
		 */
		if (c->fmtp[0]) {
			if (msgb_printf(sdp, OSMO_SDP_PREFIX_A_FMTP "%d %s\r\n", c->payload_type, c->fmtp) < 0)
				return -EINVAL;
		}
		else if (c->param_present) {
			/* Legacy */
			if (msgb_printf(sdp, OSMO_SDP_PREFIX_A_FMTP "%d %s\r\n", c->payload_type,
					OSMO_SDP_AMR_SET_OCTET_ALIGN(c->param.amr_octet_aligned))
			    < 0)
				return -EINVAL;
		}
	}

	if (conn->end.packet_duration_ms > 0 && conn->conn->endp->trunk->audio_send_ptime) {
		rc = msgb_printf(sdp, "a=ptime:%u\r\n",
				 conn->end.packet_duration_ms);
		if (rc < 0)
			return -EINVAL;
	}

	return 0;
}

/*! Generate SDP response string.
 *  \param[in] endp trunk endpoint.
 *  \param[in] conn associated rtp connection.
 *  \param[out] sdp msg buffer to append resulting SDP string data.
 *  \param[in] addr IPV4 address string (e.g. 192.168.100.1).
 *  \returns 0 on success, -1 on failure. */
int mgcp_write_response_sdp(const struct mgcp_endpoint *endp,
			    const struct mgcp_conn_rtp *conn, struct msgb *sdp,
			    const char *addr)
{
	int rc;
	bool addr_is_v6;

	OSMO_ASSERT(endp);
	OSMO_ASSERT(conn);
	OSMO_ASSERT(sdp);
	OSMO_ASSERT(addr);

	addr_is_v6 = osmo_ip_str_type(addr) == AF_INET6;

	rc = msgb_printf(sdp,
			 "v=0\r\n"
			 "o=- %s 23 IN IP%c %s\r\n"
			 "s=-\r\n"
			 "c=IN IP%c %s\r\n"
			 "t=0 0\r\n", conn->conn->id,
			 addr_is_v6 ? '6' : '4', addr,
			 addr_is_v6 ? '6' : '4', addr);

	if (rc < 0)
		goto buffer_too_small;

	/* Add all codecs related SDP lines */
	rc = add_codecs(sdp, conn);
	if (rc < 0)
		goto buffer_too_small;

	return 0;

buffer_too_small:
	LOGPCONN(conn->conn, DLMGCP, LOGL_ERROR, "SDP message too large for buffer\n");
	return -1;
}

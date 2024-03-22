/* Implementation for SDP message encoding and decoding */
/*
 * (C) 2024 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved.
 *
 * Author: Neels Janosch Hofmeyr <nhofmeyr@sysmocom.de>
 *
 * SPDX-License-Identifier: GPL-2.0+
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <inttypes.h>
#include <errno.h>
#include <ctype.h>

#include <osmocom/core/utils.h>

#include <osmocom/sdp/sdp_msg.h>
#include <osmocom/sdp/sdp_strings.h>
#include <osmocom/sdp/sdp_internal.h>

static const char * const mdir_str[] = {
	[OSMO_SDP_MDIR_UNSET] = "-",
	[OSMO_SDP_MDIR_SENDONLY] = OSMO_SDP_STR_SENDONLY,
	[OSMO_SDP_MDIR_RECVONLY] = OSMO_SDP_STR_RECVONLY,
	[OSMO_SDP_MDIR_SENDRECV] = OSMO_SDP_STR_SENDRECV,
	[OSMO_SDP_MDIR_INACTIVE] = OSMO_SDP_STR_INACTIVE,
};

/*! Convert struct osmo_sdp_msg to the actual SDP protocol representation. */
int osmo_sdp_msg_encode_buf(char *dst, size_t dst_size, const struct osmo_sdp_msg *sdp)
{
	const struct osmo_sdp_codec *codec;
	struct osmo_strbuf sb = { .buf = dst, .len = dst_size };
	const char *oip;
	char oipv;
	const char *ip;
	char ipv;

	if (!sdp) {
		OSMO_STRBUF_PRINTF(sb, "%s", "");
		return sb.chars_needed;
	}

	oip = sdp->origin.addr.ip[0] ? sdp->origin.addr.ip : "0.0.0.0";
	oipv = (osmo_ip_str_type(oip) == AF_INET6) ? '6' : '4';

	ip = sdp->rtp.ip[0] ? sdp->rtp.ip : "0.0.0.0";
	ipv = (osmo_ip_str_type(oip) == AF_INET6) ? '6' : '4';

	OSMO_STRBUF_PRINTF(sb,
			   "v=0\r\n"
			   "o=%s %s %s IN IP%c %s\r\n"
			   "s=%s\r\n"
			   "c=IN IP%c %s\r\n"
			   "t=%"PRId64" %"PRId64"\r\n"
			   "m=audio %d RTP/AVP",
			   sdp->origin.username ? : "libosmo-sdp",
			   sdp->origin.sess_id ? : "0", sdp->origin.sess_version ? : "0",
			   oipv, oip,
			   sdp->session_name ? : "-",
			   ipv, ip,
			   sdp->time_active.start,
			   sdp->time_active.stop,
			   sdp->rtp.port);

	/* Append all payload type numbers to 'm=audio <port> RTP/AVP 3 4 112' line */
	osmo_sdp_codec_list_foreach(codec, sdp->codecs)
		OSMO_STRBUF_PRINTF(sb, " %d", codec->payload_type);
	OSMO_STRBUF_PRINTF(sb, "\r\n");

	/* Add details for all codecs */
	osmo_sdp_codec_list_foreach(codec, sdp->codecs) {
		if (!osmo_sdp_codec_is_set(codec))
			continue;
		OSMO_STRBUF_PRINTF(sb, OSMO_SDP_A_PREFIX(OSMO_SDP_STR_RTPMAP) "%d %s/%d\r\n", codec->payload_type, codec->encoding_name,
				   codec->rate > 0 ? codec->rate : 8000);
		if (codec->fmtp && codec->fmtp[0])
			OSMO_STRBUF_PRINTF(sb, OSMO_SDP_A_PREFIX(OSMO_SDP_STR_FMTP) "%d %s\r\n", codec->payload_type, codec->fmtp);
	}

	if (sdp->ptime)
		OSMO_STRBUF_PRINTF(sb, OSMO_SDP_A_PREFIX(OSMO_SDP_STR_PTIME) "%d\r\n", sdp->ptime);

	if (sdp->media_direction != OSMO_SDP_MDIR_UNSET && sdp->media_direction < ARRAY_SIZE(mdir_str))
		OSMO_STRBUF_PRINTF(sb, "a=%s\r\n", mdir_str[sdp->media_direction]);

	return sb.chars_needed;
}

char *osmo_sdp_msg_encode_c(void *ctx, const struct osmo_sdp_msg *sdp)
{
	OSMO_NAME_C_IMPL(ctx, 256, "osmo_sdp_msg_to_str_c-ERROR", osmo_sdp_msg_encode_buf, sdp)
}

/* Return the first line ending (or the end of the string) at or after the given string position. */
const char *get_line_end(const char *src)
{
	const char *line_end = strchr(src, '\r');
	if (!line_end)
		line_end = strchr(src, '\n');
	if (!line_end)
		line_end = src + strlen(src);
	return line_end;
}

static bool str_is_attrib(const char *str, const char *attrib_name, char expect_next_char)
{
	char next_c;
	if (!osmo_str_startswith(str, attrib_name))
		return false;
	next_c = str[strlen(attrib_name)];
	if (expect_next_char == next_c)
		return true;
	/* Treat \0 as equivalent with line end */
	if (!expect_next_char && (next_c == '\r' || next_c == '\n'))
		return true;
	/* It started with the string, but continued otherwise */
	return false;
}

static enum osmo_sdp_media_direcion_e check_for_media_direction(const char *str)
{
	int i;
	for (i = 0; i < ARRAY_SIZE(mdir_str); i++) {
		if (i == OSMO_SDP_MDIR_UNSET)
			continue;
		if (str_is_attrib(str, mdir_str[i], 0))
			return i;
	}
	return OSMO_SDP_MDIR_UNSET;
}

static struct osmo_sdp_codec *find_or_create_payload_type(struct osmo_sdp_msg *sdp, unsigned int payload_type)
{
	struct osmo_sdp_codec *codec;
	codec = osmo_sdp_codec_list_by_payload_type(sdp->codecs, payload_type);
	if (!codec) {
		codec = osmo_sdp_codec_list_add_empty(sdp->codecs);
		codec->payload_type = payload_type;
		codec->rate = 8000;
	}
	return codec;
}


/* parse a line like 'a=rtpmap:0 PCMU/8000', 'a=fmtp:112 octet-align=1; mode-set=4', 'a=ptime:20'.
 * The src should point at the character after 'a=', e.g. at the start of 'rtpmap', 'fmtp', 'ptime'
 */
int sdp_parse_attrib(struct osmo_sdp_msg *sdp, const char *src)
{
	unsigned int payload_type;
	struct osmo_sdp_codec *codec;
	enum osmo_sdp_media_direcion_e mdir;
	const char *line_end = get_line_end(src);

	if (str_is_attrib(src, OSMO_SDP_STR_RTPMAP, ':')) {
		/* "a=rtpmap:96 AMR/8000" */
		struct token audio_name;
		const char *slash;
		if (sscanf(src, OSMO_SDP_STR_RTPMAP ":%u", &payload_type) != 1)
			return -EINVAL;

		codec = find_or_create_payload_type(sdp, payload_type);

		audio_name.start = strchr(src, ' ');
		if (!audio_name.start)
			return -EINVAL;
		audio_name.start++;
		if (audio_name.start >= get_line_end(src))
			return -EINVAL;

		slash = strchr(audio_name.start, '/');

		audio_name.end = slash ? : line_end;
		token_copy(codec, &codec->encoding_name, &audio_name);

		if (audio_name.end >= line_end) {
			/* There should be a "/8000" here. If it is missing, let's not be strict about it. */
			codec->rate = 8000;
		} else {
			unsigned int channels = 1;
			if (sscanf(audio_name.end, "/%u/%u", &codec->rate, &channels) < 1)
				return -EINVAL;

			if (channels != 1)
				return -ENOTSUP;
		}
	}

	else if (str_is_attrib(src, OSMO_SDP_STR_FMTP, ':')) {
		/* "a=fmtp:112 octet-align=1;mode-set=0,1,2,3" */
		struct token fmtp_str;
		const char *line_end = get_line_end(src);
		if (sscanf(src, OSMO_SDP_STR_FMTP ":%u", &payload_type) != 1)
			return -EINVAL;

		codec = find_or_create_payload_type(sdp, payload_type);

		fmtp_str.start = strchr(src, ' ');
		if (!fmtp_str.start)
			return -EINVAL;
		fmtp_str.start++;
		if (fmtp_str.start >= line_end)
			return -EINVAL;

		fmtp_str.end = line_end;
		token_copy(codec, &codec->fmtp, &fmtp_str);
	}

	else if (str_is_attrib(src, OSMO_SDP_STR_PTIME, ':')) {
		/* "a=ptime:20" */
		if (sscanf(src, OSMO_SDP_STR_PTIME ":%u", &sdp->ptime) != 1)
			return -EINVAL;

	}

	/* "a=sendrecv" ... */
	else if ((mdir = check_for_media_direction(src)) != OSMO_SDP_MDIR_UNSET) {
		sdp->media_direction = mdir;
	}

	return 0;
}

static const struct value_string fixed_payload_types[] = {
	{ 0, "PCMU" },
	{ 3, "GSM" },
	{ 8, "PCMA" },
	{ 18, "G729" },
	{ 110, "GSM-EFR" },
	{ 111, "GSM-HR-08" },
	{ 112, "AMR" },
	{ 113, "AMR-WB" },
	{}
};

/* Parse a line like 'm=audio 16398 RTP/AVP 0 3 8 96 112', starting after the '=' */
static int sdp_parse_media_description(struct osmo_sdp_msg *sdp, const char *src)
{
	unsigned int port;
	int i;
	const char *payload_type_str;
	const char *line_end = get_line_end(src);
	if (sscanf(src, "audio %u RTP/AVP", &port) < 1)
		return -ENOTSUP;

	if (port > 0xffff)
		return -EINVAL;

	sdp->rtp.port = port;

	/* skip "audio 12345 RTP/AVP ", i.e. 3 spaces on */
	payload_type_str = src;
	for (i = 0; i < 3; i++) {
		payload_type_str = strchr(payload_type_str, ' ');
		if (!payload_type_str)
			return -EINVAL;
		while (*payload_type_str == ' ')
			payload_type_str++;
		if (payload_type_str >= line_end)
			return -EINVAL;
	}

	/* Parse listing of payload type numbers after "RTP/AVP" */
	while (payload_type_str < line_end) {
		unsigned int payload_type;
		struct osmo_sdp_codec *codec;
		const char *encoding_name;
		if (sscanf(payload_type_str, "%u", &payload_type) < 1)
			return -EINVAL;

		codec = find_or_create_payload_type(sdp, payload_type);

		/* Fill in encoding name for fixed payload types */
		encoding_name = get_value_string_or_null(fixed_payload_types, codec->payload_type);
		if (encoding_name)
			osmo_talloc_replace_string(codec, &codec->encoding_name, encoding_name);

		payload_type_str = strchr(payload_type_str, ' ');
		if (!payload_type_str)
			payload_type_str = line_end;
		while (*payload_type_str == ' ')
			payload_type_str++;
	}

	return 0;
}

/* parse a line like 'c=IN IP4 192.168.11.151' starting after the '=' */
static int sdp_parse_connection_info(struct osmo_sdp_msg *sdp, const char *src)
{
	char ipv[10];
	char addr_str[INET6_ADDRSTRLEN];
	if (sscanf(src, "IN %s %s", ipv, addr_str) < 2)
		return -EINVAL;

	if (strcmp(ipv, "IP4") && strcmp(ipv, "IP6"))
		return -ENOTSUP;

	return osmo_sockaddr_str_from_str(&sdp->rtp, addr_str, sdp->rtp.port);
}

static void next_token(struct token *t, const char *str, const char *end)
{
	t->start = str;
	while (*t->start == ' ' && t->start < end)
		t->start++;
	t->end = t->start;
	while (*t->end != ' ' && t->end < end)
		t->end++;
}

/* parse a line like 'o=jdoe 3724394400 3724394405 IN IP4 198.51.100.1' starting after the '=' */
static int sdp_parse_origin(struct osmo_sdp_msg *sdp, const char *src)
{
	struct token t;
	char addr_str[INET6_ADDRSTRLEN + 1] = {};
	const char *line_end = get_line_end(src);

	next_token(&t, src, line_end);
	token_copy(sdp, &sdp->origin.username, &t);

	next_token(&t, t.end, line_end);
	token_copy(sdp, &sdp->origin.sess_id, &t);

	next_token(&t, t.end, line_end);
	token_copy(sdp, &sdp->origin.sess_version, &t);

	next_token(&t, t.end, line_end);
	if (strncmp("IN", t.start, t.end - t.start))
		return -ENOTSUP;

	next_token(&t, t.end, line_end);
	if (strncmp("IP4", t.start, t.end - t.start)
	    && strncmp("IP6", t.start, t.end - t.start))
		return -ENOTSUP;

	next_token(&t, t.end, line_end);
	osmo_strlcpy(addr_str, t.start, OSMO_MIN(sizeof(addr_str), t.end - t.start + 1));
	return osmo_sockaddr_str_from_str(&sdp->origin.addr, addr_str, 0);
}

static int sdp_parse_session_name(struct osmo_sdp_msg *sdp, const char *src)
{
	const char *line_end = get_line_end(src);
	if (sdp->session_name)
		talloc_free(sdp->session_name);
	if (line_end <= src)
		sdp->session_name = NULL;
	else
		sdp->session_name = talloc_strndup(sdp, src, line_end - src);
	return 0;
}

struct osmo_sdp_msg *osmo_sdp_msg_alloc(void *ctx)
{
	struct osmo_sdp_msg *sdp;
	sdp = talloc_zero(ctx, struct osmo_sdp_msg);
	sdp->codecs = osmo_sdp_codec_list_alloc(sdp);
	return sdp;
}

/* Parse SDP string into struct osmo_sdp_msg. Return 0 on success, negative on error.
 * Return a new osmo_sdp_msg instance allocated from ctx, or NULL on error.
 * When NULL is returned and if err is non-NULL, details of the error are returned in err->*.
 */
struct osmo_sdp_msg *osmo_sdp_msg_decode(void *ctx, const char *src, struct osmo_sdp_err *err)
{
	struct osmo_sdp_msg *sdp;
	const char *pos;

	if (err)
		*err = (struct osmo_sdp_err){};

	sdp = osmo_sdp_msg_alloc(ctx);

	for (pos = src; pos && *pos; pos++) {
		char attrib;
		int rc = 0;

		if (*pos == '\r' || *pos == '\n')
			continue;

		/* Expecting only lines starting with 'X='. Not being too strict about it is probably alright. */
		if (pos[1] != '=')
			goto next_line;

		attrib = *pos;
		pos += 2;
		switch (attrib) {
			/* a=... */
			case 'a':
				rc = sdp_parse_attrib(sdp, pos);
				break;
			case 'm':
				rc = sdp_parse_media_description(sdp, pos);
				break;
			case 'c':
				rc = sdp_parse_connection_info(sdp, pos);
				break;
			case 'o':
				rc = sdp_parse_origin(sdp, pos);
				break;
			case 's':
				rc = sdp_parse_session_name(sdp, pos);
				break;
			default:
				/* ignore any other parameters */
				break;
		}

		if (rc) {
			if (err) {
				const char *line_end = get_line_end(pos);
				/* shift back to include the 'x=' part as well */
				pos -= 2;
				*err = (struct osmo_sdp_err){
					.rc = rc,
					.at_input_str = pos,
					.at_input_str_len = line_end - pos,
				};
			}
			talloc_free(sdp);
			return NULL;
		}

next_line:
		pos = strstr(pos, "\r\n");
		if (!pos)
			break;
	}

	return sdp;
}

/*! Short single-line representation of an SDP message, convenient for logging.
 * To obtain a valid SDP message, use osmo_sdp_msg_encode_buf() instead.
 */
int osmo_sdp_msg_to_str_buf(char *buf, size_t buflen, const struct osmo_sdp_msg *sdp, bool summarize)
{
       struct osmo_strbuf sb = { .buf = buf, .len = buflen };
       if (!sdp) {
               OSMO_STRBUF_PRINTF(sb, "NULL");
               return sb.chars_needed;
       }

       OSMO_STRBUF_PRINTF(sb, OSMO_SOCKADDR_STR_FMT, OSMO_SOCKADDR_STR_FMT_ARGS(&sdp->rtp));
       OSMO_STRBUF_PRINTF(sb, "{");
       OSMO_STRBUF_APPEND(sb, osmo_sdp_codec_list_to_str_buf, sdp->codecs, summarize);
       OSMO_STRBUF_PRINTF(sb, "}");
       return sb.chars_needed;
}

char *osmo_sdp_msg_to_str_c(void *ctx, const struct osmo_sdp_msg *sdp, bool summarize)
{
       OSMO_NAME_C_IMPL(ctx, 128, "sdp_msg_to_str_c-ERROR", osmo_sdp_msg_to_str_buf, sdp, summarize)
}

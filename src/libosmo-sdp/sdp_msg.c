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
#include <limits.h>

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
static const char *get_line_end(const struct token *src)
{
	const char *line_end = token_chrs(src, "\r\n");
	if (!line_end)
		return src->end;
	return line_end;
}

/* See if str starts with an attribute like "rtpmap:" or "sendrecv\r\n".
 * For example:
 *   token_is_attrib({"foo: bar"}, "foo", ':') --> " bar"
 *   token_is_attrib({"sendrev\n"}, "sendrecv", 0) --> "\n"
 *   token_is_attrib({"sendrev\n"}, "foo", 0) --> NULL
 * On mismatch, return NULL.
 * On match, return the string after the expect_next_char.
 * For expect_next_char == 0, match both the end of the string as well as a line ending character ('\r' or '\n'), and in
 * both cases return the string directly after attrib_name.
 */
static const char *token_is_attrib(const struct token *str, const char *attrib_name, char expect_next_char)
{
	const char *next_c;
	int attrib_name_len = strlen(attrib_name);
	if (str->start + attrib_name_len > str->end)
		return NULL;
	if (!osmo_str_startswith(str->start, attrib_name))
		return NULL;
	next_c = str->start + strlen(attrib_name);
	if (next_c > str->end)
		return NULL;
	if (next_c == str->end) {
		if (!expect_next_char)
			return str->end;
		return NULL;
	}
	if (expect_next_char == *next_c)
		return next_c + 1;
	/* Treat expect_next_char == \0 as equivalent with line end */
	if (!expect_next_char && strchr("\r\n", *next_c))
		return next_c;
	return NULL;
}

static enum osmo_sdp_media_direcion_e check_for_media_direction(const struct token *str)
{
	int i;
	for (i = 0; i < ARRAY_SIZE(mdir_str); i++) {
		if (i == OSMO_SDP_MDIR_UNSET)
			continue;
		if (token_is_attrib(str, mdir_str[i], 0))
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


static void next_token(struct token *t, const char *str, const char *end)
{
	token_next(t, str, end, " \t");
}

/* parse a line like 'a=rtpmap:0 PCMU/8000', 'a=fmtp:112 octet-align=1; mode-set=4', 'a=ptime:20'.
 * The src should point at the character after 'a=', e.g. at the start of 'rtpmap', 'fmtp', 'ptime'
 */
static int sdp_parse_attrib(struct osmo_sdp_msg *sdp, const struct token *src)
{
	unsigned int payload_type;
	struct osmo_sdp_codec *codec;
	enum osmo_sdp_media_direcion_e mdir;
	const char *line_end = get_line_end(src);
	const char *next;
	int nr;
	struct token t;

	if ((next = token_is_attrib(src, OSMO_SDP_STR_RTPMAP, ':'))) {
		/* "a=rtpmap:96 AMR/8000" */
		next_token(&t, next, line_end);
		next = token_to_int(&nr, &t, 10, 0, 127);
		if (next != t.end)
			return -EINVAL;
		payload_type = nr;

		token_next(&t, next, line_end, " \t/");
		if (t.start >= t.end)
			return -EINVAL;
		next = t.end;

		codec = find_or_create_payload_type(sdp, payload_type);
		token_copy(codec, &codec->encoding_name, &t);

		token_next(&t, next, line_end, " \t/");
		if (t.start >= t.end) {
			/* There should be a "/8000" here. If it is missing, let's not be strict about it. */
			codec->rate = 8000;
		} else {
			next = token_to_int(&nr, &t, 10, 0, INT_MAX);
			if (next != t.end)
				return -EINVAL;
		}

		/* optional channel number, i.e. another "/1" */
		token_next(&t, t.end, line_end, " \t/");
		if (t.end > t.start) {
			int channels;
			next = token_to_int(&channels, &t, 10, 0, INT_MAX);
			if (next != t.end)
				return -EINVAL;
			if (channels != 1)
				return -ENOTSUP;
		}
	}

	else if ((next = token_is_attrib(src, OSMO_SDP_STR_FMTP, ':'))) {
		/* "a=fmtp:112 octet-align=1;mode-set=0,1,2,3" */
		next_token(&t, next, line_end);
		next = token_to_int(&nr, &t, 10, 0, 127);
		if (next != t.end)
			return -EINVAL;
		payload_type = nr;

		codec = find_or_create_payload_type(sdp, payload_type);

		/* "octet-align..." token */
		next_token(&t, next, line_end);
		if (t.start >= line_end)
			return -EINVAL;

		t.end = line_end;
		token_copy(codec, &codec->fmtp, &t);
	}

	else if ((next = token_is_attrib(src, OSMO_SDP_STR_PTIME, ':'))) {
		/* "a=ptime:20" */
		next_token(&t, next, line_end);
		next = token_to_int(&nr, &t, 10, 1, INT_MAX);
		if (!next)
			return -EINVAL;
		/* RFC8866 6.4: it could also be a 'real' nr, but we don't support that. */
		if (next < t.end)
			return -ENOTSUP;
		sdp->ptime = nr;
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
static int sdp_parse_media_description(struct osmo_sdp_msg *sdp, const struct token *src)
{
	unsigned int port;
	struct token t;
	const char *line_end = get_line_end(src);
	if (sscanf(src->start, "audio %u RTP/AVP", &port) < 1)
		return -ENOTSUP;

	if (port > 0xffff)
		return -EINVAL;

	sdp->rtp.port = port;

	/* skip "audio 12345 RTP/AVP ", i.e. 3 tokens on */
	next_token(&t, src->start, line_end);
	next_token(&t, t.end, line_end);
	next_token(&t, t.end, line_end);

	/* first payload type number */
	next_token(&t, t.end, line_end);

	/* Parse listing of payload type numbers after "RTP/AVP" */
	while (t.start < line_end) {
		unsigned int payload_type;
		struct osmo_sdp_codec *codec;
		const char *encoding_name;
		if (sscanf(t.start, "%u", &payload_type) < 1)
			return -EINVAL;

		codec = find_or_create_payload_type(sdp, payload_type);

		/* Fill in encoding name for fixed payload types */
		encoding_name = get_value_string_or_null(fixed_payload_types, codec->payload_type);
		if (encoding_name)
			osmo_talloc_replace_string(codec, &codec->encoding_name, encoding_name);

		next_token(&t, t.end, line_end);
	}

	return 0;
}

/* parse a line like 'c=IN IP4 192.168.11.151' starting after the '=' */
static int sdp_parse_connection_info(struct osmo_sdp_msg *sdp, const struct token *src)
{
	char ipv[10];
	char addr_str[INET6_ADDRSTRLEN];
	if (sscanf(src->start, "IN %s %s", ipv, addr_str) < 2)
		return -EINVAL;

	if (strcmp(ipv, "IP4") && strcmp(ipv, "IP6"))
		return -ENOTSUP;

	return osmo_sockaddr_str_from_str(&sdp->rtp, addr_str, sdp->rtp.port);
}

/* parse a line like 'o=jdoe 3724394400 3724394405 IN IP4 198.51.100.1' starting after the '=' */
static int sdp_parse_origin(struct osmo_sdp_msg *sdp, const struct token *src)
{
	struct token t;
	char addr_str[INET6_ADDRSTRLEN + 1] = {};
	const char *line_end = get_line_end(src);

	next_token(&t, src->start, line_end);
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

static int sdp_parse_session_name(struct osmo_sdp_msg *sdp, const struct token *src)
{
	struct token t = *src;
	t.end = get_line_end(src);
	if (sdp->session_name)
		talloc_free(sdp->session_name);
	if (t.start >= t.end)
		sdp->session_name = NULL;
	else
		token_copy(sdp, &sdp->session_name, &t);
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
 * When NULL is returned and if ret is non-NULL, details of the error are returned in ret->*.
 */
struct osmo_sdp_msg *osmo_sdp_msg_decode(void *ctx, const char *src_str, int src_str_len,
					 struct osmo_sdp_msg_decode_ret *ret)
{
	struct osmo_sdp_msg *sdp;
	bool found_message_start = false;
	struct token src = {
		.start = src_str,
		.end = src_str + (src_str_len < 0 ? strlen(src_str) : src_str_len),
	};

	if (ret)
		*ret = (struct osmo_sdp_msg_decode_ret){};

	sdp = osmo_sdp_msg_alloc(ctx);

	for (; src.start && src.start < src.end && *src.start; src.start++) {
		char attrib;
		int rc = 0;
		struct token t;

		if (*src.start == '\r' || *src.start == '\n')
			continue;

		t.start = src.start;
		t.end = get_line_end(&src);

		if (!found_message_start) {
			/* An SDP message must start with a line saying "v=0". */
			if (strncmp("v=0", t.start, t.end - t.start)) {
				/* report the error */
				if (ret) {
					*ret = (struct osmo_sdp_msg_decode_ret){
						.rc = -EINVAL,
						.error = {
							.at_input_str = t.start,
							.at_input_str_len = t.end - t.start,
						},
						.src_remain = t.end,
					};
				}
				talloc_free(sdp);
				return NULL;
			}
			found_message_start = true;
			goto next_line;
		}

		/* Expecting only lines starting with 'X='. Not being too strict about it is probably alright. */
		if (t.start + 1 >= t.end || t.start[1] != '=')
			goto next_line;

		attrib = *t.start;
		t.start += 2;
		switch (attrib) {
			/* a=... */
			case 'a':
				rc = sdp_parse_attrib(sdp, &t);
				break;
			case 'm':
				rc = sdp_parse_media_description(sdp, &t);
				break;
			case 'c':
				rc = sdp_parse_connection_info(sdp, &t);
				break;
			case 'o':
				rc = sdp_parse_origin(sdp, &t);
				break;
			case 's':
				rc = sdp_parse_session_name(sdp, &t);
				break;
			default:
				/* ignore any other parameters */
				break;
		}

		if (rc) {
			if (ret) {
				/* shift back to include the 'x=' part as well */
				t.start -= 2;
				*ret = (struct osmo_sdp_msg_decode_ret){
					.rc = rc,
					.error = {
						.at_input_str = t.start,
						.at_input_str_len = t.end - t.start,
					},
					.src_remain = t.end,
				};
			}
			talloc_free(sdp);
			return NULL;
		}

next_line:
		src.start = t.end;
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

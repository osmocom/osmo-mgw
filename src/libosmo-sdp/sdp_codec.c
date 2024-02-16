/* Codec management in SDP messages. */
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

#include <ctype.h>

#include <osmocom/core/utils.h>

#include <osmocom/sdp/fmtp.h>
#include <osmocom/sdp/sdp_codec.h>
#include <osmocom/sdp/sdp_internal.h>

struct osmo_sdp_codec *osmo_sdp_codec_alloc(void *ctx)
{
	return talloc_zero(ctx, struct osmo_sdp_codec);
}

int osmo_sdp_codec_set(struct osmo_sdp_codec *c,
		       int8_t payload_type, const char *encoding_name, unsigned int rate, const char *fmtp)
{
	c->rate = rate;
	osmo_sdp_codec_set_encoding_name(c, encoding_name);
	osmo_sdp_codec_set_fmtp(c, fmtp);
	c->payload_type = payload_type;
	return 0;
}

int osmo_sdp_codec_set_encoding_name(struct osmo_sdp_codec *c, const char *encoding_name)
{
	osmo_talloc_replace_string(c, &c->encoding_name, encoding_name);
	return 0;
}

int osmo_sdp_codec_set_fmtp(struct osmo_sdp_codec *c, const char *fmtp)
{
	osmo_talloc_replace_string(c, &c->fmtp, fmtp);
	return 0;
}

bool osmo_sdp_codec_is_set(const struct osmo_sdp_codec *a)
{
	return a && a->encoding_name && a->encoding_name[0];
}

int osmo_sdp_codec_to_str_buf(char *buf, size_t buflen, const struct osmo_sdp_codec *codec)
{
	struct osmo_strbuf sb = { .buf = buf, .len = buflen };
	if (!codec) {
		OSMO_STRBUF_PRINTF(sb, "NULL");
		return sb.chars_needed;
	}
	if (codec->encoding_name && codec->encoding_name[0])
		OSMO_STRBUF_PRINTF(sb, "%s", codec->encoding_name);
	if (codec->rate != 8000)
		OSMO_STRBUF_PRINTF(sb, "/%u", codec->rate);
	if (codec->fmtp && codec->fmtp[0])
		OSMO_STRBUF_PRINTF(sb, ":%s", codec->fmtp);
	OSMO_STRBUF_PRINTF(sb, "#%d", codec->payload_type);
	return sb.chars_needed;
}

char *osmo_sdp_codec_to_str_c(void *ctx, const struct osmo_sdp_codec *codec)
{
	OSMO_NAME_C_IMPL(ctx, 32, "osmo_sdp_codec_to_str_c-ERROR", osmo_sdp_codec_to_str_buf, codec)
}

/*! Parse a codec string as from osmo_sdp_codec_to_str_buf() back to an osmo_sdp_codec struct.
 * Write the parsed result to *dst, using ctx as talloc parent.
 * The input string is like <encoding_name>[:<fmtp-string>][#<payload-type-nr>]
 * for example:
 *    "FOO:my-fmtp=1;my-other-fmtp=2#42"
 * Note that ';' are separators only within the fmtp string. This function does not separate those. In above example,
 * the fmtp string part is "my-fmtp=val;my-other-fmtp=val2" and ends up in dst->ftmp as-is.
 * Parse at most str_len characters, or the entire string when str_len < 0 or str_len > strlen(str).
 * Return 0 on success, negative on failure. */
int osmo_sdp_codec_from_str(struct osmo_sdp_codec *dst, const char *str, int str_len)
{
	const char *pos = str;
	const char *str_end = str + (str_len >= 0 ? str_len : strlen(str));
	const char *p2;

	struct token token_encoding_name = {};
	struct token token_rate = {};
	struct token token_fmtp = {};
	struct token token_payload_type = {};

	struct token *new_t = NULL;
	/* start with the encoding name */
	struct token *t = &token_encoding_name;
	t->start = pos;

	for (; pos < str_end; pos++) {
		new_t = NULL;
		switch (*pos) {
		case '/':
			new_t = &token_rate;
			break;
		case ':':
			new_t = &token_fmtp;
			break;
		case '#':
			/* count this '#' only if there is no other one following. It might be part of a fmtp. */
			for (p2 = pos + 1; p2 < str_end; p2++)
				if (*p2 == '#')
					break;
			if (p2 < str_end && *p2 == '#')
				break;
			/* This is the last '#' in the string. Count it only when a digit follows. */
			if (!isdigit(pos[1]))
				break;
			new_t = &token_payload_type;
			break;
		default:
			break;
		}
		if (!new_t)
			continue;
		/* If we already have a token for a start character, don't start it again. These may be part of a fmtp
		 * string. */
		if (new_t == t)
			continue;
		t->end = pos;
		t = new_t;
		t->start = pos + 1;
	}
	t->end = pos;

	token_copy(dst, &dst->encoding_name, &token_encoding_name);
	if (token_rate.start)
		dst->rate = atoi(token_rate.start);
	else
		dst->rate = 8000;
	token_copy(dst, &dst->fmtp, &token_fmtp);
	if (token_payload_type.start)
		dst->payload_type = atoi(token_payload_type.start);
	return 0;
}

/* Compare both payload type number and fmtp string 1:1 */
const struct osmo_sdp_codec_cmp_flags osmo_sdp_codec_cmp_exact = {
	.payload_type = true,
	.encoding_name = true,
	.rate = true,
	.fmtp = OSMO_SDP_CMP_EXACT,
};

/* Ignore payload type number; compare fmtp string by meaning when possible, else 1:1 */
const struct osmo_sdp_codec_cmp_flags osmo_sdp_codec_cmp_equivalent = {
	.payload_type = false,
	.encoding_name = true,
	.rate = true,
	.fmtp = OSMO_SDP_CMP_EQUIVALENT,
};

/* Compare only encoding name */
const struct osmo_sdp_codec_cmp_flags osmo_sdp_codec_cmp_name = {
	.payload_type = false,
	.encoding_name = true,
	.rate = false,
	.fmtp = OSMO_SDP_CMP_IGNORE,
};

extern const struct osmo_sdp_codec_cmp_flags osmo_sdp_codec_cmp_equivalent;
static inline int strcmp_safe(const char *a, const char *b)
{
	return strcmp(a ? : "", b ? : "");
}

/*! Compare encoding name, rate and fmtp, returning cmp result: -1 if a < b, 0 if a == b, 1 if a > b.
 * Compare as defined in 'cmp':
 * If cmpf->payload_type is false, ignore payload_type numbers.
 * If cmpf->rate is false, ignore rate.
 * If cmpf->fmtp is OSMO_SDP_CMP_IGNORE, ignore fmtp strings.
 * If cmpf->fmtp is OSMO_SDP_CMP_EXACT, use strcmp() to match fmtp 1:1.
 * If cmpf->fmtp is OSMO_SDP_CMP_EQUIVALENT, use specific fmtp knowledge to match equivalent entries;
 *  - AMR fmtp matching is done by osmo_sdp_fmtp_amr_match().
 *  - for all others, still compare fmtp 1:1.
 */
int osmo_sdp_codec_cmp(const struct osmo_sdp_codec *a, const struct osmo_sdp_codec *b,
		       const struct osmo_sdp_codec_cmp_flags *cmpf)
{
	int cmp;
	if (a == b)
		return 0;
	if (!a)
		return -1;
	if (!b)
		return 1;

	if (!cmpf)
		cmpf = &osmo_sdp_codec_cmp_exact;

	if (cmpf->encoding_name) {
		cmp = strcmp_safe(a->encoding_name, b->encoding_name);
		if (cmp)
			return cmp;
	}

	if (cmpf->rate) {
		cmp = OSMO_CMP(a->rate, b->rate);
		if (cmp)
			return cmp;
	}

	switch (cmpf->fmtp) {
	default:
	case OSMO_SDP_CMP_EXACT:
		cmp = strcmp_safe(a->fmtp, b->fmtp);
		break;

	case OSMO_SDP_CMP_EQUIVALENT:
		/* In case of AMR, allow logical matching; we only need to do that if the strings differ. */
		cmp = strcmp_safe(a->fmtp, b->fmtp);
		if (cmp
		    && !strcmp_safe("AMR", a->encoding_name)
		    && osmo_sdp_fmtp_amr_match(a->fmtp, b->fmtp))
			cmp = 0;
		break;

	case OSMO_SDP_CMP_IGNORE:
		cmp = 0;
		break;
	}
	if (cmp)
		return cmp;

	if (cmpf->payload_type)
		cmp = OSMO_CMP(a->payload_type, b->payload_type);

	return cmp;
}

/* Public API for codec management in SDP messages. */
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
#pragma once

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/talloc.h>

/* RFC-8866 5.14 and 6.6.
 *
 * Represent the items describing an SDP codec entry, as in:
 *
 *   m=audio 1234 RTP/AVP <payload_type>
 *   a=rtpmap:<payload_type> <encoding-name>/<clock-rate>
 *   a=fmtp:<payload_type> <fmtp>
 *
 * For example:
 *
 *   m=audio 1234 RTP/AVP 98
 *   a=rtpmap:98 AMR/8000
 *   a=fmtp:98 octet-align=1;mode-set=0,2,4,7
 */
struct osmo_sdp_codec {
	/* Payload type number ("payload-type"), like 3 for GSM-FR. Limited to 0..127. */
	int8_t payload_type;

	/* Encoding name like "GSM", "AMR", "GSM-EFR".
	 *
	 * RFC-8866 defines no length limit on the encoding name. This API leaves it up to the caller to provide
	 * sufficient space, via the SDP_SIZES_* definitions.
	 *
	 * encoding-name = token
	 * token = 1*(token-char)
	 * token-char = ALPHA / DIGIT
	 *                    / "!" / "#" / "$" / "%" / "&"
	 *                    / "'" ; (single quote)
	 *                    / "*" / "+" / "-" / "." / "^" / "_"
	 *                    / "`" ; (Grave accent)
	 */
	char *encoding_name;

	/* Samplerate ("clock-rate"), usually 8000 for GSM. */
	unsigned int rate;

	/* Codec parameters as supplied in SDP line 'a=fmtp:<payload-type> <format-specific-params>'. This holds only
	 * the 'format-specific-params' bytestring. For example, for SDP line 'a=fmtp:123 param1=val1;param2=val2', this
	 * holds only the , "param1=val1;param2=val2" part. For the buffer size, see fmtp_size. */
	char *fmtp;

	/* Entry used by osmo_sdp_codec_list. */
	struct llist_head entry;

	/* For future extension, always set to false. */
	bool v2;
};

struct osmo_sdp_codec *osmo_sdp_codec_alloc(void *ctx);

int osmo_sdp_codec_set(struct osmo_sdp_codec *c,
		       int8_t payload_type, const char *encoding_name, unsigned int rate, const char *fmtp);
int osmo_sdp_codec_set_encoding_name(struct osmo_sdp_codec *c, const char *encoding_name);
int osmo_sdp_codec_set_fmtp(struct osmo_sdp_codec *c, const char *fmtp);

bool osmo_sdp_codec_is_set(const struct osmo_sdp_codec *a);

int osmo_sdp_codec_to_str_buf(char *buf, size_t buflen, const struct osmo_sdp_codec *codec);
char *osmo_sdp_codec_to_str_c(void *ctx, const struct osmo_sdp_codec *codec);

int osmo_sdp_codec_from_str(struct osmo_sdp_codec *dst, const char *str, int str_len);

enum osmo_sdp_cmp {
	OSMO_SDP_CMP_IGNORE = 0,
	OSMO_SDP_CMP_EQUIVALENT,
	OSMO_SDP_CMP_EXACT,
};

/*! Indicate how to match SDP codecs to various osmo_sdp_*() functions.
 * Callers may define own flags, or use predefined instances:
 * osmo_sdp_codec_cmp_exact, osmo_sdp_codec_cmp_equivalent, ...
 *
 * For example, to trigger some action if any item has changed, set all items to true / OSMO_SDP_CMP_EXACT (see
 * osmo_sdp_codec_cmp_exact).
 * To find codecs that are the same between two SDP sessions, set payload_type=false and fmtp=OSMO_SDP_CMP_EQUIVALENT
 * (see osmo_sdp_codec_cmp_equivalent).
 * To just list all contained "AMR" codecs, set only encoding_name=true (see osmo_sdp_codec_cmp_name).
 */
struct osmo_sdp_codec_cmp_flags {
	/*! true = compare payload type numbers 1:1; false = ignore. */
	bool payload_type;
	/*! true = compare encoding_name 1:1; false = ignore. */
	bool encoding_name;
	/*! true = compare rate 1:1; false = ignore. */
	bool rate;
	/*! OSMO_SDP_CMP_IGNORE = ignore fmtp;
	 * OSMO_SDP_CMP_EQUIVALENT = use osmo_sdp_fmtp_amr_match() for AMR, otherwise compare 1:1;
	 * OSMO_SDP_CMP_EXACT = compare 1:1.
	 */
	enum osmo_sdp_cmp fmtp;
};

extern const struct osmo_sdp_codec_cmp_flags osmo_sdp_codec_cmp_exact;
extern const struct osmo_sdp_codec_cmp_flags osmo_sdp_codec_cmp_equivalent;
extern const struct osmo_sdp_codec_cmp_flags osmo_sdp_codec_cmp_name;

int osmo_sdp_codec_cmp(const struct osmo_sdp_codec *a, const struct osmo_sdp_codec *b,
		       const struct osmo_sdp_codec_cmp_flags *cmp);

/* Public API for SDP message encoding and decoding */
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

#include <osmocom/core/sockaddr_str.h>

#include <osmocom/sdp/sdp_codec.h>
#include <osmocom/sdp/sdp_codec_list.h>

/* Media Direction Attributes "a=recvonly", "a=sendrecv", "a=sendonly", "a=inactive" RFC-8866 6.7. */
enum osmo_sdp_media_direcion_e {
	OSMO_SDP_MDIR_UNSET = 0,
	OSMO_SDP_MDIR_RECVONLY = 1,
	OSMO_SDP_MDIR_SENDRECV = 2,
	OSMO_SDP_MDIR_SENDONLY = 3,
	OSMO_SDP_MDIR_INACTIVE = 4,
};

/* Session Description Protocol (SDP) message, RFC-8866. */
struct osmo_sdp_msg {
	/* 5.2 Origin ("o="). */
	struct {
		struct osmo_sockaddr_str addr;
		char *username;
		char *sess_id;
		char *sess_version;
	} origin;

	/* 5.3 Session Name ("s="). */
	char *session_name;

	/* 5.7 Connection Information ("c=") and port from 5.14 Media Descriptions ("m="). */
	struct osmo_sockaddr_str rtp;

	/* 5.9. Time Active ("t="). */
	struct {
		int64_t start;
		int64_t stop;
	} time_active;

	/* 6.4 "a=ptime:<val>". */
	unsigned int ptime;

	/* 6.7 "a=sendrecv"... */
	enum osmo_sdp_media_direcion_e media_direction;

	/* List of codecs defined in the SDP message.
	 * This should not be NULL -- osmo_sdp_msg_alloc() returns an empty osmo_sdp_codec_list instance, ready for
	 * adding codecs.
	 * Combination of:
	 * - payload_type numbers from 5.14 Media Descriptions ("m="),
	 * - 6.6 "a=rtpmap",
	 * - 6.15 Format Parameters "a=fmtp".
	 */
	struct osmo_sdp_codec_list *codecs;

	/* For future extension, always set to false. */
	bool v2;
};

struct osmo_sdp_msg_decode_ret {
	int rc;
	/* If rc != 0 */
	struct {
		/* Point at the position that caused the error, in the src string. */
		const char *at_input_str;
		/* Nr of characters at *src_str that are relevant to the error. */
		size_t at_input_str_len;
	} error;
	/* Pointer to the remaining part of src after parsing one SDP message.
	 * For example, in MGCP, there may be multiple SDP messages concatenated. */
	const char *src_remain;
};

struct osmo_sdp_msg *osmo_sdp_msg_alloc(void *ctx);

struct osmo_sdp_msg *osmo_sdp_msg_decode(void *ctx, const char *src_str, int src_str_len,
					 struct osmo_sdp_msg_decode_ret *ret);

int osmo_sdp_msg_encode_buf(char *dst, size_t dst_size, const struct osmo_sdp_msg *sdp);
char *osmo_sdp_msg_encode_c(void *ctx, const struct osmo_sdp_msg *sdp);

int osmo_sdp_msg_to_str_buf(char *buf, size_t buflen, const struct osmo_sdp_msg *sdp, bool summarize);
char *osmo_sdp_msg_to_str_c(void *ctx, const struct osmo_sdp_msg *sdp, bool summarize);

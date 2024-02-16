/* Public API for codec management in SDP messages: list of struct osmo_sdp_codec. */
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

#include <osmocom/sdp/sdp_codec.h>

struct osmo_sdp_codec_list {
	struct llist_head list;

	/* For future extension, always set to false. */
	bool v2;
};

struct osmo_sdp_codec_list *osmo_sdp_codec_list_alloc(void *ctx);
void osmo_sdp_codec_list_free_items(struct osmo_sdp_codec_list *codec_list);

int8_t osmo_sdp_codec_list_get_unused_dyn_pt_nr(const struct osmo_sdp_codec_list *codec_list, int8_t suggest_pt_nr);

struct osmo_sdp_codec *osmo_sdp_codec_list_add_empty(struct osmo_sdp_codec_list *codec_list);
struct osmo_sdp_codec *osmo_sdp_codec_list_add(struct osmo_sdp_codec_list *codec_list,
					       const struct osmo_sdp_codec *codec,
					       const struct osmo_sdp_codec_cmp_flags *once, bool pick_unused_pt_nr);

int osmo_sdp_codec_list_remove(struct osmo_sdp_codec_list *codec_list, const struct osmo_sdp_codec *codec,
			       const struct osmo_sdp_codec_cmp_flags *cmpf);
void osmo_sdp_codec_list_remove_entry(struct osmo_sdp_codec *codec);

#define osmo_sdp_codec_list_foreach(STRUCT_SDP_CODEC_P, SDP_CODEC_LIST) \
	llist_for_each_entry(STRUCT_SDP_CODEC_P, &(SDP_CODEC_LIST)->list, entry)
#define osmo_sdp_codec_list_foreach_safe(STRUCT_SDP_CODEC_P, SAFE_P, SDP_CODEC_LIST) \
	llist_for_each_entry_safe(STRUCT_SDP_CODEC_P, SAFE_P, &(SDP_CODEC_LIST)->list, entry)

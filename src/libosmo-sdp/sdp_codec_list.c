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

#include <string.h>

#include <osmocom/core/utils.h>

#include <osmocom/sdp/sdp_codec_list.h>

struct osmo_sdp_codec_list *osmo_sdp_codec_list_alloc(void *ctx)
{
	struct osmo_sdp_codec_list *codec_list = talloc_zero(ctx, struct osmo_sdp_codec_list);
	INIT_LLIST_HEAD(&codec_list->list);
	return codec_list;
}

/*! Free all items contained in this list, do not free the list itself (leave an empty list). */
void osmo_sdp_codec_list_free_items(struct osmo_sdp_codec_list *codec_list)
{
	struct osmo_sdp_codec *c;
	while ((c = osmo_sdp_codec_list_first(codec_list))) {
		osmo_sdp_codec_list_remove_entry(c);
		talloc_free(c);
	}
}

struct osmo_sdp_codec *osmo_sdp_codec_list_add_empty(struct osmo_sdp_codec_list *codec_list)
{
	struct osmo_sdp_codec *c = osmo_sdp_codec_alloc(codec_list);
	llist_add_tail(&c->entry, &codec_list->list);
	return c;
}

int8_t osmo_sdp_codec_list_get_unused_dyn_pt_nr(const struct osmo_sdp_codec_list *codec_list, int8_t suggest_pt_nr)
{
	bool present[127 - 96 + 1] = {};
	const struct osmo_sdp_codec *c;
	bool suggest_pt_nr_exists = false;
	int i;

	osmo_sdp_codec_list_foreach (c, codec_list) {
		if (c->payload_type >= 96 && c->payload_type <= 127)
			present[c->payload_type - 96] = true;
		if (c->payload_type == suggest_pt_nr)
			suggest_pt_nr_exists = true;
	}

	if (!suggest_pt_nr_exists)
		return suggest_pt_nr;

	/* The desired number is already taken, see which of the dynamic types is not taken yet */
	for (i = 96; i <= 127; i++) {
		/* For dynamic allocations, skip these predefined numbers, taken from enum mgcp_codecs:
		 * CODEC_GSMEFR_8000_1 = 110,	3GPP TS 48.103 table 5.4.2.2.1
		 * CODEC_GSMHR_8000_1 = 111,	3GPP TS 48.103 table 5.4.2.2.1
		 * CODEC_AMR_8000_1 = 112,		3GPP TS 48.103 table 5.4.2.2.1
		 * CODEC_AMRWB_16000_1 = 113,	3GPP TS 48.103 table 5.4.2.2.1
		 * CODEC_CLEARMODE = 120,		3GPP TS 48.103 table 5.4.2.2.1
		 */
		if (i >= 110 && i <= 113)
			continue;
		else if (i == 120)
			continue;

		if (!present[i - 96])
			return i;
	}

	return -1;
}

/*! Allocate a new entry in codec_list and copy codec's values to it.
 * If once is NULL, unconditionally add a new codec entry.
 * If once is non-NULL, do not add a new entry when the list already contains a matching entry; for determining a match,
 * use the once->flags. For example, if once = &osmo_sdp_codec_cmp_equivalent, look up if codec_list has a similar
 * codec, and add the new entry only if it is not listed.
 * See osmo_sdp_codec_cmp() and osmo_sdp_fmtp_amr_match() for details.
 * Return the new entry, or the equivalent entry already present in the list.
 */
struct osmo_sdp_codec *osmo_sdp_codec_list_add(struct osmo_sdp_codec_list *codec_list,
					       const struct osmo_sdp_codec *codec,
					       const struct osmo_sdp_codec_cmp_flags *once, bool pick_unused_pt_nr)
{
	struct osmo_sdp_codec *new_entry;
	int8_t payload_type;

	if (once) {
		struct osmo_sdp_codec *c;
		osmo_sdp_codec_list_foreach (c, codec_list)
			if (!osmo_sdp_codec_cmp(codec, c, once))
				return c;
	}

	/* Adjust payload_type number? */
	payload_type = codec->payload_type;
	if (pick_unused_pt_nr)
		payload_type = osmo_sdp_codec_list_get_unused_dyn_pt_nr(codec_list, payload_type);

	/* Take provided values, possibly modified payload_type */
	new_entry = osmo_sdp_codec_list_add_empty(codec_list);
	osmo_sdp_codec_set(new_entry, payload_type, codec->encoding_name, codec->rate, codec->fmtp);

	return new_entry;
}

/*! Remove and free all entries from the codec_list that match the given codec according to osmo_sdp_codec_cmp(cmpf).
 * Return the number of entries freed. */
int osmo_sdp_codec_list_remove(struct osmo_sdp_codec_list *codec_list, const struct osmo_sdp_codec *codec,
			       const struct osmo_sdp_codec_cmp_flags *cmpf)
{
	struct osmo_sdp_codec *i, *j;
	int count = 0;
	osmo_sdp_codec_list_foreach_safe (i, j, codec_list) {
		if (osmo_sdp_codec_cmp(i, codec, cmpf))
			continue;
		osmo_sdp_codec_list_remove_entry(i);
		talloc_free(i);
		count++;
	}
	return count;
}

/*! Unlink an osmo_sdp_codec from an osmo_sdp_codec_list, if the codec instance is part of a list. Do not free the
 * struct osmo_sdp_codec.
 */
void osmo_sdp_codec_list_remove_entry(struct osmo_sdp_codec *codec)
{
	/* The codec is not part of a list in these cases:
	 * After talloc_zero(), next == NULL.
	 * After llist_del(), next == LLIST_POISON1. */
	if (codec->entry.next != NULL
	    && codec->entry.next != (struct llist_head *)LLIST_POISON1)
		llist_del(&codec->entry);
}

static inline int strcmp_safe(const char *a, const char *b)
{
	return strcmp(a ? : "", b ? : "");
}

/*! Short single-line representation of a list of SDP audio codecs, convenient for logging.
 * If summarize == true, collapse variants of the same encoding_name (in practice, don't show all of the various AMR
 * fmtp permutations). If summarize == false, print each and every codec in full.
 */
int osmo_sdp_codec_list_to_str_buf(char *buf, size_t buflen, const struct osmo_sdp_codec_list *codec_list, bool summarize)
{
	struct osmo_strbuf sb = { .buf = buf, .len = buflen };
	const struct osmo_sdp_codec *codec;
	bool first;

	if (llist_empty(&codec_list->list)) {
		OSMO_STRBUF_PRINTF(sb, "(no-codecs)");
		return sb.chars_needed;
	}

	if (!summarize) {
		first = true;
		osmo_sdp_codec_list_foreach (codec, codec_list) {
			if (!first)
				OSMO_STRBUF_PRINTF(sb, " ");
			OSMO_STRBUF_APPEND(sb, osmo_sdp_codec_to_str_buf, codec);
			first = false;
		}
		return sb.chars_needed;
	}

	/* summarize */
	first = true;
	osmo_sdp_codec_list_foreach (codec, codec_list) {
		const struct osmo_sdp_codec *c2;
		int count = 0;
		bool various_pt = false;

		/* When this encoding name has been handled before, skip it now. */
		osmo_sdp_codec_list_foreach (c2, codec_list) {
			if (c2 == codec)
				break;
			if (!strcmp_safe(codec->encoding_name, c2->encoding_name)) {
				count = 1;
				break;
			}
		}
		if (count)
			continue;

		/* Not seen this encoding_name before, count total occurences */
		count = 0;
		osmo_sdp_codec_list_foreach (c2, codec_list) {
			if (!strcmp_safe(codec->encoding_name, c2->encoding_name)) {
				count++;
				if (codec->payload_type != c2->payload_type)
					various_pt = true;
			}
		}

		if (!first)
			OSMO_STRBUF_PRINTF(sb, " ");
		if (count > 1)
			OSMO_STRBUF_PRINTF(sb, "%d*", count);
		OSMO_STRBUF_PRINTF(sb, "%s", codec->encoding_name);
		if (!various_pt)
			OSMO_STRBUF_PRINTF(sb, "#%d", codec->payload_type);
		first = false;
	}
	return sb.chars_needed;
}

char *osmo_sdp_codec_list_to_str_c(void *ctx, const struct osmo_sdp_codec_list *codec_list, bool summarize)
{
	OSMO_NAME_C_IMPL(ctx, 128, "osmo_sdp_codec_list_to_str_c-ERROR", osmo_sdp_codec_list_to_str_buf, codec_list, summarize)
}

/*! Return first entry, or NULL if the list is empty. */
struct osmo_sdp_codec *osmo_sdp_codec_list_first(const struct osmo_sdp_codec_list *list)
{
	return llist_first_entry_or_null(&list->list, struct osmo_sdp_codec, entry);
}

/*! Move entries matching 'codec' to the front of the list. Matching is done via osmo_sdp_codec_cmp(cmpf).
 * Return the number of matches that are now at the front of the list.
 */
int osmo_sdp_codec_list_move_to_first(struct osmo_sdp_codec_list *codec_list, const struct osmo_sdp_codec *codec,
				      const struct osmo_sdp_codec_cmp_flags *cmpf)
{
	struct llist_head *head = &codec_list->list;
	struct osmo_sdp_codec *i, *j;
	int matches_found = 0;
	osmo_sdp_codec_list_foreach_safe (i, j, codec_list) {
		if (osmo_sdp_codec_cmp(codec, i, cmpf))
			continue;
		/* It's a match, move to the head */
		osmo_sdp_codec_list_remove_entry(i);
		llist_add(&i->entry, head);
		matches_found++;
		/* If more matches show up later, add them *after* the one just moved to the front. */
		head = &i->entry;
	}

	return matches_found;
}

/*! Compare two lists of SDP codecs, returning cmp result: -1 if a < b, 0 if a == b, 1 if a > b.
 * The two lists are compared in order, item by item, using osmo_sdp_codec_cmp(cmpf).
 */
int osmo_sdp_codec_list_cmp(const struct osmo_sdp_codec_list *a, const struct osmo_sdp_codec_list *b,
			    const struct osmo_sdp_codec_cmp_flags *cmpf)
{
	const struct llist_head *a_start;
	const struct llist_head *a_pos;
	const struct llist_head *b_start;
	const struct llist_head *b_pos;
	int cmp;

	/* NULL pointer == empty list */
	if (a && llist_empty(&a->list))
		a = NULL;
	if (b && llist_empty(&a->list))
		b = NULL;

	/* are one or both empty? */
	if (a == b)
		return 0;
	if (!a)
		return -1;
	if (!b)
		return 1;

	/* compare item by item */
	a_start = &a->list;
	a_pos = a_start->next;
	b_start = &b->list;
	b_pos = b_start->next;

	for (; a_pos != a_start; a_pos = a_pos->next, b_pos = b_pos->next) {
		const struct osmo_sdp_codec *codec_a;
		const struct osmo_sdp_codec *codec_b;

		if (b_pos == b_start) {
			/* there is an entry in a, but b has already ended. mismatch. */
			return 1;
		}

		codec_a = llist_entry(a_pos, struct osmo_sdp_codec, entry);
		codec_b = llist_entry(b_pos, struct osmo_sdp_codec, entry);
		cmp = osmo_sdp_codec_cmp(codec_a, codec_b, cmpf);
		if (cmp)
			return cmp;
	}

	if (b_pos != b_start) {
		/* 'a' has ended, but 'b' has more items. mismatch. */
		return -1;
	}

	/* full match. */
	return 0;
}

/*! Leave only those codecs in 'dst' that are also present in 'other'.
 * The matching is made by osmo_sdp_codec_cmp(cmpf).
 * If translate_payload_type_numbers has an effect if 'dst' and 'other' have mismatching payload_type numbers for the
 * same SDP codec descriptions. If translate_payload_type_numbers is true, take the payload_type numbers from 'other'.
 * If false, keep payload_type numbers in 'dst' unchanged. */
void osmo_sdp_codec_list_intersection(struct osmo_sdp_codec_list *dst, const struct osmo_sdp_codec_list *other,
				      const struct osmo_sdp_codec_cmp_flags *cmpf,
				      bool translate_payload_type_numbers)
{
	struct osmo_sdp_codec *i, *j;
	osmo_sdp_codec_list_foreach_safe (i, j, dst) {
		struct osmo_sdp_codec *o;
		struct osmo_sdp_codec *match = NULL;
		osmo_sdp_codec_list_foreach (o, other) {
			if (osmo_sdp_codec_cmp(i, o, cmpf))
				continue;
			match = o;
			break;
		}

		if (!match) {
			osmo_sdp_codec_list_remove_entry(i);
			talloc_free(i);
			continue;
		}

		if (translate_payload_type_numbers)
			i->payload_type = match->payload_type;
	}
}

/* Find an entry for the given payload_type number in the given list of codecs. */
struct osmo_sdp_codec *osmo_sdp_codec_list_by_payload_type(struct osmo_sdp_codec_list *codec_list, int8_t payload_type)
{
	struct osmo_sdp_codec *codec;
	osmo_sdp_codec_list_foreach(codec, codec_list) {
		if (codec->payload_type == payload_type)
			return codec;
	}
	return NULL;
}

bool osmo_sdp_codec_list_is_empty(const struct osmo_sdp_codec_list *codec_list)
{
	if (!codec_list)
		return true;
	return llist_empty(&codec_list->list);
}

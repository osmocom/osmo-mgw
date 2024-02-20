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

#include <stddef.h>
#include <ctype.h>
#include <limits.h>
#include <errno.h>

#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>

#include <osmocom/sdp/sdp_internal.h>

/* Copy a string from t->start to t->end, return as talloc allocated under ctx in *dst.
 * If *dst is non-NULL, talloc_free(*dst) first. */
void token_copy(void *ctx, char **dst, const struct token *t)
{
	size_t len;
	if (*dst)
		talloc_free(*dst);
	if (!t->start || !(t->end > t->start)) {
		*dst = NULL;
		return;
	}

	len = t->end - t->start;
	*dst = talloc_size(ctx, len + 1);
	osmo_strlcpy(*dst, t->start, len + 1);
	talloc_set_name_const(*dst, *dst);
}

const char *token_chr(const struct token *src, char c)
{
	const char *pos;
	for (pos = src->start; *pos && pos < src->end; pos++) {
		if (*pos == c)
			return pos;
	}
	return NULL;
}

const char *token_chrs(const struct token *src, const char *chrs)
{
	const char *pos;
	for (pos = src->start; pos && *pos && pos < src->end; pos++) {
		if (strchr(chrs, *pos))
			return pos;
	}
	return NULL;
}

void token_next(struct token *t, const char *str, const char *end, const char *separators)
{
	t->start = str;
	while (strchr(separators, *t->start) && t->start < end)
		t->start++;
	t->end = t->start;
	while (!strchr(separators, *t->end) && t->end < end)
		t->end++;
}

/* Convert the token to an integer, and return the character afer the integer string that was parsed.
 * The difference to osmo_str_to_int64() is that this guarantees to only access the memory from t->start to t->end. */
const char *token_to_int64(int64_t *result, const struct token *t, int base, int min_val, int max_val)
{
	/* copy the number section over to a temporary buffer, because t->end may terminate the string anywhere, and
	 * functions like strtoll (which osmo_str_to_int64() uses) are not able to stay within a strict buffer length
	 * unless the string is zero terminated at the buffer boundary. */
	char buf[32];
	const char *int_end = t->start;
	if (int_end < t->end && *int_end == '-')
		int_end++;
	while (int_end < t->end && isdigit(*int_end))
		int_end++;
	if (int_end - t->start >= sizeof(buf))
		return NULL;
	osmo_strlcpy(buf, t->start, int_end - t->start + 1);
	if (osmo_str_to_int64(result, buf, base, min_val, max_val) != 0)
		return NULL;
	return int_end;
}

/* Convenience: like token_to_int64() but with a plain int. */
const char *token_to_int(int *result, const struct token *t, int base, int min_val, int max_val)
{
	int64_t val;
	const char *rc = token_to_int64(&val, t, base, min_val, max_val);
	if (val < INT_MIN) {
		if (result)
			*result = INT_MIN;
		return NULL;
	}
	if (val > INT_MAX) {
		if (result)
			*result = INT_MAX;
		return NULL;
	}
	if (result)
		*result = (int)val;
	return rc;
}

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

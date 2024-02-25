/* Public API for codec management in SDP messages: managing SDP fmtp strings. */
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

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

bool osmo_sdp_fmtp_get_val(char *val, size_t val_size, const char *fmtp, const char *option_name);
int64_t osmo_sdp_fmtp_get_int(const char *fmtp, const char *option_name, int64_t default_value);

bool osmo_sdp_fmtp_amr_is_octet_aligned(const char *fmtp);
bool osmo_sdp_fmtp_amr_match(const char *a, const char *b);

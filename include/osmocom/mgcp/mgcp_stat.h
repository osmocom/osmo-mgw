/* A Media Gateway Control Protocol Media Gateway: RFC 3435 */
/* The statistics generator */

/*
 * (C) 2009-2012 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009-2012 by On-Waves
 * (C) 2017 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#pragma once

#include <osmocom/mgcp/mgcp_internal.h>
#include <inttypes.h>

void mgcp_format_stats(char *str, size_t str_len,  struct mgcp_conn *conn);

/* Exposed for test purposes only, do not use actively */
void calc_loss(struct mgcp_conn_rtp *conn, uint32_t *expected, int *loss);

/* Exposed for test purposes only, do not use actively */
uint32_t calc_jitter(struct mgcp_rtp_state *);

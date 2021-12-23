/* IuUP connection functionalitites */

/*
 * (C) 2021 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Pau Espin Pedrol
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

#include <osmocom/core/msgb.h>

struct mgcp_conn_rtp;

int mgcp_conn_iuup_init(struct mgcp_conn_rtp *conn_rtp);
void mgcp_conn_iuup_cleanup(struct mgcp_conn_rtp *conn_rtp);
int mgcp_conn_iuup_dispatch_rtp(struct msgb *msg);
int mgcp_conn_iuup_send_rtp(struct mgcp_conn_rtp *conn_src_rtp, struct mgcp_conn_rtp *conn_dest_rtp, struct msgb *msg);
int mgcp_conn_iuup_send_dummy(struct mgcp_conn_rtp *conn_rtp);

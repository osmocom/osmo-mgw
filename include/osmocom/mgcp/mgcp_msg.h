/* A Media Gateway Control Protocol Media Gateway: RFC 3435 */
/* Message parser/generator utilities */

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

#include <stdint.h>

struct mgcp_conn;
struct mgcp_parse_data;
struct mgcp_endpoint;

void mgcp_disp_msg(unsigned char *message, unsigned int len, char *preamble);

int mgcp_parse_conn_mode(const char *msg, struct mgcp_endpoint *endp,
			 struct mgcp_conn *conn);

int mgcp_parse_header(struct mgcp_parse_data *pdata, char *data);

int mgcp_parse_osmux_cid(const char *line);

int mgcp_check_param(const struct mgcp_endpoint *endp, const char *line);

int mgcp_verify_call_id(struct mgcp_endpoint *endp, const char *callid);

int mgcp_verify_ci(struct mgcp_endpoint *endp, const char *conn_id);

char *mgcp_strline(char *str, char **saveptr);

#define for_each_line(line, save)\
	for (line = mgcp_strline(NULL, &save); line;\
	     line = mgcp_strline(NULL, &save))

#define for_each_non_empty_line(line, save)\
	for (line = strtok_r(NULL, "\r\n", &save); line;\
	     line = strtok_r(NULL, "\r\n", &save))

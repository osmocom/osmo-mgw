/*
 * SDP generation and parsing
 *
 * (C) 2009-2015 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009-2014 by On-Waves
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
#include <osmocom/mgcp/mgcp_sdp.h>

int mgcp_parse_sdp_data(const struct mgcp_endpoint *endp,
			struct mgcp_conn_rtp *conn,
			struct mgcp_parse_data *p);

int mgcp_set_audio_info(void *ctx, struct mgcp_rtp_codec *codec,
			int payload_type, const char *audio_name);

int mgcp_write_response_sdp(const struct mgcp_endpoint *endp,
			    const struct mgcp_conn_rtp *conn, struct msgb *sdp,
			    const char *addr);

/* 'mgcp_rtp_end': basically a wrapper around the RTP+RTCP ports */
/*
 * (C) 2009-2012 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009-2012 by On-Waves
 * (C) 2013-2024 by sysmocom - s.f.m.c. GmbH
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

#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>

#include <osmocom/core/select.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/osmo_io.h>
#include <osmocom/mgcp/mgcp_rtp_end.h>
#include <osmocom/mgcp/mgcp_codec.h>
#include <osmocom/mgcp/mgcp_conn.h>
#include <osmocom/mgcp/mgcp_endp.h>
#include <osmocom/mgcp/mgcp_trunk.h>

/***********************
 * mgcp_rtp_end
 **********************/

void mgcp_rtp_end_init(struct mgcp_rtp_end *end, struct mgcp_conn_rtp *conn_rtp)
{
	struct mgcp_config *cfg = conn_rtp->conn->endp->trunk->cfg;

	end->conn_rtp = conn_rtp;
	end->rtp = NULL;
	end->rtcp = NULL;
	memset(&end->addr, 0, sizeof(end->addr));
	end->rtcp_port = 0;

	/* Set default values */
	end->frames_per_packet = 0;	/* unknown */
	end->output_enabled = false;
	end->maximum_packet_time = -1;


	if (cfg->force_ptime) {
		end->packet_duration_ms = cfg->force_ptime;
		end->force_output_ptime = 1;
	} else {
		end->packet_duration_ms = DEFAULT_RTP_AUDIO_PACKET_DURATION_MS;
	}

	/* Make sure codec table is reset */
	mgcp_codecset_reset(&end->cset);
}

void mgcp_rtp_end_cleanup(struct mgcp_rtp_end *end)
{
	mgcp_rtp_end_free_port(end);
	mgcp_codecset_reset(&end->cset);
}

void mgcp_rtp_end_set_packet_duration_ms(struct mgcp_rtp_end *end, uint32_t packet_duration_ms)
{
	if (end->force_output_ptime)
		return;
	end->packet_duration_ms = packet_duration_ms;
}

bool mgcp_rtp_end_remote_addr_available(const struct mgcp_rtp_end *rtp_end)
{
	return (osmo_sockaddr_port(&rtp_end->addr.u.sa) != 0) &&
	       (osmo_sockaddr_is_any(&rtp_end->addr) == 0);
}

/*! free allocated RTP and RTCP ports.
 *  \param[in] end RTP end */
void mgcp_rtp_end_free_port(struct mgcp_rtp_end *end)
{
	if (end->rtp) {
		osmo_iofd_free(end->rtp);
		end->rtp = NULL;
	}

	if (end->rtcp) {
		osmo_iofd_free(end->rtcp);
		end->rtcp = NULL;
	}
}

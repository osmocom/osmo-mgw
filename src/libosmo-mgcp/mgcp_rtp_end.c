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

/***********************
 * mgcp_rtp_end
 **********************/

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

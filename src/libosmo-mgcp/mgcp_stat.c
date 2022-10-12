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

#include <limits.h>
#include <inttypes.h>
#include <osmocom/mgcp/mgcp_protocol.h>
#include <osmocom/mgcp/mgcp_conn.h>
#include <osmocom/mgcp/mgcp_stat.h>
#include <osmocom/mgcp/mgcp_endp.h>
#include <osmocom/mgcp/mgcp_trunk.h>

/* Helper function for mgcp_format_stats_rtp() to calculate packet loss */
#if defined(__has_attribute)
#if __has_attribute(no_sanitize)
__attribute__((no_sanitize("undefined")))
#endif
#endif
void calc_loss(struct mgcp_conn_rtp *conn, uint32_t *expected, int *loss)
{
	struct mgcp_rtp_state *state = &conn->state;
	struct rate_ctr *packets_rx = rate_ctr_group_get_ctr(conn->ctrg, RTP_PACKETS_RX_CTR);

	*expected = state->stats.cycles + state->stats.max_seq;
	*expected = *expected - state->stats.base_seq + 1;

	if (!state->stats.initialized) {
		*expected = 0;
		*loss = 0;
		return;
	}

	/*
	 * Make sure the sign is correct and use the biggest
	 * positive/negative number that fits.
	 */
	*loss = *expected - packets_rx->current;
	if (*expected < packets_rx->current) {
		if (*loss > 0)
			*loss = INT_MIN;
	} else {
		if (*loss < 0)
			*loss = INT_MAX;
	}
}

/* Helper function for mgcp_format_stats_rtp() to calculate jitter */
uint32_t calc_jitter(struct mgcp_rtp_state *state)
{
	if (!state->stats.initialized)
		return 0;
	return state->stats.jitter >> 4;
}

/* Generate statistics for an RTP connection */
static void mgcp_format_stats_rtp(char *str, size_t str_len,
				  struct mgcp_conn_rtp *conn)
{
	uint32_t expected, jitter;
	int ploss;
	int nchars;

	struct rate_ctr *packets_rx = rate_ctr_group_get_ctr(conn->ctrg, RTP_PACKETS_RX_CTR);
	struct rate_ctr *octets_rx = rate_ctr_group_get_ctr(conn->ctrg, RTP_OCTETS_RX_CTR);
	struct rate_ctr *packets_tx = rate_ctr_group_get_ctr(conn->ctrg, RTP_PACKETS_TX_CTR);
	struct rate_ctr *octets_tx = rate_ctr_group_get_ctr(conn->ctrg, RTP_OCTETS_TX_CTR);

	calc_loss(conn, &expected, &ploss);
	jitter = calc_jitter(&conn->state);

	nchars = snprintf(str, str_len,
			  "\r\nP: PS=%" PRIu64 ", OS=%" PRIu64 ", PR=%" PRIu64 ", OR=%" PRIu64 ", PL=%d, JI=%u",
			  packets_tx->current, octets_tx->current,
			  packets_rx->current, octets_rx->current,
			  ploss, jitter);
	if (nchars < 0 || nchars >= str_len)
		goto truncate;

	str += nchars;
	str_len -= nchars;

	if (conn->conn->endp->trunk->cfg->osmux.usage != OSMUX_USAGE_OFF) {
		/* Error Counter */
		nchars = snprintf(str, str_len,
				  "\r\nX-Osmo-CP: EC TI=%" PRIu64 ", TO=%" PRIu64,
				  conn->state.in_stream.err_ts_ctr->current,
				  conn->state.out_stream.err_ts_ctr->current);
		if (nchars < 0 || nchars >= str_len)
			goto truncate;

		str += nchars;
		str_len -= nchars;

		if (conn->osmux.state == OSMUX_STATE_ENABLED) {
			struct rate_ctr *osmux_chunks_rx, *osmux_octets_rx;
			osmux_chunks_rx = rate_ctr_group_get_ctr(conn->ctrg, OSMUX_CHUNKS_RX_CTR);
			osmux_octets_rx = rate_ctr_group_get_ctr(conn->ctrg, OSMUX_OCTETS_RX_CTR);
			snprintf(str, str_len,
				 "\r\nX-Osmux-ST: CR=%" PRIu64 ", BR=%" PRIu64,
				 osmux_chunks_rx->current, osmux_octets_rx->current);
		}
	}

truncate:
	str[str_len - 1] = '\0';
}

/*! format statistics into an mgcp parameter string.
 *  \param[out] str resulting string
 *  \param[in] str_len length of the string buffer
 *  \param[in] conn connection to evaluate */
void mgcp_format_stats(char *str, size_t str_len, struct mgcp_conn *conn)
{
	memset(str, 0, str_len);
	if (!conn)
		return;

	/* NOTE: At the moment we only support generating statistics for
	 * RTP connections. However, in the future we may also want to
	 * generate statistics for other connection types as well. Lets
	 * keep this option open: */
	switch (conn->type) {
	case MGCP_CONN_TYPE_RTP:
		mgcp_format_stats_rtp(str, str_len, &conn->u.rtp);
		break;
	default:
		break;
	}
}

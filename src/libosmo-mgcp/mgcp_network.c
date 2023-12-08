/* A Media Gateway Control Protocol Media Gateway: RFC 3435 */
/* The protocol implementation */

/*
 * (C) 2009-2012 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009-2012 by On-Waves
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
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <limits.h>
#include <arpa/inet.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/select.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/byteswap.h>
#include <osmocom/netif/rtp.h>
#include <osmocom/netif/amr.h>
#include <osmocom/mgcp/mgcp.h>
#include <osmocom/mgcp/mgcp_common.h>
#include <osmocom/mgcp/mgcp_network.h>
#include <osmocom/mgcp/mgcp_protocol.h>
#include <osmocom/mgcp/mgcp_stat.h>
#include <osmocom/mgcp/osmux.h>
#include <osmocom/mgcp/mgcp_conn.h>
#include <osmocom/mgcp/mgcp_endp.h>
#include <osmocom/mgcp/mgcp_trunk.h>
#include <osmocom/mgcp/mgcp_codec.h>
#include <osmocom/mgcp/debug.h>
#include <osmocom/codec/codec.h>
#include <osmocom/mgcp/mgcp_e1.h>
#include <osmocom/mgcp/mgcp_iuup.h>

#define RTP_SEQ_MOD		(1 << 16)
#define RTP_MAX_DROPOUT		3000
#define RTP_MAX_MISORDER	100

void rtpconn_rate_ctr_add(struct mgcp_conn_rtp *conn_rtp, struct mgcp_endpoint *endp,
				 int id, int inc)
{
	struct rate_ctr_group *conn_stats = conn_rtp->ctrg;
	struct rate_ctr_group *mgw_stats = endp->trunk->ratectr.all_rtp_conn_stats;

	/* add to both the per-connection and the global stats */
	rate_ctr_add(rate_ctr_group_get_ctr(conn_stats, id), inc);
	rate_ctr_add(rate_ctr_group_get_ctr(mgw_stats, id), inc);
}

void rtpconn_rate_ctr_inc(struct mgcp_conn_rtp *conn_rtp, struct mgcp_endpoint *endp, int id)
{
	rtpconn_rate_ctr_add(conn_rtp, endp, id, 1);
}

static int rx_rtp(struct msgb *msg);

bool mgcp_rtp_end_remote_addr_available(const struct mgcp_rtp_end *rtp_end)
{
	return (osmo_sockaddr_port(&rtp_end->addr.u.sa) != 0) &&
	       (osmo_sockaddr_is_any(&rtp_end->addr) == 0);
}

/*! Determine the local rtp bind IP-address.
 *  \param[out] addr caller provided memory to store the resulting IP-Address.
 *  \param[in] endp mgcp endpoint, that holds a copy of the VTY parameters.
 * \ returns 0 on success, -1 if no local address could be provided.
 *
 *  The local bind IP-address is automatically selected by probing the
 *  IP-Address of the interface that is pointing towards the remote IP-Address,
 *  if no remote IP-Address is known yet, the statically configured
 *  IP-Addresses are used as fallback. */
int mgcp_get_local_addr(char *addr, struct mgcp_conn_rtp *conn)
{
	const struct mgcp_endpoint *endp = conn->conn->endp;
	const struct mgcp_config *cfg = endp->trunk->cfg;
	char ipbuf[INET6_ADDRSTRLEN];
	int rc;
	bool rem_addr_set = osmo_sockaddr_is_any(&conn->end.addr) == 0;
	const char *bind_addr;

	/* Osmux: No smart IP addresses allocation is supported yet. Simply
	 * return the one set in VTY config: */
	if (mgcp_conn_rtp_is_osmux(conn)) {
		if (rem_addr_set) {
			/* Match IP version with what was requested from remote: */
			bind_addr = conn->end.addr.u.sa.sa_family == AF_INET6 ?
				    cfg->osmux.local_addr_v6 :
				    cfg->osmux.local_addr_v4;
		} else {
			/* Choose any of the bind addresses, preferring v6 over v4 if available: */
			bind_addr = cfg->osmux.local_addr_v6;
			if (!bind_addr)
				bind_addr = cfg->osmux.local_addr_v4;
		}
		if (!bind_addr) {
			LOGPCONN(conn->conn, DOSMUX, LOGL_ERROR,
				"Unable to locate local Osmux address, check your configuration! v4=%u v6=%u remote_known=%s\n",
				!!cfg->osmux.local_addr_v4,
				!!cfg->osmux.local_addr_v6,
				rem_addr_set ? osmo_sockaddr_ntop(&conn->end.addr.u.sa, ipbuf) : "no");
			return -1;
		}
		LOGPCONN(conn->conn, DOSMUX, LOGL_DEBUG,
			 "Using configured osmux bind ip as local bind ip %s\n",
			 bind_addr);
		osmo_strlcpy(addr, bind_addr, INET6_ADDRSTRLEN);
		return 0;
	}

	/* Try probing the local IP-Address */
	if (cfg->net_ports.bind_addr_probe && rem_addr_set) {
		rc = osmo_sock_local_ip(addr, osmo_sockaddr_ntop(&conn->end.addr.u.sa, ipbuf));
		if (rc < 0)
			LOGPCONN(conn->conn, DRTP, LOGL_ERROR,
				 "local interface auto detection failed, using configured addresses...\n");
		else {
			LOGPCONN(conn->conn, DRTP, LOGL_DEBUG,
				 "selected local rtp bind ip %s by probing using remote ip %s\n",
				 addr, osmo_sockaddr_ntop(&conn->end.addr.u.sa, ipbuf));
			return 0;
		}
	}

	/* Select from preconfigured IP-Addresses. */
	if (rem_addr_set) {
		/* Check there is a bind IP for the RTP traffic configured,
		 * if so, use that IP-Address */
		bind_addr = conn->end.addr.u.sa.sa_family == AF_INET6 ?
				cfg->net_ports.bind_addr_v6 :
				cfg->net_ports.bind_addr_v4;
	} else {
		/* Choose any of the bind addresses, preferring v6 over v4 */
		bind_addr = cfg->net_ports.bind_addr_v6;
		if (!strlen(bind_addr))
			bind_addr = cfg->net_ports.bind_addr_v4;
	}
	if (strlen(bind_addr)) {
		LOGPCONN(conn->conn, DRTP, LOGL_DEBUG,
			 "using configured rtp bind ip as local bind ip %s\n",
			 bind_addr);
	} else {
		/* No specific bind IP is configured for the RTP traffic, so
		 * assume the IP where we listen for incoming MGCP messages
		 * as bind IP */
		bind_addr = cfg->source_addr;
		LOGPCONN(conn->conn, DRTP, LOGL_DEBUG,
			"using mgcp bind ip as local rtp bind ip: %s\n", bind_addr);
	}
	osmo_strlcpy(addr, bind_addr, INET6_ADDRSTRLEN);
	return 0;
}

/* This does not need to be a precision timestamp and
 * is allowed to wrap quite fast. The returned value is
 * 1/codec_rate seconds. */
uint32_t mgcp_get_current_ts(unsigned codec_rate)
{
	struct timespec tp;
	uint64_t ret;

	if (!codec_rate)
		return 0;

	memset(&tp, 0, sizeof(tp));
	if (clock_gettime(CLOCK_MONOTONIC, &tp) != 0)
		LOGP(DRTP, LOGL_NOTICE, "Getting the clock failed.\n");

	/* convert it to 1/unit seconds */
	ret = tp.tv_sec;
	ret *= codec_rate;
	ret += (int64_t) tp.tv_nsec * codec_rate / 1000 / 1000 / 1000;

	return ret;
}

/* Compute timestamp alignment error */
static int32_t ts_alignment_error(const struct mgcp_rtp_stream_state *sstate,
				  int ptime, uint32_t timestamp)
{
	int32_t timestamp_delta;

	if (ptime == 0)
		return 0;

	/* Align according to: T - Tlast = k * Tptime */
	timestamp_delta = timestamp - sstate->last_timestamp;

	return timestamp_delta % ptime;
}

/* Check timestamp and sequence number for plausibility */
static int check_rtp_timestamp(const struct mgcp_endpoint *endp,
			       const struct mgcp_rtp_state *state,
			       const struct mgcp_rtp_stream_state *sstate,
			       const struct mgcp_rtp_end *rtp_end,
			       const struct osmo_sockaddr *addr,
			       uint16_t seq, uint32_t timestamp,
			       const char *text, int32_t * tsdelta_out)
{
	int32_t tsdelta;
	int32_t timestamp_error;
	char ipbuf[INET6_ADDRSTRLEN];

	/* Not fully intialized, skip */
	if (sstate->last_tsdelta == 0 && timestamp == sstate->last_timestamp)
		return 0;

	if (seq == sstate->last_seq) {
		if (timestamp != sstate->last_timestamp) {
			rate_ctr_inc(sstate->err_ts_ctr);
			LOGPENDP(endp, DRTP, LOGL_ERROR,
				 "The %s timestamp delta is != 0 but the sequence "
				 "number %d is the same, "
				 "TS offset: %d, SeqNo offset: %d "
				 "on SSRC: %u timestamp: %u "
				 "from %s:%d\n",
				 text, seq,
				 state->patch.timestamp_offset, state->patch.seq_offset,
				 sstate->ssrc, timestamp,
				 osmo_sockaddr_ntop(&addr->u.sa, ipbuf),
				 osmo_sockaddr_port(&addr->u.sa));
		}
		return 0;
	}

	tsdelta =
	    (int32_t)(timestamp - sstate->last_timestamp) /
	    (int16_t)(seq - sstate->last_seq);

	if (tsdelta == 0) {
		/* Don't update *tsdelta_out */
		LOGPENDP(endp, DRTP, LOGL_NOTICE,
			 "The %s timestamp delta is %d "
			 "on SSRC: %u timestamp: %u "
			 "from %s:%d\n",
			 text, tsdelta, sstate->ssrc, timestamp,
			 osmo_sockaddr_ntop(&addr->u.sa, ipbuf),
			 osmo_sockaddr_port(&addr->u.sa));

		return 0;
	}

	if (sstate->last_tsdelta != tsdelta) {
		if (sstate->last_tsdelta) {
			LOGPENDP(endp, DRTP, LOGL_INFO,
				 "The %s timestamp delta changes from %d to %d "
				 "on SSRC: %u timestamp: %u from %s:%d\n",
				 text, sstate->last_tsdelta, tsdelta,
				 sstate->ssrc, timestamp,
				 osmo_sockaddr_ntop(&addr->u.sa, ipbuf),
				 osmo_sockaddr_port(&addr->u.sa));
		}
	}

	if (tsdelta_out)
		*tsdelta_out = tsdelta;

	timestamp_error =
	    ts_alignment_error(sstate, state->packet_duration, timestamp);

	if (timestamp_error) {
		rate_ctr_inc(sstate->err_ts_ctr);
		LOGPENDP(endp, DRTP, LOGL_NOTICE,
			 "The %s timestamp has an alignment error of %d "
			 "on SSRC: %u "
			 "SeqNo delta: %d, TS delta: %d, dTS/dSeq: %d "
			 "from %s:%d. ptime: %d\n",
			 text, timestamp_error,
			 sstate->ssrc,
			 (int16_t)(seq - sstate->last_seq),
			 (int32_t)(timestamp - sstate->last_timestamp),
			 tsdelta,
			 osmo_sockaddr_ntop(&addr->u.sa, ipbuf),
			 osmo_sockaddr_port(&addr->u.sa),
			 state->packet_duration);
	}
	return 1;
}

/* Set the timestamp offset according to the packet duration. */
static int adjust_rtp_timestamp_offset(const struct mgcp_endpoint *endp,
				       struct mgcp_rtp_state *state,
				       const struct mgcp_rtp_end *rtp_end,
				       const struct osmo_sockaddr *addr,
				       int16_t delta_seq, uint32_t in_timestamp,
				       bool marker_bit)
{
	int32_t tsdelta = state->packet_duration;
	int timestamp_offset;
	uint32_t out_timestamp;
	char ipbuf[INET6_ADDRSTRLEN];

	if (marker_bit) {
		/* If RTP pkt contains marker bit, the timestamps are not longer
		 * in sync, so we can erase timestamp offset patching. */
		state->patch.timestamp_offset = 0;
		return 0;
	}

	if (tsdelta == 0) {
		tsdelta = state->out_stream.last_tsdelta;
		if (tsdelta != 0) {
			LOGPENDP(endp, DRTP, LOGL_NOTICE,
				 "A fixed packet duration is not available, "
				 "using last output timestamp delta instead: %d "
				 "from %s:%d\n", tsdelta,
				 osmo_sockaddr_ntop(&addr->u.sa, ipbuf),
				 osmo_sockaddr_port(&addr->u.sa));
		} else {
			tsdelta = rtp_end->codec->rate * 20 / 1000;
			LOGPENDP(endp, DRTP, LOGL_NOTICE,
				 "Fixed packet duration and last timestamp delta "
				 "are not available, "
				 "using fixed 20ms instead: %d "
				 "from %s:%d\n", tsdelta,
				 osmo_sockaddr_ntop(&addr->u.sa, ipbuf),
				 osmo_sockaddr_port(&addr->u.sa));
		}
	}

	out_timestamp = state->out_stream.last_timestamp + delta_seq * tsdelta;
	timestamp_offset = out_timestamp - in_timestamp;

	if (state->patch.timestamp_offset != timestamp_offset) {
		state->patch.timestamp_offset = timestamp_offset;
		LOGPENDP(endp, DRTP, LOGL_NOTICE,
			 "Timestamp offset change on SSRC: %u "
			 "SeqNo delta: %d, TS offset: %d, "
			 "from %s:%d\n", state->in_stream.ssrc,
			 delta_seq, state->patch.timestamp_offset,
			 osmo_sockaddr_ntop(&addr->u.sa, ipbuf),
			 osmo_sockaddr_port(&addr->u.sa));
	}

	return timestamp_offset;
}

/* Set the timestamp offset according to the packet duration. */
static int align_rtp_timestamp_offset(const struct mgcp_endpoint *endp,
				      struct mgcp_rtp_state *state,
				      const struct mgcp_rtp_end *rtp_end,
				      const struct osmo_sockaddr *addr,
				      uint32_t timestamp, bool marker_bit)
{
	char ipbuf[INET6_ADDRSTRLEN];
	int ts_error = 0;
	int ts_check = 0;
	int ptime = state->packet_duration;

	if (marker_bit) {
		/* If RTP pkt contains marker bit, the timestamps are not longer
		 * in sync, so no alignment is needed. */
		return 0;
	}

	/* Align according to: T + Toffs - Tlast = k * Tptime */

	ts_error = ts_alignment_error(&state->out_stream, ptime,
				      timestamp + state->patch.timestamp_offset);

	/* If there is an alignment error, we have to compensate it */
	if (ts_error) {
		state->patch.timestamp_offset += ptime - ts_error;
		LOGPENDP(endp, DRTP, LOGL_NOTICE,
			 "Corrected timestamp alignment error of %d on SSRC: %u "
			 "new TS offset: %d, "
			 "from %s:%d\n",
			 ts_error, state->in_stream.ssrc,
			 state->patch.timestamp_offset,
			 osmo_sockaddr_ntop(&addr->u.sa, ipbuf),
			 osmo_sockaddr_port(&addr->u.sa));
	}

	/* Check we really managed to compensate the timestamp
	 * offset. There should not be any remaining error, failing
	 * here would point to a serous problem with the alignment
	 * error computation function */
	ts_check = ts_alignment_error(&state->out_stream, ptime,
				      timestamp + state->patch.timestamp_offset);
	OSMO_ASSERT(ts_check == 0);

	/* Return alignment error before compensation */
	return ts_error;
}

/*! dummy callback to disable transcoding (see also cfg->rtp_processing_cb).
 *  \param[in] associated endpoint.
 *  \param[in] destination RTP end.
 *  \param[in,out] pointer to buffer with voice data.
 *  \param[in] voice data length.
 *  \param[in] maximum size of caller provided voice data buffer.
 *  \returns ignores input parameters, return always 0. */
int mgcp_rtp_processing_default(struct mgcp_endpoint *endp,
				struct mgcp_rtp_end *dst_end,
				char *data, int *len, int buf_size)
{
	LOGPENDP(endp, DRTP, LOGL_DEBUG, "transcoding disabled\n");
	return 0;
}

/*! dummy callback to disable transcoding (see also cfg->setup_rtp_processing_cb).
 *  \param[in] associated endpoint.
 *  \param[in] destination RTP connnection.
 *  \param[in] source RTP connection.
 *  \returns ignores input parameters, return always 0. */
int mgcp_setup_rtp_processing_default(struct mgcp_endpoint *endp,
				      struct mgcp_conn_rtp *conn_dst,
				      struct mgcp_conn_rtp *conn_src)
{
	LOGPENDP(endp, DRTP, LOGL_DEBUG, "transcoding disabled\n");
	return 0;
}

void mgcp_get_net_downlink_format_default(struct mgcp_endpoint *endp,
					  const struct mgcp_rtp_codec **codec,
					  const char **fmtp_extra,
					  struct mgcp_conn_rtp *conn)
{
	LOGPENDP(endp, DRTP, LOGL_DEBUG, "conn:%s using format defaults\n",
		 mgcp_conn_dump(conn->conn));

	*codec = conn->end.codec;
	*fmtp_extra = conn->end.fmtp_extra;
}

void mgcp_rtp_annex_count(const struct mgcp_endpoint *endp,
			  struct mgcp_rtp_state *state, const uint16_t seq,
			  const int32_t transit, const uint32_t ssrc,
			  const bool marker_bit)
{
	int32_t d;

	/* initialize or re-initialize */
	if (!state->stats.initialized || state->stats.ssrc != ssrc || marker_bit) {
		state->stats.initialized = 1;
		state->stats.base_seq = seq;
		state->stats.max_seq = seq - 1;
		state->stats.ssrc = ssrc;
		state->stats.jitter = 0;
		state->stats.transit = transit;
		state->stats.cycles = 0;
	} else {
		uint16_t udelta;

		/* The below takes the shape of the validation of
		 * Appendix A. Check if there is something weird with
		 * the sequence number, otherwise check for a wrap
		 * around in the sequence number.
		 * It can't wrap during the initialization so let's
		 * skip it here. The Appendix A probably doesn't have
		 * this issue because of the probation. */
		udelta = seq - state->stats.max_seq;
		if (udelta < RTP_MAX_DROPOUT) {
			if (seq < state->stats.max_seq)
				state->stats.cycles += RTP_SEQ_MOD;
		} else if (udelta <= RTP_SEQ_MOD - RTP_MAX_MISORDER) {
			LOGPENDP(endp, DRTP, LOGL_NOTICE,
				 "RTP seqno made a very large jump on delta: %u\n",
				 udelta);
		}
	}

	/* Calculate the jitter between the two packages. The TS should be
	 * taken closer to the read function. This was taken from the
	 * Appendix A of RFC 3550. Timestamp and arrival_time have a 1/rate
	 * resolution. */
	d = transit - state->stats.transit;
	state->stats.transit = transit;
	if (d < 0)
		d = -d;
	state->stats.jitter += d - ((state->stats.jitter + 8) >> 4);
	state->stats.max_seq = seq;
}

/* There may be different payload type numbers negotiated for two connections.
 * Patch the payload type of an RTP packet so that it uses the payload type
 * of the codec that is set for the destination connection (conn_dst) */
static int mgcp_patch_pt(struct mgcp_conn_rtp *conn_dst, struct msgb *msg)
{
	struct rtp_hdr *rtp_hdr;

	if (msgb_length(msg) < sizeof(struct rtp_hdr)) {
		LOG_CONN_RTP(conn_dst, LOGL_NOTICE, "RTP packet too short (%u < %zu)\n",
			     msgb_length(msg), sizeof(struct rtp_hdr));
		return -EINVAL;
	}
	rtp_hdr = (struct rtp_hdr *)msgb_data(msg);

	if (!conn_dst->end.codec) {
		LOG_CONN_RTP(conn_dst, LOGL_NOTICE, "no codec set on destination connection!\n");
		return -EINVAL;
	}
	rtp_hdr->payload_type = (uint8_t) conn_dst->end.codec->payload_type;

	return 0;
}

/* The RFC 3550 Appendix A assumes there are multiple sources but
 * some of the supported endpoints (e.g. the nanoBTS) can only handle
 * one source and this code will patch RTP header to appear as if there
 * is only one source.
 * There is also no probation period for new sources. Every RTP header
 * we receive will be seen as a switch in streams. */
void mgcp_patch_and_count(const struct mgcp_endpoint *endp,
			  struct mgcp_rtp_state *state,
			  struct mgcp_rtp_end *rtp_end,
			  struct osmo_sockaddr *addr, struct msgb *msg)
{
	char ipbuf[INET6_ADDRSTRLEN];
	uint32_t arrival_time;
	int32_t transit;
	uint16_t seq;
	uint32_t timestamp, ssrc;
	bool marker_bit;
	struct rtp_hdr *rtp_hdr;
	int payload = rtp_end->codec->payload_type;
	unsigned int len = msgb_length(msg);

	if (len < sizeof(*rtp_hdr))
		return;

	rtp_hdr = (struct rtp_hdr *)msgb_data(msg);
	seq = ntohs(rtp_hdr->sequence);
	timestamp = ntohl(rtp_hdr->timestamp);
	arrival_time = mgcp_get_current_ts(rtp_end->codec->rate);
	ssrc = ntohl(rtp_hdr->ssrc);
	marker_bit = !!rtp_hdr->marker;
	transit = arrival_time - timestamp;

	mgcp_rtp_annex_count(endp, state, seq, transit, ssrc, marker_bit);

	if (!state->initialized) {
		state->initialized = 1;
		state->in_stream.last_seq = seq - 1;
		state->in_stream.ssrc = state->patch.orig_ssrc = ssrc;
		state->in_stream.last_tsdelta = 0;
		state->packet_duration =
		    mgcp_rtp_packet_duration(endp, rtp_end);
		state->out_stream.last_seq = seq - 1;
		state->out_stream.ssrc = state->patch.orig_ssrc = ssrc;
		state->out_stream.last_tsdelta = 0;
		state->out_stream.last_timestamp = timestamp;
		state->out_stream.ssrc = ssrc - 1;	/* force output SSRC change */
		LOGPENDP(endp, DRTP, LOGL_INFO,
			 "initializing stream, SSRC: %u timestamp: %u "
			 "pkt-duration: %d, from %s:%d\n",
			 state->in_stream.ssrc,
			 state->patch.seq_offset, state->packet_duration,
			 osmo_sockaddr_ntop(&addr->u.sa, ipbuf),
			 osmo_sockaddr_port(&addr->u.sa));
		if (state->packet_duration == 0) {
			state->packet_duration =
			    rtp_end->codec->rate * 20 / 1000;
			LOGPENDP(endp, DRTP, LOGL_NOTICE,
				 "fixed packet duration is not available, "
				 "using fixed 20ms instead: %d from %s:%d\n",
				 state->packet_duration,
				 osmo_sockaddr_ntop(&addr->u.sa, ipbuf),
				 osmo_sockaddr_port(&addr->u.sa));
		}
	} else if (state->in_stream.ssrc != ssrc) {
		LOGPENDP(endp, DRTP, LOGL_NOTICE,
			 "SSRC changed: %u -> %u  "
			 "from %s:%d\n",
			 state->in_stream.ssrc, rtp_hdr->ssrc,
			 osmo_sockaddr_ntop(&addr->u.sa, ipbuf),
			 osmo_sockaddr_port(&addr->u.sa));

		state->in_stream.ssrc = ssrc;
		if (rtp_end->force_constant_ssrc) {
			int16_t delta_seq;

			/* Always increment seqno by 1 */
			state->patch.seq_offset =
			    (state->out_stream.last_seq + 1) - seq;

			/* Estimate number of packets that would have been sent */
			delta_seq =
			    (arrival_time - state->in_stream.last_arrival_time
			     + state->packet_duration / 2) /
			    state->packet_duration;

			adjust_rtp_timestamp_offset(endp, state, rtp_end, addr,
						    delta_seq, timestamp, marker_bit);

			state->patch.patch_ssrc = true;
			ssrc = state->patch.orig_ssrc;
			if (rtp_end->force_constant_ssrc != -1)
				rtp_end->force_constant_ssrc -= 1;

			LOGPENDP(endp, DRTP, LOGL_NOTICE,
				 "SSRC patching enabled, SSRC: %u "
				 "SeqNo offset: %d, TS offset: %d "
				 "from %s:%d\n", state->in_stream.ssrc,
				 state->patch.seq_offset, state->patch.timestamp_offset,
				 osmo_sockaddr_ntop(&addr->u.sa, ipbuf),
	 		 	 osmo_sockaddr_port(&addr->u.sa));
		}

		state->in_stream.last_tsdelta = 0;
	} else {
		if (!marker_bit) {
			/* Compute current per-packet timestamp delta */
			check_rtp_timestamp(endp, state, &state->in_stream, rtp_end,
					    addr, seq, timestamp, "input",
					    &state->in_stream.last_tsdelta);
		} else {
			state->in_stream.last_tsdelta = 0;
		}

		if (state->patch.patch_ssrc)
			ssrc = state->patch.orig_ssrc;
	}

	/* Save before patching */
	state->in_stream.last_timestamp = timestamp;
	state->in_stream.last_seq = seq;
	state->in_stream.last_arrival_time = arrival_time;

	if (rtp_end->force_aligned_timing &&
	    state->out_stream.ssrc == ssrc && state->packet_duration)
		/* Align the timestamp offset */
		align_rtp_timestamp_offset(endp, state, rtp_end, addr,
					   timestamp, marker_bit);

	/* Store the updated SSRC back to the packet */
	if (state->patch.patch_ssrc)
		rtp_hdr->ssrc = htonl(ssrc);

	/* Apply the offset and store it back to the packet.
	 * This won't change anything if the offset is 0, so the conditional is
	 * omitted. */
	seq += state->patch.seq_offset;
	rtp_hdr->sequence = htons(seq);
	timestamp += state->patch.timestamp_offset;
	rtp_hdr->timestamp = htonl(timestamp);

	/* Check again, whether the timestamps are still valid */
	if (!marker_bit) {
		if (state->out_stream.ssrc == ssrc)
			check_rtp_timestamp(endp, state, &state->out_stream, rtp_end,
					    addr, seq, timestamp, "output",
					    &state->out_stream.last_tsdelta);
	} else {
		state->out_stream.last_tsdelta = 0;
	}

	/* Save output values */
	state->out_stream.last_seq = seq;
	state->out_stream.last_timestamp = timestamp;
	state->out_stream.ssrc = ssrc;

	if (payload < 0)
		return;

#if 0
	LOGPENDP(endp, DRTP, LOGL_DEBUG, "payload hdr payload %u -> endp payload %u\n",
		 rtp_hdr->payload_type, payload);
	rtp_hdr->payload_type = payload;
#endif
}

/* There are different dialects used to format and transfer voice data. When
 * the receiving end expects GSM-HR data to be formated after RFC 5993, this
 * function is used to convert between RFC 5993 and TS 101318, which we normally
 * use.
 * Return 0 on sucess, negative on errors like invalid data length. */
static int rfc5993_hr_convert(struct mgcp_endpoint *endp, struct msgb *msg)
{
	struct rtp_hdr *rtp_hdr;
	if (msgb_length(msg) < sizeof(struct rtp_hdr)) {
		LOGPENDP(endp, DRTP, LOGL_ERROR, "RTP packet too short (%d < %zu)\n",
			 msgb_length(msg), sizeof(struct rtp_hdr));
		return -EINVAL;
	}

	rtp_hdr = (struct rtp_hdr *)msgb_data(msg);

	if (msgb_length(msg) == GSM_HR_BYTES + sizeof(struct rtp_hdr)) {
		/* TS 101318 encoding => RFC 5993 encoding */
		msgb_put(msg, 1);
		memmove(rtp_hdr->data + 1, rtp_hdr->data, GSM_HR_BYTES);
		rtp_hdr->data[0] = 0x00;
	} else if (msgb_length(msg) == GSM_HR_BYTES + sizeof(struct rtp_hdr) + 1) {
		/* RFC 5993 encoding => TS 101318 encoding */
		memmove(rtp_hdr->data, rtp_hdr->data + 1, GSM_HR_BYTES);
		msgb_trim(msg, msgb_length(msg) - 1);
	} else {
		/* It is possible that multiple payloads occur in one RTP
		 * packet. This is not supported yet. */
		LOGPENDP(endp, DRTP, LOGL_ERROR,
			 "cannot figure out how to convert RTP packet\n");
		return -ENOTSUP;
	}
	return 0;
}

/*! Convert msg to AMR RTP framing mode specified by target_is_oa.
 *  \param[in] endp MGCP Endpoint where this message belongs to (used for logging purposes)
 *  \param[in] msg Message containing an AMR RTP payload (in octet-aligned or bandwidth-efficient format).
 *  \param[in] target_is_oa the target framing mode that msg will contain after this function succeeds.
 *  \returns The size of the new RTP AMR content on success, negative on error.
 *
 * For AMR RTP two framing modes are defined RFC3267. There is a bandwidth
 * efficient encoding scheme where all fields are packed together one after
 * another and an octet aligned mode where all fields are aligned to octet
 * boundaries. This function is used to convert between the two modes.
 */
int amr_oa_bwe_convert(struct mgcp_endpoint *endp, struct msgb *msg,
			      bool target_is_oa)
{
	/* NOTE: the msgb has an allocated length of RTP_BUF_SIZE, so there is
	 * plenty of space available to store the slightly larger, converted
	 * data */
	struct rtp_hdr *rtp_hdr;
	unsigned int payload_len;
	int rc;
	bool orig_is_oa;

	if (msgb_length(msg) < sizeof(struct rtp_hdr)) {
		LOGPENDP(endp, DRTP, LOGL_ERROR, "AMR RTP packet too short (%d < %zu)\n", msgb_length(msg), sizeof(struct rtp_hdr));
		return -EINVAL;
	}

	rtp_hdr = (struct rtp_hdr *)msgb_data(msg);
	payload_len = msgb_length(msg) - sizeof(struct rtp_hdr);
	orig_is_oa = osmo_amr_is_oa(rtp_hdr->data, payload_len);

	if (orig_is_oa) {
		if (!target_is_oa)
			/* Input data is oa an target format is bwe
			 * ==> convert */
			rc = osmo_amr_oa_to_bwe(rtp_hdr->data, payload_len);
		else
			/* Input data is already bew, but we accept it anyway
			 * ==> no conversion needed */
			rc = payload_len;
	} else {
		if (target_is_oa)
			/* Input data is bwe an target format is oa
			 * ==> convert */
			rc = osmo_amr_bwe_to_oa(rtp_hdr->data, payload_len,
						RTP_BUF_SIZE);
		else
			/* Input data is already oa, but we accept it anyway
			 * ==> no conversion needed */
			rc = payload_len;
	}
	if (rc < 0) {
		LOGPENDP(endp, DRTP, LOGL_ERROR,
			 "RTP AMR packet conversion %s->%s failed: %s\n",
			 orig_is_oa ? "OA" : "BWE",
			 target_is_oa ? "OA" : "BWE",
			 osmo_hexdump(rtp_hdr->data, payload_len));
		return -EINVAL;
	}

	return msgb_trim(msg, rc + sizeof(struct rtp_hdr));
}

/* Return whether an RTP packet with AMR payload is in octet-aligned mode.
 * Return 0 if in bandwidth-efficient mode, 1 for octet-aligned mode, and negative if the RTP data is invalid. */
static int amr_oa_check(char *data, int len)
{
	struct rtp_hdr *rtp_hdr;
	unsigned int payload_len;

	if (len < sizeof(struct rtp_hdr))
		return -EINVAL;

	rtp_hdr = (struct rtp_hdr *)data;

	payload_len = len - sizeof(struct rtp_hdr);
	if (payload_len < sizeof(struct amr_hdr))
		return -EINVAL;

	return osmo_amr_is_oa(rtp_hdr->data, payload_len) ? 1 : 0;
}

/* Forward data to a debug tap. This is debug function that is intended for
 * debugging the voice traffic with tools like gstreamer */
void forward_data_tap(int fd, struct mgcp_rtp_tap *tap, struct msgb *msg)
{
	int rc;

	if (!tap->enabled)
		return;

	rc = sendto(fd, msgb_data(msg), msgb_length(msg), 0, (struct sockaddr *)&tap->forward,
		    sizeof(tap->forward));

	if (rc < 0)
		LOGP(DRTP, LOGL_ERROR,
		     "Forwarding tapped (debug) voice data failed.\n");
}

/* Generate an RTP header if it is missing */
static void gen_rtp_header(struct msgb *msg, struct mgcp_rtp_end *rtp_end,
			   struct mgcp_rtp_state *state)
{
	struct rtp_hdr *hdr = (struct rtp_hdr *)msgb_data(msg);

	if (hdr->version > 0)
		return;

	hdr->version = 2;
	hdr->payload_type = rtp_end->codec->payload_type;
	hdr->timestamp = osmo_htonl(mgcp_get_current_ts(rtp_end->codec->rate));
	hdr->sequence = osmo_htons(state->alt_rtp_tx_sequence);
	hdr->ssrc = state->alt_rtp_tx_ssrc;
}

/* Check if the origin (addr) matches the address/port data of the RTP
 * connections. */
static int check_rtp_origin(struct mgcp_conn_rtp *conn, struct osmo_sockaddr *addr)
{
	char ipbuf[INET6_ADDRSTRLEN];

	if (osmo_sockaddr_is_any(&conn->end.addr) != 0 ||
	    osmo_sockaddr_port(&conn->end.addr.u.sa) == 0) {
		if (mgcp_conn_rtp_is_iuup(conn) && !conn->iuup.configured) {
			/* Allow IuUP Initialization to get through even if we don't have a remote address set yet.
			 * This is needed because hNodeB doesn't announce its IuUP remote IP addr to the MGCP client
			 * (RAB Assignment Response at HNBGW) until it has gone through IuUP Initialization against
			 * this MGW here. Hence the MGW may not yet know the remote IuUP address and port at the time
			 * of receiving IuUP Initialization from the hNodeB.
			 */
			LOGPCONN(conn->conn, DRTP, LOGL_INFO,
				 "Rx RTP from %s: allowing unknown src for IuUP Initialization\n",
				 osmo_sockaddr_to_str(addr));
			return 0;
		}
		/* Receiving early media before the endpoint is configured. Instead of logging
		 * this as an error that occurs on every call, keep it more low profile to not
		 * confuse humans with expected errors. */
		LOGPCONN(conn->conn, DRTP, LOGL_INFO,
			 "Rx RTP from %s, but remote address not set: dropping early media\n",
			 osmo_sockaddr_to_str(addr));
		return -1;
	}

	/* Note: Check if the inbound RTP data comes from the same host to
	 * which we send our outgoing RTP traffic. */
	if (conn->end.addr.u.sa.sa_family != addr->u.sa.sa_family ||
	    (conn->end.addr.u.sa.sa_family == AF_INET &&
	     conn->end.addr.u.sin.sin_addr.s_addr != addr->u.sin.sin_addr.s_addr) ||
	    (conn->end.addr.u.sa.sa_family == AF_INET6 &&
	     memcmp(&conn->end.addr.u.sin6.sin6_addr, &addr->u.sin6.sin6_addr,
		    sizeof(struct in6_addr)))) {
		LOGPCONN(conn->conn, DRTP, LOGL_ERROR,
			 "data from wrong src %s, expected IP Address %s. Packet tossed.\n",
			 osmo_sockaddr_to_str(addr), osmo_sockaddr_ntop(&conn->end.addr.u.sa, ipbuf));
		return -1;
	}

	/* Note: Usually the remote remote port of the data we receive will be
	 * the same as the remote port where we transmit outgoing RTP traffic
	 * to (set by MDCX). We use this to check the origin of the data for
	 * plausibility. */
	if (osmo_sockaddr_port(&conn->end.addr.u.sa) != osmo_sockaddr_port(&addr->u.sa) &&
	    ntohs(conn->end.rtcp_port) != osmo_sockaddr_port(&addr->u.sa)) {
		LOGPCONN(conn->conn, DRTP, LOGL_ERROR,
			 "data from wrong src %s, expected port: %u for RTP or %u for RTCP. Packet tossed.\n",
			 osmo_sockaddr_to_str(addr), osmo_sockaddr_port(&conn->end.addr.u.sa),
			 ntohs(conn->end.rtcp_port));
		return -1;
	}

	return 0;
}

/* Check the if the destination address configuration of an RTP connection
 * makes sense */
static int check_rtp_destin(struct mgcp_conn_rtp *conn)
{
	char ipbuf[INET6_ADDRSTRLEN];
	bool ip_is_any = osmo_sockaddr_is_any(&conn->end.addr) != 0;
	uint16_t port = osmo_sockaddr_port(&conn->end.addr.u.sa);

	/* Note: it is legal to create a connection but never setting a port
	 * and IP-address for outgoing data. */
	if (ip_is_any && port == 0) {
		LOGPCONN(conn->conn, DRTP, LOGL_DEBUG,
			 "destination IP-address and rtp port is not (yet) known (%s:%u)\n",
			 osmo_sockaddr_ntop(&conn->end.addr.u.sa, ipbuf), port);
		return -1;
	}

	if (ip_is_any) {
		LOGPCONN(conn->conn, DRTP, LOGL_ERROR,
			 "destination IP-address is invalid (%s:%u)\n",
			 osmo_sockaddr_ntop(&conn->end.addr.u.sa, ipbuf), port);
		return -1;
	}

	if (port == 0) {
		LOGPCONN(conn->conn, DRTP, LOGL_ERROR,
			 "destination rtp port is invalid (%s:%u)\n",
			 osmo_sockaddr_ntop(&conn->end.addr.u.sa, ipbuf), port);
		return -1;
	}

	return 0;
}

/* Do some basic checks to make sure that the RTCP packets we are going to
 * process are not complete garbage */
static int check_rtcp(struct mgcp_conn_rtp *conn_src, struct msgb *msg)
{
	struct rtcp_hdr *hdr;
	unsigned int len;
	uint8_t type;

	/* RTPC packets that are just a header without data do not make
	 * any sense. */
	if (msgb_length(msg) < sizeof(struct rtcp_hdr)) {
		LOG_CONN_RTP(conn_src, LOGL_ERROR, "RTCP packet too short (%u < %zu)\n",
			     msgb_length(msg), sizeof(struct rtcp_hdr));
		return -EINVAL;
	}

	/* Make sure that the length of the received packet does not exceed
	 * the available buffer size */
	hdr = (struct rtcp_hdr *)msgb_data(msg);
	len = (osmo_ntohs(hdr->length) + 1) * 4;
	if (len > msgb_length(msg)) {
		LOG_CONN_RTP(conn_src, LOGL_ERROR, "RTCP header length exceeds packet size (%u > %u)\n",
			     len, msgb_length(msg));
		return -EINVAL;
	}

	/* Make sure we accept only packets that have a proper packet type set
	 * See also: http://www.iana.org/assignments/rtp-parameters/rtp-parameters.xhtml */
	type = hdr->type;
	if ((type < 192 || type > 195) && (type < 200 || type > 213)) {
		LOG_CONN_RTP(conn_src, LOGL_ERROR, "RTCP header: invalid type: %u\n", type);
		return -EINVAL;
	}

	return 0;
}

/* Do some basic checks to make sure that the RTP packets we are going to
 * process are not complete garbage */
static int check_rtp(struct mgcp_conn_rtp *conn_src, struct msgb *msg)
{
	size_t min_size = sizeof(struct rtp_hdr);
	if (msgb_length(msg) < min_size) {
		LOG_CONN_RTP(conn_src, LOGL_ERROR, "RTP packet too short (%u < %zu)\n",
			     msgb_length(msg), min_size);
		return -1;
	}

	/* FIXME: Add more checks, the reason why we do not check more than
	 * the length is because we currently handle IUUP packets as RTP
	 * packets, so they must pass this check, if we weould be more
	 * strict here, we would possibly break 3G. (see also FIXME note
	 * below.*/

	return 0;
}

/*! Dispatch msg bridged from the sister conn in the endpoint.
 *  \param[in] conn_dst The destination conn that should handle and transmit the content to
 *			its peer outside MGW.
 *  \param[in] msg msgb containing an RTP pkt received by the sister conn in the endpoint,
 *  \returns bytes sent, -1 on error.
 *
 * Possible options are standard RTP packet transmission, transmission
 * via IuUP or transmission via an osmux connection.
 */
static int mgcp_conn_rtp_dispatch_rtp(struct mgcp_conn_rtp *conn_dst, struct msgb *msg)
{
	struct osmo_rtp_msg_ctx *mc = OSMO_RTP_MSG_CTX(msg);
	enum rtp_proto proto = mc->proto;
	struct mgcp_conn_rtp *conn_src = mc->conn_src;
	struct mgcp_endpoint *endp = conn_src->conn->endp;

	LOGPENDP(endp, DRTP, LOGL_DEBUG, "destin conn:%s\n",
		 mgcp_conn_dump(conn_dst->conn));

	/* Before we try to deliver the packet, we check if the destination
	 * port and IP-Address make sense at all. If not, we will be unable
	 * to deliver the packet. */
	if (check_rtp_destin(conn_dst) != 0)
		return -1;

	/* Depending on the RTP connection type, deliver the RTP packet to the
	 * destination connection. */
	switch (conn_dst->type) {
	case MGCP_RTP_DEFAULT:
		LOGPENDP(endp, DRTP, LOGL_DEBUG,
			 "endpoint type is MGCP_RTP_DEFAULT, "
			 "using mgcp_send() to forward data directly\n");
		return mgcp_send(endp, proto == MGCP_PROTO_RTP,
				 mc->from_addr, msg, conn_src, conn_dst);
	case MGCP_RTP_OSMUX:
		LOGPENDP(endp, DRTP, LOGL_DEBUG,
			 "endpoint type is MGCP_RTP_OSMUX, "
			 "using osmux_xfrm_to_osmux() to forward data through OSMUX\n");
		return conn_osmux_send_rtp(conn_dst, msg);
	case MGCP_RTP_IUUP:
		if (proto == MGCP_PROTO_RTP) {
			LOGPENDP(endp, DRTP, LOGL_DEBUG,
				 "endpoint type is MGCP_RTP_IUUP, "
				 "using mgcp_conn_iuup_send_rtp() to forward data over IuUP\n");
			return mgcp_conn_iuup_send_rtp(conn_src, conn_dst, msg);
		}
		/* RTCP: we forward as usual for regular RTP connection */
		LOGPENDP(endp, DRTP, LOGL_DEBUG,
			 "endpoint type is MGCP_RTP_IUUP and proto!=MGCP_PROTO_RTP, "
			 "using mgcp_send() to forward data directly\n");
		return mgcp_send(endp, false,
				 mc->from_addr, msg, conn_src, conn_dst);
	}

	/* If the data has not been handled/forwarded until here, it will
	 * be discarded, this should not happen, normally the MGCP type
	 * should be properly set */
	LOGPENDP(endp, DRTP, LOGL_ERROR, "bad MGCP type -- data discarded!\n");

	return -1;
}

/*! send udp packet.
 *  \param[in] fd associated file descriptor.
 *  \param[in] addr destination ip-address.
 *  \param[in] buf buffer that holds the data to be send.
 *  \param[in] len length of the data to be sent.
 *  \returns bytes sent, -1 on error. */
int mgcp_udp_send(int fd, const struct osmo_sockaddr *addr, const char *buf, int len)
{
	char ipbuf[INET6_ADDRSTRLEN];
	size_t addr_len;

	LOGP(DRTP, LOGL_DEBUG,
	     "sending %i bytes length packet to %s:%u ...\n", len,
	     osmo_sockaddr_ntop(&addr->u.sa, ipbuf),
	     osmo_sockaddr_port(&addr->u.sa));

	if (addr->u.sa.sa_family == AF_INET6) {
		addr_len = sizeof(addr->u.sin6);
	} else {
		addr_len = sizeof(addr->u.sin);
	}

	return sendto(fd, buf, len, 0, &addr->u.sa, addr_len);
}

/*! send RTP dummy packet (to keep NAT connection open).
 *  \param[in] endp mcgp endpoint that holds the RTP connection.
 *  \param[in] conn associated RTP connection.
 *  \returns bytes sent, -1 on error. */
int mgcp_send_dummy(struct mgcp_endpoint *endp, struct mgcp_conn_rtp *conn)
{
	int rc;
	int was_rtcp = 0;
	struct osmo_sockaddr rtcp_addr;

	OSMO_ASSERT(endp);
	OSMO_ASSERT(conn);

	LOGPCONN(conn->conn, DRTP, LOGL_DEBUG, "sending dummy packet... %s\n",
		 mgcp_conn_dump(conn->conn));

	/* Before we try to deliver the packet, we check if the destination
	 * port and IP-Address make sense at all. If not, we will be unable
	 * to deliver the packet. */
	if (check_rtp_destin(conn) != 0)
		goto failed;

	if (mgcp_conn_rtp_is_iuup(conn))
		rc = mgcp_conn_iuup_send_dummy(conn);
	else
		rc = mgcp_udp_send(conn->end.rtp.fd, &conn->end.addr,
				   rtp_dummy_payload, sizeof(rtp_dummy_payload));

	if (rc == -1)
		goto failed;

	if (endp->trunk->omit_rtcp)
		return rc;

	was_rtcp = 1;
	rtcp_addr = conn->end.addr;
	osmo_sockaddr_set_port(&rtcp_addr.u.sa, ntohs(conn->end.rtcp_port));
	rc = mgcp_udp_send(conn->end.rtcp.fd, &rtcp_addr,
			   rtp_dummy_payload, sizeof(rtp_dummy_payload));

	if (rc >= 0)
		return rc;

failed:
	LOGPCONN(conn->conn, DRTP, LOGL_ERROR,
		 "Failed to send dummy %s packet.\n",
		 was_rtcp ? "RTCP" : "RTP");

	return -1;
}

/*! Send RTP/RTCP data to a specified destination connection.
 *  \param[in] endp associated endpoint (for configuration, logging).
 *  \param[in] is_rtp flag to specify if the packet is of type RTP or RTCP.
 *  \param[in] addr spoofed source address (set to NULL to disable).
 *  \param[in] msg message buffer that contains the RTP/RTCP data.
 *  \param[in] conn_src associated source connection.
 *  \param[in] conn_dst associated destination connection.
 *  \returns 0 on success, negative on ERROR. */
int mgcp_send(struct mgcp_endpoint *endp, int is_rtp, struct osmo_sockaddr *addr,
	      struct msgb *msg, struct mgcp_conn_rtp *conn_src,
	      struct mgcp_conn_rtp *conn_dst)
{
	/*! When no destination connection is available (e.g. when only one
	 *  connection in loopback mode exists), then the source connection
	 *  shall be specified as destination connection */

	struct mgcp_trunk *trunk = endp->trunk;
	struct mgcp_rtp_end *rtp_end;
	struct mgcp_rtp_state *rtp_state;
	char ipbuf[INET6_ADDRSTRLEN];
	char *dest_name;
	int rc;
	int len;

	OSMO_ASSERT(conn_src);
	OSMO_ASSERT(conn_dst);

	if (is_rtp)
		LOGPENDP(endp, DRTP, LOGL_DEBUG, "delivering RTP packet...\n");
	else
		LOGPENDP(endp, DRTP, LOGL_DEBUG, "delivering RTCP packet...\n");

	/* Patch the payload type number: translate from conn_src to conn_dst.
	 * Do not patch for IuUP, where the correct payload type number is already set in bridge_iuup_to_rtp_peer():
	 * IuUP -> AMR: calls this function, skip patching if conn_src is IuUP.
	 * {AMR or IuUP} -> IuUP: calls mgcp_udp_send() directly, skipping this function: No need to examine dst. */
	if (is_rtp && !mgcp_conn_rtp_is_iuup(conn_src)) {
		if (mgcp_patch_pt(conn_dst, msg) < 0) {
			LOGPENDP(endp, DRTP, LOGL_NOTICE, "unable to patch payload type RTP packet, discarding...\n");
			return -EINVAL;
		}
	}

	/* Note: In case of loopback configuration, both, the source and the
	 * destination will point to the same connection. */
	rtp_end = &conn_dst->end;
	rtp_state = &conn_src->state;
	dest_name = conn_dst->conn->name;

	/* Ensure we have an alternative SSRC in case we need it, see also
	 * gen_rtp_header() */
	if (rtp_state->alt_rtp_tx_ssrc == 0)
		rtp_state->alt_rtp_tx_ssrc = rand();

	if (!rtp_end->output_enabled) {
		rtpconn_rate_ctr_inc(conn_dst, endp, RTP_DROPPED_PACKETS_CTR);
		LOGPENDP(endp, DRTP, LOGL_DEBUG,
			 "output disabled, drop to %s %s "
			 "rtp_port:%u rtcp_port:%u\n",
			 dest_name,
			 osmo_sockaddr_ntop(&rtp_end->addr.u.sa, ipbuf),
			 osmo_sockaddr_port(&rtp_end->addr.u.sa), ntohs(rtp_end->rtcp_port)
		    );
	} else if (is_rtp) {
		int cont;
		int nbytes = 0;
		int buflen = msgb_length(msg);

		/* Make sure we have a valid RTP header, in cases where no RTP
		 * header is present, we will generate one. */
		gen_rtp_header(msg, rtp_end, rtp_state);

		do {
			/* Run transcoder */
			cont = endp->trunk->cfg->rtp_processing_cb(endp, rtp_end, (char *)msgb_data(msg), &buflen, RTP_BUF_SIZE);
			if (cont < 0)
				break;

			if (addr)
				mgcp_patch_and_count(endp, rtp_state, rtp_end,
						     addr, msg);

			if (mgcp_conn_rtp_is_iuup(conn_dst) || mgcp_conn_rtp_is_iuup(conn_src)) {
				/* the iuup code will correctly transform to the correct AMR mode */
			} else if (mgcp_codec_amr_align_mode_is_indicated(conn_dst->end.codec)) {
				rc = amr_oa_bwe_convert(endp, msg,
							conn_dst->end.codec->param.amr_octet_aligned);
				if (rc < 0) {
					LOGPENDP(endp, DRTP, LOGL_ERROR,
						 "Error in AMR octet-aligned <-> bandwidth-efficient mode conversion (target=%s)\n",
						 conn_dst->end.codec->param.amr_octet_aligned ? "octet-aligned" : "bandwidth-efficient");
					break;
				}
			} else if (rtp_end->rfc5993_hr_convert &&
				   strcmp(conn_src->end.codec->subtype_name, "GSM-HR-08") == 0) {
				rc = rfc5993_hr_convert(endp, msg);
				if (rc < 0) {
					LOGPENDP(endp, DRTP, LOGL_ERROR, "Error while converting to GSM-HR-08\n");
					break;
				}
			}

			LOGPENDP(endp, DRTP, LOGL_DEBUG,
				 "process/send to %s %s "
				 "rtp_port:%u rtcp_port:%u\n",
				 dest_name,
				 osmo_sockaddr_ntop(&rtp_end->addr.u.sa, ipbuf),
				 osmo_sockaddr_port(&rtp_end->addr.u.sa), ntohs(rtp_end->rtcp_port)
				);

			/* Forward a copy of the RTP data to a debug ip/port */
			forward_data_tap(rtp_end->rtp.fd, &conn_src->tap_out,
				     msg);

			len = mgcp_udp_send(rtp_end->rtp.fd, &rtp_end->addr,
					    (char *)msgb_data(msg), msgb_length(msg));

			if (len <= 0)
				return len;

			rtpconn_rate_ctr_inc(conn_dst, endp, RTP_PACKETS_TX_CTR);
			rtpconn_rate_ctr_add(conn_dst, endp, RTP_OCTETS_TX_CTR, len);
			rtp_state->alt_rtp_tx_sequence++;

			nbytes += len;
			buflen = cont;
		} while (buflen > 0);
		return nbytes;
	} else if (!trunk->omit_rtcp) {
		struct osmo_sockaddr rtcp_addr = rtp_end->addr;
		osmo_sockaddr_set_port(&rtcp_addr.u.sa, rtp_end->rtcp_port);
		LOGPENDP(endp, DRTP, LOGL_DEBUG,
			 "send to %s %s rtp_port:%u rtcp_port:%u\n",
			 dest_name, osmo_sockaddr_ntop(&rtcp_addr.u.sa, ipbuf),
			 osmo_sockaddr_port(&rtp_end->addr.u.sa),
			 osmo_sockaddr_port(&rtcp_addr.u.sa)
			);

		len = mgcp_udp_send(rtp_end->rtcp.fd, &rtcp_addr,
				    (char *)msgb_data(msg), msgb_length(msg));

		rtpconn_rate_ctr_inc(conn_dst, endp, RTP_PACKETS_TX_CTR);
		rtpconn_rate_ctr_add(conn_dst, endp, RTP_OCTETS_TX_CTR, len);
		rtp_state->alt_rtp_tx_sequence++;

		return len;
	}

	return 0;
}

/*! Dispatch incoming RTP packet to opposite RTP connection.
 * \param[in] msg Message buffer to bridge, coming from source connection.
 *            msg shall contain "struct osmo_rtp_msg_ctx *" attached in
 *            "OSMO_RTP_MSG_CTX(msg)".
 *  \returns 0 on success, -1 on ERROR.
 */
int mgcp_dispatch_rtp_bridge_cb(struct msgb *msg)
{
	struct osmo_rtp_msg_ctx *mc = OSMO_RTP_MSG_CTX(msg);
	struct mgcp_conn_rtp *conn_src = mc->conn_src;
	struct mgcp_conn *conn = conn_src->conn;
	struct mgcp_conn *conn_dst;
	struct mgcp_endpoint *endp = conn->endp;
	struct osmo_sockaddr *from_addr = mc->from_addr;
	char ipbuf[INET6_ADDRSTRLEN];
	int rc = 0;

	/*! NOTE: This callback function implements the endpoint specific
	 *  dispatch behaviour of an rtp bridge/proxy endpoint. It is assumed
	 *  that the endpoint will hold only two connections. This premise
	 *  is used to determine the opposite connection (it is always the
	 *  connection that is not the originating connection). Once the
	 *  destination connection is known the RTP packet is sent via
	 *  the destination connection. */

	/* If source is IuUP, we need to handle state, forward it through specific bridge path: */
	if (mgcp_conn_rtp_is_iuup(conn_src) && mc->proto == MGCP_PROTO_RTP)
		return mgcp_conn_iuup_dispatch_rtp(msg);

	 /* Check if the connection is in loopback mode, if yes, just send the
	 * incoming data back to the origin */
	if (conn->mode == MGCP_CONN_LOOPBACK) {
		/* When we are in loopback mode, we loop back all incoming
		 * packets back to their origin. We will use the originating
		 * address data from the UDP packet header to patch the
		 * outgoing address in connection on the fly */
		if (osmo_sockaddr_port(&conn->u.rtp.end.addr.u.sa) == 0) {
			memcpy(&conn->u.rtp.end.addr, from_addr,
			       sizeof(conn->u.rtp.end.addr));
			LOG_CONN_RTP(conn_src, LOGL_NOTICE,
				     "loopback mode: implicitly using source address (%s:%u) as destination address\n",
				     osmo_sockaddr_ntop(&from_addr->u.sa, ipbuf),
				     osmo_sockaddr_port(&conn->u.rtp.end.addr.u.sa));
		}
		return mgcp_conn_rtp_dispatch_rtp(conn_src, msg);
	}

	/* If the mode does not allow receiving RTP, we are done. */
	switch (conn->mode) {
	case MGCP_CONN_RECV_ONLY:
	case MGCP_CONN_RECV_SEND:
	case MGCP_CONN_CONFECHO:
		break;
	default:
		return rc;
	}

	/* If the mode is "confecho", send RTP back to the sender. */
	if (conn->mode == MGCP_CONN_CONFECHO)
		rc = mgcp_conn_rtp_dispatch_rtp(conn_src, msg);

	/* Dispatch RTP packet to all other connection(s) that send audio. */
	llist_for_each_entry(conn_dst, &endp->conns, entry) {
		if (conn_dst == conn)
			continue;
		switch (conn_dst->mode) {
		case MGCP_CONN_SEND_ONLY:
		case MGCP_CONN_RECV_SEND:
		case MGCP_CONN_CONFECHO:
			rc = mgcp_conn_rtp_dispatch_rtp(&conn_dst->u.rtp, msg);
			break;
		default:
			break;
		}
	}
	return rc;
}

/*! dispatch incoming RTP packet to E1 subslot, handle RTCP packets locally.
 *  \param[in] proto protocol (MGCP_CONN_TYPE_RTP or MGCP_CONN_TYPE_RTCP).
 *  \param[in] addr socket address where the RTP packet has been received from.
 *  \param[in] buf buffer that hold the RTP payload.
 *  \param[in] buf_size size data length of buf.
 *  \param[in] conn originating connection.
 *  \returns 0 on success, -1 on ERROR. */
int mgcp_dispatch_e1_bridge_cb(struct msgb *msg)
{
	struct osmo_rtp_msg_ctx *mc = OSMO_RTP_MSG_CTX(msg);
	struct mgcp_conn_rtp *conn_src = mc->conn_src;
	struct mgcp_conn *conn = conn_src->conn;
	struct osmo_sockaddr *from_addr = mc->from_addr;
	char ipbuf[INET6_ADDRSTRLEN];

	/* Check if the connection is in loopback mode, if yes, just send the
	 * incoming data back to the origin */
	if (conn->mode == MGCP_CONN_LOOPBACK) {
		/* When we are in loopback mode, we loop back all incoming
		 * packets back to their origin. We will use the originating
		 * address data from the UDP packet header to patch the
		 * outgoing address in connection on the fly */
		if (osmo_sockaddr_port(&conn->u.rtp.end.addr.u.sa) == 0) {
			memcpy(&conn->u.rtp.end.addr, from_addr,
			       sizeof(conn->u.rtp.end.addr));
			LOG_CONN_RTP(conn_src, LOGL_NOTICE,
				     "loopback mode: implicitly using source address (%s:%u) as destination address\n",
				     osmo_sockaddr_ntop(&from_addr->u.sa, ipbuf),
				     osmo_sockaddr_port(&conn->u.rtp.end.addr.u.sa));
		}
		return mgcp_conn_rtp_dispatch_rtp(conn_src, msg);
	}

	/* Forward to E1 */
	return mgcp_e1_send_rtp(conn->endp, conn->u.rtp.end.codec, msg);
}

/*! cleanup an endpoint when a connection on an RTP bridge endpoint is removed.
 *  \param[in] endp Endpoint on which the connection resides.
 *  \param[in] conn Connection that is about to be removed (ignored). */
void mgcp_cleanup_rtp_bridge_cb(struct mgcp_endpoint *endp, struct mgcp_conn *conn)
{
	struct mgcp_conn *conn_cleanup;

	/* In mgcp_dispatch_rtp_bridge_cb() we use conn->priv to cache the
	 * pointer to the destination connection, so that we do not have
	 * to go through the list every time an RTP packet arrives. To prevent
	 * a use-after-free situation we invalidate this information for all
	 * connections present when one connection is removed from the
	 * endpoint. */
	llist_for_each_entry(conn_cleanup, &endp->conns, entry) {
		if (conn_cleanup->priv == conn)
			conn_cleanup->priv = NULL;
	}
}

/*! cleanup an endpoint when a connection on an E1 endpoint is removed.
 *  \param[in] endp Endpoint on which the connection resides.
 *  \param[in] conn Connection that is about to be removed (ignored). */
void mgcp_cleanup_e1_bridge_cb(struct mgcp_endpoint *endp, struct mgcp_conn *conn)
{
	/* Cleanup tasks for E1 are the same as for regular endpoint. The
	 * shut down of the E1 part is handled separately. */
	mgcp_cleanup_rtp_bridge_cb(endp, conn);
}

/* Handle incoming RTP data from NET */
static int rtp_data_net(struct osmo_fd *fd, unsigned int what)
{
	/* NOTE: This is a generic implementation. RTP data is received. In
	 * case of loopback the data is just sent back to its origin. All
	 * other cases implement endpoint specific behaviour (e.g. how is the
	 * destination connection determined?). That specific behaviour is
	 * implemented by the callback function that is called at the end of
	 * the function */

	struct mgcp_conn_rtp *conn_src;
	struct mgcp_endpoint *endp;
	struct osmo_sockaddr addr;
	socklen_t slen = sizeof(addr);
	char ipbuf[INET6_ADDRSTRLEN];
	int ret;
	enum rtp_proto proto;
	struct osmo_rtp_msg_ctx *mc;
	struct msgb *msg;
	int rc;

	conn_src = (struct mgcp_conn_rtp *)fd->data;
	OSMO_ASSERT(conn_src);
	endp = conn_src->conn->endp;
	OSMO_ASSERT(endp);
	msg = msgb_alloc_c(endp->trunk, RTP_BUF_SIZE, "RTP-rx");

	proto = (fd == &conn_src->end.rtp)? MGCP_PROTO_RTP : MGCP_PROTO_RTCP;

	ret = recvfrom(fd->fd, msgb_data(msg), msg->data_len, 0, (struct sockaddr *)&addr.u.sa, &slen);

	if (ret <= 0) {
		LOG_CONN_RTP(conn_src, LOGL_ERROR, "recvfrom error: %s\n", strerror(errno));
		rc = -1;
		goto out;
	}

	msgb_put(msg, ret);

	LOG_CONN_RTP(conn_src, LOGL_DEBUG, "%s: rx %u bytes from %s:%u\n",
		     proto == MGCP_PROTO_RTP ? "RTP" : "RTCP",
		     msgb_length(msg), osmo_sockaddr_ntop(&addr.u.sa, ipbuf),
		     osmo_sockaddr_port(&addr.u.sa));

	if ((proto == MGCP_PROTO_RTP && check_rtp(conn_src, msg))
	    || (proto == MGCP_PROTO_RTCP && check_rtcp(conn_src, msg))) {
		/* Logging happened in the two check_ functions */
		rc = -1;
		goto out;
	}

	if (mgcp_is_rtp_dummy_payload(msg)) {
		LOG_CONN_RTP(conn_src, LOGL_DEBUG, "rx dummy packet (dropped)\n");
		rc = 0;
		goto out;
	}

	/* Since the msgb remains owned and freed by this function, the msg ctx data struct can just be on the stack and
	 * needs not be allocated with the msgb. */
	mc = OSMO_RTP_MSG_CTX(msg);
	*mc = (struct osmo_rtp_msg_ctx){
		.proto = proto,
		.conn_src = conn_src,
		.from_addr = &addr,
	};
	LOG_CONN_RTP(conn_src, LOGL_DEBUG, "msg ctx: %d %p %s\n",
		     mc->proto, mc->conn_src,
		     osmo_hexdump((void*)mc->from_addr,
				  mc->from_addr->u.sa.sa_family == AF_INET6 ?
					sizeof(struct sockaddr_in6) :
					sizeof(struct sockaddr_in)));

	/* Increment RX statistics */
	rate_ctr_inc(rate_ctr_group_get_ctr(conn_src->ctrg, RTP_PACKETS_RX_CTR));
	rate_ctr_add(rate_ctr_group_get_ctr(conn_src->ctrg, RTP_OCTETS_RX_CTR), msgb_length(msg));
	/* FIXME: count RTP and RTCP separately, also count IuUP payload-less separately */

	/* Forward a copy of the RTP data to a debug ip/port */
	forward_data_tap(fd->fd, &conn_src->tap_in, msg);

	rc = rx_rtp(msg);

out:
	msgb_free(msg);
	return rc;
}

/* Note: This function is able to handle RTP and RTCP */
static int rx_rtp(struct msgb *msg)
{
	struct osmo_rtp_msg_ctx *mc = OSMO_RTP_MSG_CTX(msg);
	struct mgcp_conn_rtp *conn_src = mc->conn_src;
	struct osmo_sockaddr *from_addr = mc->from_addr;
	struct mgcp_conn *conn = conn_src->conn;
	struct mgcp_trunk *trunk = conn->endp->trunk;

	LOG_CONN_RTP(conn_src, LOGL_DEBUG, "rx_rtp(%u bytes)\n", msgb_length(msg));

	/* Check if the origin of the RTP packet seems plausible */
	if (!trunk->rtp_accept_all && check_rtp_origin(conn_src, from_addr))
		return -1;

	/* Handle AMR frame format conversion (octet-aligned vs. bandwith-efficient) */
	if (mc->proto == MGCP_PROTO_RTP
	    && conn_src->end.codec
	    && mgcp_codec_amr_align_mode_is_indicated(conn_src->end.codec)) {
		/* Make sure that the incoming AMR frame format matches the frame format that the call agent has
		 * communicated via SDP when the connection was created/modfied. */
		int oa = amr_oa_check((char*)msgb_data(msg), msgb_length(msg));
		if (oa < 0)
			return -1;
		if (((bool)oa) != conn_src->end.codec->param.amr_octet_aligned) {
			LOG_CONN_RTP(conn_src, LOGL_NOTICE,
				     "rx_rtp(%u bytes): Expected RTP AMR octet-aligned=%u but got octet-aligned=%u."
				     " check the config of your call-agent!\n",
				     msgb_length(msg), conn_src->end.codec->param.amr_octet_aligned, oa);
			return -1;
		}
	}

	mgcp_conn_watchdog_kick(conn_src->conn);

	/* Execute endpoint specific implementation that handles the
	 * dispatching of the RTP data */
	return conn->endp->type->dispatch_rtp_cb(msg);
}

/*! bind RTP port to osmo_fd.
 *  \param[in] source_addr source (local) address to bind on.
 *  \param[in] fd associated file descriptor.
 *  \param[in] port to bind on.
 *  \param[in] dscp IP DSCP value to use.
 *  \param[in] prio socket priority to use.
 *  \returns 0 on success, -1 on ERROR. */
int mgcp_create_bind(const char *source_addr, struct osmo_fd *fd, int port, uint8_t dscp,
		     uint8_t prio)
{
	int rc;

	rc = osmo_sock_init2(AF_UNSPEC, SOCK_DGRAM, IPPROTO_UDP, source_addr, port,
			     NULL, 0, OSMO_SOCK_F_BIND | OSMO_SOCK_F_DSCP(dscp) |
			     OSMO_SOCK_F_PRIO(prio));
	if (rc < 0) {
		LOGP(DRTP, LOGL_ERROR, "failed to bind UDP port (%s:%i).\n",
		     source_addr, port);
		return -1;
	}
	fd->fd = rc;
	LOGP(DRTP, LOGL_DEBUG, "created socket + bound UDP port (%s:%i).\n", source_addr, port);

	return 0;
}

/* Bind RTP and RTCP port (helper function for mgcp_bind_net_rtp_port()) */
static int bind_rtp(struct mgcp_config *cfg, const char *source_addr,
		    struct mgcp_rtp_end *rtp_end, struct mgcp_endpoint *endp)
{
	/* NOTE: The port that is used for RTCP is the RTP port incremented by one
	 * (e.g. RTP-Port = 16000 ==> RTCP-Port = 16001) */

	if (mgcp_create_bind(source_addr, &rtp_end->rtp, rtp_end->local_port,
			     cfg->endp_dscp, cfg->endp_priority) != 0) {
		LOGPENDP(endp, DRTP, LOGL_ERROR,
			 "failed to create RTP port: %s:%d\n",
			 source_addr, rtp_end->local_port);
		goto cleanup0;
	}

	if (mgcp_create_bind(source_addr, &rtp_end->rtcp, rtp_end->local_port + 1,
			     cfg->endp_dscp, cfg->endp_priority) != 0) {
		LOGPENDP(endp, DRTP, LOGL_ERROR,
			 "failed to create RTCP port: %s:%d\n",
			 source_addr, rtp_end->local_port + 1);
		goto cleanup1;
	}

	if (osmo_fd_register(&rtp_end->rtp) != 0) {
		LOGPENDP(endp, DRTP, LOGL_ERROR,
			 "failed to register RTP port %d\n",
			 rtp_end->local_port);
		goto cleanup2;
	}

	if (osmo_fd_register(&rtp_end->rtcp) != 0) {
		LOGPENDP(endp, DRTP, LOGL_ERROR,
			 "failed to register RTCP port %d\n",
			 rtp_end->local_port + 1);
		goto cleanup3;
	}

	return 0;

cleanup3:
	osmo_fd_unregister(&rtp_end->rtp);
cleanup2:
	close(rtp_end->rtcp.fd);
	rtp_end->rtcp.fd = -1;
cleanup1:
	close(rtp_end->rtp.fd);
	rtp_end->rtp.fd = -1;
cleanup0:
	return -1;
}

/*! bind RTP port to endpoint/connection.
 *  \param[in] endp endpoint that holds the RTP connection.
 *  \param[in] rtp_port port number to bind on.
 *  \param[in] conn associated RTP connection.
 *  \returns 0 on success, -1 on ERROR. */
int mgcp_bind_net_rtp_port(struct mgcp_endpoint *endp, int rtp_port,
			   struct mgcp_conn_rtp *conn)
{
	char name[512];
	struct mgcp_rtp_end *end;

	snprintf(name, sizeof(name), "%s-%s", conn->conn->name, conn->conn->id);
	end = &conn->end;

	if (end->rtp.fd != -1 || end->rtcp.fd != -1) {
		LOGPENDP(endp, DRTP, LOGL_ERROR, "%u was already bound on conn:%s\n",
			 rtp_port, mgcp_conn_dump(conn->conn));

		/* Double bindings should never occour! Since we always allocate
		 * connections dynamically and free them when they are not
		 * needed anymore, there must be no previous binding leftover.
		 * Should there be a connection bound twice, we have a serious
		 * problem and must exit immediately! */
		OSMO_ASSERT(false);
	}

	end->local_port = rtp_port;
	osmo_fd_setup(&end->rtp, -1, OSMO_FD_READ, rtp_data_net, conn, 0);
	osmo_fd_setup(&end->rtcp, -1, OSMO_FD_READ, rtp_data_net, conn, 0);

	return bind_rtp(endp->trunk->cfg, conn->end.local_addr, end, endp);
}

/*! free allocated RTP and RTCP ports.
 *  \param[in] end RTP end */
void mgcp_free_rtp_port(struct mgcp_rtp_end *end)
{
	if (end->rtp.fd != -1) {
		osmo_fd_unregister(&end->rtp);
		close(end->rtp.fd);
		end->rtp.fd = -1;
	}

	if (end->rtcp.fd != -1) {
		osmo_fd_unregister(&end->rtcp);
		close(end->rtcp.fd);
		end->rtcp.fd = -1;
	}
}

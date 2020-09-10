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
#include <osmocom/mgcp/iuup_cn_node.h>
#include <osmocom/mgcp/iuup_protocol.h>


#define RTP_SEQ_MOD		(1 << 16)
#define RTP_MAX_DROPOUT		3000
#define RTP_MAX_MISORDER	100

enum rtp_proto {
	MGCP_PROTO_RTP,
	MGCP_PROTO_RTCP,
};

static void rtpconn_rate_ctr_add(struct mgcp_conn_rtp *conn_rtp, struct mgcp_endpoint *endp,
				 int id, int inc)
{
	struct rate_ctr_group *conn_stats = conn_rtp->rate_ctr_group;
	struct rate_ctr_group *mgw_stats = endp->trunk->ratectr.all_rtp_conn_stats;

	/* add to both the per-connection and the global stats */
	rate_ctr_add(&conn_stats->ctr[id], inc);
	rate_ctr_add(&mgw_stats->ctr[id], inc);
}

static void rtpconn_rate_ctr_inc(struct mgcp_conn_rtp *conn_rtp, struct mgcp_endpoint *endp, int id)
{
	rtpconn_rate_ctr_add(conn_rtp, endp, id, 1);
}

static int rx_rtp(struct msgb *msg);

static bool addr_is_any(struct osmo_sockaddr *osa) {
	if (osa->u.sa.sa_family == AF_INET6) {
		struct in6_addr ip6_any = IN6ADDR_ANY_INIT;
		return memcmp(&osa->u.sin6.sin6_addr,
				   &ip6_any, sizeof(ip6_any)) == 0;
	} else {
		return osa->u.sin.sin_addr.s_addr == 0;
	}
}

/*! Determine the local rtp bind IP-address.
 *  \param[out] addr caller provided memory to store the resulting IP-Address.
 *  \param[in] endp mgcp endpoint, that holds a copy of the VTY parameters.
 *
 *  The local bind IP-address is automatically selected by probing the
 *  IP-Address of the interface that is pointing towards the remote IP-Address,
 *  if no remote IP-Address is known yet, the statically configured
 *  IP-Addresses are used as fallback. */
void mgcp_get_local_addr(char *addr, struct mgcp_conn_rtp *conn)
{

	struct mgcp_endpoint *endp;
	char ipbuf[INET6_ADDRSTRLEN];
	int rc;
	endp = conn->conn->endp;
	bool rem_addr_set = !addr_is_any(&conn->end.addr);
	char *bind_addr;

	/* Try probing the local IP-Address */
	if (endp->cfg->net_ports.bind_addr_probe && rem_addr_set) {
		rc = osmo_sock_local_ip(addr, osmo_sockaddr_ntop(&conn->end.addr.u.sa, ipbuf));
		if (rc < 0)
			LOGPCONN(conn->conn, DRTP, LOGL_ERROR,
				 "local interface auto detection failed, using configured addresses...\n");
		else {
			LOGPCONN(conn->conn, DRTP, LOGL_DEBUG,
				 "selected local rtp bind ip %s by probing using remote ip %s\n",
				 addr, osmo_sockaddr_ntop(&conn->end.addr.u.sa, ipbuf));
			return;
		}
	}

	/* Select from preconfigured IP-Addresses. We don't have bind_addr for Osmux (yet?). */
	if (rem_addr_set) {
		/* Check there is a bind IP for the RTP traffic configured,
		 * if so, use that IP-Address */
		bind_addr = conn->end.addr.u.sa.sa_family == AF_INET6 ?
				endp->cfg->net_ports.bind_addr_v6 :
				endp->cfg->net_ports.bind_addr_v4;
	} else {
		/* Choose any of the bind addresses, preferring v6 over v4 */
		bind_addr = endp->cfg->net_ports.bind_addr_v6;
		if (!bind_addr)
			bind_addr = endp->cfg->net_ports.bind_addr_v4;
	}
	if (bind_addr) {
		LOGPCONN(conn->conn, DRTP, LOGL_DEBUG,
			 "using configured rtp bind ip as local bind ip %s\n",
			 bind_addr);
	} else {
		/* No specific bind IP is configured for the RTP traffic, so
		 * assume the IP where we listen for incoming MGCP messages
		 * as bind IP */
		bind_addr = endp->cfg->source_addr;
		LOGPCONN(conn->conn, DRTP, LOGL_DEBUG,
			"using mgcp bind ip as local rtp bind ip: %s\n", bind_addr);
	}
	osmo_strlcpy(addr, bind_addr, INET6_ADDRSTRLEN);
}

/* This does not need to be a precision timestamp and
 * is allowed to wrap quite fast. The returned value is
 * 1/codec_rate seconds. */
static uint32_t get_current_ts(unsigned codec_rate)
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

/*! send udp packet.
 *  \param[in] fd associated file descriptor.
 *  \param[in] addr destination ip-address.
 *  \param[in] port destination UDP port (network byte order).
 *  \param[in] buf buffer that holds the data to be send.
 *  \param[in] len length of the data to be sent.
 *  \returns bytes sent, -1 on error. */
int mgcp_udp_send(int fd, struct osmo_sockaddr *addr, int port, char *buf, int len)
{
	char ipbuf[INET6_ADDRSTRLEN];
	size_t addr_len;
	bool is_ipv6 =  addr->u.sa.sa_family == AF_INET6;

	LOGP(DRTP, LOGL_DEBUG,
	     "sending %i bytes length packet to %s:%u ...\n", len,
	     osmo_sockaddr_ntop(&addr->u.sa, ipbuf),
	     ntohs(port));

	if (is_ipv6) {
		addr->u.sin6.sin6_port = port;
		addr_len = sizeof(addr->u.sin6);
	} else {
		addr->u.sin.sin_port = port;
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
	static char buf[] = { MGCP_DUMMY_LOAD };
	int rc;
	int was_rtcp = 0;

	OSMO_ASSERT(endp);
	OSMO_ASSERT(conn);

	LOGPCONN(conn->conn, DRTP, LOGL_DEBUG,"sending dummy packet... %s\n",
		 mgcp_conn_dump(conn->conn));

	rc = mgcp_udp_send(conn->end.rtp.fd, &conn->end.addr,
			   conn->end.rtp_port, buf, 1);

	if (rc == -1)
		goto failed;

	if (endp->trunk->omit_rtcp)
		return rc;

	was_rtcp = 1;
	rc = mgcp_udp_send(conn->end.rtcp.fd, &conn->end.addr,
			   conn->end.rtcp_port, buf, 1);

	if (rc >= 0)
		return rc;

failed:
	LOGPCONN(conn->conn, DRTP, LOGL_ERROR,
		 "Failed to send dummy %s packet.\n",
		 was_rtcp ? "RTCP" : "RTP");

	return -1;
}

/* Compute timestamp alignment error */
static int32_t ts_alignment_error(struct mgcp_rtp_stream_state *sstate,
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
static int check_rtp_timestamp(struct mgcp_endpoint *endp,
			       struct mgcp_rtp_state *state,
			       struct mgcp_rtp_stream_state *sstate,
			       struct mgcp_rtp_end *rtp_end,
			       struct osmo_sockaddr *addr,
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
static int adjust_rtp_timestamp_offset(struct mgcp_endpoint *endp,
				       struct mgcp_rtp_state *state,
				       struct mgcp_rtp_end *rtp_end,
				       struct osmo_sockaddr *addr,
				       int16_t delta_seq, uint32_t in_timestamp)
{
	int32_t tsdelta = state->packet_duration;
	int timestamp_offset;
	uint32_t out_timestamp;
	char ipbuf[INET6_ADDRSTRLEN];

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
static int align_rtp_timestamp_offset(struct mgcp_endpoint *endp,
				      struct mgcp_rtp_state *state,
				      struct mgcp_rtp_end *rtp_end,
				      struct osmo_sockaddr *addr,
				      uint32_t timestamp)
{
	char ipbuf[INET6_ADDRSTRLEN];
	int ts_error = 0;
	int ts_check = 0;
	int ptime = state->packet_duration;

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

void mgcp_rtp_annex_count(struct mgcp_endpoint *endp,
			  struct mgcp_rtp_state *state, const uint16_t seq,
			  const int32_t transit, const uint32_t ssrc)
{
	int32_t d;

	/* initialize or re-initialize */
	if (!state->stats.initialized || state->stats.ssrc != ssrc) {
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
 * that is valid for the destination connection (conn_dst) */
static int mgcp_patch_pt(struct mgcp_conn_rtp *conn_src,
			 struct mgcp_conn_rtp *conn_dst, struct msgb *msg)
{
	struct rtp_hdr *rtp_hdr;
	uint8_t pt_in;
	int pt_out;

	if (msgb_length(msg) < sizeof(struct rtp_hdr)) {
		LOG_CONN_RTP(conn_src, LOGL_ERROR, "RTP packet too short (%u < %zu)\n",
			     msgb_length(msg), sizeof(struct rtp_hdr));
		return -EINVAL;
	}

	rtp_hdr = (struct rtp_hdr *)msgb_data(msg);

	if (conn_src->iuup) {
		/* The source is an IuUP payload. We have received a dynamic payload type number on the IuUP side, and
		 * towards the pure RTP side it should go out as "AMR/8000". Make sure that the payload type number in
		 * the RTP packet matches the a=rtpmap:N payload type number configured for AMR. */
		const struct mgcp_rtp_codec *amr_codec = mgcp_codec_pt_find_by_subtype_name(conn_dst, "AMR", 0);

		if (!amr_codec) {
			/* There is no AMR codec configured on the outgoing conn. */
			return -EINVAL;
		}

		pt_out = amr_codec->payload_type;
	} else if (conn_dst->iuup) {
		/* The destination is an IuUP payload. Use whatever payload number was negotiated during IuUP
		 * Initialization. */
		pt_out = conn_dst->iuup->rtp_payload_type;
	} else {
		/* Both sides are normal RTP payloads. Consult the rtpmap settings received by SDP. */
		pt_in = rtp_hdr->payload_type;
		pt_out = mgcp_codec_pt_translate(conn_src, conn_dst, pt_in);
		if (pt_out < 0)
			return -EINVAL;
	}

	rtp_hdr->payload_type = (uint8_t) pt_out;
	return 0;
}

/* The RFC 3550 Appendix A assumes there are multiple sources but
 * some of the supported endpoints (e.g. the nanoBTS) can only handle
 * one source and this code will patch RTP header to appear as if there
 * is only one source.
 * There is also no probation period for new sources. Every RTP header
 * we receive will be seen as a switch in streams. */
void mgcp_patch_and_count(struct mgcp_endpoint *endp,
			  struct mgcp_rtp_state *state,
			  struct mgcp_rtp_end *rtp_end,
			  struct osmo_sockaddr *addr, struct msgb *msg)
{
	char ipbuf[INET6_ADDRSTRLEN];
	uint32_t arrival_time;
	int32_t transit;
	uint16_t seq;
	uint32_t timestamp, ssrc;
	struct rtp_hdr *rtp_hdr;
	int payload = rtp_end->codec->payload_type;
	unsigned int len = msgb_length(msg);

	if (len < sizeof(*rtp_hdr))
		return;

	rtp_hdr = (struct rtp_hdr *)msgb_data(msg);
	seq = ntohs(rtp_hdr->sequence);
	timestamp = ntohl(rtp_hdr->timestamp);
	arrival_time = get_current_ts(rtp_end->codec->rate);
	ssrc = ntohl(rtp_hdr->ssrc);
	transit = arrival_time - timestamp;

	mgcp_rtp_annex_count(endp, state, seq, transit, ssrc);

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
						    delta_seq, timestamp);

			state->patch.patch_ssrc = 1;
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
		/* Compute current per-packet timestamp delta */
		check_rtp_timestamp(endp, state, &state->in_stream, rtp_end,
				    addr, seq, timestamp, "input",
				    &state->in_stream.last_tsdelta);

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
					   timestamp);

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
	if (state->out_stream.ssrc == ssrc)
		check_rtp_timestamp(endp, state, &state->out_stream, rtp_end,
				    addr, seq, timestamp, "output",
				    &state->out_stream.last_tsdelta);

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
		LOGPENDP(endp, DRTP, LOGL_ERROR, "AMR RTP packet too short (%d < %zu)\n",
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

/* For AMR RTP two framing modes are defined RFC3267. There is a bandwith
 * efficient encoding scheme where all fields are packed together one after
 * another and an octet aligned mode where all fields are aligned to octet
 * boundaries. This function is used to convert between the two modes */
static int amr_oa_bwe_convert(struct mgcp_endpoint *endp, struct msgb *msg,
			      bool target_is_oa)
{
	/* NOTE: the msgb has an allocated length of RTP_BUF_SIZE, so there is
	 * plenty of space available to store the slightly larger, converted
	 * data */
	struct rtp_hdr *rtp_hdr;
	unsigned int payload_len;
	int rc;

	if (msgb_length(msg) < sizeof(struct rtp_hdr)) {
		LOGPENDP(endp, DRTP, LOGL_ERROR, "AMR RTP packet too short (%d < %zu)\n", msgb_length(msg), sizeof(struct rtp_hdr));
		return -EINVAL;
	}

	rtp_hdr = (struct rtp_hdr *)msgb_data(msg);

	payload_len = msgb_length(msg) - sizeof(struct rtp_hdr);

	if (osmo_amr_is_oa(rtp_hdr->data, payload_len)) {
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
			 "AMR RTP packet conversion failed\n");
		return -EINVAL;
	}

	return msgb_trim(msg, rc + sizeof(struct rtp_hdr));
}

/* Check if a conversion between octet-aligned and bandwith-efficient mode is
 * indicated. */
static bool amr_oa_bwe_convert_indicated(struct mgcp_rtp_codec *codec)
{
	if (codec->param_present == false)
		return false;
	if (!codec->param.amr_octet_aligned_present)
		return false;
	if (strcmp(codec->subtype_name, "AMR") != 0)
		return false;
	return true;
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
static void forward_data(int fd, struct mgcp_rtp_tap *tap, struct msgb *msg)
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
	hdr->timestamp = osmo_htonl(get_current_ts(rtp_end->codec->rate));
	hdr->sequence = osmo_htons(state->alt_rtp_tx_sequence);
	hdr->ssrc = state->alt_rtp_tx_ssrc;
}


/*! Send RTP/RTCP data to a specified destination connection.
 *  \param[in] endp associated endpoint (for configuration, logging).
 *  \param[in] is_rtp flag to specify if the packet is of type RTP or RTCP.
 *  \param[in] spoofed source address (set to NULL to disable).
 *  \param[in] buf buffer that contains the RTP/RTCP data.
 *  \param[in] len length of the buffer that contains the RTP/RTCP data.
 *  \param[in] conn_src associated source connection.
 *  \param[in] conn_dst associated destination connection.
 *  \returns 0 on success, -1 on ERROR. */
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

	if (is_rtp) {
		LOGPENDP(endp, DRTP, LOGL_DEBUG, "delivering RTP packet...\n");
	} else {
		LOGPENDP(endp, DRTP, LOGL_DEBUG, "delivering RTCP packet...\n");
	}

	/* FIXME: It is legal that the payload type on the egress connection is
	 * different from the payload type that has been negotiated on the
	 * ingress connection. Essentially the codecs are the same so we can
	 * match them and patch the payload type. However, if we can not find
	 * the codec pendant (everything ist equal except the PT), we are of
	 * course unable to patch the payload type. A situation like this
	 * should not occur if transcoding is consequently avoided. Until
	 * we have transcoding support in osmo-mgw we can not resolve this. */
	if (is_rtp) {
		rc = mgcp_patch_pt(conn_src, conn_dst, msg);
		if (rc < 0) {
			LOGPENDP(endp, DRTP, LOGL_DEBUG,
				 "can not patch PT because no suitable egress codec was found.\n");
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
			 ntohs(rtp_end->rtp_port), ntohs(rtp_end->rtcp_port)
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
			cont = endp->cfg->rtp_processing_cb(endp, rtp_end,
							    (char*)msgb_data(msg), &buflen,
							    RTP_BUF_SIZE);
			if (cont < 0)
				break;

			if (addr)
				mgcp_patch_and_count(endp, rtp_state, rtp_end,
						     addr, msg);

			if (amr_oa_bwe_convert_indicated(conn_dst->end.codec)) {
				rc = amr_oa_bwe_convert(endp, msg,
							conn_dst->end.codec->param.amr_octet_aligned);
				if (rc < 0) {
					LOGPENDP(endp, DRTP, LOGL_ERROR,
						 "Error in AMR octet-aligned <-> bandwidth-efficient mode conversion\n");
					break;
				}
			}
			else if (rtp_end->rfc5993_hr_convert
			    && strcmp(conn_src->end.codec->subtype_name,
				      "GSM-HR-08") == 0) {
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
				 ntohs(rtp_end->rtp_port), ntohs(rtp_end->rtcp_port)
				);

			/* Forward a copy of the RTP data to a debug ip/port */
			forward_data(rtp_end->rtp.fd, &conn_src->tap_out,
				     msg);

#if 0
			/* FIXME: HACK HACK HACK. See OS#2459.
			 * The ip.access nano3G needs the first RTP payload's first two bytes to read hex
			 * 'e400', or it will reject the RAB assignment. It seems to not harm other femto
			 * cells (as long as we patch only the first RTP payload in each stream).
			 */
			if (!rtp_state->patched_first_rtp_payload
			    && conn_src->conn->mode == MGCP_CONN_LOOPBACK) {
				uint8_t *data = msgb_data(msg) + 12;
				if (data[0] == 0xe0) {
					data[0] = 0xe4;
					data[1] = 0x00;
					rtp_state->patched_first_rtp_payload = true;
					LOGPENDP(endp, DRTP, LOGL_DEBUG,
						 "Patching over first two bytes"
						 " to fake an IuUP Initialization Ack\n");
				}
			}
#endif

			if (conn_dst->iuup)
				len = osmo_iuup_cn_tx_payload(conn_dst->iuup, msg);
			else
				len = mgcp_udp_send(rtp_end->rtp.fd, &rtp_end->addr, rtp_end->rtp_port,
						    (char*)msgb_data(msg), msgb_length(msg));

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
		LOGPENDP(endp, DRTP, LOGL_DEBUG,
			 "send to %s %s rtp_port:%u rtcp_port:%u\n",
			 dest_name, osmo_sockaddr_ntop(&rtp_end->addr.u.sa, ipbuf),
			 ntohs(rtp_end->rtp_port), ntohs(rtp_end->rtcp_port)
			);

		len = mgcp_udp_send(rtp_end->rtcp.fd,
				    &rtp_end->addr,
				    rtp_end->rtcp_port, (char*)msgb_data(msg), msgb_length(msg));

		rtpconn_rate_ctr_inc(conn_dst, endp, RTP_PACKETS_TX_CTR);
		rtpconn_rate_ctr_add(conn_dst, endp, RTP_OCTETS_TX_CTR, len);
		rtp_state->alt_rtp_tx_sequence++;

		return len;
	}

	return 0;
}

/* Check if the origin (addr) matches the address/port data of the RTP
 * connections. */
static int check_rtp_origin(struct mgcp_conn_rtp *conn, struct osmo_sockaddr *addr)
{
	char ipbuf[INET6_ADDRSTRLEN];

	if (addr_is_any(&conn->end.addr)) {
		switch (conn->conn->mode) {
		case MGCP_CONN_LOOPBACK:
			/* HACK: for IuUP, we want to reply with an IuUP Initialization ACK upon the first RTP
			 * message received. We currently hackishly accomplish that by putting the endpoint in
			 * loopback mode and patching over the looped back RTP message to make it look like an
			 * ack. We don't know the femto cell's IP address and port until the RAB Assignment
			 * Response is received, but the nano3G expects an IuUP Initialization Ack before it even
			 * sends the RAB Assignment Response. Hence, if the remote address is 0.0.0.0 and the
			 * MGCP port is in loopback mode, allow looping back the packet to any source. */
			LOGPCONN(conn->conn, DRTP, LOGL_ERROR,
				 "In loopback mode and remote address not set:"
				 " allowing data from address: %s\n",
				 osmo_sockaddr_ntop(&addr->u.sa, ipbuf));
			return 0;

		default:
			/* Receiving early media before the endpoint is configured. Instead of logging
			 * this as an error that occurs on every call, keep it more low profile to not
			 * confuse humans with expected errors. */
			LOGPCONN(conn->conn, DRTP, LOGL_INFO,
				 "Rx RTP from %s, but remote address not set:"
				 " dropping early media\n",
				 osmo_sockaddr_ntop(&addr->u.sa, ipbuf));
			return -1;
		}
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
			 "data from wrong address: %s, ",
			 osmo_sockaddr_ntop(&addr->u.sa, ipbuf));
		LOGPC(DRTP, LOGL_ERROR, "expected: %s\n",
		      osmo_sockaddr_ntop(&conn->end.addr.u.sa, ipbuf));
		LOGPCONN(conn->conn, DRTP, LOGL_ERROR, "packet tossed\n");
		return -1;
	}

	/* Note: Usually the remote remote port of the data we receive will be
	 * the same as the remote port where we transmit outgoing RTP traffic
	 * to (set by MDCX). We use this to check the origin of the data for
	 * plausibility. */
	if (ntohs(conn->end.rtp_port) != osmo_sockaddr_port(&addr->u.sa) &&
	    ntohs(conn->end.rtcp_port) != osmo_sockaddr_port(&addr->u.sa)) {
		LOGPCONN(conn->conn, DRTP, LOGL_ERROR,
			 "data from wrong source port: %d, ",
			 osmo_sockaddr_port(&addr->u.sa));
		LOGPC(DRTP, LOGL_ERROR,
		      "expected: %d for RTP or %d for RTCP\n",
		      ntohs(conn->end.rtp_port), ntohs(conn->end.rtcp_port));
		LOGPCONN(conn->conn, DRTP, LOGL_ERROR, "packet tossed\n");
		return -1;
	}

	return 0;
}

/* Check the if the destination address configuration of an RTP connection
 * makes sense */
static int check_rtp_destin(struct mgcp_conn_rtp *conn)
{
	char ipbuf[INET6_ADDRSTRLEN];
	bool ip_is_any = addr_is_any(&conn->end.addr);

	/* Note: it is legal to create a connection but never setting a port
	 * and IP-address for outgoing data. */
	if (ip_is_any && conn->end.rtp_port == 0) {
		LOGPCONN(conn->conn, DRTP, LOGL_DEBUG,
			 "destination IP-address and rtp port is (not yet) known (%s:%u)\n",
			 osmo_sockaddr_ntop(&conn->end.addr.u.sa, ipbuf), conn->end.rtp_port);
		return -1;
	}

	if (ip_is_any) {
		LOGPCONN(conn->conn, DRTP, LOGL_ERROR,
			 "destination IP-address is invalid (%s:%u)\n",
			 osmo_sockaddr_ntop(&conn->end.addr.u.sa, ipbuf), conn->end.rtp_port);
		return -1;
	}

	if (conn->end.rtp_port == 0) {
		LOGPCONN(conn->conn, DRTP, LOGL_ERROR,
			 "destination rtp port is invalid (%s:%u)\n",
			 osmo_sockaddr_ntop(&conn->end.addr.u.sa, ipbuf), conn->end.rtp_port);
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
	if (conn_src->iuup)
		min_size += sizeof(struct osmo_iuup_hdr_data);
	if (msgb_length(msg) < min_size) {
		LOG_CONN_RTP(conn_src, LOGL_ERROR, "RTP packet too short (%u < %zu)\n",
			     msgb_length(msg), min_size);
		return -1;
	}

	/* FIXME: Add more checks, the reason why we do not check more than
	 * the length is because we currently handle IUUP packets as RTP
	 * packets, so they must pass this check, if we weould be more
	 * strict here, we would possibly break 3G. (see also FIXME note
	 * below */

	return 0;
}

/* Send RTP data. Possible options are standard RTP packet
 * transmission or trsmission via an osmux connection */
static int mgcp_send_rtp(struct mgcp_conn_rtp *conn_dst, struct msgb *msg)
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
	case MGCP_OSMUX_BSC_NAT:
	case MGCP_OSMUX_BSC:
		LOGPENDP(endp, DRTP, LOGL_DEBUG,
			 "endpoint type is MGCP_OSMUX_BSC_NAT, "
			 "using osmux_xfrm_to_osmux() to forward data through OSMUX\n");
		return osmux_xfrm_to_osmux((char*)msgb_data(msg), msgb_length(msg), conn_dst);
	}

	/* If the data has not been handled/forwarded until here, it will
	 * be discarded, this should not happen, normally the MGCP type
	 * should be properly set */
	LOGPENDP(endp, DRTP, LOGL_ERROR, "bad MGCP type -- data discarded!\n");

	return -1;
}

/*! dispatch incoming RTP packet to opposite RTP connection.
 *  \param[in] proto protocol (MGCP_CONN_TYPE_RTP or MGCP_CONN_TYPE_RTCP).
 *  \param[in] addr socket address where the RTP packet has been received from.
 *  \param[in] buf buffer that hold the RTP payload.
 *  \param[in] buf_size size data length of buf.
 *  \param[in] conn originating connection.
 *  \returns 0 on success, -1 on ERROR. */
int mgcp_dispatch_rtp_bridge_cb(struct msgb *msg)
{
	struct osmo_rtp_msg_ctx *mc = OSMO_RTP_MSG_CTX(msg);
	struct mgcp_conn_rtp *conn_src = mc->conn_src;
	struct mgcp_conn *conn = conn_src->conn;
	struct mgcp_conn *conn_dst;
	struct osmo_sockaddr *from_addr = mc->from_addr;

	/*! NOTE: This callback function implements the endpoint specific
	 *  dispatch behaviour of an rtp bridge/proxy endpoint. It is assumed
	 *  that the endpoint will hold only two connections. This premise
	 *  is used to determine the opposite connection (it is always the
	 *  connection that is not the originating connection). Once the
	 *  destination connection is known the RTP packet is sent via
	 *  the destination connection. */


	 /* Check if the connection is in loopback mode, if yes, just send the
	 * incoming data back to the origin */
	if (conn->mode == MGCP_CONN_LOOPBACK) {
		/* When we are in loopback mode, we loop back all incoming
		 * packets back to their origin. We will use the originating
		 * address data from the UDP packet header to patch the
		 * outgoing address in connection on the fly */
		if (conn->u.rtp.end.rtp_port == 0) {
			OSMO_ASSERT(conn->u.rtp.end.addr.u.sa.sa_family == from_addr->u.sa.sa_family);
			switch (from_addr->u.sa.sa_family) {
			case AF_INET:
				conn->u.rtp.end.addr.u.sin.sin_addr = from_addr->u.sin.sin_addr;
				conn->u.rtp.end.rtp_port = from_addr->u.sin.sin_port;
				break;
			case AF_INET6:
				conn->u.rtp.end.addr.u.sin6.sin6_addr = from_addr->u.sin6.sin6_addr;
				conn->u.rtp.end.rtp_port = from_addr->u.sin6.sin6_port;
				break;
			default:
				OSMO_ASSERT(false);
			}
		}
		return mgcp_send_rtp(conn_src, msg);
	}

	/* Find a destination connection. */
	/* NOTE: This code path runs every time an RTP packet is received. The
	 * function mgcp_find_dst_conn() we use to determine the detination
	 * connection will iterate the connection list inside the endpoint.
	 * Since list iterations are quite costly, we will figure out the
	 * destination only once and use the optional private data pointer of
	 * the connection to cache the destination connection pointer. */
	if (!conn->priv) {
		conn_dst = mgcp_find_dst_conn(conn);
		conn->priv = conn_dst;
	} else {
		conn_dst = (struct mgcp_conn *)conn->priv;
	}

	/* There is no destination conn, stop here */
	if (!conn_dst) {
		LOGPCONN(conn, DRTP, LOGL_DEBUG,
			 "no connection to forward an incoming RTP packet to\n");
		return -1;
	}

	/* The destination conn is not an RTP connection */
	if (conn_dst->type != MGCP_CONN_TYPE_RTP) {
		LOGPCONN(conn, DRTP, LOGL_ERROR,
			 "unable to find suitable destination conn\n");
		return -1;
	}

	/* Dispatch RTP packet to destination RTP connection */
	return mgcp_send_rtp(&conn_dst->u.rtp, msg);
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

	/* Check if the connection is in loopback mode, if yes, just send the
	 * incoming data back to the origin */
	if (conn->mode == MGCP_CONN_LOOPBACK) {
		/* When we are in loopback mode, we loop back all incoming
		 * packets back to their origin. We will use the originating
		 * address data from the UDP packet header to patch the
		 * outgoing address in connection on the fly */
		if (conn->u.rtp.end.rtp_port == 0) {
			OSMO_ASSERT(conn->u.rtp.end.addr.u.sa.sa_family == from_addr->u.sa.sa_family);
			switch (from_addr->u.sa.sa_family) {
			case AF_INET:
				conn->u.rtp.end.addr.u.sin.sin_addr = from_addr->u.sin.sin_addr;
				conn->u.rtp.end.rtp_port = from_addr->u.sin.sin_port;
				break;
			case AF_INET6:
				conn->u.rtp.end.addr.u.sin6.sin6_addr = from_addr->u.sin6.sin6_addr;
				conn->u.rtp.end.rtp_port = from_addr->u.sin6.sin6_port;
				break;
			default:
				OSMO_ASSERT(false);
			}
		}
		return mgcp_send_rtp(conn_src, msg);
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

static bool is_dummy_msg(enum rtp_proto proto, struct msgb *msg)
{
	return msgb_length(msg) == 1 && msgb_data(msg)[0] == MGCP_DUMMY_LOAD;
}

/* IuUP CN node has stripped an IuUP header and forwards RTP data to distribute to the peers. */
int iuup_rx_payload(struct msgb *msg, void *node_priv)
{
	struct osmo_rtp_msg_ctx *mc = OSMO_RTP_MSG_CTX(msg);
	struct mgcp_conn_rtp *conn_src = mc->conn_src;
	LOG_CONN_RTP(conn_src, LOGL_DEBUG, "iuup_rx_payload(%u bytes)\n", msgb_length(msg));
	return rx_rtp(msg);
}

/* IuUP CN node has composed a message that contains an IuUP header and asks us to send to the IuUP peer.
 */
int iuup_tx_msg(struct msgb *msg, void *node_priv)
{
	struct osmo_rtp_msg_ctx *mc = OSMO_RTP_MSG_CTX(msg);
	struct mgcp_conn_rtp *conn_src = mc->conn_src;
	struct mgcp_conn_rtp *conn_dst = node_priv;
	struct mgcp_rtp_end *rtp_end = &conn_dst->end;
	struct osmo_sockaddr *to_addr = &rtp_end->addr;
	uint16_t to_port = osmo_sockaddr_port(&to_addr->u.sa);
	char ipbuf[INET6_ADDRSTRLEN];

	if (conn_src == conn_dst && to_addr->u.sa.sa_family == AF_UNSPEC && !to_port) {
		LOG_CONN_RTP(conn_dst, LOGL_DEBUG, "iuup_tx_msg(): direct IuUP reply\n");
		/* IuUP wants to send a message back to the same peer that sent an RTP package, but there
		 * is no address configured for that peer yet. It is probably an IuUP Initialization ACK
		 * reply. Use the sender address to send the reply.
		 *
		 * During 3G RAB Assignment, a 3G cell might first probe the MGW and expect an IuUP
		 * Initialization ACK before it replies to the MSC with a successful RAB Assignment; only
		 * after that reply does MSC officially know which RTP address+port the 3G cell wants to
		 * use and can tell this MGW about it, so this "loopback" is, for some 3G cells, the only
		 * chance we have to get a successful RAB Assignment done (particularly the nano3G does
		 * this). */
		to_addr = mc->from_addr;
		to_port = osmo_sockaddr_port(&to_addr->u.sa);
	}
	LOG_CONN_RTP(conn_dst, LOGL_DEBUG, "iuup_tx_msg(%u bytes) to %s:%u\n", msgb_length(msg),
		     osmo_sockaddr_ntop(&to_addr->u.sa, ipbuf), to_port);

	return mgcp_udp_send(rtp_end->rtp.fd, to_addr, to_port, (char*)msgb_data(msg), msgb_length(msg));
}

static void iuup_init(struct mgcp_conn_rtp *conn_src)
{
	struct osmo_iuup_cn_cfg cfg = {
		.node_priv = conn_src,
		.rx_payload = iuup_rx_payload,
		.tx_msg = iuup_tx_msg,
	};

	if (conn_src->iuup) {
		LOG_CONN_RTP(conn_src, LOGL_NOTICE, "Rx IuUP init, but already initialized. Ignoring.\n");
		return;
	}

	conn_src->iuup = osmo_iuup_cn_init(conn_src->conn, &cfg, "endp_%s_conn_%s",
					   conn_src->conn->endp->name, conn_src->conn->id);
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
	struct msgb *msg = msgb_alloc_headroom(RTP_BUF_SIZE + OSMO_IUUP_HEADROOM,
					       OSMO_IUUP_HEADROOM, "RTP-rx");
	int rc;

	conn_src = (struct mgcp_conn_rtp *)fd->data;
	OSMO_ASSERT(conn_src);
	endp = conn_src->conn->endp;
	OSMO_ASSERT(endp);

	proto = (fd == &conn_src->end.rtp)? MGCP_PROTO_RTP : MGCP_PROTO_RTCP;

	ret = recvfrom(fd->fd, msgb_data(msg), msg->data_len, 0, (struct sockaddr *)&addr.u.sa, &slen);

	if (ret <= 0) {
		LOG_CONN_RTP(conn_src, LOGL_ERROR, "recvfrom error: %s\n", strerror(errno));
		rc = -1;
		goto out;
	}

	msgb_put(msg, ret);

	LOG_CONN_RTP(conn_src, LOGL_DEBUG, "%s: rx %u bytes from %s:%u\n",
		     proto == MGCP_PROTO_RTP ? "RTP" : "RTPC",
		     msgb_length(msg), osmo_sockaddr_ntop(&addr.u.sa, ipbuf),
		     osmo_sockaddr_port(&addr.u.sa));

	if ((proto == MGCP_PROTO_RTP && check_rtp(conn_src, msg))
	    || (proto == MGCP_PROTO_RTCP && check_rtcp(conn_src, msg))) {
		/* Logging happened in the two check_ functions */
		rc = -1;
		goto out;
	}

	if (is_dummy_msg(proto, msg)) {
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
	rate_ctr_inc(&conn_src->rate_ctr_group->ctr[RTP_PACKETS_RX_CTR]);
	rate_ctr_add(&conn_src->rate_ctr_group->ctr[RTP_OCTETS_RX_CTR], msgb_length(msg));
	/* FIXME: count RTP and RTCP separately, also count IuUP payload-less separately */

	/* Forward a copy of the RTP data to a debug ip/port */
	forward_data(fd->fd, &conn_src->tap_in, msg);

	if (proto == MGCP_PROTO_RTP && osmo_iuup_is_init(msg))
		iuup_init(conn_src);

	if (conn_src->iuup && proto == MGCP_PROTO_RTP)
		rc = osmo_iuup_cn_rx_pdu(conn_src->iuup, msg);
	else
		rc = rx_rtp(msg);

out:
	msgb_free(msg);
	return rc;
}

static int rx_rtp(struct msgb *msg)
{
	struct osmo_rtp_msg_ctx *mc = OSMO_RTP_MSG_CTX(msg);
	struct mgcp_conn_rtp *conn_src = mc->conn_src;
	struct osmo_sockaddr *from_addr = mc->from_addr;
	struct mgcp_conn *conn = conn_src->conn;
	struct mgcp_trunk *trunk = conn->endp->trunk;

	LOG_CONN_RTP(conn_src, LOGL_DEBUG, "rx_rtp(%u bytes)\n", msgb_length(msg));

	mgcp_conn_watchdog_kick(conn_src->conn);

	/* If AMR is configured for the ingress connection a conversion of the
	 * framing mode (octet-aligned vs. bandwith-efficient is explicitly
	 * define, then we check if the incoming payload matches that
	 * expectation. */
	if (amr_oa_bwe_convert_indicated(conn_src->end.codec)) {
		int oa = amr_oa_check((char*)msgb_data(msg), msgb_length(msg));
		if (oa < 0)
			return -1;
		if (((bool)oa) != conn_src->end.codec->param.amr_octet_aligned)
			return -1;
	}

	/* Check if the origin of the RTP packet seems plausible */
	if (!trunk->rtp_accept_all && check_rtp_origin(conn_src, from_addr))
		return -1;

	/* Execute endpoint specific implementation that handles the
	 * dispatching of the RTP data */
	return conn->endp->type->dispatch_rtp_cb(msg);
}

/*! set IP Type of Service parameter.
 *  \param[in] fd associated file descriptor.
 *  \param[in] tos dscp value.
 *  \returns 0 on success, -1 on ERROR. */
int mgcp_set_ip_tos(int fd, int tos)
{
	int ret;
	ret = setsockopt(fd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));

	if (ret < 0)
		return -1;
	return 0;
}

/*! bind RTP port to osmo_fd.
 *  \param[in] source_addr source (local) address to bind on.
 *  \param[in] fd associated file descriptor.
 *  \param[in] port to bind on.
 *  \returns 0 on success, -1 on ERROR. */
int mgcp_create_bind(const char *source_addr, struct osmo_fd *fd, int port)
{
	int rc;

	rc = osmo_sock_init2(AF_UNSPEC, SOCK_DGRAM, IPPROTO_UDP, source_addr, port,
			     NULL, 0, OSMO_SOCK_F_BIND);
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

	if (mgcp_create_bind(source_addr, &rtp_end->rtp,
			     rtp_end->local_port) != 0) {
		LOGPENDP(endp, DRTP, LOGL_ERROR,
			 "failed to create RTP port: %s:%d\n",
			 source_addr, rtp_end->local_port);
		goto cleanup0;
	}

	if (mgcp_create_bind(source_addr, &rtp_end->rtcp,
			     rtp_end->local_port + 1) != 0) {
		LOGPENDP(endp, DRTP, LOGL_ERROR,
			 "failed to create RTCP port: %s:%d\n",
			 source_addr, rtp_end->local_port + 1);
		goto cleanup1;
	}

	/* Set Type of Service (DSCP-Value) as configured via VTY */
	mgcp_set_ip_tos(rtp_end->rtp.fd, cfg->endp_dscp);
	mgcp_set_ip_tos(rtp_end->rtcp.fd, cfg->endp_dscp);

	rtp_end->rtp.when = OSMO_FD_READ;
	if (osmo_fd_register(&rtp_end->rtp) != 0) {
		LOGPENDP(endp, DRTP, LOGL_ERROR,
			 "failed to register RTP port %d\n",
			 rtp_end->local_port);
		goto cleanup2;
	}

	rtp_end->rtcp.when = OSMO_FD_READ;
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
	end->rtp.cb = rtp_data_net;
	end->rtp.data = conn;
	end->rtcp.data = conn;
	end->rtcp.cb = rtp_data_net;

	return bind_rtp(endp->cfg, conn->end.local_addr, end, endp);
}

/*! free allocated RTP and RTCP ports.
 *  \param[in] end RTP end */
void mgcp_free_rtp_port(struct mgcp_rtp_end *end)
{
	if (end->rtp.fd != -1) {
		close(end->rtp.fd);
		end->rtp.fd = -1;
		osmo_fd_unregister(&end->rtp);
	}

	if (end->rtcp.fd != -1) {
		close(end->rtcp.fd);
		end->rtcp.fd = -1;
		osmo_fd_unregister(&end->rtcp);
	}
}

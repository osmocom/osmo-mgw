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
#include <osmocom/mgcp/mgcp.h>
#include <osmocom/mgcp/mgcp_common.h>
#include <osmocom/mgcp/mgcp_internal.h>
#include <osmocom/mgcp/mgcp_stat.h>
#include <osmocom/mgcp/osmux.h>
#include <osmocom/mgcp/mgcp_conn.h>
#include <osmocom/mgcp/mgcp_endp.h>
#include <osmocom/mgcp/mgcp_codec.h>
#include <osmocom/mgcp/debug.h>


#define RTP_SEQ_MOD		(1 << 16)
#define RTP_MAX_DROPOUT		3000
#define RTP_MAX_MISORDER	100
#define RTP_BUF_SIZE		4096

enum {
	MGCP_PROTO_RTP,
	MGCP_PROTO_RTCP,
};

/*! Determine the local rtp bind IP-address.
 *  \param[out] addr caller provided memory to store the resulting IP-Address
 *  \param[in] endp mgcp endpoint, that holds a copy of the VTY parameters
 *
 *  The local bind IP-address is automatically selected by probing the
 *  IP-Address of the interface that is pointing towards the remote IP-Address,
 *  if no remote IP-Address is known yet, the statically configured
 *  IP-Addresses are used as fallback. */
void mgcp_get_local_addr(char *addr, struct mgcp_conn_rtp *conn)
{

	struct mgcp_endpoint *endp;
	int rc;
	endp = conn->conn->endp;

	/* Try probing the local IP-Address */
	if (endp->cfg->net_ports.bind_addr_probe && conn->end.addr.s_addr != 0) {
		rc = osmo_sock_local_ip(addr, inet_ntoa(conn->end.addr));
		if (rc < 0)
			LOGP(DRTP, LOGL_ERROR,
			     "endpoint:0x%x CI:%s local interface auto detection failed, using configured addresses...\n",
			     ENDPOINT_NUMBER(endp), conn->conn->id);
		else {
			LOGP(DRTP, LOGL_DEBUG,
			     "endpoint:0x%x CI:%s selected local rtp bind ip %s by probing using remote ip %s\n",
			     ENDPOINT_NUMBER(endp), conn->conn->id, addr,
			     inet_ntoa(conn->end.addr));
			return;
		}
	}

	/* Select from preconfigured IP-Addresses */
	if (endp->cfg->net_ports.bind_addr) {
		/* Check there is a bind IP for the RTP traffic configured,
		 * if so, use that IP-Address */
		osmo_strlcpy(addr, endp->cfg->net_ports.bind_addr, INET_ADDRSTRLEN);
		LOGP(DRTP, LOGL_DEBUG,
		     "endpoint:0x%x CI:%s using configured rtp bind ip as local bind ip %s\n",
		     ENDPOINT_NUMBER(endp), conn->conn->id, addr);
	} else {
		/* No specific bind IP is configured for the RTP traffic, so
		 * assume the IP where we listen for incoming MGCP messages
		 * as bind IP */
		osmo_strlcpy(addr, endp->cfg->source_addr, INET_ADDRSTRLEN);
		LOGP(DRTP, LOGL_DEBUG,
		     "endpoint:0x%x CI:%s using mgcp bind ip as local rtp bind ip: %s\n",
		     ENDPOINT_NUMBER(endp), conn->conn->id, addr);
	}
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
 *  \param[in] fd associated file descriptor
 *  \param[in] addr destination ip-address
 *  \param[in] port destination UDP port
 *  \param[in] buf buffer that holds the data to be send
 *  \param[in] len length of the data to be sent
 *  \returns bytes sent, -1 on error */
int mgcp_udp_send(int fd, struct in_addr *addr, int port, char *buf, int len)
{
	struct sockaddr_in out;

	LOGP(DRTP, LOGL_DEBUG,
	     "sending %i bytes length packet to %s:%u ...\n",
	     len, inet_ntoa(*addr), ntohs(port));

	out.sin_family = AF_INET;
	out.sin_port = port;
	memcpy(&out.sin_addr, addr, sizeof(*addr));

	return sendto(fd, buf, len, 0, (struct sockaddr *)&out, sizeof(out));
}

/*! send RTP dummy packet (to keep NAT connection open).
 *  \param[in] endp mcgp endpoint that holds the RTP connection
 *  \param[in] conn associated RTP connection
 *  \returns bytes sent, -1 on error */
int mgcp_send_dummy(struct mgcp_endpoint *endp, struct mgcp_conn_rtp *conn)
{
	static char buf[] = { MGCP_DUMMY_LOAD };
	int rc;
	int was_rtcp = 0;

	OSMO_ASSERT(endp);
	OSMO_ASSERT(conn);

	LOGP(DRTP, LOGL_DEBUG,
	     "endpoint:0x%x sending dummy packet...\n", ENDPOINT_NUMBER(endp));
	LOGP(DRTP, LOGL_DEBUG, "endpoint:0x%x conn:%s\n",
	     ENDPOINT_NUMBER(endp), mgcp_conn_dump(conn->conn));

	rc = mgcp_udp_send(conn->end.rtp.fd, &conn->end.addr,
			   conn->end.rtp_port, buf, 1);

	if (rc == -1)
		goto failed;

	if (endp->tcfg->omit_rtcp)
		return rc;

	was_rtcp = 1;
	rc = mgcp_udp_send(conn->end.rtcp.fd, &conn->end.addr,
			   conn->end.rtcp_port, buf, 1);

	if (rc >= 0)
		return rc;

failed:
	LOGP(DRTP, LOGL_ERROR,
	     "endpoint:0x%x Failed to send dummy %s packet.\n",
	     ENDPOINT_NUMBER(endp), was_rtcp ? "RTCP" : "RTP");

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
			       struct sockaddr_in *addr,
			       uint16_t seq, uint32_t timestamp,
			       const char *text, int32_t * tsdelta_out)
{
	int32_t tsdelta;
	int32_t timestamp_error;

	/* Not fully intialized, skip */
	if (sstate->last_tsdelta == 0 && timestamp == sstate->last_timestamp)
		return 0;

	if (seq == sstate->last_seq) {
		if (timestamp != sstate->last_timestamp) {
			rate_ctr_inc(sstate->err_ts_ctr);
			LOGP(DRTP, LOGL_ERROR,
			     "The %s timestamp delta is != 0 but the sequence "
			     "number %d is the same, "
			     "TS offset: %d, SeqNo offset: %d "
			     "on 0x%x SSRC: %u timestamp: %u "
			     "from %s:%d\n",
			     text, seq,
			     state->patch.timestamp_offset, state->patch.seq_offset,
			     ENDPOINT_NUMBER(endp), sstate->ssrc, timestamp,
			     inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));
		}
		return 0;
	}

	tsdelta =
	    (int32_t)(timestamp - sstate->last_timestamp) /
	    (int16_t)(seq - sstate->last_seq);

	if (tsdelta == 0) {
		/* Don't update *tsdelta_out */
		LOGP(DRTP, LOGL_NOTICE,
		     "The %s timestamp delta is %d "
		     "on 0x%x SSRC: %u timestamp: %u "
		     "from %s:%d\n",
		     text, tsdelta,
		     ENDPOINT_NUMBER(endp), sstate->ssrc, timestamp,
		     inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));

		return 0;
	}

	if (sstate->last_tsdelta != tsdelta) {
		if (sstate->last_tsdelta) {
			LOGP(DRTP, LOGL_INFO,
			     "The %s timestamp delta changes from %d to %d "
			     "on 0x%x SSRC: %u timestamp: %u from %s:%d\n",
			     text, sstate->last_tsdelta, tsdelta,
			     ENDPOINT_NUMBER(endp), sstate->ssrc, timestamp,
			     inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));
		}
	}

	if (tsdelta_out)
		*tsdelta_out = tsdelta;

	timestamp_error =
	    ts_alignment_error(sstate, state->packet_duration, timestamp);

	if (timestamp_error) {
		rate_ctr_inc(sstate->err_ts_ctr);
		LOGP(DRTP, LOGL_NOTICE,
		     "The %s timestamp has an alignment error of %d "
		     "on 0x%x SSRC: %u "
		     "SeqNo delta: %d, TS delta: %d, dTS/dSeq: %d "
		     "from %s:%d. ptime: %d\n",
		     text, timestamp_error,
		     ENDPOINT_NUMBER(endp), sstate->ssrc,
		     (int16_t)(seq - sstate->last_seq),
		     (int32_t)(timestamp - sstate->last_timestamp),
		     tsdelta,
		     inet_ntoa(addr->sin_addr), ntohs(addr->sin_port),
		     state->packet_duration);
	}
	return 1;
}

/* Set the timestamp offset according to the packet duration. */
static int adjust_rtp_timestamp_offset(struct mgcp_endpoint *endp,
				       struct mgcp_rtp_state *state,
				       struct mgcp_rtp_end *rtp_end,
				       struct sockaddr_in *addr,
				       int16_t delta_seq, uint32_t in_timestamp)
{
	int32_t tsdelta = state->packet_duration;
	int timestamp_offset;
	uint32_t out_timestamp;

	if (tsdelta == 0) {
		tsdelta = state->out_stream.last_tsdelta;
		if (tsdelta != 0) {
			LOGP(DRTP, LOGL_NOTICE,
			     "A fixed packet duration is not available on 0x%x, "
			     "using last output timestamp delta instead: %d "
			     "from %s:%d\n",
			     ENDPOINT_NUMBER(endp), tsdelta,
			     inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));
		} else {
			tsdelta = rtp_end->codec->rate * 20 / 1000;
			LOGP(DRTP, LOGL_NOTICE,
			     "Fixed packet duration and last timestamp delta "
			     "are not available on 0x%x, "
			     "using fixed 20ms instead: %d "
			     "from %s:%d\n",
			     ENDPOINT_NUMBER(endp), tsdelta,
			     inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));
		}
	}

	out_timestamp = state->out_stream.last_timestamp + delta_seq * tsdelta;
	timestamp_offset = out_timestamp - in_timestamp;

	if (state->patch.timestamp_offset != timestamp_offset) {
		state->patch.timestamp_offset = timestamp_offset;

		LOGP(DRTP, LOGL_NOTICE,
		     "Timestamp offset change on 0x%x SSRC: %u "
		     "SeqNo delta: %d, TS offset: %d, "
		     "from %s:%d\n",
		     ENDPOINT_NUMBER(endp), state->in_stream.ssrc,
		     delta_seq, state->patch.timestamp_offset,
		     inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));
	}

	return timestamp_offset;
}

/* Set the timestamp offset according to the packet duration. */
static int align_rtp_timestamp_offset(struct mgcp_endpoint *endp,
				      struct mgcp_rtp_state *state,
				      struct mgcp_rtp_end *rtp_end,
				      struct sockaddr_in *addr,
				      uint32_t timestamp)
{
	int ts_error = 0;
	int ts_check = 0;
	int ptime = state->packet_duration;

	/* Align according to: T + Toffs - Tlast = k * Tptime */

	ts_error = ts_alignment_error(&state->out_stream, ptime,
				      timestamp + state->patch.timestamp_offset);

	/* If there is an alignment error, we have to compensate it */
	if (ts_error) {
		state->patch.timestamp_offset += ptime - ts_error;

		LOGP(DRTP, LOGL_NOTICE,
		     "Corrected timestamp alignment error of %d on 0x%x SSRC: %u "
		     "new TS offset: %d, "
		     "from %s:%d\n",
		     ts_error,
		     ENDPOINT_NUMBER(endp), state->in_stream.ssrc,
		     state->patch.timestamp_offset, inet_ntoa(addr->sin_addr),
		     ntohs(addr->sin_port));
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
 *  \param[in] associated endpoint
 *  \param[in] destination RTP end
 *  \param[in,out] pointer to buffer with voice data
 *  \param[in] voice data length
 *  \param[in] maximum size of caller provided voice data buffer
 *  \returns ignores input parameters, return always 0 */
int mgcp_rtp_processing_default(struct mgcp_endpoint *endp,
				struct mgcp_rtp_end *dst_end,
				char *data, int *len, int buf_size)
{
	LOGP(DRTP, LOGL_DEBUG, "endpoint:0x%x transcoding disabled\n",
	     ENDPOINT_NUMBER(endp));
	return 0;
}

/*! dummy callback to disable transcoding (see also cfg->setup_rtp_processing_cb).
 *  \param[in] associated endpoint
 *  \param[in] destination RTP connnection
 *  \param[in] source RTP connection
 *  \returns ignores input parameters, return always 0 */
int mgcp_setup_rtp_processing_default(struct mgcp_endpoint *endp,
				      struct mgcp_conn_rtp *conn_dst,
				      struct mgcp_conn_rtp *conn_src)
{
	LOGP(DRTP, LOGL_DEBUG, "endpoint:0x%x transcoding disabled\n",
	     ENDPOINT_NUMBER(endp));
	return 0;
}

void mgcp_get_net_downlink_format_default(struct mgcp_endpoint *endp,
					  int *payload_type,
					  const char **audio_name,
					  const char **fmtp_extra,
					  struct mgcp_conn_rtp *conn)
{
	LOGP(DRTP, LOGL_DEBUG,
	     "endpoint:0x%x conn:%s using format defaults\n",
	     ENDPOINT_NUMBER(endp), mgcp_conn_dump(conn->conn));

	*payload_type = conn->end.codec->payload_type;
	*audio_name = conn->end.codec->audio_name;
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
			LOGP(DRTP, LOGL_NOTICE,
			     "RTP seqno made a very large jump on 0x%x delta: %u\n",
			     ENDPOINT_NUMBER(endp), udelta);
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
			 struct mgcp_conn_rtp *conn_dst, char *data, int len)
{
	struct rtp_hdr *rtp_hdr;
	uint8_t pt_in;
	int pt_out;

	OSMO_ASSERT(len >= sizeof(struct rtp_hdr));
	rtp_hdr = (struct rtp_hdr *)data;

	pt_in = rtp_hdr->payload_type;
	pt_out = mgcp_codec_pt_translate(conn_src, conn_dst, pt_in);
	if (pt_out < 0)
		return -EINVAL;

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
			  struct sockaddr_in *addr, char *data, int len)
{
	uint32_t arrival_time;
	int32_t transit;
	uint16_t seq;
	uint32_t timestamp, ssrc;
	struct rtp_hdr *rtp_hdr;
	int payload = rtp_end->codec->payload_type;

	if (len < sizeof(*rtp_hdr))
		return;

	rtp_hdr = (struct rtp_hdr *)data;
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
		LOGP(DRTP, LOGL_INFO,
		     "endpoint:0x%x initializing stream, SSRC: %u timestamp: %u "
		     "pkt-duration: %d, from %s:%d\n",
		     ENDPOINT_NUMBER(endp), state->in_stream.ssrc,
		     state->patch.seq_offset, state->packet_duration,
		     inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));
		if (state->packet_duration == 0) {
			state->packet_duration =
			    rtp_end->codec->rate * 20 / 1000;
			LOGP(DRTP, LOGL_NOTICE,
			     "endpoint:0x%x fixed packet duration is not available, "
			     "using fixed 20ms instead: %d from %s:%d\n",
			     ENDPOINT_NUMBER(endp), state->packet_duration,
			     inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));
		}
	} else if (state->in_stream.ssrc != ssrc) {
		LOGP(DRTP, LOGL_NOTICE,
		     "endpoint:0x%x SSRC changed: %u -> %u  "
		     "from %s:%d\n",
		     ENDPOINT_NUMBER(endp),
		     state->in_stream.ssrc, rtp_hdr->ssrc,
		     inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));

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

			LOGP(DRTP, LOGL_NOTICE,
			     "endpoint:0x%x SSRC patching enabled, SSRC: %u "
			     "SeqNo offset: %d, TS offset: %d "
			     "from %s:%d\n",
			     ENDPOINT_NUMBER(endp), state->in_stream.ssrc,
			     state->patch.seq_offset, state->patch.timestamp_offset,
			     inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));
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
	DEBUGP(DRTP,
	       "endpoint:0x%x payload hdr payload %u -> endp payload %u\n",
	       ENDPOINT_NUMBER(endp), rtp_hdr->payload_type, payload);
	rtp_hdr->payload_type = payload;
#endif
}

/* Forward data to a debug tap. This is debug function that is intended for
 * debugging the voice traffic with tools like gstreamer */
static void forward_data(int fd, struct mgcp_rtp_tap *tap, const char *buf,
			 int len)
{
	int rc;

	if (!tap->enabled)
		return;

	rc = sendto(fd, buf, len, 0, (struct sockaddr *)&tap->forward,
		    sizeof(tap->forward));

	if (rc < 0)
		LOGP(DRTP, LOGL_ERROR,
		     "Forwarding tapped (debug) voice data failed.\n");
}

/*! Send RTP/RTCP data to a specified destination connection.
 *  \param[in] endp associated endpoint (for configuration, logging)
 *  \param[in] is_rtp flag to specify if the packet is of type RTP or RTCP
 *  \param[in] spoofed source address (set to NULL to disable)
 *  \param[in] buf buffer that contains the RTP/RTCP data
 *  \param[in] len length of the buffer that contains the RTP/RTCP data
 *  \param[in] conn_src associated source connection
 *  \param[in] conn_dst associated destination connection
 *  \returns 0 on success, -1 on ERROR */
int mgcp_send(struct mgcp_endpoint *endp, int is_rtp, struct sockaddr_in *addr,
	      char *buf, int len, struct mgcp_conn_rtp *conn_src,
	      struct mgcp_conn_rtp *conn_dst)
{
	/*! When no destination connection is available (e.g. when only one
	 *  connection in loopback mode exists), then the source connection
	 *  shall be specified as destination connection */

	struct mgcp_trunk_config *tcfg = endp->tcfg;
	struct mgcp_rtp_end *rtp_end;
	struct mgcp_rtp_state *rtp_state;
	char *dest_name;
	int rc;

	OSMO_ASSERT(conn_src);
	OSMO_ASSERT(conn_dst);

	if (is_rtp) {
		LOGP(DRTP, LOGL_DEBUG,
		     "endpoint:0x%x delivering RTP packet...\n",
		     ENDPOINT_NUMBER(endp));
	} else {
		LOGP(DRTP, LOGL_DEBUG,
		     "endpoint:0x%x delivering RTCP packet...\n",
		     ENDPOINT_NUMBER(endp));
	}

	LOGP(DRTP, LOGL_DEBUG,
	     "endpoint:0x%x loop:%d, mode:%d%s\n",
	     ENDPOINT_NUMBER(endp), tcfg->audio_loop, conn_src->conn->mode,
	     conn_src->conn->mode == MGCP_CONN_LOOPBACK ? " (loopback)" : "");

	/* FIXME: It is legal that the payload type on the egress connection is
	 * different from the payload type that has been negotiated on the
	 * ingress connection. Essentially the codecs are the same so we can
	 * match them and patch the payload type. However, if we can not find
	 * the codec pendant (everything ist equal except the PT), we are of
	 * course unable to patch the payload type. A situation like this
	 * should not occur if transcoding is consequently avoided. Until
	 * we have transcoding support in osmo-mgw we can not resolve this. */
	if (is_rtp) {
		rc = mgcp_patch_pt(conn_src, conn_dst, buf, len);
		if (rc < 0) {
			LOGP(DRTP, LOGL_ERROR,
			     "endpoint:0x%x can not patch PT because no suitable egress codec was found.\n",
			     ENDPOINT_NUMBER(endp));
		}
	}

	/* Note: In case of loopback configuration, both, the source and the
	 * destination will point to the same connection. */
	rtp_end = &conn_dst->end;
	rtp_state = &conn_src->state;
	dest_name = conn_dst->conn->name;

	if (!rtp_end->output_enabled) {
		rate_ctr_inc(&conn_dst->rate_ctr_group->ctr[RTP_DROPPED_PACKETS_CTR]);
		LOGP(DRTP, LOGL_DEBUG,
		     "endpoint:0x%x output disabled, drop to %s %s "
		     "rtp_port:%u rtcp_port:%u\n",
		     ENDPOINT_NUMBER(endp),
		     dest_name,
		     inet_ntoa(rtp_end->addr),
		     ntohs(rtp_end->rtp_port), ntohs(rtp_end->rtcp_port)
		    );
	} else if (is_rtp) {
		int cont;
		int nbytes = 0;
		int buflen = len;
		do {
			/* Run transcoder */
			cont = endp->cfg->rtp_processing_cb(endp, rtp_end,
							    buf, &buflen,
							    RTP_BUF_SIZE);
			if (cont < 0)
				break;

			if (addr)
				mgcp_patch_and_count(endp, rtp_state, rtp_end,
						     addr, buf, buflen);
			LOGP(DRTP, LOGL_DEBUG,
			     "endpoint:0x%x process/send to %s %s "
			     "rtp_port:%u rtcp_port:%u\n",
			     ENDPOINT_NUMBER(endp), dest_name,
			     inet_ntoa(rtp_end->addr), ntohs(rtp_end->rtp_port),
			     ntohs(rtp_end->rtcp_port)
			    );

			/* Forward a copy of the RTP data to a debug ip/port */
			forward_data(rtp_end->rtp.fd, &conn_src->tap_out,
				     buf, buflen);

			/* FIXME: HACK HACK HACK. See OS#2459.
			 * The ip.access nano3G needs the first RTP payload's first two bytes to read hex
			 * 'e400', or it will reject the RAB assignment. It seems to not harm other femto
			 * cells (as long as we patch only the first RTP payload in each stream).
			 */
			if (!rtp_state->patched_first_rtp_payload
			    && conn_src->conn->mode == MGCP_CONN_LOOPBACK) {
				uint8_t *data = (uint8_t *) & buf[12];
				if (data[0] == 0xe0) {
					data[0] = 0xe4;
					data[1] = 0x00;
					rtp_state->patched_first_rtp_payload = true;
					LOGP(DRTP, LOGL_DEBUG,
					     "endpoint:0x%x Patching over first two bytes"
					     " to fake an IuUP Initialization Ack\n",
					     ENDPOINT_NUMBER(endp));
				}
			}

			len = mgcp_udp_send(rtp_end->rtp.fd,
					    &rtp_end->addr,
					    rtp_end->rtp_port, buf, buflen);

			if (len <= 0)
				return len;

			rate_ctr_inc(&conn_dst->rate_ctr_group->ctr[RTP_PACKETS_TX_CTR]);
			rate_ctr_add(&conn_dst->rate_ctr_group->ctr[RTP_OCTETS_TX_CTR], len);

			nbytes += len;
			buflen = cont;
		} while (buflen > 0);
		return nbytes;
	} else if (!tcfg->omit_rtcp) {
		LOGP(DRTP, LOGL_DEBUG,
		     "endpoint:0x%x send to %s %s rtp_port:%u rtcp_port:%u\n",
		     ENDPOINT_NUMBER(endp),
		     dest_name,
		     inet_ntoa(rtp_end->addr),
		     ntohs(rtp_end->rtp_port), ntohs(rtp_end->rtcp_port)
		    );

		len = mgcp_udp_send(rtp_end->rtcp.fd,
				    &rtp_end->addr,
				    rtp_end->rtcp_port, buf, len);

		rate_ctr_inc(&conn_dst->rate_ctr_group->ctr[RTP_PACKETS_TX_CTR]);
		rate_ctr_add(&conn_dst->rate_ctr_group->ctr[RTP_OCTETS_TX_CTR], len);

		return len;
	}

	return 0;
}

/* Helper function for mgcp_recv(),
   Receive one RTP Packet + Originating address from file descriptor */
static int receive_from(struct mgcp_endpoint *endp, int fd,
			struct sockaddr_in *addr, char *buf, int bufsize)
{
	int rc;
	socklen_t slen = sizeof(*addr);
	struct sockaddr_in addr_sink;
	char buf_sink[RTP_BUF_SIZE];
	bool tossed = false;

	if (!addr)
		addr = &addr_sink;
	if (!buf) {
		tossed = true;
		buf = buf_sink;
		bufsize = sizeof(buf_sink);
	}

	rc = recvfrom(fd, buf, bufsize, 0, (struct sockaddr *)addr, &slen);

	LOGP(DRTP, LOGL_DEBUG,
	     "receiving %u bytes length packet from %s:%u ...\n",
	     rc, inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));

	if (rc < 0) {
		LOGP(DRTP, LOGL_ERROR,
		     "endpoint:0x%x failed to receive packet, errno: %d/%s\n",
		     ENDPOINT_NUMBER(endp), errno, strerror(errno));
		return -1;
	}

	if (tossed) {
		LOGP(DRTP, LOGL_ERROR, "endpoint:0x%x packet tossed\n",
		     ENDPOINT_NUMBER(endp));
	}

	return rc;
}

/* Check if the origin (addr) matches the address/port data of the RTP
 * connections. */
static int check_rtp_origin(struct mgcp_conn_rtp *conn,
			    struct sockaddr_in *addr)
{
	struct mgcp_endpoint *endp;
	endp = conn->conn->endp;
	struct sockaddr_in zero_addr = {};

	if (memcmp(&zero_addr.sin_addr, &conn->end.addr, sizeof(zero_addr.sin_addr)) == 0) {
		switch (conn->conn->mode) {
		case MGCP_CONN_LOOPBACK:
			/* HACK: for IuUP, we want to reply with an IuUP Initialization ACK upon the first RTP
			 * message received. We currently hackishly accomplish that by putting the endpoint in
			 * loopback mode and patching over the looped back RTP message to make it look like an
			 * ack. We don't know the femto cell's IP address and port until the RAB Assignment
			 * Response is received, but the nano3G expects an IuUP Initialization Ack before it even
			 * sends the RAB Assignment Response. Hence, if the remote address is 0.0.0.0 and the
			 * MGCP port is in loopback mode, allow looping back the packet to any source. */
			LOGP(DRTP, LOGL_ERROR,
			     "endpoint:0x%x In loopback mode and remote address not set:"
			     " allowing data from address: %s\n",
			     ENDPOINT_NUMBER(endp), inet_ntoa(addr->sin_addr));
			return 0;

		default:
			/* Receiving early media before the endpoint is configured. Instead of logging
			 * this as an error that occurs on every call, keep it more low profile to not
			 * confuse humans with expected errors. */
			LOGP(DRTP, LOGL_INFO,
			     "endpoint:0x%x I:%s Rx RTP from %s, but remote address not set:"
			     " dropping early media\n",
			     ENDPOINT_NUMBER(endp), conn->conn->id, inet_ntoa(addr->sin_addr));
			return -1;
		}
	}

	/* Note: Check if the inbound RTP data comes from the same host to
	 * which we send our outgoing RTP traffic. */
	if (memcmp(&addr->sin_addr, &conn->end.addr, sizeof(addr->sin_addr))
	    != 0) {
		LOGP(DRTP, LOGL_ERROR,
		     "endpoint:0x%x data from wrong address: %s, ",
		     ENDPOINT_NUMBER(endp), inet_ntoa(addr->sin_addr));
		LOGPC(DRTP, LOGL_ERROR, "expected: %s\n",
		      inet_ntoa(conn->end.addr));
		LOGP(DRTP, LOGL_ERROR, "endpoint:0x%x packet tossed\n",
		     ENDPOINT_NUMBER(endp));
		return -1;
	}

	/* Note: Usually the remote remote port of the data we receive will be
	 * the same as the remote port where we transmit outgoing RTP traffic
	 * to (set by MDCX). We use this to check the origin of the data for
	 * plausibility. */
	if (conn->end.rtp_port != addr->sin_port &&
	    conn->end.rtcp_port != addr->sin_port) {
		LOGP(DRTP, LOGL_ERROR,
		     "endpoint:0x%x data from wrong source port: %d, ",
		     ENDPOINT_NUMBER(endp), ntohs(addr->sin_port));
		LOGPC(DRTP, LOGL_ERROR,
		      "expected: %d for RTP or %d for RTCP\n",
		      ntohs(conn->end.rtp_port), ntohs(conn->end.rtcp_port));
		LOGP(DRTP, LOGL_ERROR, "endpoint:0x%x packet tossed\n",
		     ENDPOINT_NUMBER(endp));
		return -1;
	}

	return 0;
}

/* Check the if the destination address configuration of an RTP connection
 * makes sense */
static int check_rtp_destin(struct mgcp_conn_rtp *conn)
{
	struct mgcp_endpoint *endp;
	endp = conn->conn->endp;

	/* Note: it is legal to create a connection but never setting a port
	 * and IP-address for outgoing data. */
	if (strcmp(inet_ntoa(conn->end.addr), "0.0.0.0") == 0 && conn->end.rtp_port == 0) {
		LOGP(DRTP, LOGL_DEBUG,
		     "endpoint:0x%x destination IP-address and rtp port is (not yet) known\n",
		     ENDPOINT_NUMBER(endp));
		return -1;
	}

	if (strcmp(inet_ntoa(conn->end.addr), "0.0.0.0") == 0) {
		LOGP(DRTP, LOGL_ERROR,
		     "endpoint:0x%x destination IP-address is invalid\n",
		     ENDPOINT_NUMBER(endp));
		return -1;
	}

	if (conn->end.rtp_port == 0) {
		LOGP(DRTP, LOGL_ERROR,
		     "endpoint:0x%x destination rtp port is invalid\n",
		     ENDPOINT_NUMBER(endp));
		return -1;
	}

	return 0;
}

/* Do some basic checks to make sure that the RTCP packets we are going to
 * process are not complete garbage */
static int check_rtcp(char *buf, unsigned int buf_size)
{
	struct rtcp_hdr *hdr;
	unsigned int len;
	uint8_t type;

	/* RTPC packets that are just a header without data do not make
	 * any sense. */
	if (buf_size < sizeof(struct rtcp_hdr))
		return -EINVAL;

	/* Make sure that the length of the received packet does not exceed
	 * the available buffer size */
	hdr = (struct rtcp_hdr *)buf;
	len = (osmo_ntohs(hdr->length) + 1) * 4;
	if (len > buf_size)
		return -EINVAL;

	/* Make sure we accept only packets that have a proper packet type set
	 * See also: http://www.iana.org/assignments/rtp-parameters/rtp-parameters.xhtml */
	type = hdr->type;
	if ((type < 192 || type > 195) && (type < 200 || type > 213))
		return -EINVAL;

	return 0;
}

/* Do some basic checks to make sure that the RTP packets we are going to
 * process are not complete garbage */
static int check_rtp(char *buf, unsigned int buf_size)
{
	/* RTP packets that are just a header without data do not make
	 * any sense. */
	if (buf_size < sizeof(struct rtp_hdr))
		return -EINVAL;

	/* FIXME: Add more checks, the reason why we do not check more than
	 * the length is because we currently handle IUUP packets as RTP
	 * packets, so they must pass this check, if we weould be more
	 * strict here, we would possibly break 3G. (see also FIXME note
	 * below */

	return 0;
}

/* Receive RTP data from a specified source connection and dispatch it to a
 * destination connection. */
static int mgcp_recv(int *proto, struct sockaddr_in *addr, char *buf,
		     unsigned int buf_size, struct osmo_fd *fd)
{
	struct mgcp_endpoint *endp;
	struct mgcp_conn_rtp *conn;
	struct mgcp_trunk_config *tcfg;
	int rc;

	conn = (struct mgcp_conn_rtp*) fd->data;
	endp = conn->conn->endp;
	tcfg = endp->tcfg;

	LOGP(DRTP, LOGL_DEBUG, "endpoint:0x%x receiving RTP/RTCP packet...\n",
	     ENDPOINT_NUMBER(endp));

	rc = receive_from(endp, fd->fd, addr, buf, buf_size);
	if (rc <= 0)
		return -1;

	/* FIXME: The way how we detect the protocol looks odd. We should look
	 * into the packet header. Also we should introduce a packet type
	 * MGCP_PROTO_IUUP because currently we handle IUUP packets like RTP
	 * packets which is problematic. */
	*proto = fd == &conn->end.rtp ? MGCP_PROTO_RTP : MGCP_PROTO_RTCP;

	if (*proto == MGCP_PROTO_RTP) {
		if (check_rtp(buf, rc) < 0) {
			LOGP(DRTP, LOGL_ERROR,
			     "endpoint:0x%x invalid RTP packet received -- packet tossed\n",
			     ENDPOINT_NUMBER(endp));
			return -1;
		}
	} else if (*proto == MGCP_PROTO_RTCP) {
		if (check_rtcp(buf, rc) < 0) {
			LOGP(DRTP, LOGL_ERROR,
			     "endpoint:0x%x invalid RTCP packet received -- packet tossed\n",
			     ENDPOINT_NUMBER(endp));
			return -1;
		}
	}

	LOGP(DRTP, LOGL_DEBUG, "endpoint:0x%x ", ENDPOINT_NUMBER(endp));
	LOGPC(DRTP, LOGL_DEBUG, "receiving from %s %s %d\n",
	      conn->conn->name, inet_ntoa(addr->sin_addr),
	      ntohs(addr->sin_port));
	LOGP(DRTP, LOGL_DEBUG, "endpoint:0x%x conn:%s\n", ENDPOINT_NUMBER(endp),
	     mgcp_conn_dump(conn->conn));

	/* Check if the origin of the RTP packet seems plausible */
	if (tcfg->rtp_accept_all == 0) {
		if (check_rtp_origin(conn, addr) != 0)
			return -1;
	}

	/* Filter out dummy message */
	if (rc == 1 && buf[0] == MGCP_DUMMY_LOAD) {
		LOGP(DRTP, LOGL_NOTICE,
		     "endpoint:0x%x dummy message received\n",
		     ENDPOINT_NUMBER(endp));
		LOGP(DRTP, LOGL_ERROR,
		     "endpoint:0x%x packet tossed\n", ENDPOINT_NUMBER(endp));
		return 0;
	}

	/* Increment RX statistics */
	rate_ctr_inc(&conn->rate_ctr_group->ctr[RTP_PACKETS_RX_CTR]);
	rate_ctr_add(&conn->rate_ctr_group->ctr[RTP_OCTETS_RX_CTR], rc);

	/* Forward a copy of the RTP data to a debug ip/port */
	forward_data(fd->fd, &conn->tap_in, buf, rc);

	return rc;
}

/* Send RTP data. Possible options are standard RTP packet
 * transmission or trsmission via an osmux connection */
static int mgcp_send_rtp(int proto, struct sockaddr_in *addr, char *buf,
			 unsigned int buf_size,
			 struct mgcp_conn_rtp *conn_src,
			 struct mgcp_conn_rtp *conn_dst)
{
	struct mgcp_endpoint *endp;
	endp = conn_src->conn->endp;

	LOGP(DRTP, LOGL_DEBUG, "endpoint:0x%x destin conn:%s\n",
	     ENDPOINT_NUMBER(endp), mgcp_conn_dump(conn_dst->conn));

	/* Before we try to deliver the packet, we check if the destination
	 * port and IP-Address make sense at all. If not, we will be unable
	 * to deliver the packet. */
	if (check_rtp_destin(conn_dst) != 0)
		return -1;

	/* Depending on the RTP connection type, deliver the RTP packet to the
	 * destination connection. */
	switch (conn_dst->type) {
	case MGCP_RTP_DEFAULT:
		LOGP(DRTP, LOGL_DEBUG,
		     "endpoint:0x%x endpoint type is MGCP_RTP_DEFAULT, "
		     "using mgcp_send() to forward data directly\n",
		     ENDPOINT_NUMBER(endp));
		return mgcp_send(endp, proto == MGCP_PROTO_RTP,
				 addr, buf, buf_size, conn_src, conn_dst);
	case MGCP_OSMUX_BSC_NAT:
	case MGCP_OSMUX_BSC:
		LOGP(DRTP, LOGL_DEBUG,
		     "endpoint:0x%x endpoint type is MGCP_OSMUX_BSC_NAT, "
		     "using osmux_xfrm_to_osmux() to forward data through OSMUX\n",
		     ENDPOINT_NUMBER(endp));
		return osmux_xfrm_to_osmux(buf, buf_size, conn_dst);
	}

	/* If the data has not been handled/forwarded until here, it will
	 * be discarded, this should not happen, normally the MGCP type
	 * should be properly set */
	LOGP(DRTP, LOGL_ERROR,
	     "endpoint:0x%x bad MGCP type -- data discarded!\n",
	     ENDPOINT_NUMBER(endp));

	return -1;
}

/*! dispatch incoming RTP packet to opposite RTP connection.
 *  \param[in] proto protocol (MGCP_CONN_TYPE_RTP or MGCP_CONN_TYPE_RTCP)
 *  \param[in] addr socket address where the RTP packet has been received from
 *  \param[in] buf buffer that hold the RTP payload
 *  \param[in] buf_size size data length of buf
 *  \param[in] conn originating connection
 *  \returns 0 on success, -1 on ERROR */
int mgcp_dispatch_rtp_bridge_cb(int proto, struct sockaddr_in *addr, char *buf,
				unsigned int buf_size, struct mgcp_conn *conn)
{
	struct mgcp_conn *conn_dst;
	struct mgcp_endpoint *endp;
	endp = conn->endp;

	/*! NOTE: This callback function implements the endpoint specific
	 *  dispatch bahviour of an rtp bridge/proxy endpoint. It is assumed
	 *  that the endpoint will hold only two connections. This premise
	 *  is used to determine the opposite connection (it is always the
	 *  connection that is not the originating connection). Once the
	 *  destination connection is known the RTP packet is sent via
	 *  the destination connection. */

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
		LOGP(DRTP, LOGL_ERROR,
		     "endpoint:0x%x unable to find destination conn\n",
		     ENDPOINT_NUMBER(endp));
		return -1;
	}

	/* The destination conn is not an RTP connection */
	if (conn_dst->type != MGCP_CONN_TYPE_RTP) {
		LOGP(DRTP, LOGL_ERROR,
		     "endpoint:0x%x unable to find suitable destination conn\n",
		     ENDPOINT_NUMBER(endp));
		return -1;
	}

	/* Dispatch RTP packet to destination RTP connection */
	return mgcp_send_rtp(proto, addr, buf,
			     buf_size, &conn->u.rtp, &conn_dst->u.rtp);

}

/*! cleanup an endpoint when a connection on an RTP bridge endpoint is removed.
 *  \param[in] endp Endpoint on which the connection resides.
 *  \param[in] conn Connection that is about to be removed (ignored).
 *  \returns 0 on success, -1 on ERROR. */
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
		conn_cleanup->priv = NULL;
	}
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
	struct sockaddr_in addr;

	char buf[RTP_BUF_SIZE];
	int proto;
	int len;

	conn_src = (struct mgcp_conn_rtp *)fd->data;
	OSMO_ASSERT(conn_src);
	endp = conn_src->conn->endp;
	OSMO_ASSERT(endp);

	LOGP(DRTP, LOGL_DEBUG, "endpoint:0x%x source conn:%s\n",
	     ENDPOINT_NUMBER(endp), mgcp_conn_dump(conn_src->conn));

	/* Receive packet */
	len = mgcp_recv(&proto, &addr, buf, sizeof(buf), fd);
	if (len < 0)
		return -1;

	/* Check if the connection is in loopback mode, if yes, just send the
	 * incoming data back to the origin */
	if (conn_src->conn->mode == MGCP_CONN_LOOPBACK) {
		/* When we are in loopback mode, we loop back all incoming
		 * packets back to their origin. We will use the originating
		 * address data from the UDP packet header to patch the
		 * outgoing address in connection on the fly */
		if (conn_src->end.rtp_port == 0) {
			conn_src->end.addr = addr.sin_addr;
			conn_src->end.rtp_port = addr.sin_port;
		}
		return mgcp_send_rtp(proto, &addr, buf,
				     len, conn_src, conn_src);
	}

	/* Execute endpoint specific implementation that handles the
	 * dispatching of the RTP data */
	return endp->type->dispatch_rtp_cb(proto, &addr, buf, len,
					   conn_src->conn);
}

/*! set IP Type of Service parameter.
 *  \param[in] fd associated file descriptor
 *  \param[in] tos dscp value
 *  \returns 0 on success, -1 on ERROR */
int mgcp_set_ip_tos(int fd, int tos)
{
	int ret;
	ret = setsockopt(fd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));

	if (ret < 0)
		return -1;
	return 0;
}

/*! bind RTP port to osmo_fd.
 *  \param[in] source_addr source (local) address to bind on
 *  \param[in] fd associated file descriptor
 *  \param[in] port to bind on
 *  \returns 0 on success, -1 on ERROR */
int mgcp_create_bind(const char *source_addr, struct osmo_fd *fd, int port)
{
	int rc;

	rc = osmo_sock_init2(AF_INET, SOCK_DGRAM, IPPROTO_UDP, source_addr, port,
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
		    struct mgcp_rtp_end *rtp_end, int endpno)
{
	/* NOTE: The port that is used for RTCP is the RTP port incremented by one
	 * (e.g. RTP-Port = 16000 ==> RTCP-Port = 16001) */

	if (mgcp_create_bind(source_addr, &rtp_end->rtp,
			     rtp_end->local_port) != 0) {
		LOGP(DRTP, LOGL_ERROR,
		     "endpoint:0x%x failed to create RTP port: %s:%d\n", endpno,
		     source_addr, rtp_end->local_port);
		goto cleanup0;
	}

	if (mgcp_create_bind(source_addr, &rtp_end->rtcp,
			     rtp_end->local_port + 1) != 0) {
		LOGP(DRTP, LOGL_ERROR,
		     "endpoint:0x%x failed to create RTCP port: %s:%d\n", endpno,
		     source_addr, rtp_end->local_port + 1);
		goto cleanup1;
	}

	/* Set Type of Service (DSCP-Value) as configured via VTY */
	mgcp_set_ip_tos(rtp_end->rtp.fd, cfg->endp_dscp);
	mgcp_set_ip_tos(rtp_end->rtcp.fd, cfg->endp_dscp);

	rtp_end->rtp.when = BSC_FD_READ;
	if (osmo_fd_register(&rtp_end->rtp) != 0) {
		LOGP(DRTP, LOGL_ERROR,
		     "endpoint:0x%x failed to register RTP port %d\n", endpno,
		     rtp_end->local_port);
		goto cleanup2;
	}

	rtp_end->rtcp.when = BSC_FD_READ;
	if (osmo_fd_register(&rtp_end->rtcp) != 0) {
		LOGP(DRTP, LOGL_ERROR,
		     "endpoint:0x%x failed to register RTCP port %d\n", endpno,
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
 *  \param[in] endp endpoint that holds the RTP connection
 *  \param[in] rtp_port port number to bind on
 *  \param[in] conn associated RTP connection
 *  \returns 0 on success, -1 on ERROR */
int mgcp_bind_net_rtp_port(struct mgcp_endpoint *endp, int rtp_port,
			   struct mgcp_conn_rtp *conn)
{
	char name[512];
	struct mgcp_rtp_end *end;
	char local_ip_addr[INET_ADDRSTRLEN];

	snprintf(name, sizeof(name), "%s-%s", conn->conn->name, conn->conn->id);
	end = &conn->end;

	if (end->rtp.fd != -1 || end->rtcp.fd != -1) {
		LOGP(DRTP, LOGL_ERROR,
		     "endpoint:0x%x %u was already bound on conn:%s\n",
		     ENDPOINT_NUMBER(endp), rtp_port,
		     mgcp_conn_dump(conn->conn));

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

	mgcp_get_local_addr(local_ip_addr, conn);

	return bind_rtp(endp->cfg, local_ip_addr, end,
			ENDPOINT_NUMBER(endp));
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

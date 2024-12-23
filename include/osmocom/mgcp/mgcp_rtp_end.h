#pragma once

#include <inttypes.h>
#include <stdbool.h>

#include <osmocom/core/socket.h>
#include <osmocom/core/osmo_io.h>

#include <osmocom/mgcp/mgcp.h>
#include <osmocom/mgcp/mgcp_codec.h>

/* 'mgcp_rtp_end': basically a wrapper around the RTP+RTCP ports */
struct mgcp_rtp_end {
	/* remote IP address of the RTP socket */
	struct osmo_sockaddr addr;

	/* in network byte order */
	uint16_t rtcp_port;

	struct mgcp_rtp_codecset cset;

	/* per endpoint data */
	int  frames_per_packet;
	uint32_t packet_duration_ms;
	int maximum_packet_time; /* -1: not set */
	/* are we transmitting packets (true) or dropping (false) outbound packets */
	bool output_enabled;
	/* FIXME: This parameter can be set + printed, but is nowhere used! */
	int force_output_ptime;

	/* RTP patching */
	int force_constant_ssrc; /* -1: always, 0: don't, 1: once */
	/* should we perform align_rtp_timestamp_offset() (1) or not (0) */
	int force_aligned_timing;
	bool rfc5993_hr_convert;

	/* Each end has a separate socket for RTP and RTCP */
	struct osmo_io_fd *rtp;
	struct osmo_io_fd *rtcp;

	/* local UDP port number of the RTP socket; RTCP is +1 */
	int local_port;
	/* where the endpoint RTP connection binds to, set during CRCX and
	 * possibly updated during MDCX */
	char local_addr[INET6_ADDRSTRLEN];
};

void mgcp_rtp_end_init(struct mgcp_rtp_end *end);
void mgcp_rtp_end_cleanup(struct mgcp_rtp_end *end);
bool mgcp_rtp_end_remote_addr_available(const struct mgcp_rtp_end *rtp_end);
void mgcp_rtp_end_free_port(struct mgcp_rtp_end *end);

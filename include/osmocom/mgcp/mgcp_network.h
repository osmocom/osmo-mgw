#pragma once

#include <inttypes.h>
#include <stdbool.h>

#include <osmocom/core/socket.h>
#include <osmocom/core/osmo_io.h>

#include <osmocom/mgcp/mgcp.h>

/* The following constant defines an RTP dummy payload that is used for
 * "UDP Hole Punching" (NAT) */
#define MGCP_DUMMY_LOAD 0x23
static const char rtp_dummy_payload[] = { MGCP_DUMMY_LOAD };

/* Check if the data in a given message buffer matches the rtp dummy payload
 * defined above */
#define mgcp_is_rtp_dummy_payload(msg) \
	(msgb_length(msg) == sizeof(rtp_dummy_payload) && \
	memcmp(msgb_data(msg), rtp_dummy_payload, sizeof(rtp_dummy_payload)) == 0)

#define RTP_BUF_SIZE	4096

struct mgcp_rtp_stream_state {
	uint32_t ssrc;
	uint16_t last_seq;
	uint32_t last_timestamp;
	struct rate_ctr *err_ts_ctr;
	int32_t last_tsdelta;
	uint32_t last_arrival_time;
};

struct mgcp_rtp_state {
	/* has this state structure been initialized? */
	int initialized;

	struct {
		/* are we patching the SSRC value? */
		bool patch_ssrc;
		/* original SSRC (to which we shall patch any different SSRC) */
		uint32_t orig_ssrc;
		/* offset to apply on the sequence number */
		int seq_offset;
		/* offset to apply on the timestamp number */
		int32_t timestamp_offset;
	} patch;

	/* duration of a packet (FIXME: in which unit?) */
	uint32_t packet_duration;

	/* Note: These states are not continuously updated, they serve as an
	 * information source to patch certain values in the RTP header. Do
	 * not use this state if constantly updated data about the RTP stream
	 * is needed. (see also mgcp_patch_and_count() */
	struct mgcp_rtp_stream_state in_stream;
	struct mgcp_rtp_stream_state out_stream;

	/* jitter and packet loss calculation */
	struct {
		int initialized;
		uint16_t base_seq;
		uint16_t max_seq;
		uint32_t ssrc;
		uint32_t jitter;
		int32_t transit;
		int cycles;
	} stats;

	/* Alternative values for RTP tx, in case no sufficient header
	 * information is available so the header needs to be generated
	 * locally (when just forwarding packets, the header of incoming
	 * data is just re-used) */
	uint16_t alt_rtp_tx_sequence;
	uint32_t alt_rtp_tx_ssrc;
};

struct mgcp_rtp_codec {
	uint32_t rate;
	int channels;
	uint32_t frame_duration_num;
	uint32_t frame_duration_den;

	int payload_type;
	char audio_name[64];
	char subtype_name[64];

	bool param_present;
	struct mgcp_codec_param param;
};

/* 'mgcp_rtp_end': basically a wrapper around the RTP+RTCP ports */
struct mgcp_rtp_end {
	/* remote IP address of the RTP socket */
	struct osmo_sockaddr addr;

	/* in network byte order */
	int rtcp_port;

	/* currently selected audio codec */
	struct mgcp_rtp_codec *codec;

	/* array with assigned audio codecs to choose from (SDP) */
	struct mgcp_rtp_codec codecs[MGCP_MAX_CODECS];

	/* number of assigned audio codecs (SDP) */
	unsigned int codecs_assigned;

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

bool mgcp_rtp_end_remote_addr_available(const struct mgcp_rtp_end *rtp_end);

struct mgcp_rtp_tap {
	/* is this tap active (1) or not (0) */
	int enabled;
	/* IP/port to which we're forwarding the tapped data */
	struct osmo_sockaddr forward;
};

struct mgcp_conn;

int mgcp_send(struct mgcp_endpoint *endp, int is_rtp, struct osmo_sockaddr *addr,
	      struct msgb *msg, struct mgcp_conn_rtp *conn_src,
	      struct mgcp_conn_rtp *conn_dst);
int mgcp_send_dummy(struct mgcp_endpoint *endp, struct mgcp_conn_rtp *conn);
int mgcp_dispatch_rtp_bridge_cb(struct msgb *msg);
void mgcp_cleanup_rtp_bridge_cb(struct mgcp_endpoint *endp, struct mgcp_conn *conn);
int mgcp_dispatch_e1_bridge_cb(struct msgb *msg);
void mgcp_cleanup_e1_bridge_cb(struct mgcp_endpoint *endp, struct mgcp_conn *conn);
int mgcp_bind_net_rtp_port(struct mgcp_endpoint *endp, int rtp_port,
			   struct mgcp_conn_rtp *conn);
void mgcp_free_rtp_port(struct mgcp_rtp_end *end);
void mgcp_patch_and_count(const struct mgcp_endpoint *endp,
			  struct mgcp_rtp_state *state,
			  struct mgcp_rtp_end *rtp_end,
			  struct osmo_sockaddr *addr, struct msgb *msg);
int mgcp_get_local_addr(char *addr, struct mgcp_conn_rtp *conn);

/* payload processing default functions */
int mgcp_rtp_processing_default(struct mgcp_endpoint *endp, struct mgcp_rtp_end *dst_end, struct msgb *msg);

int mgcp_setup_rtp_processing_default(struct mgcp_endpoint *endp,
				      struct mgcp_conn_rtp *conn_dst,
				      struct mgcp_conn_rtp *conn_src);

void mgcp_get_net_downlink_format_default(struct mgcp_endpoint *endp,
					  const struct mgcp_rtp_codec **codec,
					  const char **fmtp_extra,
					  struct mgcp_conn_rtp *conn);

/* internal RTP Annex A counting */
void mgcp_rtp_annex_count(const struct mgcp_endpoint *endp, struct mgcp_rtp_state *state,
			const uint16_t seq, const int32_t transit,
			const uint32_t ssrc, const bool marker_bit);

void rtpconn_rate_ctr_add(struct mgcp_conn_rtp *conn_rtp, struct mgcp_endpoint *endp,
				 int id, int inc);
void rtpconn_rate_ctr_inc(struct mgcp_conn_rtp *conn_rtp, struct mgcp_endpoint *endp,
				 int id);
void forward_data_tap(struct osmo_io_fd *iofd, struct mgcp_rtp_tap *tap, struct msgb *msg);
uint32_t mgcp_get_current_ts(unsigned codec_rate);

int amr_oa_bwe_convert(struct mgcp_endpoint *endp, struct msgb *msg, bool target_is_oa);

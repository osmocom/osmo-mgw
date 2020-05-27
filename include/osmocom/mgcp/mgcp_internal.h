/* MGCP Private Data */

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

#pragma once

#include <string.h>
#include <inttypes.h>
#include <osmocom/core/select.h>
#include <osmocom/mgcp/mgcp.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/counter.h>
#include <osmocom/core/rate_ctr.h>

#define CI_UNUSED 0

/* FIXME: This this is only needed to compile the currently
 * broken OSMUX support. Remove when fixed */
#define CONN_ID_BTS "0"
#define CONN_ID_NET "1"

enum mgcp_trunk_type {
	MGCP_TRUNK_VIRTUAL,
	MGCP_TRUNK_E1,
};

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
		int patch_ssrc;
		/* original SSRC (to which we shall patch any different SSRC) */
		uint32_t orig_ssrc;
		/* offset to apply on the sequence number */
		int seq_offset;
		/* offset to apply on the timestamp number */
		int32_t timestamp_offset;
	} patch;

	/* duration of a packet (FIXME: in which unit?) */
	uint32_t packet_duration;

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

	bool patched_first_rtp_payload; /* FIXME: drop this, see OS#2459 */
};

struct mgcp_rtp_codec {
	uint32_t rate;
	int channels;
	uint32_t frame_duration_num;
	uint32_t frame_duration_den;

	int payload_type;
	char *audio_name;
	char *subtype_name;

	bool param_present;
	struct mgcp_codec_param param;
};

/* 'mgcp_rtp_end': basically a wrapper around the RTP+RTCP ports */
struct mgcp_rtp_end {
	/* local IP address of the RTP socket */
	struct in_addr addr;

	/* in network byte order */
	int rtp_port, rtcp_port;

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
	char *fmtp_extra;
	/* are we transmitting packets (1) or dropping (0) outbound packets */
	int output_enabled;
	/* FIXME: This parameter can be set + printed, but is nowhere used! */
	int force_output_ptime;

	/* RTP patching */
	int force_constant_ssrc; /* -1: always, 0: don't, 1: once */
	/* should we perform align_rtp_timestamp_offset() (1) or not (0) */
	int force_aligned_timing;
	bool rfc5993_hr_convert;

	/* Each end has a separate socket for RTP and RTCP */
	struct osmo_fd rtp;
	struct osmo_fd rtcp;

	/* local UDP port number of the RTP socket; RTCP is +1 */
	int local_port;
};

struct mgcp_rtp_tap {
	/* is this tap active (1) or not (0) */
	int enabled;
	/* IP/port to which we're forwarding the tapped data */
	struct sockaddr_in forward;
};

struct mgcp_lco {
	char *string;
	char *codec;
	int pkt_period_min; /* time in ms */
	int pkt_period_max; /* time in ms */
};

/* Specific rtp connection type (see struct mgcp_conn_rtp) */
enum mgcp_conn_rtp_type {
	MGCP_RTP_DEFAULT	= 0,
	MGCP_OSMUX_BSC,
	MGCP_OSMUX_BSC_NAT,
};

#include <osmocom/mgcp/osmux.h>
struct mgcp_conn;

/* MGCP connection (RTP) */
struct mgcp_conn_rtp {

	/* Backpointer to conn struct */
	struct mgcp_conn *conn;

	/* Specific connection type */
	enum mgcp_conn_rtp_type type;

	/* Port status */
	struct mgcp_rtp_end end;

	/* Sequence bits */
	struct mgcp_rtp_state state;

	/* taps for the rtp connection; one per direction */
	struct mgcp_rtp_tap tap_in;
	struct mgcp_rtp_tap tap_out;

	/* Osmux states (optional) */
	struct {
		/* Osmux state: disabled, activating, active */
		enum osmux_state state;
		/* Is cid holding valid data? is it allocated from pool? */
		bool cid_allocated;
		/* Allocated Osmux circuit ID for this conn */
		uint8_t cid;
		/* handle to batch messages */
		struct osmux_in_handle *in;
		/* handle to unbatch messages */
		struct osmux_out_handle out;
		/* statistics */
		struct {
			uint32_t chunks;
			uint32_t octets;
		} stats;
	} osmux;

	struct rate_ctr_group *rate_ctr_group;
};

/*! Connection type, specifies which member of the union "u" in mgcp_conn
 *  contains a useful connection description (currently only RTP) */
enum mgcp_conn_type {
	MGCP_CONN_TYPE_RTP,
};

/*! MGCP connection (untyped) */
struct mgcp_conn {
	/*! list head */
	struct llist_head entry;

	/*! Backpointer to the endpoint where the conn belongs to */
	struct mgcp_endpoint *endp;

	/*! type of the connection (union) */
	enum mgcp_conn_type type;

	/*! mode of the connection */
	enum mgcp_connection_mode mode;

	/*! copy of the mode to restore the original setting (VTY) */
	enum mgcp_connection_mode mode_orig;

	/*! connection id to identify the connection */
	char id[MGCP_CONN_ID_MAXLEN];

	/*! human readable name (vty, logging) */
	char name[256];

	/*! activity tracker (for cleaning up inactive connections) */
	struct osmo_timer_list watchdog;

	/*! union with connection description */
	union {
		struct mgcp_conn_rtp rtp;
	} u;

	/*! pointer to optional private data */
	void *priv;
};

#include <osmocom/mgcp/mgcp_conn.h>

struct mgcp_endpoint_type;





/**
 * Internal structure while parsing a request
 */
struct mgcp_parse_data {
	struct mgcp_config *cfg;
	struct mgcp_endpoint *endp;
	char *trans;
	char *save;
};

int mgcp_send(struct mgcp_endpoint *endp, int is_rtp, struct sockaddr_in *addr,
	      char *buf, int rc, struct mgcp_conn_rtp *conn_src,
	      struct mgcp_conn_rtp *conn_dst);
int mgcp_send_dummy(struct mgcp_endpoint *endp, struct mgcp_conn_rtp *conn);
int mgcp_dispatch_rtp_bridge_cb(int proto, struct sockaddr_in *addr, char *buf,
				unsigned int buf_size, struct mgcp_conn *conn);
void mgcp_cleanup_rtp_bridge_cb(struct mgcp_endpoint *endp, struct mgcp_conn *conn);
int mgcp_bind_net_rtp_port(struct mgcp_endpoint *endp, int rtp_port,
			   struct mgcp_conn_rtp *conn);
void mgcp_free_rtp_port(struct mgcp_rtp_end *end);

/* For transcoding we need to manage an in and an output that are connected */
static inline int endp_back_channel(int endpoint)
{
	return endpoint + 60;
}

struct mgcp_trunk_config *mgcp_trunk_alloc(struct mgcp_config *cfg, int index);
struct mgcp_trunk_config *mgcp_trunk_num(struct mgcp_config *cfg, int index);

char *get_lco_identifier(const char *options);
int check_local_cx_options(void *ctx, const char *options);
void mgcp_rtp_end_config(struct mgcp_endpoint *endp, int expect_ssrc_change,
			 struct mgcp_rtp_end *rtp);
uint32_t mgcp_rtp_packet_duration(struct mgcp_endpoint *endp,
				  struct mgcp_rtp_end *rtp);

/* payload processing default functions */
int mgcp_rtp_processing_default(struct mgcp_endpoint *endp, struct mgcp_rtp_end *dst_end,
				char *data, int *len, int buf_size);

int mgcp_setup_rtp_processing_default(struct mgcp_endpoint *endp,
				      struct mgcp_conn_rtp *conn_dst,
				      struct mgcp_conn_rtp *conn_src);

void mgcp_get_net_downlink_format_default(struct mgcp_endpoint *endp,
					  const struct mgcp_rtp_codec **codec,
					  const char **fmtp_extra,
					  struct mgcp_conn_rtp *conn);

/* internal RTP Annex A counting */
void mgcp_rtp_annex_count(struct mgcp_endpoint *endp, struct mgcp_rtp_state *state,
			const uint16_t seq, const int32_t transit,
			const uint32_t ssrc);

int mgcp_set_ip_tos(int fd, int tos);

/* Was conn configured to handle Osmux? */
static inline bool mgcp_conn_rtp_is_osmux(const struct mgcp_conn_rtp *conn) {
	return conn->type == MGCP_OSMUX_BSC || conn->type == MGCP_OSMUX_BSC_NAT;
}

enum {
	MGCP_DEST_NET = 0,
	MGCP_DEST_BTS,
};


#define MGCP_DUMMY_LOAD 0x23


/**
 * SDP related information
 */
/* Assume audio frame length of 20ms */
#define DEFAULT_RTP_AUDIO_FRAME_DUR_NUM 20
#define DEFAULT_RTP_AUDIO_FRAME_DUR_DEN 1000
#define DEFAULT_RTP_AUDIO_PACKET_DURATION_MS 20
#define DEFAULT_RTP_AUDIO_DEFAULT_RATE  8000
#define DEFAULT_RTP_AUDIO_DEFAULT_CHANNELS 1

#define PTYPE_UNDEFINED (-1)

void mgcp_get_local_addr(char *addr, struct mgcp_conn_rtp *conn);
void mgcp_conn_watchdog_kick(struct mgcp_conn *conn);

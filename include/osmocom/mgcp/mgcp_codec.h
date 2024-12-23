#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <osmocom/mgcp/mgcp_common.h>

#define DEFAULT_RTP_AUDIO_FRAME_DUR_NUM 20
#define DEFAULT_RTP_AUDIO_FRAME_DUR_DEN 1000
#define DEFAULT_RTP_AUDIO_PACKET_DURATION_MS 20
#define DEFAULT_RTP_AUDIO_DEFAULT_RATE  8000
#define DEFAULT_RTP_AUDIO_DEFAULT_CHANNELS 1

#define PTYPE_UNDEFINED (-1)

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

struct mgcp_conn_rtp;

void mgcp_codec_summary(struct mgcp_conn_rtp *conn);
void mgcp_codec_reset_all(struct mgcp_conn_rtp *conn);
int mgcp_codec_add(struct mgcp_conn_rtp *conn, int payload_type, const char *audio_name, const struct mgcp_codec_param *param);
int mgcp_codec_decide(struct mgcp_conn_rtp *conn_src, struct mgcp_conn_rtp *conn_dst);
const struct mgcp_rtp_codec *mgcp_codec_pt_find_by_subtype_name(struct mgcp_conn_rtp *conn,
								const char *subtype_name, unsigned int match_nr);
bool mgcp_codec_amr_align_mode_is_indicated(const struct mgcp_rtp_codec *codec);
bool mgcp_codec_amr_is_octet_aligned(const struct mgcp_rtp_codec *codec);
struct mgcp_rtp_codec *mgcp_codec_from_pt(struct mgcp_conn_rtp *conn, int payload_type);

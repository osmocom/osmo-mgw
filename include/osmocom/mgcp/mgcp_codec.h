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

bool mgcp_codec_amr_align_mode_is_indicated(const struct mgcp_rtp_codec *codec);
bool mgcp_codec_amr_is_octet_aligned(const struct mgcp_rtp_codec *codec);

struct mgcp_rtp_codecset {
	/* currently selected audio codec */
	struct mgcp_rtp_codec *codec;
	/* array with assigned audio codecs to choose from (SDP) */
	struct mgcp_rtp_codec codecs[MGCP_MAX_CODECS];
	/* number of assigned audio codecs (SDP) */
	unsigned int codecs_assigned;
};

void mgcp_codecset_reset(struct mgcp_rtp_codecset *cset);
void mgcp_codecset_summary(struct mgcp_rtp_codecset *cset, const char *prefix_str);
int mgcp_codecset_add_codec(struct mgcp_rtp_codecset *cset, int payload_type,
			    const char *audio_name, const struct mgcp_codec_param *param);
int mgcp_codecset_decide(struct mgcp_rtp_codecset *cset_src, struct mgcp_rtp_codecset *cset_dst);
const struct mgcp_rtp_codec *mgcp_codecset_pt_find_by_subtype_name(const struct mgcp_rtp_codecset *cset,
								const char *subtype_name, unsigned int match_nr);
struct mgcp_rtp_codec *mgcp_codecset_find_codec_from_pt(struct mgcp_rtp_codecset *cset, int payload_type);

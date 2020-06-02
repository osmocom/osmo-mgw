#pragma once

struct mgcp_trunk {
	struct llist_head entry;

	struct mgcp_config *cfg;

	int trunk_nr;
	int trunk_type;

	char *audio_fmtp_extra;
	char *audio_name;
	int audio_payload;
	int audio_send_ptime;
	int audio_send_name;
	int audio_loop;

	int no_audio_transcoding;

	int omit_rtcp;
	int keepalive_interval;

	/* RTP patching */
	int force_constant_ssrc; /* 0: don't, 1: once */
	int force_aligned_timing;
	bool rfc5993_hr_convert;

	/* spec handling */
	int force_realloc;

	/* timer */
	struct osmo_timer_list keepalive_timer;

	/* When set, incoming RTP packets are not filtered
	 * when ports and ip-address do not match (debug) */
	int rtp_accept_all;

	unsigned int number_endpoints;
	unsigned int vty_number_endpoints;
	struct mgcp_endpoint **endpoints;

	/* global rate counters to measure the trunks overall performance and health */
	struct mgcp_ratectr_trunk ratectr;
};

struct mgcp_trunk *mgcp_trunk_alloc(struct mgcp_config *cfg, enum mgcp_trunk_type ttype, int nr);
int mgcp_trunk_alloc_endpts(struct mgcp_trunk *tcfg);
struct mgcp_trunk *mgcp_trunk_by_num(const struct mgcp_config *cfg, int index);
struct mgcp_trunk *mgcp_trunk_by_name(const struct mgcp_config *cfg, const char *epname);

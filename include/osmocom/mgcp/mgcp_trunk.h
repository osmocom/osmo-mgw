#pragma once

#include <osmocom/gsm/i460_mux.h>
#include <osmocom/abis/e1_input.h>

#define LOGPTRUNK(trunk, cat, level, fmt, args...) \
LOGP(cat, level, "trunk:%u " fmt, \
     trunk ? trunk->trunk_nr : 0, \
     ## args)

enum mgcp_trunk_type {
	MGCP_TRUNK_VIRTUAL,
	MGCP_TRUNK_E1,
};

struct mgcp_trunk {
	struct llist_head entry;

	struct mgcp_config *cfg;

	int trunk_nr;
	enum mgcp_trunk_type trunk_type;

	char *audio_fmtp_extra;
	int audio_send_ptime;
	int audio_send_name;

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
	struct mgcp_endpoint **endpoints;

	/* global rate counters to measure the trunks overall performance and health */
	struct mgcp_ratectr_trunk ratectr;

	union {
		/* Virtual trunk specific */
		struct {
			unsigned int vty_number_endpoints;
		} v;
		/* E1 specific */
		struct {
			unsigned int vty_line_nr;
			bool ts_in_use[NUM_E1_TS-1];
			struct osmo_i460_timeslot i460_ts[NUM_E1_TS-1];
			/* Note: on an E1 line TS 0 is devoted to framing and
			 * alignment and therefore only NUM_E1_TS-1 timeslots
			 * are available for traffic. */
		} e1;
	};
};

struct mgcp_trunk *mgcp_trunk_alloc(struct mgcp_config *cfg, enum mgcp_trunk_type ttype, int nr);
int mgcp_trunk_equip(struct mgcp_trunk *trunk);
struct mgcp_trunk *mgcp_trunk_by_num(const struct mgcp_config *cfg, enum mgcp_trunk_type ttype, int nr);
struct mgcp_trunk *mgcp_trunk_by_name(const struct mgcp_config *cfg, const char *epname);
int e1_trunk_nr_from_epname(const char *epname);
struct mgcp_trunk *mgcp_trunk_by_line_num(const struct mgcp_config *cfg, unsigned int num);

/* The virtual trunk is always created on trunk id 0 for historical reasons,
 * use this define constant as ID when allocating a virtual trunk. Other
 * trunks may be assigned with arbritrary id numbers */
#define MGCP_VIRT_TRUNK_ID 0

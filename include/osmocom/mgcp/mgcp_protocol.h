#pragma once

#include <osmocom/core/utils.h>
#include <osmocom/mgcp/mgcp_common.h>

#define MGCP_PARSE_HDR_PARS_OSMUX_CID_UNSET (-2)
#define MGCP_PARSE_HDR_PARS_OSMUX_CID_WILDCARD (-1)

struct mgcp_parse_hdr_pars {
	const char *local_options;
	const char *callid;
	const char *connid;
	enum mgcp_connection_mode mode;
	int remote_osmux_cid;
	bool have_sdp;
	/*! MGCP_X_OSMO_IGN_* flags from 'X-Osmo-IGN:' header */
	uint32_t x_osmo_ign;
};

static inline void mgcp_parse_hdr_pars_init(struct mgcp_parse_hdr_pars *hpars)
{
	*hpars = (struct mgcp_parse_hdr_pars){
		.local_options = NULL,
		.callid = NULL,
		.connid = NULL,
		.mode = MGCP_CONN_NONE,
		.remote_osmux_cid = MGCP_PARSE_HDR_PARS_OSMUX_CID_UNSET,
		.have_sdp = false,
		.x_osmo_ign = 0,
	};
}

/* Internal structure while parsing a request */
struct mgcp_parse_data {
	struct mgcp_config *cfg;
	char *save;
	/* MGCP Header: */
	char *epname;
	char *trans;
	struct mgcp_parse_hdr_pars hpars;
};

/* Local connection options */
struct mgcp_lco {
	char *string;
	char *codec;
	int pkt_period_min; /* time in ms */
	int pkt_period_max; /* time in ms */
};

char *mgcp_debug_get_last_endpoint_name(void);

char *get_lco_identifier(const char *options);
int check_local_cx_options(void *ctx, const char *options);

struct mgcp_rtp_end;
struct mgcp_endpoint;

uint32_t mgcp_rtp_packet_duration(const struct mgcp_endpoint *endp,
				  const struct mgcp_rtp_end *rtp);

extern const struct value_string mgcp_connection_mode_strs[];
static inline const char *mgcp_cmode_name(enum mgcp_connection_mode mode)
{
	return get_value_string(mgcp_connection_mode_strs, mode);
}

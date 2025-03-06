#pragma once

#include <stdint.h>
#include <sys/socket.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/socket.h>
#include <osmocom/mgcp/mgcp_common.h>
#include <osmocom/mgcp/mgcp_codec.h>

enum mgcp_verb {
	MGCP_VERB_CRCX,
	MGCP_VERB_MDCX,
	MGCP_VERB_DLCX,
	MGCP_VERB_AUEP,
	MGCP_VERB_RQNT,
	MGCP_VERB_RSIP,
};
extern const struct value_string mgcp_verb_names[];
static inline const char *mgcp_verb_name(enum mgcp_verb val)
{ return get_value_string(mgcp_verb_names, val); }


#define MGCP_PARSE_SDP_PTIME_UNSET (-1)
#define MGCP_PARSE_SDP_MAXPTIME_UNSET (-1)
#define MGCP_PARSE_SDP_RTP_PORT_UNSET (0)

struct mgcp_parse_sdp {
	int ptime;
	int maxptime;
	int rtp_port;
	struct osmo_sockaddr rem_addr; /* Only IP address, port is in rtp_port above */
	struct mgcp_rtp_codecset cset;
};

static inline void mgcp_parse_sdp_init(struct mgcp_parse_sdp *sdp)
{
	sdp->ptime = MGCP_PARSE_SDP_PTIME_UNSET;
	sdp->maxptime = MGCP_PARSE_SDP_MAXPTIME_UNSET;
	sdp->rtp_port = MGCP_PARSE_SDP_RTP_PORT_UNSET;
	sdp->rem_addr = (struct osmo_sockaddr){ .u.sa.sa_family = AF_UNSPEC };
	mgcp_codecset_reset(&sdp->cset);
}


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
	char *save;
	/* MGCP Header: */
	char *epname;
	char *trans;
	struct mgcp_parse_hdr_pars hpars;
	/* MGCP Body: */
	struct mgcp_parse_sdp sdp;
};

/* Request data passed to the request handler */
struct mgcp_request_data {
	enum mgcp_verb verb;
	/* Verb string (e.g. "MDCX") */
	char name[4+1];

	/* Global MGW config */
	struct mgcp_config *cfg;

	/* parsing results from the MGCP header (trans id, endpoint name ...) */
	struct mgcp_parse_data *pdata;

	/* pointer to endpoint resource (may be NULL for wildcarded requests) */
	struct mgcp_endpoint *endp;

	/* pointer to trunk resource */
	struct mgcp_trunk *trunk;

	/* set to true when the request has been classified as wildcarded */
	bool wildcarded;

	/* Set to true when the request is targeted at the "null" endpoint */
	bool null_endp;

	/* contains cause code in case of problems during endp/trunk resolution */
	int mgcp_cause;
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

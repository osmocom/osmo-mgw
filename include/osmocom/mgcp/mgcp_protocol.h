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

/* Local connection options */
struct mgcp_lco {
	bool present;
	char *codec; /* talloc-allocated to some parent */
	int pkt_period_min; /* time in ms */
	int pkt_period_max; /* time in ms */
};
static inline void mgcp_lco_init(struct mgcp_lco *lco)
{
	*lco = (struct mgcp_lco){};
}
char *get_lco_identifier(const char *options);
int check_local_cx_options(void *ctx, const char *options);

#define MGCP_PARSE_HDR_PARS_OSMUX_CID_UNSET (-2)
#define MGCP_PARSE_HDR_PARS_OSMUX_CID_WILDCARD (-1)

struct mgcp_parse_hdr_pars {
	const char *lco_string;
	struct mgcp_lco lco;
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
	hpars->lco_string = NULL;
	mgcp_lco_init(&hpars->lco);
	hpars->callid = NULL;
	hpars->connid = NULL;
	hpars->mode = MGCP_CONN_NONE;
	hpars->remote_osmux_cid = MGCP_PARSE_HDR_PARS_OSMUX_CID_UNSET;
	hpars->have_sdp = false;
	hpars->x_osmo_ign = 0;
}

/* Internal structure while parsing a request */
struct mgcp_request_data;
struct mgcp_parse_data {
	struct mgcp_request_data *rq; /* backpointer to request context */
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

char *mgcp_debug_get_last_endpoint_name(void);


struct mgcp_rtp_end;
struct mgcp_endpoint;

uint32_t mgcp_rtp_packet_duration(const struct mgcp_endpoint *endp,
				  const struct mgcp_rtp_end *rtp);

extern const struct value_string mgcp_connection_mode_strs[];
static inline const char *mgcp_cmode_name(enum mgcp_connection_mode mode)
{
	return get_value_string(mgcp_connection_mode_strs, mode);
}

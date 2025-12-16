#pragma once

#include <stdint.h>
#include <arpa/inet.h>

#include <osmocom/mgcp_client/defs.h>
#include <osmocom/mgcp_client/mgcp_common.h>

/* See also: RFC 3435, chapter 3.5 Transmission over UDP */
#define MGCP_CLIENT_LOCAL_ADDR_DEFAULT NULL /* INADDR(6)_ANY */
#define MGCP_CLIENT_LOCAL_PORT_DEFAULT 0
#define MGCP_CLIENT_REMOTE_ADDR_DEFAULT "127.0.0.1"
#define MGCP_CLIENT_REMOTE_PORT_DEFAULT 2427
#define MGCP_CLIENT_KEEPALIVE_DEFAULT_ENDP "null"
#define MGCP_CLIENT_MGW_STR "Configure MGCP connection to Media Gateway\n"

struct msgb;
struct vty;
struct mgcp_client;

struct mgcp_client_conf {
	const char *local_addr;
	int local_port;
	const char *remote_addr;
	int remote_port;

	/* By default, we are always addressing the MGW with e.g. 'rtpbridge/123@mgw'.
	 * If this is nonempty, the contained name will be used instead of 'mgw'. */
	char endpoint_domain_name[MGCP_ENDPOINT_MAXLEN];

	/* The user may configure certain endpoint names that are reset via DLCX
	 * on startup. Usually this will be one wildcarded endpoint e.g.
	 * 'rtpbridge/(wildcard)' or a number of specific E1 like e.g.
	 * 'ds/e1-0/s-3/su16-4' */
	struct llist_head reset_epnames;

	/* human readable name / description */
	char *description;

	struct {
		uint32_t timeout_sec;
		uint32_t req_interval_sec;
		char req_endpoint_name[MGCP_ENDPOINT_MAXLEN];
	} keepalive;
};

typedef unsigned int mgcp_trans_id_t;

/*! Enumeration of the codec types that mgcp_client is able to handle. */
enum mgcp_codecs {
	CODEC_PCMU_8000_1 = 0,
	CODEC_GSM_8000_1 = 3,
	CODEC_PCMA_8000_1 = 8,
	CODEC_G729_8000_1 = 18,
	CODEC_GSMEFR_8000_1 = 110,	/* 3GPP TS 48.103 table 5.4.2.2.1 */
	CODEC_GSMHR_8000_1 = 111,	/* 3GPP TS 48.103 table 5.4.2.2.1 */
	CODEC_AMR_8000_1 = 112,		/* 3GPP TS 48.103 table 5.4.2.2.1 */
	CODEC_AMRWB_16000_1 = 113,	/* 3GPP TS 48.103 table 5.4.2.2.1 */
	CODEC_IUFP = 96,
	CODEC_CLEARMODE = 120,		/* 3GPP TS 48.103 table 5.4.2.2.1 */
	CODEC_COMPR_CSD = 127,		/* compressed CSD per TW-TS-007 */
};
/* Note: when new codec types are added, the corresponding value strings
 * in mgcp_client.c (codec_table) must be updated as well. Enumerations
 * in enum mgcp_codecs must correspond to a valid payload type. However,
 * this is an internal assumption that is made to avoid lookup tables.
 * The API-User should not rely on this coincidence! */

extern const struct value_string osmo_mgcpc_codec_names[];
static inline const char *osmo_mgcpc_codec_name(enum mgcp_codecs val)
{ return get_value_string(osmo_mgcpc_codec_names, val); }

/*! Structure to build a payload type map to allow the defiition custom payload
 *  types. */
struct ptmap {
	/*! codec for which a payload type number should be defined */
	enum mgcp_codecs codec;

	/*! payload type number (96-127) */
	unsigned int pt;

	/*! the MGCP 'a=fmtp:N <...>' string, e.g. "mode-set=1,2,3;octet-align=0". */
	char fmtp[256];
};

int ptmap_cmp(const struct ptmap *a, const struct ptmap *b);

enum mgcp_verb {
	MGCP_VERB_CRCX,
	MGCP_VERB_MDCX,
	MGCP_VERB_DLCX,
	MGCP_VERB_AUEP,
	MGCP_VERB_RSIP,
};

struct mgcp_client_conf *mgcp_client_conf_alloc(void *ctx);
void mgcp_client_conf_init(struct mgcp_client_conf *conf) OSMO_DEPRECATED_OUTSIDE_LIBOSMOMGCPCLIENT("use mgcp_client_conf_alloc() (or even better, switch to the mgcp_client_pool API!)");
void mgcp_client_vty_init(void *talloc_ctx, int node, struct mgcp_client_conf *conf);
int mgcp_client_config_write(struct vty *vty, const char *indent);
struct mgcp_client_conf *mgcp_client_conf_actual(struct mgcp_client *mgcp);

struct mgcp_client *mgcp_client_init(void *ctx,
				     struct mgcp_client_conf *conf);
int mgcp_client_connect(struct mgcp_client *mgcp);
int mgcp_client_connect2(struct mgcp_client *mgcp, unsigned int retry_n_ports) OSMO_DEPRECATED("Use mgcp_client_connect() instead");
void mgcp_client_disconnect(struct mgcp_client *mgcp);

const char *mgcp_client_remote_addr_str(struct mgcp_client *mgcp);
uint16_t mgcp_client_remote_port(struct mgcp_client *mgcp);
uint32_t mgcp_client_remote_addr_n(struct mgcp_client *mgcp) OSMO_DEPRECATED("deprecated, returns 0");

const char *mgcp_client_endpoint_domain(const struct mgcp_client *mgcp);
const char *mgcp_client_rtpbridge_wildcard(const struct mgcp_client *mgcp);
const char *mgcp_client_transcoder_wildcard(const struct mgcp_client *mgcp);
const char *mgcp_client_e1_epname(void *ctx, const struct mgcp_client *mgcp, uint8_t trunk_id, uint8_t ts,
				  uint8_t rate, uint8_t offset);

enum mgcp_connection_mode;

extern const struct value_string mgcp_client_connection_mode_strs[];
static inline const char *mgcp_client_cmode_name(enum mgcp_connection_mode mode)
{
	return get_value_string(mgcp_client_connection_mode_strs, mode);
}

enum mgcp_codecs map_str_to_codec(const char *str);
unsigned int map_codec_to_pt(const struct ptmap *ptmap, unsigned int ptmap_len,
			     enum mgcp_codecs codec);
enum mgcp_codecs map_pt_to_codec(struct ptmap *ptmap, unsigned int ptmap_len,
				 unsigned int pt);

const char *mgcp_client_name(const struct mgcp_client *mgcp);

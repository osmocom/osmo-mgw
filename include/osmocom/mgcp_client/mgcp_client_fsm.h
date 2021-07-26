#pragma once

#include <osmocom/mgcp_client/mgcp_common.h>
#include <osmocom/mgcp_client/mgcp_client.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>

/*! This struct organizes the connection infromation one connection side
 *  (either remote or local). It is used to pass parameters (local) to the FSM
 *  and get responses (remote) from the FSM as pointer attached to the FSM
 *  event.
 *
 *  When modifiying a connection, the endpoint and call_id members may be left
 *  unpopulated. The call_id field is ignored in this case. If an endpoint
 *  identifier is supplied it is checked against the internal state to make
 *  sure it is correct. */
struct mgcp_conn_peer {
	/*! RTP connection IP-Address (optional, string e.g. "127.0.0.1") */
	char addr[INET6_ADDRSTRLEN];

	/*! RTP connection IP-Port (optional)  */
	uint16_t port;

	/*! RTP endpoint */
	char endpoint[MGCP_ENDPOINT_MAXLEN];

	/*! CALL ID (unique per connection) */
	unsigned int call_id;

	/*! RTP packetization interval (optional) */
	unsigned int ptime;

	/*! RTP codec list (optional) */
	enum mgcp_codecs codecs[MGCP_MAX_CODECS];

	/*! Number of codecs in RTP codec list (optional) */
	unsigned int codecs_len;

	/*! RTP payload type map (optional, only needed when payload types are
	 * used that differ from what IANA/3GPP defines) */
	struct ptmap ptmap[MGCP_MAX_CODECS];

	/*! RTP payload type map length (optional, only needed when payload
	 * types are used that differ from what IANA/3GPP defines) */
	unsigned int ptmap_len;

	/*! If nonzero, send 'X-Osmo-IGN:' header. This is useful e.g. for SCCPlite MSCs where the MSC is
	 * known to issue incoherent or unknown CallIDs / to issue CRCX commands with a different domain
	 * name than the BSC. An OsmoMGW will then ignore these and not fail on mismatches. */
	uint32_t x_osmo_ign;

	/*! send 'X-Osmux: %d' header (or "*" as wildcard). */
	bool x_osmo_osmux_use;
	/*! -1 means send wildcard. */
	int x_osmo_osmux_cid;

	/*! If left MGCP_CONN_NONE, use MGCP_CONN_RECV_ONLY or MGCP_CONN_RECV_SEND, depending on whether an audio RTP
	 * address is set. If != MGCP_CONN_NONE, force this conn mode. */
	enum mgcp_connection_mode conn_mode;

	/*! If the codec requires additional format parameters (fmtp), those cann be set here, see also
	 * mgcp_common.h */
	bool param_present;
	struct mgcp_codec_param param;
};

struct osmo_fsm_inst *mgcp_conn_create(struct mgcp_client *mgcp, struct osmo_fsm_inst *parent_fi, uint32_t parent_term_evt,
				       uint32_t parent_evt, struct mgcp_conn_peer *conn_peer);
int mgcp_conn_modify(struct osmo_fsm_inst *fi, uint32_t parent_evt, struct mgcp_conn_peer *conn_peer);
void mgcp_conn_delete(struct osmo_fsm_inst *fi);

const char *mgcp_conn_get_ci(struct osmo_fsm_inst *fi);
struct mgcp_client *mgcp_conn_get_client(struct osmo_fsm_inst *fi);

const char *osmo_mgcpc_conn_peer_name(const struct mgcp_conn_peer *info);

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
	/*!< RTP connection IP-Address (optional, string e.g. "127.0.0.1") */
	char addr[INET_ADDRSTRLEN];

	/*!< RTP connection IP-Port (optional)  */
	uint16_t port;

	/*!< RTP endpoint */
	char endpoint[MGCP_ENDPOINT_MAXLEN];

	/*!< CALL ID (unique per connection) */
	unsigned int call_id;

	/*!< RTP packetization interval (optional) */
	unsigned int ptime;

	/*!< RTP codec list (optional) */
	enum mgcp_codecs codecs[MGCP_MAX_CODECS];

	/*!< Number of codecs in RTP codec list (optional) */
	unsigned int codecs_len;
};

struct osmo_fsm_inst *mgcp_conn_create(struct mgcp_client *mgcp, struct osmo_fsm_inst *parent_fi, uint32_t parent_term_evt,
				       uint32_t parent_evt, struct mgcp_conn_peer *conn_peer);
int mgcp_conn_modify(struct osmo_fsm_inst *fi, uint32_t parent_evt, struct mgcp_conn_peer *conn_peer);
void mgcp_conn_delete(struct osmo_fsm_inst *fi);

const char *mgcp_conn_get_ci(struct osmo_fsm_inst *fi);

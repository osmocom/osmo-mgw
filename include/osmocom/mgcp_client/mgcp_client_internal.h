#pragma once

#include <osmocom/core/osmo_io.h>
#include <osmocom/core/timer.h>

#include <osmocom/mgcp_client/mgcp_client.h>

#define MSGB_CB_MGCP_TRANS_ID 0

/* Struct that holds one endpoint name */
struct reset_ep {
	struct llist_head list;
	char name[MGCP_ENDPOINT_MAXLEN];
};

struct mgcp_client {
	struct mgcp_client_conf actual;
	struct osmo_io_fd *iofd;
	mgcp_trans_id_t next_trans_id;
	struct llist_head responses_pending;
	struct mgcp_client_pool_member *pool_member;
	struct osmo_timer_list keepalive_tx_timer;
	struct osmo_timer_list keepalive_rx_timer;
	bool conn_up;
};

struct mgcp_response_head {
	int response_code;
	mgcp_trans_id_t trans_id;
	char comment[MGCP_COMMENT_MAXLEN];
	char conn_id[MGCP_CONN_ID_MAXLEN];
	char endpoint[MGCP_ENDPOINT_MAXLEN];
	bool x_osmo_osmux_use;
	uint8_t x_osmo_osmux_cid;
};

struct mgcp_response {
	char *body;
	struct mgcp_response_head head;
	uint16_t audio_port;
	char audio_ip[INET6_ADDRSTRLEN];
	unsigned int ptime;
	struct ptmap ptmap[MGCP_MAX_CODECS];
	unsigned int ptmap_len;
};

/* Invoked when an MGCP response is received or sending failed.  When the
 * response is passed as NULL, this indicates failure during transmission. */
typedef void (*mgcp_response_cb_t)(struct mgcp_response *response, void *priv);

struct mgcp_response_pending {
	struct llist_head entry;

	mgcp_trans_id_t trans_id;
	mgcp_response_cb_t response_cb;
	void *priv;
};

int mgcp_client_rx(struct mgcp_client *mgcp, struct msgb *msg);

struct mgcp_response_pending * mgcp_client_pending_add(
					struct mgcp_client *mgcp,
					mgcp_trans_id_t trans_id,
					mgcp_response_cb_t response_cb,
					void *priv);

#define MGCP_MSG_PRESENCE_ENDPOINT	0x0001
#define MGCP_MSG_PRESENCE_CALL_ID	0x0002
#define MGCP_MSG_PRESENCE_CONN_ID	0x0004
#define MGCP_MSG_PRESENCE_AUDIO_IP	0x0008
#define MGCP_MSG_PRESENCE_AUDIO_PORT	0x0010
#define MGCP_MSG_PRESENCE_CONN_MODE	0x0020
#define MGCP_MSG_PRESENCE_SIGNAL_REQ	0x0040
#define MGCP_MSG_PRESENCE_X_SIDE	0x2000
#define MGCP_MSG_PRESENCE_X_OSMO_OSMUX_CID 0x4000
#define MGCP_MSG_PRESENCE_X_OSMO_IGN	0x8000

struct mgcp_msg {
	enum mgcp_verb verb;
	/* See MGCP_MSG_PRESENCE_* constants */
	uint32_t presence;
	char endpoint[MGCP_ENDPOINT_MAXLEN];
	unsigned int call_id;
	char *conn_id;
	uint16_t audio_port;
	char *audio_ip;
	enum mgcp_connection_mode conn_mode;
	unsigned int ptime;
	struct ptmap ptmap[MGCP_MAX_CODECS];
	unsigned int ptmap_len;
	char *signal_req;
	uint32_t x_osmo_ign;
	bool x_osmo_osmux_use;
	int x_osmo_osmux_cid; /* -1 is wildcard */
	char x_side[MGCP_SIDE_ID_MAXLEN];
	bool param_present;
	struct mgcp_codec_param param;
};

int mgcp_response_parse_params(struct mgcp_response *r);

int mgcp_client_tx(struct mgcp_client *mgcp, struct msgb *msg,
		   mgcp_response_cb_t response_cb, void *priv);
int mgcp_client_cancel(struct mgcp_client *mgcp, mgcp_trans_id_t trans_id);

struct msgb *mgcp_msg_gen(struct mgcp_client *mgcp, struct mgcp_msg *mgcp_msg);
mgcp_trans_id_t mgcp_msg_trans_id(struct msgb *msg);

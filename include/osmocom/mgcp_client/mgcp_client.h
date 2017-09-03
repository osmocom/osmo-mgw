#pragma once

#include <stdint.h>

#define MGCP_CLIENT_LOCAL_ADDR_DEFAULT "0.0.0.0"
#define MGCP_CLIENT_LOCAL_PORT_DEFAULT 0
#define MGCP_CLIENT_REMOTE_ADDR_DEFAULT "127.0.0.1"
#define MGCP_CLIENT_REMOTE_PORT_DEFAULT 2427

struct msgb;
struct vty;
struct mgcp_client;

struct mgcp_client_conf {
	const char *local_addr;
	int local_port;
	const char *remote_addr;
	int remote_port;
	uint16_t first_endpoint;
	uint16_t last_endpoint;
	uint16_t bts_base;
};

typedef unsigned int mgcp_trans_id_t;

struct mgcp_response_head {
       int response_code;
       mgcp_trans_id_t trans_id;
       const char *comment;
};

struct mgcp_response {
	char *body;
	struct mgcp_response_head head;
	uint16_t audio_port;
};

void mgcp_client_conf_init(struct mgcp_client_conf *conf);
void mgcp_client_vty_init(void *talloc_ctx, int node, struct mgcp_client_conf *conf);
int mgcp_client_config_write(struct vty *vty, const char *indent);
struct mgcp_client_conf *mgcp_client_conf_actual(struct mgcp_client *mgcp);

struct mgcp_client *mgcp_client_init(void *ctx,
				     struct mgcp_client_conf *conf);
int mgcp_client_connect(struct mgcp_client *mgcp);

const char *mgcp_client_remote_addr_str(struct mgcp_client *mgcp);
uint16_t mgcp_client_remote_port(struct mgcp_client *mgcp);
uint32_t mgcp_client_remote_addr_n(struct mgcp_client *mgcp);

int mgcp_client_next_endpoint(struct mgcp_client *client);
void mgcp_client_release_endpoint(uint16_t id, struct mgcp_client *client);

/* Invoked when an MGCP response is received or sending failed.  When the
 * response is passed as NULL, this indicates failure during transmission. */
typedef void (* mgcp_response_cb_t )(struct mgcp_response *response, void *priv);
int mgcp_response_parse_params(struct mgcp_response *r);

int mgcp_client_tx(struct mgcp_client *mgcp, struct msgb *msg,
		   mgcp_response_cb_t response_cb, void *priv);

enum mgcp_connection_mode;

struct msgb *mgcp_msg_crcx(struct mgcp_client *mgcp,
			   uint16_t rtp_endpoint, unsigned int call_id,
			   enum mgcp_connection_mode mode);

struct msgb *mgcp_msg_mdcx(struct mgcp_client *mgcp,
			   uint16_t rtp_endpoint, const char *rtp_conn_addr,
			   uint16_t rtp_port, enum mgcp_connection_mode mode);

struct msgb *mgcp_msg_dlcx(struct mgcp_client *mgcp, uint16_t rtp_endpoint,
			   unsigned int call_id);

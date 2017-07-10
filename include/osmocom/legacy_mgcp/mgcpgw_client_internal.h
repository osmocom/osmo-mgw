#pragma once

#define MSGB_CB_MGCP_TRANS_ID 0

struct mgcpgw_client {
	struct mgcpgw_client_conf actual;
	uint32_t remote_addr;
	struct osmo_wqueue wq;
	mgcp_trans_id_t next_trans_id;
	struct llist_head responses_pending;
	struct llist_head inuse_endpoints;
};

struct mgcp_inuse_endpoint {
	struct llist_head entry;
	uint16_t id;
};

struct mgcp_response_pending {
	struct llist_head entry;

	mgcp_trans_id_t trans_id;
	mgcp_response_cb_t response_cb;
	void *priv;
};

int mgcpgw_client_rx(struct mgcpgw_client *mgcp, struct msgb *msg);

struct mgcp_response_pending * mgcpgw_client_pending_add(
					struct mgcpgw_client *mgcp,
					mgcp_trans_id_t trans_id,
					mgcp_response_cb_t response_cb,
					void *priv);

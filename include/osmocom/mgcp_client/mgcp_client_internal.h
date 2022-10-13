#pragma once

#include <osmocom/core/write_queue.h>

#define MSGB_CB_MGCP_TRANS_ID 0

/* Struct that holds one endpoint name */
struct reset_ep {
	struct llist_head list;
	char name[MGCP_ENDPOINT_MAXLEN];
};

struct mgcp_client {
	struct mgcp_client_conf actual;
	struct osmo_wqueue wq;
	mgcp_trans_id_t next_trans_id;
	struct llist_head responses_pending;
	struct llist_head inuse_endpoints;
	struct mgcp_client_pool_member *pool_member;
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

int mgcp_client_rx(struct mgcp_client *mgcp, struct msgb *msg);

struct mgcp_response_pending * mgcp_client_pending_add(
					struct mgcp_client *mgcp,
					mgcp_trans_id_t trans_id,
					mgcp_response_cb_t response_cb,
					void *priv);

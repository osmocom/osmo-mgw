#pragma once

struct mgcp_client;
struct mgcp_client_pool;

struct mgcp_client_pool *mgcp_client_pool_alloc(void *talloc_ctx);
void mgcp_client_pool_vty_init(int parent_node, int mgw_node, const char *indent, struct mgcp_client_pool *pool);
unsigned int mgcp_client_pool_connect(struct mgcp_client_pool *pool);
void mgcp_client_pool_register_single(struct mgcp_client_pool *pool, struct mgcp_client *mgcp_client);
struct mgcp_client *mgcp_client_pool_get(struct mgcp_client_pool *pool);
void mgcp_client_pool_put(struct mgcp_client *mgcp_client);

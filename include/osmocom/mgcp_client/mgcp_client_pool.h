#pragma once

#include <stdbool.h>

#include <osmocom/vty/vty.h>

struct mgcp_client;
struct mgcp_client_pool;
struct mgcp_client_pool_member;

struct mgcp_client_pool *mgcp_client_pool_alloc(void *talloc_ctx);

void mgcp_client_pool_vty_init(int parent_node, int mgw_node, const char *indent, struct mgcp_client_pool *pool);
int mgcp_client_pool_config_write(struct vty *vty, const char *indent);
unsigned int mgcp_client_pool_connect(struct mgcp_client_pool *pool);
void mgcp_client_pool_register_single(struct mgcp_client_pool *pool, struct mgcp_client *mgcp_client);
bool mgcp_client_pool_empty(const struct mgcp_client_pool *pool);

struct mgcp_client *mgcp_client_pool_get(struct mgcp_client_pool *pool);
void mgcp_client_pool_put(struct mgcp_client *mgcp_client);

struct mgcp_client_pool_member *mgcp_client_pool_find_member_by_nr(struct mgcp_client_pool *pool, unsigned int nr);
struct mgcp_client *mgcp_client_pool_member_get(struct mgcp_client_pool_member *pool_member);
bool mgcp_client_pool_member_is_blocked(const struct mgcp_client_pool_member *pool_member);

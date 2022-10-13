#pragma once

/* Struct to handle a member of a pool of MGWs. */
struct mgcp_client_pool_member {
	/* Entry in llist mgcp_client_pool->pool. */
	struct llist_head list;

	/* Reference number assinged by VTY. This number is used to manage the pool from the VTY and to identify it in
	 * the log. */
	unsigned int nr;

	/* MGCP client configuration, this is not the running configuration, when mgcp_client_init() is executed, a
	 * copy of this config is created. */
	struct mgcp_client_conf conf;

	/* MGCP client descriptor, will be automatically allocated when mgcp_client_pool_connect() is called. (the MGCP
	 * client is connected when this pointer is populated) */
	struct mgcp_client *client;

	/* A pool member may be set as 'blocked' from the VTY, this means that the pool member may still work and serve
	 * ongoing calls, but it won't be picked from the pool anymore. */
	bool blocked;

	/* Reference counter to count how often this pool member is currently picked. */
	unsigned int refcount;
};

/* Struct to handle a pool of MGWs. (Use _pool functions) */
struct mgcp_client_pool {

	/* A pointer to a 'single' mgcp client. This is a non-pooled MGCP client that is configured using
	 * mgcp_client_vty_init() and actively registered by the API user using mgcp_client_pool_register_single() */
	struct mgcp_client *mgcp_client_single;

	/* A list that manages the pool members (see mgcp_client_pool_member->list above) */
	struct llist_head pool;

	/* String to use for indentation when writing the configuration file to the VTY. This field is populated by
	 * mgcp_client_pool_vty_init() */
	char *vty_indent;

	/* VTY node specification used with this pool. This field is populated by mgcp_client_pool_vty_init() */
	struct cmd_node *vty_node;
};

const char *mgcp_client_pool_member_name(const struct mgcp_client_pool_member *pool_member);

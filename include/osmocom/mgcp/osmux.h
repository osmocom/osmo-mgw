#pragma once

#include <osmocom/core/socket.h>

#include <osmocom/netif/osmux.h>
struct mgcp_conn_rtp;
enum {
	OSMUX_ROLE_BSC = 0,
	OSMUX_ROLE_BSC_NAT,
};

struct mgcp_trunk;
struct mgcp_endpoint;
struct mgcp_conn_rtp;

int osmux_init(int role, struct mgcp_trunk *trunk);
int osmux_enable_conn(struct mgcp_endpoint *endp, struct mgcp_conn_rtp *conn,
		      const struct osmo_sockaddr *addr);
void conn_osmux_disable(struct mgcp_conn_rtp *conn);
int conn_osmux_allocate_local_cid(struct mgcp_conn_rtp *conn);
void conn_osmux_release_local_cid(struct mgcp_conn_rtp *conn);
int osmux_xfrm_to_osmux(char *buf, int buf_len, struct mgcp_conn_rtp *conn);
int osmux_send_dummy(struct mgcp_endpoint *endp, struct mgcp_conn_rtp *conn);

void osmux_cid_pool_get(uint8_t osmux_cid);
int osmux_cid_pool_get_next(void);
void osmux_cid_pool_put(uint8_t osmux_cid);
bool osmux_cid_pool_allocated(uint8_t osmux_cid);
int osmux_cid_pool_count_used(void);

enum osmux_state {
	OSMUX_STATE_DISABLED = 0, /* Osmux not being currently used by endp */
	OSMUX_STATE_ACTIVATING,   /* Osmux was accepted in MGCP CRCX ACK. It can now be enabled by \ref osmux_enable_endpoint. */
	OSMUX_STATE_ENABLED,	  /* Osmux was initialized by \ref osmux_enable_endpoint and can process frames */
};

extern const struct value_string osmux_state_strs[];
static inline const char *osmux_state_str(enum osmux_state val)
{ return get_value_string(osmux_state_strs, val); }

enum osmux_usage {
	OSMUX_USAGE_OFF = 0,
	OSMUX_USAGE_ON = 1,
	OSMUX_USAGE_ONLY = 2,
};

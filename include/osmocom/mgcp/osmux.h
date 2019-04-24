#pragma once


#include <osmocom/netif/osmux.h>
struct mgcp_conn_rtp;

#define OSMUX_PORT	1984

enum {
	OSMUX_ROLE_BSC = 0,
	OSMUX_ROLE_BSC_NAT,
};

int osmux_init(int role, struct mgcp_config *cfg);
int osmux_enable_conn(struct mgcp_endpoint *endp, struct mgcp_conn_rtp *conn,
		      struct in_addr *addr, uint16_t port);
void osmux_disable_conn(struct mgcp_conn_rtp *conn);
int conn_osmux_allocate_cid(struct mgcp_conn_rtp *conn, int osmux_cid);
void conn_osmux_release_cid(struct mgcp_conn_rtp *conn);
int osmux_xfrm_to_osmux(char *buf, int buf_len, struct mgcp_conn_rtp *conn);
int osmux_send_dummy(struct mgcp_endpoint *endp, struct mgcp_conn_rtp *conn);

void osmux_cid_pool_get(uint8_t osmux_cid);
int osmux_cid_pool_get_next(void);
void osmux_cid_pool_put(uint8_t osmux_cid);
bool osmux_cid_pool_allocated(uint8_t osmux_cid);
int osmux_cid_pool_count_used(void);

enum osmux_state {
	OSMUX_STATE_DISABLED = 0, /* Osmux not being currently used by endp */
	OSMUX_STATE_NEGOTIATING,  /* Osmux was locally requested in MGCP CRCX */
	OSMUX_STATE_ACTIVATING,   /* Osmux was accepted in MGCP CRCX ACK. It can now be enabled by \ref osmux_enable_endpoint. */
	OSMUX_STATE_ENABLED,	  /* Osmux was initialized by \ref osmux_enable_endpoint and can process frames */
};

enum osmux_usage {
	OSMUX_USAGE_OFF = 0,
	OSMUX_USAGE_ON = 1,
	OSMUX_USAGE_ONLY = 2,
};

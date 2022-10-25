#pragma once

#include <stdint.h>

#include <osmocom/core/socket.h>

#include <osmocom/netif/osmux.h>
struct mgcp_conn_rtp;
struct mgcp_trunk;
struct mgcp_endpoint;
struct mgcp_conn_rtp;

int osmux_init(struct mgcp_trunk *trunk);
int osmux_init_conn(struct mgcp_conn_rtp *conn);
int conn_osmux_enable(struct mgcp_conn_rtp *conn);
void conn_osmux_disable(struct mgcp_conn_rtp *conn);
int conn_osmux_event_rx_crcx_mdcx(struct mgcp_conn_rtp *conn);
int conn_osmux_send_rtp(struct mgcp_conn_rtp *conn, struct msgb *msg);
int osmux_send_dummy(struct mgcp_conn_rtp *conn);

void osmux_cid_pool_get(uint8_t osmux_cid);
int osmux_cid_pool_get_next(void);
void osmux_cid_pool_put(uint8_t osmux_cid);
bool osmux_cid_pool_allocated(uint8_t osmux_cid);
int osmux_cid_pool_count_used(void);

enum osmux_state {
	OSMUX_STATE_DISABLED = 0, /* Osmux not being currently used by endp */
	OSMUX_STATE_ACTIVATING,   /* Osmux was accepted in MGCP CRCX ACK. It can now be enabled by \ref conn_osmux_enable. */
	OSMUX_STATE_ENABLED,	  /* Osmux was initialized by \ref conn_osmux_enable and can process frames */
};

extern const struct value_string osmux_state_strs[];
static inline const char *osmux_state_str(enum osmux_state val)
{ return get_value_string(osmux_state_strs, val); }

enum osmux_usage {
	OSMUX_USAGE_OFF = 0,
	OSMUX_USAGE_ON = 1,
	OSMUX_USAGE_ONLY = 2,
};

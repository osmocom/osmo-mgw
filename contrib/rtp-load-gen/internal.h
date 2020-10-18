#pragma once
#include <stdint.h>
#include <liburing.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/sockaddr_str.h>
#include <osmocom/core/rate_ctr.h>

/* configuration of one RTP connection/socket */
struct rtpsim_connection_cfg {
	struct osmo_sockaddr_str local;
	struct osmo_sockaddr_str remote;
	uint8_t pt;
	uint32_t ssrc;
	uint32_t duration;
};

/* TX side state of RTP connection/socket */
struct rtpsim_connection_tx {
	bool enabled;
	uint32_t timestamp;
	uint16_t seq;

	/* transmit buffer for outgoing messages */
	uint8_t *buf;
	/* used part of buffer */
	size_t buf_len;
};

/* RX side state of RTP connection/socket */
struct rtpsim_connection_rx {
	bool enabled;
	/* receive buffer for incoming messages */
	uint8_t *buf;
	/* used length of buffer */
	size_t buf_len;
};

struct rtpsim_instance;

/* One RTP connection/socket */
struct rtpsim_connection {
	/* index in rtp_instance.connections */
	unsigned int idx;
	/* back-pointer */
	struct rtpsim_instance *inst;

	struct rtpsim_connection_cfg cfg;
	struct rtpsim_connection_tx tx;
	struct rtpsim_connection_rx rx;
	struct rate_ctr_group *ctrg;

	/* socket file descriptor */
	int fd;
	char *cname;
};

struct rtpsim_instance_cfg {
	int num;
	void *ctx;
	uint16_t base_port;
	unsigned int num_flows;
};

/* one instance of the RTP simulator; typically one per worker thread */
struct rtpsim_instance {
	/* element in application global list of instances */
	struct llist_head list;
	struct rtpsim_instance_cfg cfg;
	/* per-instance io_uring */
	struct io_uring ring;
	/* per-instance timerfd */
	int timerfd;
	/* counter group of per-instance counters */
	struct rate_ctr_group *ctrg;

	struct rtpsim_connection **connections;
	/* size of 'connections' in number of pointers */
	unsigned int connections_size;
};


enum {
	DMAIN,
};

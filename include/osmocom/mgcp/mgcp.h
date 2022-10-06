/* A Media Gateway Control Protocol Media Gateway: RFC 3435 */

/*
 * (C) 2009-2012 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009-2012 by On-Waves
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#pragma once

#include <osmocom/core/msgb.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/write_queue.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/logging.h>

#include <osmocom/mgcp/mgcp_common.h>
#include <osmocom/mgcp/osmux.h>

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>

#include "mgcp_ratectr.h"

#define RTP_PORT_DEFAULT_RANGE_START 16002
#define RTP_PORT_DEFAULT_RANGE_END RTP_PORT_DEFAULT_RANGE_START + 64

/*
 * Handling of MGCP Endpoints and the MGCP Config
 */
struct mgcp_endpoint;
struct mgcp_config;
struct mgcp_trunk;
struct mgcp_rtp_end;

#define MGCP_ENDP_CRCX 1
#define MGCP_ENDP_DLCX 2
#define MGCP_ENDP_MDCX 3

/*
 * what to do with the msg?
 *	- continue as usual?
 *	- reject and send a failure code?
 *	- defer? do not send anything
 */
#define MGCP_POLICY_CONT	4
#define MGCP_POLICY_REJECT	5
#define MGCP_POLICY_DEFER	6

typedef int (*mgcp_reset)(struct mgcp_trunk *cfg);
typedef int (*mgcp_rqnt)(struct mgcp_endpoint *endp, char tone);

/**
 * Return:
 *   <  0 in case no audio was processed
 *   >= 0 in case audio was processed. The remaining payload
 *   length will be returned.
 */
typedef int (*mgcp_processing)(struct mgcp_endpoint *endp,
			       struct mgcp_rtp_end *dst_end,
			       char *data, int *len, int buf_size);

struct mgcp_conn_rtp;

typedef int (*mgcp_processing_setup)(struct mgcp_endpoint *endp,
				     struct mgcp_conn_rtp *conn_dst,
				     struct mgcp_conn_rtp *conn_src);

struct mgcp_rtp_codec;

typedef void (*mgcp_get_format)(struct mgcp_endpoint *endp,
				const struct mgcp_rtp_codec **codec,
				const char **fmtp_extra,
				struct mgcp_conn_rtp *conn);

/**
 * This holds information on how to allocate ports
 */
struct mgcp_port_range {
	pthread_mutex_t lock;
	/* addr or NULL to fall-back to default */
	char bind_addr_v4[INET6_ADDRSTRLEN];
	char bind_addr_v6[INET6_ADDRSTRLEN];

	/* dynamically allocated */
	int range_start;
	int range_end;
	int last_port;

	/* set to true to enable automatic probing
	 * of the local bind IP-Address, bind_addr
	 * (or its fall back) is used when automatic
	 * probing fails */
	bool bind_addr_probe;
};

/* There are up to three modes in which the keep-alive dummy packet can be
 * sent. The behaviour is controlled via the keepalive_interval member of the
 * trunk config. If that member is set to 0 (MGCP_KEEPALIVE_NEVER) no dummy-
 * packet is sent at all and the timer that sends regular dummy packets
 * is no longer scheduled. If the keepalive_interval is set to -1, only
 * one dummy packet is sent when an CRCX or an MDCX is performed. No timer
 * is scheduled. For all vales greater 0, the timer is scheduled and the
 * value is used as interval. See also mgcp_keepalive_timer_cb(),
 * handle_modify_con(), and handle_create_con() */
#define MGCP_KEEPALIVE_ONCE (-1)
#define MGCP_KEEPALIVE_NEVER 0

enum mgcp_role {
	MGCP_BSC = 0,
	MGCP_BSC_NAT,
};

struct mgcp_config {
	int source_port;
	char local_ip[INET6_ADDRSTRLEN];
	char source_addr[INET6_ADDRSTRLEN];
	char call_agent_addr[INET6_ADDRSTRLEN];

	/* RTP processing */
	mgcp_processing rtp_processing_cb;
	mgcp_processing_setup setup_rtp_processing_cb;

	mgcp_get_format get_net_downlink_format_cb;

	struct osmo_wqueue gw_fd;

	struct mgcp_port_range net_ports;
	int endp_dscp;
	int endp_priority;

	int force_ptime;

	mgcp_reset reset_cb;
	mgcp_rqnt rqnt_cb;
	void *data;

	/* list holding the trunks */
	struct llist_head trunks;

	enum mgcp_role role;

	/* Osmux usage policy: */
	enum osmux_usage osmux_use;
	/* addr to bind the server to */
	char *osmux_addr_v4;
	char *osmux_addr_v6;
	/* The BSC-NAT may ask for enabling osmux on demand. This tells us if
	 * the osmux socket is already initialized.
	 */
	bool osmux_initialized;
	/* osmux batch factor: from 1 to 4 maximum */
	int osmux_batch;
	/* osmux batch size (in bytes) */
	int osmux_batch_size;
	/* osmux port */
	uint16_t osmux_port;
	/* Pad circuit with dummy AMR frames if no payload to transmit is available */
	bool osmux_dummy;
	/* domain name of the media gateway */
	char domain[255+1];

	/* time after which inactive connections (CIs) get closed */
	int conn_timeout;

	/* osmocom CTRL interface */
	struct ctrl_handle *ctrl;

	/* global rate counters to measure the MGWs overall performance and
	 * health */
	struct mgcp_ratectr_global ratectr;
};

/* config management */
struct mgcp_config *mgcp_config_alloc(void);
int mgcp_parse_config(const char *config_file, struct mgcp_config *cfg,
		      enum mgcp_role role);
int mgcp_vty_init(void);
void mgcp_trunk_set_keepalive(struct mgcp_trunk *trunk, int interval);

/*
 * format helper functions
 */
struct msgb *mgcp_handle_message(struct mgcp_config *cfg, struct msgb *msg);


int mgcp_send_reset_ep(struct mgcp_endpoint *endp);
int mgcp_send_reset_all(struct mgcp_config *cfg);


int mgcp_create_bind(const char *source_addr, struct osmo_fd *fd, int port, uint8_t dscp,
		     uint8_t prio);
int mgcp_udp_send(int fd, const struct osmo_sockaddr *addr, const char *buf, int len);

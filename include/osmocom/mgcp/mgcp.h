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
#include <osmocom/core/write_queue.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/logging.h>

#include <osmocom/mgcp/mgcp_common.h>

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define RTP_PORT_DEFAULT_RANGE_START 16002
#define RTP_PORT_DEFAULT_RANGE_END RTP_PORT_DEFAULT_RANGE_START + 64

/*
 * Handling of MGCP Endpoints and the MGCP Config
 */
struct mgcp_endpoint;
struct mgcp_config;
struct mgcp_trunk_config;
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

typedef int (*mgcp_realloc)(struct mgcp_trunk_config *cfg, int endpoint);
typedef int (*mgcp_change)(struct mgcp_trunk_config *cfg, int endpoint, int state);
typedef int (*mgcp_policy)(struct mgcp_trunk_config *cfg, int endpoint, int state, const char *transactio_id);
typedef int (*mgcp_reset)(struct mgcp_trunk_config *cfg);
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

typedef void (*mgcp_get_format)(struct mgcp_endpoint *endp,
				int *payload_type,
				const char**subtype_name,
				const char**fmtp_extra,
				struct mgcp_conn_rtp *conn);

/**
 * This holds information on how to allocate ports
 */
struct mgcp_port_range {
	/* addr or NULL to fall-back to default */
	char *bind_addr;

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

/* Global MCGP CRCX related rate counters */
enum {
	MGCP_CRCX_SUCCESS,
	MGCP_CRCX_FAIL_BAD_ACTION,
	MGCP_CRCX_FAIL_UNHANDLED_PARAM,
	MGCP_CRCX_FAIL_MISSING_CALLID,
	MGCP_CRCX_FAIL_INVALID_MODE,
	MGCP_CRCX_FAIL_LIMIT_EXCEEDED,
	MGCP_CRCX_FAIL_UNKNOWN_CALLID,
	MGCP_CRCX_FAIL_ALLOC_CONN,
	MGCP_CRCX_FAIL_NO_REMOTE_CONN_DESC,
	MGCP_CRCX_FAIL_START_RTP,
	MGCP_CRCX_FAIL_REJECTED_BY_POLICY,
	MGCP_CRCX_FAIL_NO_OSMUX,
	MGCP_CRCX_FAIL_INVALID_CONN_OPTIONS,
	MGCP_CRCX_FAIL_CODEC_NEGOTIATION,
	MGCP_CRCX_FAIL_BIND_PORT,
};

/* Global MCGP MDCX related rate counters */
enum {
	MGCP_MDCX_SUCCESS,
	MGCP_MDCX_FAIL_WILDCARD,
	MGCP_MDCX_FAIL_NO_CONN,
	MGCP_MDCX_FAIL_INVALID_CALLID,
	MGCP_MDCX_FAIL_INVALID_CONNID,
	MGCP_MDCX_FAIL_UNHANDLED_PARAM,
	MGCP_MDCX_FAIL_NO_CONNID,
	MGCP_MDCX_FAIL_CONN_NOT_FOUND,
	MGCP_MDCX_FAIL_INVALID_MODE,
	MGCP_MDCX_FAIL_INVALID_CONN_OPTIONS,
	MGCP_MDCX_FAIL_NO_REMOTE_CONN_DESC,
	MGCP_MDCX_FAIL_START_RTP,
	MGCP_MDCX_FAIL_REJECTED_BY_POLICY,
	MGCP_MDCX_DEFERRED_BY_POLICY
};

/* Global MCGP DLCX related rate counters */
enum {
	MGCP_DLCX_SUCCESS,
	MGCP_DLCX_FAIL_WILDCARD,
	MGCP_DLCX_FAIL_NO_CONN,
	MGCP_DLCX_FAIL_INVALID_CALLID,
	MGCP_DLCX_FAIL_INVALID_CONNID,
	MGCP_DLCX_FAIL_UNHANDLED_PARAM,
	MGCP_DLCX_FAIL_REJECTED_BY_POLICY,
	MGCP_DLCX_DEFERRED_BY_POLICY,
};

struct mgcp_trunk_config {
	struct llist_head entry;

	struct mgcp_config *cfg;

	int trunk_nr;
	int trunk_type;

	char *audio_fmtp_extra;
	char *audio_name;
	int audio_payload;
	int audio_send_ptime;
	int audio_send_name;
	int audio_loop;

	int no_audio_transcoding;

	int omit_rtcp;
	int keepalive_interval;

	/* RTP patching */
	int force_constant_ssrc; /* 0: don't, 1: once */
	int force_aligned_timing;

	/* spec handling */
	int force_realloc;

	/* timer */
	struct osmo_timer_list keepalive_timer;

	/* When set, incoming RTP packets are not filtered
	 * when ports and ip-address do not match (debug) */
	int rtp_accept_all;

	unsigned int number_endpoints;
	int vty_number_endpoints;
	struct mgcp_endpoint *endpoints;

	/* Rate counter group which contains stats for processed CRCX commands. */
	struct rate_ctr_group *mgcp_crcx_ctr_group;
	/* Rate counter group which contains stats for processed MDCX commands. */
	struct rate_ctr_group *mgcp_mdcx_ctr_group;
	/* Rate counter group which contains stats for processed DLCX commands. */
	struct rate_ctr_group *mgcp_dlcx_ctr_group;
	/* Rate counter group which aggregates stats of individual RTP connections. */
	struct rate_ctr_group *all_rtp_conn_stats;
};

enum mgcp_role {
	MGCP_BSC = 0,
	MGCP_BSC_NAT,
};

struct mgcp_config {
	int source_port;
	char *local_ip;
	char *source_addr;
	char *call_agent_addr;

	/* RTP processing */
	mgcp_processing rtp_processing_cb;
	mgcp_processing_setup setup_rtp_processing_cb;

	mgcp_get_format get_net_downlink_format_cb;

	struct osmo_wqueue gw_fd;

	struct mgcp_port_range net_ports;
	int endp_dscp;

	int force_ptime;

	mgcp_change change_cb;
	mgcp_policy policy_cb;
	mgcp_reset reset_cb;
	mgcp_realloc realloc_cb;
	mgcp_rqnt rqnt_cb;
	void *data;

	uint32_t last_call_id;

	/* trunk handling */
	struct mgcp_trunk_config trunk;
	struct llist_head trunks;

	enum mgcp_role role;

	/* osmux translator: 0 means disabled, 1 means enabled */
	int osmux;
	/* addr to bind the server to */
	char *osmux_addr;
	/* The BSC-NAT may ask for enabling osmux on demand. This tells us if
	 * the osmux socket is already initialized.
	 */
	int osmux_init;
	/* osmux batch factor: from 1 to 4 maximum */
	int osmux_batch;
	/* osmux batch size (in bytes) */
	int osmux_batch_size;
	/* osmux port */
	uint16_t osmux_port;
	/* Pad circuit with dummy messages until we see the first voice
	 * message.
	 */
	uint16_t osmux_dummy;
	/* domain name of the media gateway */
	char domain[255+1];

	/* time after which inactive connections (CIs) get closed */
	unsigned int conn_timeout;
};

/* config management */
struct mgcp_config *mgcp_config_alloc(void);
int mgcp_parse_config(const char *config_file, struct mgcp_config *cfg,
		      enum mgcp_role role);
int mgcp_vty_init(void);
int mgcp_endpoints_allocate(struct mgcp_trunk_config *cfg);
void mgcp_trunk_set_keepalive(struct mgcp_trunk_config *tcfg, int interval);

/*
 * format helper functions
 */
struct msgb *mgcp_handle_message(struct mgcp_config *cfg, struct msgb *msg);


int mgcp_send_reset_ep(struct mgcp_endpoint *endp, int endpoint);
int mgcp_send_reset_all(struct mgcp_config *cfg);


int mgcp_create_bind(const char *source_addr, struct osmo_fd *fd, int port);
int mgcp_udp_send(int fd, struct in_addr *addr, int port, char *buf, int len);

/*
 * (C) 2012-2013 by Pablo Neira Ayuso <pablo@gnumonks.org>
 * (C) 2012-2013 by On Waves ehf <http://www.on-waves.com>
 * All rights not specifically granted under this license are reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Affero General Public License as published by the
 * Free Software Foundation; either version 3 of the License, or (at your
 * option) any later version.
 */

#include <stdio.h> /* for printf */
#include <string.h> /* for memcpy */
#include <stdlib.h> /* for abs */
#include <inttypes.h> /* for PRIu64 */
#include <netinet/in.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/talloc.h>

#include <osmocom/netif/osmux.h>
#include <osmocom/netif/rtp.h>
#include <osmocom/netif/amr.h>

#include <osmocom/mgcp/debug.h>
#include <osmocom/mgcp/mgcp.h>
#include <osmocom/mgcp/mgcp_protocol.h>
#include <osmocom/mgcp/osmux.h>
#include <osmocom/mgcp/mgcp_conn.h>
#include <osmocom/mgcp/mgcp_endp.h>
#include <osmocom/mgcp/mgcp_trunk.h>

static struct osmo_fd osmux_fd;

static LLIST_HEAD(osmux_handle_list);

struct osmux_handle {
	struct llist_head head;
	struct osmux_in_handle *in;
	struct osmo_sockaddr rem_addr;
	int refcnt;
};

const struct value_string osmux_state_strs[] = {
	{ OSMUX_STATE_DISABLED,		"disabled" },
	{ OSMUX_STATE_ACTIVATING,	"activating" },
	{ OSMUX_STATE_ENABLED,		"enabled" },
	{ 0, NULL }
};

static const struct rate_ctr_group_desc rate_ctr_group_osmux_desc = {
	.group_name_prefix = "conn_osmux",
	.group_description = "Osmux connection statistics",
	.class_id = 1,
	.num_ctr = ARRAY_SIZE(mgcp_conn_osmux_rate_ctr_desc),
	.ctr_desc = mgcp_conn_osmux_rate_ctr_desc
};

static void rtpconn_osmux_rate_ctr_add(struct mgcp_conn_rtp *conn_rtp, int id, int inc)
{
	struct rate_ctr_group *conn_osmux_stats = conn_rtp->osmux.ctrg;
	struct rate_ctr_group *trunk_osmux_stats = conn_rtp->conn->endp->trunk->ratectr.all_osmux_conn_stats;

	/* add to both the per-connection and the global stats */
	rate_ctr_add(rate_ctr_group_get_ctr(conn_osmux_stats, id), inc);
	rate_ctr_add(rate_ctr_group_get_ctr(trunk_osmux_stats, id), inc);
}

static void rtpconn_osmux_rate_ctr_inc(struct mgcp_conn_rtp *conn_rtp, int id)
{
	rtpconn_osmux_rate_ctr_add(conn_rtp, id, 1);
}

/* Deliver OSMUX batch to the remote end */
static void osmux_deliver_cb(struct msgb *batch_msg, void *data)
{
	struct osmux_handle *handle = data;
	socklen_t dest_len;
	int rc;
	struct mgcp_trunk *trunk = (struct mgcp_trunk *)osmux_fd.data;
	struct rate_ctr_group *all_osmux_stats = trunk->ratectr.all_osmux_conn_stats;

	switch (handle->rem_addr.u.sa.sa_family) {
	case AF_INET6:
		dest_len = sizeof(handle->rem_addr.u.sin6);
		break;
	case AF_INET:
	default:
		dest_len = sizeof(handle->rem_addr.u.sin);
		break;
	}
	rc = sendto(osmux_fd.fd, batch_msg->data, batch_msg->len, 0,
		    (struct sockaddr *)&handle->rem_addr.u.sa, dest_len);
	if (rc < 0) {
		char errbuf[129];
		strerror_r(errno, errbuf, sizeof(errbuf));
		LOGP(DOSMUX, LOGL_NOTICE, "osmux sendto(%s) failed: %s\n",
			 osmo_sockaddr_to_str(&handle->rem_addr), errbuf);
		rate_ctr_inc(rate_ctr_group_get_ctr(all_osmux_stats, OSMUX_DROPPED_PACKETS_CTR));
	} else {
		rate_ctr_inc(rate_ctr_group_get_ctr(all_osmux_stats, OSMUX_PACKETS_TX_CTR));
	}
	msgb_free(batch_msg);
}

/* Lookup existing OSMUX handle for specified destination address. */
static struct osmux_handle *
osmux_handle_find_get(const struct osmo_sockaddr *rem_addr)
{
	struct osmux_handle *h;

	llist_for_each_entry(h, &osmux_handle_list, head) {
		if (osmo_sockaddr_cmp(&h->rem_addr, rem_addr) == 0) {
			h->refcnt++;
			LOGP(DOSMUX, LOGL_DEBUG,
			     "Using existing OSMUX handle for addr=%s (rfcnt=%u)\n",
			     osmo_sockaddr_to_str(rem_addr), h->refcnt);
			return h;
		}
	}

	return NULL;
}

/* Put down no longer needed OSMUX handle */
static void osmux_handle_put(struct osmux_in_handle *in)
{
	struct osmux_handle *h;

	llist_for_each_entry(h, &osmux_handle_list, head) {
		if (h->in == in) {
			LOGP(DOSMUX, LOGL_DEBUG,
			     "Putting existing OSMUX handle for addr=%s (rfcnt=%u)\n",
			     osmo_sockaddr_to_str(&h->rem_addr), h->refcnt);
			if (--h->refcnt == 0) {
				LOGP(DOSMUX, LOGL_INFO,
				     "Releasing unused osmux handle for %s\n",
				     osmo_sockaddr_to_str(&h->rem_addr));
				llist_del(&h->head);
				TALLOC_FREE(h->in);
				talloc_free(h);
			}
			return;
		}
	}
	LOGP(DOSMUX, LOGL_ERROR, "Cannot find Osmux input handle %p\n", in);
}

/* Allocate free OSMUX handle */
static struct osmux_handle *
osmux_handle_alloc(struct mgcp_conn_rtp *conn, const struct osmo_sockaddr *rem_addr)
{
	struct osmux_handle *h;
	struct mgcp_trunk *trunk = conn->conn->endp->trunk;
	struct mgcp_config *cfg = trunk->cfg;

	h = talloc_zero(trunk, struct osmux_handle);
	if (!h)
		return NULL;
	h->rem_addr = *rem_addr;
	h->refcnt++;

	h->in = osmux_xfrm_input_alloc(h);
	if (!h->in) {
		talloc_free(h);
		return NULL;
	}
	/* sequence number to start OSMUX message from */
	osmux_xfrm_input_set_initial_seqnum(h->in, 0);
	osmux_xfrm_input_set_batch_factor(h->in, cfg->osmux_batch);
	/* If batch size is zero, the library defaults to 1472 bytes. */
	osmux_xfrm_input_set_batch_size(h->in, cfg->osmux_batch_size);
	osmux_xfrm_input_set_deliver_cb(h->in, osmux_deliver_cb, h);

	llist_add(&h->head, &osmux_handle_list);

	LOGP(DOSMUX, LOGL_DEBUG, "Created new OSMUX handle for rem_addr=%s\n",
	     osmo_sockaddr_to_str(rem_addr));

	return h;
}

/* Lookup existing handle for a specified address, if the handle can not be
 * found, the function will automatically allocate one */
static struct osmux_in_handle *
osmux_handle_find_or_create(struct mgcp_conn_rtp *conn, const struct osmo_sockaddr *rem_addr)
{
	struct osmux_handle *h;

	if (rem_addr->u.sa.sa_family != AF_INET) {
		LOGP(DOSMUX, LOGL_DEBUG, "IPv6 not supported in osmux yet!\n");
		return NULL;
	}

	h = osmux_handle_find_get(rem_addr);
	if (h != NULL)
		return h->in;

	h = osmux_handle_alloc(conn, rem_addr);
	if (h == NULL)
		return NULL;

	return h->in;
}

/*! send RTP packet through OSMUX connection.
 *  \param[in] buf rtp data
 *  \param[in] buf_len length of rtp data
 *  \param[in] conn associated RTP connection
 *  \returns 0 on success, -1 on ERROR */
int osmux_xfrm_to_osmux(char *buf, int buf_len, struct mgcp_conn_rtp *conn)
{
	int ret;
	struct msgb *msg;

	if (!conn->end.output_enabled) {
		rtpconn_osmux_rate_ctr_inc(conn, OSMUX_RTP_PACKETS_TX_DROPPED_CTR);
		return -1;
	}

	if (conn->osmux.state != OSMUX_STATE_ENABLED) {
		LOGPCONN(conn->conn, DOSMUX, LOGL_INFO, "forwarding RTP to Osmux conn not yet enabled, dropping (cid=%d)\n",
		conn->osmux.remote_cid);
		rtpconn_osmux_rate_ctr_inc(conn, OSMUX_RTP_PACKETS_TX_DROPPED_CTR);
		return -1;
	}

	msg = msgb_alloc(4096, "RTP");
	if (!msg)
		return -1;

	memcpy(msg->data, buf, buf_len);
	msgb_put(msg, buf_len);

	while ((ret = osmux_xfrm_input(conn->osmux.in, msg, conn->osmux.remote_cid)) > 0) {
		/* batch full, build and deliver it */
		osmux_xfrm_input_deliver(conn->osmux.in);
	}
	if (ret < 0) {
		rtpconn_osmux_rate_ctr_inc(conn, OSMUX_RTP_PACKETS_TX_DROPPED_CTR);
	} else {
		rtpconn_osmux_rate_ctr_inc(conn, OSMUX_RTP_PACKETS_TX_CTR);
		rtpconn_osmux_rate_ctr_add(conn, OSMUX_AMR_OCTETS_TX_CTR, buf_len - sizeof(struct rtp_hdr));
	}
	return 0;
}

/* Lookup the endpoint that corresponds to the specified address (port) */
static struct mgcp_conn_rtp*
osmux_conn_lookup(struct mgcp_trunk *trunk, uint8_t local_cid, const struct osmo_sockaddr *rem_addr)
{
	struct mgcp_endpoint *endp;
	struct mgcp_conn *conn = NULL;
	struct mgcp_conn_rtp * conn_rtp;
	int i;

	for (i = 0; i < trunk->number_endpoints; i++) {

		endp = trunk->endpoints[i];

		llist_for_each_entry(conn, &endp->conns, entry) {
			if (conn->type != MGCP_CONN_TYPE_RTP)
				continue;

			conn_rtp = &conn->u.rtp;
			if (!mgcp_conn_rtp_is_osmux(conn_rtp))
				continue;

			/* FIXME: Match remote address! */

			if (conn_rtp->osmux.local_cid == local_cid)
				return conn_rtp;
		}
	}

	LOGP(DOSMUX, LOGL_DEBUG, "Cannot find osmux conn with rem_addr=%s local_cid=%d\n",
	     osmo_sockaddr_to_str(rem_addr), local_cid);

	return NULL;
}

static void scheduled_from_osmux_tx_rtp_cb(struct msgb *msg, void *data)
{
	struct mgcp_conn_rtp *conn = data;
	struct mgcp_endpoint *endp = conn->conn->endp;
	struct osmo_sockaddr addr = { /* FIXME: do we know the source address?? */ };
	struct osmo_rtp_msg_ctx *mc = OSMO_RTP_MSG_CTX(msg);
	*mc = (struct osmo_rtp_msg_ctx){
		.proto = MGCP_PROTO_RTP,
		.conn_src = conn,
		.from_addr = &addr,
	};

	endp->type->dispatch_rtp_cb(msg);
	msgb_free(msg);
}

static struct msgb *osmux_recv(struct osmo_fd *ofd, struct osmo_sockaddr *addr)
{
	struct msgb *msg;
	socklen_t slen = sizeof(addr->u.sas);
	int ret;

	msg = msgb_alloc(4096, "OSMUX");
	if (!msg) {
		LOGP(DOSMUX, LOGL_ERROR, "cannot allocate message\n");
		return NULL;
	}
	ret = recvfrom(ofd->fd, msg->data, msg->data_len, 0, &addr->u.sa, &slen);
	if (ret <= 0) {
		msgb_free(msg);
		LOGP(DOSMUX, LOGL_ERROR, "cannot receive message\n");
		return NULL;
	}
	msgb_put(msg, ret);

	return msg;
}

/* Updates endp osmux state and returns 0 if it can process messages, -1 otherwise */
static int endp_osmux_state_check(struct mgcp_endpoint *endp, struct mgcp_conn_rtp *conn,
				  bool sending)
{
	struct osmo_sockaddr rem_addr;

	switch(conn->osmux.state) {
	case OSMUX_STATE_ACTIVATING:
		rem_addr = conn->end.addr;
		osmo_sockaddr_set_port(&rem_addr.u.sa, ntohs(conn->end.rtp_port));
		if (osmux_enable_conn(endp, conn, &rem_addr) < 0) {
			LOGPCONN(conn->conn, DOSMUX, LOGL_ERROR,
				 "Could not enable osmux for conn on %s: %s\n",
				 sending ? "sent" : "received",
				 mgcp_conn_dump(conn->conn));
			return -1;
		}
		LOGPCONN(conn->conn, DOSMUX, LOGL_INFO,
			 "Osmux %s CID %u towards %s is now enabled\n",
			 sending ? "sent" : "received",
			 sending ? conn->osmux.remote_cid : conn->osmux.local_cid,
			 osmo_sockaddr_to_str(&rem_addr));
		return 0;
	case OSMUX_STATE_ENABLED:
		return 0;
	default:
		LOGPCONN(conn->conn, DOSMUX, LOGL_ERROR,
			 "Osmux %s in conn %s without full negotiation, state %d\n",
			 sending ? "sent" : "received",
			 mgcp_conn_dump(conn->conn), conn->osmux.state);
		return -1;
	}
}

static int osmux_legacy_dummy_parse_cid(const struct osmo_sockaddr *rem_addr, struct msgb *msg,
					uint8_t *osmux_cid)
{
	if (msg->len < 1 + sizeof(*osmux_cid)) {
		LOGP(DOSMUX, LOGL_ERROR,
		     "Discarding truncated Osmux dummy load: %s\n", osmo_hexdump(msg->data, msg->len));
		return -1;
	}

	/* extract the osmux CID from the dummy message */
	memcpy(osmux_cid, &msg->data[1], sizeof(*osmux_cid));
	return 0;
}

/* This is called from the bsc-nat */
static int osmux_handle_dummy(struct mgcp_trunk *trunk, const struct osmo_sockaddr *rem_addr,
			      struct msgb *msg)
{
	uint8_t osmux_cid;
	struct mgcp_conn_rtp *conn;

	if (osmux_legacy_dummy_parse_cid(rem_addr, msg, &osmux_cid) < 0)
		goto out;

	conn = osmux_conn_lookup(trunk, osmux_cid, rem_addr);
	if (!conn) {
		LOGP(DOSMUX, LOGL_DEBUG,
		     "Cannot find conn for Osmux CID %d\n", osmux_cid);
		goto out;
	}

	endp_osmux_state_check(conn->conn->endp, conn, false);
	/* Only needed to punch hole in firewall, it can be dropped */
out:
	msgb_free(msg);
	return 0;
}

#define osmux_chunk_length(msg, rem) ((rem) - (msg)->len)
static int osmux_read_fd_cb(struct osmo_fd *ofd, unsigned int what)
{
	struct msgb *msg;
	struct osmux_hdr *osmuxh;
	struct osmo_sockaddr rem_addr;
	uint32_t rem;
	struct mgcp_trunk *trunk = ofd->data;
	struct rate_ctr_group *all_rtp_stats = trunk->ratectr.all_osmux_conn_stats;

	msg = osmux_recv(ofd, &rem_addr);
	if (!msg)
		return -1;

	rate_ctr_inc(rate_ctr_group_get_ctr(all_rtp_stats, OSMUX_PACKETS_RX_CTR));

	if (trunk->cfg->osmux_use == OSMUX_USAGE_OFF) {
		LOGP(DOSMUX, LOGL_ERROR,
		     "bsc-nat wants to use Osmux but bsc did not request it\n");
		goto out;
	}

	/* not any further processing dummy messages */
	if (mgcp_is_rtp_dummy_payload(msg))
		return osmux_handle_dummy(trunk, &rem_addr, msg);

	rem = msg->len;
	while((osmuxh = osmux_xfrm_output_pull(msg)) != NULL) {
		struct mgcp_endpoint *endp;
		struct mgcp_conn_rtp *conn_src;
		conn_src = osmux_conn_lookup(trunk, osmuxh->circuit_id,
					     &rem_addr);
		if (!conn_src) {
			LOGP(DOSMUX, LOGL_DEBUG,
			     "Cannot find a src conn for circuit_id=%d\n",
			     osmuxh->circuit_id);
			rem = msg->len;
			continue;
		}
		endp = conn_src->conn->endp;
		mgcp_conn_watchdog_kick(conn_src->conn);

		if (endp_osmux_state_check(endp, conn_src, false) == 0) {
			rtpconn_osmux_rate_ctr_inc(conn_src, OSMUX_CHUNKS_RX_CTR);
			rtpconn_osmux_rate_ctr_add(conn_src, OSMUX_OCTETS_RX_CTR,
						   osmux_chunk_length(msg, rem));
			osmux_xfrm_output_sched(conn_src->osmux.out, osmuxh);
		}
		rem = msg->len;
	}
out:
	msgb_free(msg);
	return 0;
}

int osmux_init(int role, struct mgcp_trunk *trunk)
{
	int ret;
	struct mgcp_config *cfg = trunk->cfg;

	/* So far we only support running on one trunk: */
	OSMO_ASSERT(trunk == mgcp_trunk_by_num(cfg, MGCP_TRUNK_VIRTUAL, MGCP_VIRT_TRUNK_ID));

	osmo_fd_setup(&osmux_fd, -1, OSMO_FD_READ, osmux_read_fd_cb, trunk, 0);

	ret = mgcp_create_bind(cfg->osmux_addr, &osmux_fd, cfg->osmux_port,
				cfg->endp_dscp, cfg->endp_priority);
	if (ret < 0) {
		LOGP(DOSMUX, LOGL_ERROR, "cannot bind OSMUX socket to %s:%u\n",
		     cfg->osmux_addr, cfg->osmux_port);
		return ret;
	}

	ret = osmo_fd_register(&osmux_fd);
	if (ret < 0) {
		LOGP(DOSMUX, LOGL_ERROR, "cannot register OSMUX socket %s\n",
		     osmo_sock_get_name2(osmux_fd.fd));
		return ret;
	}
	cfg->osmux_initialized = true;

	LOGP(DOSMUX, LOGL_INFO, "OSMUX socket listening on %s\n",
		 osmo_sock_get_name2(osmux_fd.fd));

	return 0;
}

/*! Initialize Osmux bits of a conn.
 *  \param[in] conn Osmux connection to initialize
 *  \returns 0 on success, negative on ERROR */
int osmux_init_conn(struct mgcp_conn_rtp *conn)
{
	if (conn_osmux_allocate_local_cid(conn) == -1)
		return -1;
	conn->osmux.ctrg = rate_ctr_group_alloc(conn->conn, &rate_ctr_group_osmux_desc, conn->ctrg->idx);

	conn->osmux.state = OSMUX_STATE_ACTIVATING;
	return 0;
}

/*! enable OSXMUX circuit for a specified connection.
 *  \param[in] endp mgcp endpoint (configuration)
 *  \param[in] conn connection to disable
 *  \param[in] addr IP address and port of remote OSMUX endpoint
 *  \returns 0 on success, -1 on ERROR */
int osmux_enable_conn(struct mgcp_endpoint *endp, struct mgcp_conn_rtp *conn,
		      const struct osmo_sockaddr *rem_addr)
{
	/*! If osmux is enabled, initialize the output handler. This handler is
	 *  used to reconstruct the RTP flow from osmux. The RTP SSRC is
	 *  allocated based on the circuit ID (conn_net->osmux.cid), which is unique
	 *  in the local scope to the BSC/BSC-NAT. We use it to divide the RTP
	 *  SSRC space (2^32) by the OSMUX_CID_MAX + 1 possible circuit IDs, then randomly
	 *  select one value from that window. Thus, we have no chance to have
	 *  overlapping RTP SSRC traveling to the BTSes behind the BSC,
	 *  similarly, for flows traveling to the MSC.
	 */
	struct in6_addr addr_unset = {};
	static const uint32_t rtp_ssrc_winlen = UINT32_MAX / (OSMUX_CID_MAX + 1);
	uint16_t osmux_dummy = endp->trunk->cfg->osmux_dummy;

	/* Check if osmux is enabled for the specified connection */
	if (conn->osmux.state != OSMUX_STATE_ACTIVATING) {
		LOGPCONN(conn->conn, DOSMUX, LOGL_ERROR,
			 "conn:%s didn't negotiate Osmux, state %d\n",
			 mgcp_conn_dump(conn->conn), conn->osmux.state);
		return -1;
	}

	/* Wait until we have the connection information from MDCX */
	if (memcmp(&conn->end.addr, &addr_unset,
		   conn->end.addr.u.sa.sa_family == AF_INET6 ?
			sizeof(struct in6_addr) :
			sizeof(struct in_addr)) == 0) {
		LOGPCONN(conn->conn, DOSMUX, LOGL_INFO,
			"Osmux remote address/port still unknown\n");
		return -1;
	}

	conn->osmux.in = osmux_handle_find_or_create(conn, rem_addr);
	if (!conn->osmux.in) {
		LOGPCONN(conn->conn, DOSMUX, LOGL_ERROR,
			"Cannot allocate input osmux handle for conn:%s\n",
			mgcp_conn_dump(conn->conn));
		return -1;
	}
	if (osmux_xfrm_input_open_circuit(conn->osmux.in, conn->osmux.remote_cid, osmux_dummy) < 0) {
		LOGPCONN(conn->conn, DOSMUX, LOGL_ERROR,
			"Cannot open osmux circuit %u for conn:%s\n",
		     conn->osmux.remote_cid, mgcp_conn_dump(conn->conn));
		return -1;
	}

	conn->osmux.out = osmux_xfrm_output_alloc(conn->conn);
	osmux_xfrm_output_set_rtp_ssrc(conn->osmux.out,
				       (conn->osmux.remote_cid * rtp_ssrc_winlen) +
				       (random() % rtp_ssrc_winlen));
	osmux_xfrm_output_set_rtp_pl_type(conn->osmux.out, conn->end.codec->payload_type);
	osmux_xfrm_output_set_tx_cb(conn->osmux.out,
				    scheduled_from_osmux_tx_rtp_cb, conn);

	conn->osmux.state = OSMUX_STATE_ENABLED;

	return 0;
}

/*! disable OSXMUX circuit for a specified connection.
 *  \param[in] conn connection to disable */
void conn_osmux_disable(struct mgcp_conn_rtp *conn)
{
	OSMO_ASSERT(conn->osmux.state != OSMUX_STATE_DISABLED);

	LOGPCONN(conn->conn, DOSMUX, LOGL_INFO,
		"Releasing connection using local Osmux CID %u\n", conn->osmux.local_cid);

	struct rate_ctr_group *all_osmux_stats = conn->conn->endp->trunk->ratectr.all_osmux_conn_stats;
	rate_ctr_inc(rate_ctr_group_get_ctr(all_osmux_stats, OSMUX_NUM_CONNECTIONS));

	if (conn->osmux.state == OSMUX_STATE_ENABLED) {
		/* We are closing, we don't need pending RTP packets to be transmitted */
		osmux_xfrm_output_set_tx_cb(conn->osmux.out, NULL, NULL);
		TALLOC_FREE(conn->osmux.out);

		osmux_xfrm_input_close_circuit(conn->osmux.in, conn->osmux.remote_cid);
		conn->osmux.state = OSMUX_STATE_DISABLED;
		osmux_handle_put(conn->osmux.in);
		conn->osmux.remote_cid = 0;
		conn->osmux.remote_cid_present = false;
	}

	conn_osmux_release_local_cid(conn);

	rate_ctr_group_free(conn->osmux.ctrg);
	conn->osmux.ctrg = NULL;
}

/*! relase OSXMUX cid, that had been allocated to this connection.
 *  \param[in] conn connection with OSMUX cid to release */
void conn_osmux_release_local_cid(struct mgcp_conn_rtp *conn)
{
	if (conn->osmux.local_cid_allocated)
		osmux_cid_pool_put(conn->osmux.local_cid);
	conn->osmux.local_cid = 0;
	conn->osmux.local_cid_allocated = false;
}

/*! allocate local OSMUX cid to connection.
 *  \param[in] conn connection for which we allocate the local OSMUX cid
 * \returns Allocated OSMUX cid, -1 on error (no free CIDs avail).
 */
int conn_osmux_allocate_local_cid(struct mgcp_conn_rtp *conn)
{
	OSMO_ASSERT(conn->osmux.local_cid_allocated == false);
	int osmux_cid = osmux_cid_pool_get_next();
	if (osmux_cid == -1) {
		LOGPCONN(conn->conn, DOSMUX, LOGL_INFO,
			 "no available local Osmux CID to allocate!\n");
		return -1;
	}

	conn->osmux.local_cid = (uint8_t) osmux_cid;
	conn->osmux.local_cid_allocated = true;
	conn->type = MGCP_OSMUX_BSC;
	return osmux_cid;
}

/*! send RTP dummy packet to OSMUX connection port.
 *  \param[in] endp mcgp endpoint that holds the RTP connection
 *  \param[in] conn associated RTP connection
 *  \returns bytes sent, -1 on error */
int osmux_send_dummy(struct mgcp_endpoint *endp, struct mgcp_conn_rtp *conn)
{
	char ipbuf[INET6_ADDRSTRLEN];
	struct osmux_hdr *osmuxh;
	int buf_len;
	struct in_addr addr_unset = {};

	/*! The dummy packet will not be sent via the actual OSMUX connection,
	 *  instead it is sent out of band to port where the remote OSMUX
	 *  multplexer is listening. The goal is to ensure that the connection
	 *  is kept open */

	/*! We don't need to send the dummy load for osmux so often as another
	 *  endpoint may have already punched the hole in the firewall. This
	 *  approach is simple though. */

	/* Wait until we have the connection information from MDCX */
	if (memcmp(&conn->end.addr, &addr_unset, sizeof(addr_unset)) == 0)
		return 0;

	if (endp_osmux_state_check(endp, conn, true) < 0)
		return 0;

	buf_len = sizeof(struct osmux_hdr) + osmo_amr_bytes(AMR_FT_0);
	osmuxh = (struct osmux_hdr *) alloca(buf_len);
	memset(osmuxh, 0, buf_len);
	osmuxh->ft = OSMUX_FT_DUMMY;
	osmuxh->amr_ft = AMR_FT_0;
	osmuxh->circuit_id = conn->osmux.remote_cid;

	LOGPCONN(conn->conn, DOSMUX, LOGL_DEBUG,
		 "sending OSMUX dummy load to %s:%u CID %u\n",
		 osmo_sockaddr_ntop(&conn->end.addr.u.sa, ipbuf),
		 ntohs(conn->end.rtp_port), conn->osmux.remote_cid);

	return mgcp_udp_send(osmux_fd.fd, &conn->end.addr,
			     conn->end.rtp_port, (char*)osmuxh, buf_len);
}

/* bsc-nat allocates/releases the Osmux circuit ID. +7 to round up to 8 bit boundary. */
static uint8_t osmux_cid_bitmap[(OSMUX_CID_MAX + 1 + 7) / 8];

/*! count the number of taken OSMUX cids.
 *  \returns number of OSMUX cids in use */
int osmux_cid_pool_count_used(void)
{
	int i, j, used = 0;

	for (i = 0; i < sizeof(osmux_cid_bitmap); i++) {
		for (j = 0; j < 8; j++) {
			if (osmux_cid_bitmap[i] & (1 << j))
				used += 1;
		}
	}

	return used;
}

/*! take a free OSMUX cid.
 *  \returns OSMUX cid */
int osmux_cid_pool_get_next(void)
{
	int i, j;

	for (i = 0; i < sizeof(osmux_cid_bitmap); i++) {
		for (j = 0; j < 8; j++) {
			if (osmux_cid_bitmap[i] & (1 << j))
				continue;

			osmux_cid_bitmap[i] |= (1 << j);
			LOGP(DOSMUX, LOGL_DEBUG,
			     "Allocating Osmux CID %u from pool\n", (i * 8) + j);
			return (i * 8) + j;
		}
	}

	LOGP(DOSMUX, LOGL_ERROR, "All Osmux circuits are in use!\n");
	return -1;
}

/*! take a specific OSMUX cid.
 *  \param[in] osmux_cid OSMUX cid */
void osmux_cid_pool_get(uint8_t osmux_cid)
{
	LOGP(DOSMUX, LOGL_DEBUG, "Allocating Osmux CID %u from pool\n", osmux_cid);
	osmux_cid_bitmap[osmux_cid / 8] |= (1 << (osmux_cid % 8));
}

/*! put back a no longer used OSMUX cid.
 *  \param[in] osmux_cid OSMUX cid */
void osmux_cid_pool_put(uint8_t osmux_cid)
{
	LOGP(DOSMUX, LOGL_DEBUG, "Osmux CID %u is back to the pool\n", osmux_cid);
	osmux_cid_bitmap[osmux_cid / 8] &= ~(1 << (osmux_cid % 8));
}

/*! check if OSMUX cid is already taken */
bool osmux_cid_pool_allocated(uint8_t osmux_cid)
{
	return !!(osmux_cid_bitmap[osmux_cid / 8] & (1 << (osmux_cid % 8)));
}

/*
 * (C) 2012-2013 by Pablo Neira Ayuso <pablo@gnumonks.org>
 * (C) 2012-2013 by On Waves ehf <http://www.on-waves.com>
 * (C) 2013-2024 by sysmocom - s.f.m.c. GmbH
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
#include <unistd.h> /* for PRIu64 */
#include <netinet/in.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/osmo_io.h>
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

static struct osmo_io_fd *osmux_fd_v4;
static struct osmo_io_fd *osmux_fd_v6;

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
	int rc;
	struct osmo_io_fd *iofd;
	struct mgcp_trunk *trunk = (struct mgcp_trunk *) osmo_iofd_get_data(osmux_fd_v4);
	struct rate_ctr_group *all_osmux_stats = trunk->ratectr.all_osmux_conn_stats;

	switch (handle->rem_addr.u.sa.sa_family) {
	case AF_INET6:
		iofd = osmux_fd_v6;
		break;
	case AF_INET:
	default:
		iofd = osmux_fd_v4;
		break;
	}
	rc = osmo_iofd_sendto_msgb(iofd, batch_msg, 0, &handle->rem_addr);
	if (rc < 0) {
		char errbuf[129];
		strerror_r(-rc, errbuf, sizeof(errbuf));
		LOGP(DOSMUX, LOGL_NOTICE, "osmux sendto(%s) failed: %s\n",
			 osmo_sockaddr_to_str(&handle->rem_addr), errbuf);
		rate_ctr_inc(rate_ctr_group_get_ctr(all_osmux_stats, OSMUX_DROPPED_PACKETS_CTR));
		msgb_free(batch_msg);
	} else {
		rate_ctr_inc(rate_ctr_group_get_ctr(all_osmux_stats, OSMUX_PACKETS_TX_CTR));
	}
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
osmux_handle_alloc(const struct mgcp_trunk *trunk, const struct osmo_sockaddr *rem_addr)
{
	struct osmux_handle *h;
	const struct mgcp_config *cfg = trunk->cfg;
	char name[128] = "r=";

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

	osmo_sockaddr_to_str_buf(name + 2, sizeof(name) - 2, rem_addr);
	osmux_xfrm_input_set_name(h->in, name);
	/* sequence number to start OSMUX message from */
	osmux_xfrm_input_set_initial_seqnum(h->in, 0);
	osmux_xfrm_input_set_batch_factor(h->in, cfg->osmux.batch_factor);
	/* If batch size is zero, the library defaults to 1472 bytes. */
	osmux_xfrm_input_set_batch_size(h->in, cfg->osmux.batch_size);
	osmux_xfrm_input_set_deliver_cb(h->in, osmux_deliver_cb, h);

	llist_add(&h->head, &osmux_handle_list);

	LOGP(DOSMUX, LOGL_DEBUG, "Created new OSMUX handle for rem_addr=%s\n",
	     osmo_sockaddr_to_str(rem_addr));

	return h;
}

/* Lookup existing handle for a specified address, if the handle can not be
 * found, the function will automatically allocate one */
static struct osmux_in_handle *
osmux_handle_find_or_create(const struct mgcp_trunk *trunk, const struct osmo_sockaddr *rem_addr)
{
	struct osmux_handle *h;

	h = osmux_handle_find_get(rem_addr);
	if (h != NULL)
		return h->in;

	h = osmux_handle_alloc(trunk, rem_addr);
	if (h == NULL)
		return NULL;

	return h->in;
}

/*! send RTP packet through OSMUX connection. Takes ownership of msg.
 *  \param[in] conn associated RTP connection
 *  \param[in] msg msgb containing an RTP AMR packet
 *  \returns 0 on success, -1 on ERROR */
int conn_osmux_send_rtp(struct mgcp_conn_rtp *conn, struct msgb *msg)
{
	int ret;

	if (!conn->end.output_enabled) {
		rtpconn_osmux_rate_ctr_inc(conn, OSMUX_RTP_PACKETS_TX_DROPPED_CTR);
		msgb_free(msg);
		return -1;
	}

	if (conn->osmux.state != OSMUX_STATE_ENABLED) {
		LOGPCONN(conn->conn, DOSMUX, LOGL_INFO, "forwarding RTP to Osmux conn not yet enabled, dropping (cid=%d)\n",
		conn->osmux.remote_cid);
		rtpconn_osmux_rate_ctr_inc(conn, OSMUX_RTP_PACKETS_TX_DROPPED_CTR);
		msgb_free(msg);
		return -1;
	}

	/* Osmux implementation works with AMR OA only, make sure we convert to it if needed: */
	if (amr_oa_bwe_convert(conn->conn->endp, msg, true) < 0) {
		LOGPCONN(conn->conn, DOSMUX, LOGL_ERROR,
			 "Error converting to AMR octet-aligned mode\n");
		msgb_free(msg);
		return -1;
	}

	while ((ret = osmux_xfrm_input(conn->osmux.in, msg, conn->osmux.remote_cid)) > 0) {
		/* batch full, build and deliver it */
		osmux_xfrm_input_deliver(conn->osmux.in);
	}
	if (ret < 0) {
		rtpconn_osmux_rate_ctr_inc(conn, OSMUX_RTP_PACKETS_TX_DROPPED_CTR);
	} else {
		rtpconn_osmux_rate_ctr_inc(conn, OSMUX_RTP_PACKETS_TX_CTR);
		rtpconn_osmux_rate_ctr_add(conn, OSMUX_AMR_OCTETS_TX_CTR, msgb_length(msg) - sizeof(struct rtp_hdr));
	}
	return 0;
}

/* Lookup the endpoint that corresponds to the specified address (port) */
static struct mgcp_conn_rtp*
osmux_conn_lookup(const struct mgcp_trunk *trunk, uint8_t local_cid, const struct osmo_sockaddr *rem_addr)
{
	struct mgcp_endpoint *endp;
	struct mgcp_conn *conn = NULL;
	struct mgcp_conn_rtp *conn_rtp;
	struct osmux_handle *h;
	int i;

	for (i = 0; i < trunk->number_endpoints; i++) {

		endp = trunk->endpoints[i];

		llist_for_each_entry(conn, &endp->conns, entry) {
			if (conn->type != MGCP_CONN_TYPE_RTP)
				continue;

			conn_rtp = mgcp_conn_get_conn_rtp(conn);
			if (!mgcp_conn_rtp_is_osmux(conn_rtp))
				continue;

			/* If Osmux peer is behind NAT:
			 * + state OSMUX_STATE_ACTIVATING: we cannot validate the remote address & port for
			 *   the conn since we actually set conn's remote IP address from the info we received
			 *   from this source address. NOTE: This means if Osmux peer is behind NAT we cannot
			 *   have more than 1 osmux trunk since it's not possible to differentiate based on
			 *   remote address.
			 * + state OSMUX_STATE_ENABLED: the conn is fully established (remote address is known),
			 *   it is now posssible to validate the remote address doesn't change.
			 * If Osmux peer is not behind NAT:
			 * We can always validate the remote IP address is matching the one we received in
			 * CRCX/MDCX, we can support several parallel Osmux trunks since we can differentiate same CID
			 * based on remote IP addr+port. However, if Osmux peer is not behind NAT it means it will go
			 * into OSMUX_STATE_ENABLED as soon as the remote address is known, meaning if the conn is not
			 * in that state we cannot (nor want) validate the IP address, we want to skip it until it is
			 * ready (to avoid 3rd party data injections).
			 * TLDR: When in OSMUX_STATE_ENABLED we can always validate remote address+port.
			 *       When in OSMUX_STATE_ACTIVATING, in case peer behind NAT we select it,
			 *					 in case peer NOT behind NAT we skip it.
			 */
			if (conn_rtp->osmux.state == OSMUX_STATE_ENABLED) {
				h = osmux_xfrm_input_get_deliver_cb_data(conn_rtp->osmux.in);
				if (osmo_sockaddr_cmp(&h->rem_addr, rem_addr) != 0)
					continue;
			} else if (!trunk->cfg->osmux.peer_behind_nat) {
				LOGPCONN(conn, DOSMUX, LOGL_DEBUG, "osmux_conn_lookup(rem_addr=%s local_cid=%d): Skipping because not (yet) ENABLED\n",
					 osmo_sockaddr_to_str(rem_addr), local_cid);
				continue; /* skip, read above */
			} /* else: continue CID validation below: */

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
	const struct mgcp_endpoint *endp = conn->conn->endp;
	struct osmux_handle *h = osmux_xfrm_input_get_deliver_cb_data(conn->osmux.in);
	struct osmo_rtp_msg_ctx *mc = OSMO_RTP_MSG_CTX(msg);
	*mc = (struct osmo_rtp_msg_ctx){
		.proto = MGCP_PROTO_RTP,
		.conn_src = conn,
		.from_addr = &h->rem_addr,
	};

	endp->type->dispatch_rtp_cb(msg);
	/* dispatch_rtp_cb() has taken ownership of the msgb */
}

/* To be called every time some AMR data is received on a connection
 * returns: 0 if conn can process data, negative if an error ocurred and data should not be further processed */
static int conn_osmux_event_data_received(struct mgcp_conn_rtp *conn, const struct osmo_sockaddr *rem_addr)
{
	const struct mgcp_config *cfg;
	switch(conn->osmux.state) {
	case OSMUX_STATE_ACTIVATING:
		/* If peer is not behind NAT, transition to OSMUX_STATE_ENABLED is done through
		 * conn_osmux_rx_mdcx() whenever a CRCX/MDCX with the remote address is received.
		 */
		cfg = conn->conn->endp->trunk->cfg;
		if (!cfg->osmux.peer_behind_nat) {
			/* osmux_conn_lookup() should never provide us with an
			 * ACTIVATING conn without NAT in first place. This should never happen. */
			LOGPCONN(conn->conn, DOSMUX, LOGL_ERROR,
				 "Unexpected rx osmux data for conn in ACTIVATING state without NAT\n");
			return -1;
		}
		/* We have to wait until we received the remote CID from CRCX/MDCX. */
		if (!conn->osmux.remote_cid_present)
			return -1;

		/* Update remote address with the src address of the package we received */
		conn->end.addr = *rem_addr;
		/* mgcp_rtp_end_remote_addr_available() is now true and we can enable the conn: */
		if (conn_osmux_enable(conn) < 0) {
			LOGPCONN(conn->conn, DOSMUX, LOGL_ERROR,
				 "Could not enable osmux conn: %s\n",
				 mgcp_conn_dump(conn->conn));
			return -1;
		}
		return 0;
	case OSMUX_STATE_ENABLED:
		return 0;
	default:
		return -1;
	}
}

/* To be called every time an CRCX/MDCX is received.
 * returns: 0 if conn can continue, negative if an error ocurred during setup */
int conn_osmux_event_rx_crcx_mdcx(struct mgcp_conn_rtp *conn)
{
	struct mgcp_config *cfg;

	switch (conn->osmux.state) {
	case OSMUX_STATE_ACTIVATING:
		/* If peer is behind NAT, we have to wait until 1st osmux frame is received
		* to discover peer's real remote address */
		cfg = conn->conn->endp->trunk->cfg;
		if (cfg->osmux.peer_behind_nat)
			return 0;
		/* Keep waiting to receive remote CID through CRCX/MDCX */
		if (!conn->osmux.remote_cid_present)
			return 0;
		/* keep waiting to receive remote address through CRCX/MDCX */
		if (!mgcp_rtp_end_remote_addr_available(&conn->end))
			return 0;
		/* Since the peer is not behind NAT, we can enable the conn right away since the proper
		 * remote address is now known: */
		if (conn_osmux_enable(conn) < 0)
			return -1;
		/* We have already transitioned to OSMUX_STATE_ENABLED here */
		return 0;
	case OSMUX_STATE_ENABLED:
		return 0;
	default:
		OSMO_ASSERT(NULL);
	}
	return 0;
}

/* Old versions of osmux used to send dummy packets [0x23 0x<CID>] to punch the
 * hole in the NAT. Let's handle them speficially. */
static int osmux_handle_legacy_dummy(const struct mgcp_trunk *trunk, const struct osmo_sockaddr *rem_addr,
				     struct msgb *msg)
{
	uint8_t osmux_cid = msg->data[1];
	struct mgcp_conn_rtp *conn;

	conn = osmux_conn_lookup(trunk, osmux_cid, rem_addr);
	if (!conn) {
		LOGP(DOSMUX, LOGL_DEBUG,
		     "Cannot find conn for Osmux CID %d\n", osmux_cid);
		goto out;
	}

	conn_osmux_event_data_received(conn, rem_addr);
	/* Only needed to punch hole in firewall, it can be dropped */
out:
	msgb_free(msg);
	return 0;
}

#define osmux_chunk_length(msg, rem) ((rem) - (msg)->len)
static void osmux_recvfrom_cb(struct osmo_io_fd *iofd, int res, struct msgb *msg, const struct osmo_sockaddr *rem_addr)
{
	struct osmux_hdr *osmuxh;
	struct mgcp_trunk *trunk = osmo_iofd_get_data(iofd);
	struct rate_ctr_group *all_rtp_stats = trunk->ratectr.all_osmux_conn_stats;
	uint32_t rem;
	char addr_str[64];

	rate_ctr_inc(rate_ctr_group_get_ctr(all_rtp_stats, OSMUX_PACKETS_RX_CTR));
	osmo_sockaddr_to_str_buf(addr_str, sizeof(addr_str), rem_addr);

	if (trunk->cfg->osmux.usage == OSMUX_USAGE_OFF) {
		LOGP(DOSMUX, LOGL_ERROR,
		     "Peer %s wants to use Osmux but MGCP Client did not request it\n",
		     addr_str);
		goto out;
	}

	/* Catch legacy dummy message and process them separately: */
	if (msg->len == 2 && msg->data[0] == MGCP_DUMMY_LOAD) {
		osmux_handle_legacy_dummy(trunk, rem_addr, msg);
		return;
	}

	rem = msg->len;
	while((osmuxh = osmux_xfrm_output_pull(msg)) != NULL) {
		struct mgcp_conn_rtp *conn_src;
		conn_src = osmux_conn_lookup(trunk, osmuxh->circuit_id,
					     rem_addr);
		if (!conn_src) {
			LOGP(DOSMUX, LOGL_DEBUG,
			     "Cannot find a src conn for %s CID=%d\n",
			     addr_str, osmuxh->circuit_id);
			goto next;
		}

		if (conn_osmux_event_data_received(conn_src, rem_addr) < 0)
			goto next;

		mgcp_conn_watchdog_kick(conn_src->conn);

		rtpconn_osmux_rate_ctr_inc(conn_src, OSMUX_CHUNKS_RX_CTR);
		rtpconn_osmux_rate_ctr_add(conn_src, OSMUX_OCTETS_RX_CTR,
						osmux_chunk_length(msg, rem));
		osmux_xfrm_output_sched(conn_src->osmux.out, osmuxh);
next:
		rem = msg->len;
	}
out:
	msgb_free(msg);
}

static void osmux_sendto_cb(struct osmo_io_fd *iofd, int res, struct msgb *msg, const struct osmo_sockaddr *rem_addr)
{
	/* nothing; osmo_io takes care of msgb_free */
	if (res < 0) {
		struct mgcp_trunk *trunk = (struct mgcp_trunk *) osmo_iofd_get_data(iofd);
		struct rate_ctr_group *all_osmux_stats = trunk->ratectr.all_osmux_conn_stats;
		char errbuf[129];
		strerror_r(-res, errbuf, sizeof(errbuf));
		LOGP(DOSMUX, LOGL_NOTICE, "osmux sendto(%s) failed: %s\n", osmo_sockaddr_to_str(rem_addr), errbuf);
		rate_ctr_inc(rate_ctr_group_get_ctr(all_osmux_stats, OSMUX_DROPPED_PACKETS_CTR));
	}
}

static const struct osmo_io_ops osmux_ioops = {
	.recvfrom_cb = osmux_recvfrom_cb,
	.sendto_cb = osmux_sendto_cb,
};

int osmux_init(struct mgcp_trunk *trunk)
{
	int ret, fd;
	struct mgcp_config *cfg = trunk->cfg;

	/* So far we only support running on one trunk: */
	OSMO_ASSERT(trunk == mgcp_trunk_by_num(cfg, MGCP_TRUNK_VIRTUAL, MGCP_VIRT_TRUNK_ID));

	osmux_fd_v4 = osmo_iofd_setup(trunk, -1, "osmux_fd_v4", OSMO_IO_FD_MODE_RECVFROM_SENDTO, &osmux_ioops, trunk);
	if (!osmux_fd_v4)
		goto out;
	osmo_iofd_set_alloc_info(osmux_fd_v4, 4096, 0);

	if (cfg->osmux.local_addr_v4) {
		ret = mgcp_create_bind(cfg->osmux.local_addr_v4, cfg->osmux.local_port,
					cfg->endp_dscp, cfg->endp_priority);
		if (ret < 0) {
			LOGP(DOSMUX, LOGL_ERROR, "Cannot bind OSMUX IPv4 socket to %s:%u\n",
			     cfg->osmux.local_addr_v4, cfg->osmux.local_port);
			goto out_free_v4;
		}
		fd = ret;

		ret = osmo_iofd_register(osmux_fd_v4, fd);
		if (ret < 0) {
			LOGP(DOSMUX, LOGL_ERROR, "Cannot register OSMUX IPv4 socket %s\n", osmo_sock_get_name2(fd));
			close(fd);
			goto out_free_v4;
		}
		LOGP(DOSMUX, LOGL_INFO, "OSMUX IPv4 socket listening on %s\n", osmo_sock_get_name2(fd));
	}

	osmux_fd_v6 = osmo_iofd_setup(trunk, -1, "osmux_fd_v6", OSMO_IO_FD_MODE_RECVFROM_SENDTO, &osmux_ioops, trunk);
	if (!osmux_fd_v6)
		goto out_free_v4;
	osmo_iofd_set_alloc_info(osmux_fd_v6, 4096, 0);

	if (cfg->osmux.local_addr_v6) {
		ret = mgcp_create_bind(cfg->osmux.local_addr_v6, cfg->osmux.local_port,
					cfg->endp_dscp, cfg->endp_priority);
		if (ret < 0) {
			LOGP(DOSMUX, LOGL_ERROR, "Cannot bind OSMUX IPv6 socket to [%s]:%u\n",
			     cfg->osmux.local_addr_v6, cfg->osmux.local_port);
			goto out_free_v6;
		}
		fd = ret;

		ret = osmo_iofd_register(osmux_fd_v6, fd);
		if (ret < 0) {
			LOGP(DOSMUX, LOGL_ERROR, "Cannot register OSMUX IPv6 socket %s\n", osmo_sock_get_name2(fd));
			close(fd);
			goto out_free_v6;
		}
		LOGP(DOSMUX, LOGL_INFO, "OSMUX IPv6 socket listening on %s\n", osmo_sock_get_name2(fd));
	}
	cfg->osmux.initialized = true;
	return 0;

out_free_v6:
	/* osmo_iofd_free performs unregister + close */
	osmo_iofd_free(osmux_fd_v6);
	osmux_fd_v6 = NULL;
out_free_v4:
	/* osmo_iofd_free performs unregister + close */
	osmo_iofd_free(osmux_fd_v4);
	osmux_fd_v4 = NULL;
out:
	return -1;
}

/*! relase OSXMUX cid, that had been allocated to this connection.
 *  \param[in] conn connection with OSMUX cid to release */
static void conn_osmux_release_local_cid(struct mgcp_conn_rtp *conn)
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
static int conn_osmux_allocate_local_cid(struct mgcp_conn_rtp *conn)
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
	return osmux_cid;
}

/*! Initialize Osmux bits of a conn.
 *  \param[in] conn Osmux connection to initialize
 *  \returns 0 on success, negative on ERROR */
int osmux_init_conn(struct mgcp_conn_rtp *conn)
{
	if (conn_osmux_allocate_local_cid(conn) == -1)
		return -1;
	conn->osmux.ctrg = rate_ctr_group_alloc(conn->conn, &rate_ctr_group_osmux_desc, conn->ctrg->idx);

	conn->type = MGCP_RTP_OSMUX;
	/* Annotate Osmux circuit ID and set it to negotiating state until this
	 * is fully set up from the dummy load. */
	conn->osmux.state = OSMUX_STATE_ACTIVATING;
	return 0;
}

/*! enable OSXMUX circuit for a specified connection.
 *  \param[in] conn connection to enable
 *  \returns 0 on success, -1 on ERROR */
int conn_osmux_enable(struct mgcp_conn_rtp *conn)
{
	OSMO_ASSERT(conn->osmux.state == OSMUX_STATE_ACTIVATING);
	OSMO_ASSERT(conn->osmux.remote_cid_present == true);
	/*! If osmux is enabled, initialize the output handler. This handler is
	 *  used to reconstruct the RTP flow from osmux. The RTP SSRC is
	 *  allocated based on the circuit ID (conn_net->osmux.cid), which is unique
	 *  in the local scope to the BSC/BSC-NAT. We use it to divide the RTP
	 *  SSRC space (2^32) by the OSMUX_CID_MAX + 1 possible circuit IDs, then randomly
	 *  select one value from that window. Thus, we have no chance to have
	 *  overlapping RTP SSRC traveling to the BTSes behind the BSC,
	 *  similarly, for flows traveling to the MSC.
	 */
	const struct mgcp_trunk *trunk = conn->conn->endp->trunk;
	static const uint32_t rtp_ssrc_winlen = UINT32_MAX / (OSMUX_CID_MAX + 1);
	bool osmux_dummy = trunk->cfg->osmux.dummy_padding;

	/* Wait until we have the remote connection information, be it from MDCX (peer not behind NAT)
	 * or later learned from first received remote osmux packet (peer behind NAT) */
	if (!mgcp_rtp_end_remote_addr_available(&conn->end)) {
		LOGPCONN(conn->conn, DOSMUX, LOGL_INFO,
			 "Osmux remote address/port still unknown\n");
		return -1;
	}

	conn->osmux.in = osmux_handle_find_or_create(trunk, &conn->end.addr);
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
	osmux_xfrm_output_set_rtp_pl_type(conn->osmux.out, conn->end.cset.codec->payload_type);
	osmux_xfrm_output_set_tx_cb(conn->osmux.out,
				    scheduled_from_osmux_tx_rtp_cb, conn);

	conn->osmux.state = OSMUX_STATE_ENABLED;
	LOGPCONN(conn->conn, DOSMUX, LOGL_INFO,
		 "Osmux CID %u towards %s is now enabled\n",
		 conn->osmux.remote_cid,
		 osmo_sockaddr_to_str(&conn->end.addr));
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

/*! send RTP dummy packet to OSMUX connection port.
 *  \param[in] conn associated RTP connection
 *  \returns 0 in case of success, -1 on error */
int osmux_send_dummy(struct mgcp_conn_rtp *conn)
{
	char ipbuf[INET6_ADDRSTRLEN];
	struct osmux_hdr *osmuxh;
	int buf_len;

	/*! The dummy packet will not be sent via the actual OSMUX connection,
	 *  instead it is sent out of band to port where the remote OSMUX
	 *  multplexer is listening. The goal is to ensure that the connection
	 *  is kept open */

	/*! We don't need to send the dummy load for osmux so often as another
	 *  endpoint may have already punched the hole in the firewall. This
	 *  approach is simple though. */

	buf_len = sizeof(struct osmux_hdr) + osmo_amr_bytes(AMR_FT_0);
	osmuxh = (struct osmux_hdr *) alloca(buf_len);
	memset(osmuxh, 0, buf_len);
	osmuxh->ft = OSMUX_FT_DUMMY;
	osmuxh->amr_ft = AMR_FT_0;
	osmuxh->circuit_id = conn->osmux.remote_cid;

	LOGPCONN(conn->conn, DOSMUX, LOGL_DEBUG,
		 "sending OSMUX dummy load to %s:%u CID %u\n",
		 osmo_sockaddr_ntop(&conn->end.addr.u.sa, ipbuf),
		 osmo_sockaddr_port(&conn->end.addr.u.sa), conn->osmux.remote_cid);

	return mgcp_udp_send(osmux_fd_v4, &conn->end.addr, (char *)osmuxh, buf_len);
}

/* Keeps track of locally allocated Osmux circuit ID. +7 to round up to 8 bit boundary. */
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

/*! Find and reserve a free OSMUX cid. Keep state of last allocated CID to
 *  rotate allocated CIDs over time. This helps in letting CIDs unused for some
 *  time after last use.
 *  \returns OSMUX cid */
int osmux_cid_pool_get_next(void)
{
	static uint8_t next_free_osmux_cid_lookup = 0;
	uint8_t start_i, start_j;
	uint8_t i, j, cid;

	/* i = octet index, j = bit index inside ith octet */
	start_i = next_free_osmux_cid_lookup >> 3;
	start_j = next_free_osmux_cid_lookup & 0x07;

	for (i = start_i; i < sizeof(osmux_cid_bitmap); i++) {
		for (j = start_j; j < 8; j++) {
			if (osmux_cid_bitmap[i] & (1 << j))
				continue;
			goto found;
		}
	}

	for (i = 0; i <= start_i; i++) {
		for (j = 0; j < start_j; j++) {
			if (osmux_cid_bitmap[i] & (1 << j))
				continue;
			goto found;
		}
	}

	LOGP(DOSMUX, LOGL_ERROR, "All Osmux circuits are in use!\n");
	return -1;

found:
	osmux_cid_bitmap[i] |= (1 << j);
	cid = (i << 3) | j;
	next_free_osmux_cid_lookup = (cid + 1) & 0xff;
	LOGP(DOSMUX, LOGL_DEBUG,
		"Allocating Osmux CID %u from pool\n", cid);
	return cid;
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

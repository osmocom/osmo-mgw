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
#include <osmocom/core/talloc.h>

#include <osmocom/netif/osmux.h>
#include <osmocom/netif/rtp.h>

#include <osmocom/mgcp/mgcp.h>
#include <osmocom/mgcp/mgcp_internal.h>
#include <osmocom/mgcp/osmux.h>
#include <osmocom/mgcp/mgcp_conn.h>
#include <osmocom/mgcp/mgcp_endp.h>

static struct osmo_fd osmux_fd;

static LLIST_HEAD(osmux_handle_list);

struct osmux_handle {
	struct llist_head head;
	struct osmux_in_handle *in;
	struct in_addr rem_addr;
	int rem_port;
	int refcnt;
};

static void *osmux;

/* Deliver OSMUX batch to the remote end */
static void osmux_deliver_cb(struct msgb *batch_msg, void *data)
{
	struct osmux_handle *handle = data;
	struct sockaddr_in out = {
		.sin_family = AF_INET,
		.sin_port = handle->rem_port,
	};

	memcpy(&out.sin_addr, &handle->rem_addr, sizeof(handle->rem_addr));
	sendto(osmux_fd.fd, batch_msg->data, batch_msg->len, 0,
		(struct sockaddr *)&out, sizeof(out));
	msgb_free(batch_msg);
}

/* Lookup existing OSMUX handle for specified destination address. */
static struct osmux_handle *
osmux_handle_find_get(struct in_addr *addr, int rem_port)
{
	struct osmux_handle *h;

	llist_for_each_entry(h, &osmux_handle_list, head) {
		if (memcmp(&h->rem_addr, addr, sizeof(struct in_addr)) == 0 &&
		    h->rem_port == rem_port) {
			LOGP(DLMGCP, LOGL_DEBUG, "using existing OSMUX handle "
						"for addr=%s:%d\n",
				inet_ntoa(*addr), ntohs(rem_port));
			h->refcnt++;
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
			if (--h->refcnt == 0) {
				LOGP(DLMGCP, LOGL_INFO,
				     "Releasing unused osmux handle for %s:%d\n",
				     inet_ntoa(h->rem_addr),
				     ntohs(h->rem_port));
				LOGP(DLMGCP, LOGL_INFO, "Stats: "
				     "input RTP msgs: %u bytes: %"PRIu64" "
				     "output osmux msgs: %u bytes: %"PRIu64"\n",
				     in->stats.input_rtp_msgs,
				     in->stats.input_rtp_bytes,
				     in->stats.output_osmux_msgs,
				     in->stats.output_osmux_bytes);
				llist_del(&h->head);
				osmux_xfrm_input_fini(h->in);
				talloc_free(h);
			}
			return;
		}
	}
	LOGP(DLMGCP, LOGL_ERROR, "cannot find Osmux input handle %p\n", in);
}

/* Allocate free OSMUX handle */
static struct osmux_handle *
osmux_handle_alloc(struct mgcp_config *cfg, struct in_addr *addr, int rem_port)
{
	struct osmux_handle *h;

	h = talloc_zero(osmux, struct osmux_handle);
	if (!h)
		return NULL;
	h->rem_addr = *addr;
	h->rem_port = rem_port;
	h->refcnt++;

	h->in = talloc_zero(h, struct osmux_in_handle);
	if (!h->in) {
		talloc_free(h);
		return NULL;
	}

	/* sequence number to start OSMUX message from */
	h->in->osmux_seq = 0;

	h->in->batch_factor = cfg->osmux_batch;

	/* If batch size is zero, the library defaults to 1470 bytes. */
	h->in->batch_size = cfg->osmux_batch_size;
	h->in->deliver = osmux_deliver_cb;
	osmux_xfrm_input_init(h->in);
	h->in->data = h;

	llist_add(&h->head, &osmux_handle_list);

	LOGP(DLMGCP, LOGL_DEBUG, "created new OSMUX handle for addr=%s:%d\n",
		inet_ntoa(*addr), ntohs(rem_port));

	return h;
}

/* Lookup existing handle for a specified address, if the handle can not be
 * found, the function will automatically allocate one */
static struct osmux_in_handle *
osmux_handle_lookup(struct mgcp_config *cfg, struct in_addr *addr, int rem_port)
{
	struct osmux_handle *h;

	h = osmux_handle_find_get(addr, rem_port);
	if (h != NULL)
		return h->in;

	h = osmux_handle_alloc(cfg, addr, rem_port);
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

	msg = msgb_alloc(4096, "RTP");
	if (!msg)
		return -1;

	memcpy(msg->data, buf, buf_len);
	msgb_put(msg, buf_len);

	while ((ret = osmux_xfrm_input(conn->osmux.in, msg, conn->osmux.cid)) > 0) {
		/* batch full, build and deliver it */
		osmux_xfrm_input_deliver(conn->osmux.in);
	}
	return 0;
}

/* Lookup the endpoint that corresponds to the specified address (port) */
static struct mgcp_endpoint *
endpoint_lookup(struct mgcp_config *cfg, int cid,
		struct in_addr *from_addr, int type)
{
	struct mgcp_endpoint *endp = NULL;
	int i;
	struct mgcp_conn_rtp *conn_net = NULL;
	struct mgcp_conn_rtp *conn_bts = NULL;

	for (i=0; i<cfg->trunk.number_endpoints; i++) {
		struct in_addr *this;

		endp = &cfg->trunk.endpoints[i];

#if 0
		if (!tmp->allocated)
			continue;
#endif

		switch(type) {
		case MGCP_DEST_NET:
			/* FIXME: Get rid of CONN_ID_XXX! */
			conn_net = mgcp_conn_get_rtp(endp, CONN_ID_NET);
			if (conn_net)
				this = &conn_net->end.addr;
			else
				this = NULL;
			break;
		case MGCP_DEST_BTS:
			/* FIXME: Get rid of CONN_ID_XXX! */
			conn_bts = mgcp_conn_get_rtp(endp, CONN_ID_BTS);
			if (conn_bts)
				this = &conn_bts->end.addr;
			else
				this = NULL;
			break;
		default:
			/* Should not ever happen */
			LOGP(DLMGCP, LOGL_ERROR, "Bad type %d. Fix your code.\n", type);
			return NULL;
		}

		/* FIXME: Get rid of CONN_ID_XXX! */
		conn_net = mgcp_conn_get_rtp(endp, CONN_ID_NET);
		if (conn_net && this && conn_net->osmux.cid == cid
		    && this->s_addr == from_addr->s_addr)
			return endp;
	}

	LOGP(DLMGCP, LOGL_ERROR, "Cannot find endpoint with cid=%d\n", cid);

	return NULL;
}

static void scheduled_tx_net_cb(struct msgb *msg, void *data)
{
	struct mgcp_endpoint *endp = data;
	struct mgcp_conn_rtp *conn_net = NULL;
	struct mgcp_conn_rtp *conn_bts = NULL;

	/* FIXME: Get rid of CONN_ID_XXX! */
	conn_bts = mgcp_conn_get_rtp(endp, CONN_ID_BTS);
	conn_net = mgcp_conn_get_rtp(endp, CONN_ID_NET);
	if (!conn_bts || !conn_net)
		return;

	struct sockaddr_in addr = {
		.sin_addr = conn_net->end.addr,
		.sin_port = conn_net->end.rtp_port,
	};

	rate_ctr_inc(&conn_bts->rate_ctr_group->ctr[RTP_PACKETS_TX_CTR]);
	rate_ctr_add(&conn_bts->rate_ctr_group->ctr[RTP_OCTETS_TX_CTR], msg->len);

	/* Send RTP data to NET */
	/* FIXME: Get rid of conn_bts and conn_net! */
	mgcp_send(endp, 1, &addr, (char *)msg->data, msg->len,
		  conn_bts, conn_net);
	msgb_free(msg);
}

static void scheduled_tx_bts_cb(struct msgb *msg, void *data)
{
	struct mgcp_endpoint *endp = data;
	struct mgcp_conn_rtp *conn_net = NULL;
	struct mgcp_conn_rtp *conn_bts = NULL;

	/* FIXME: Get rid of CONN_ID_XXX! */
	conn_bts = mgcp_conn_get_rtp(endp, CONN_ID_BTS);
	conn_net = mgcp_conn_get_rtp(endp, CONN_ID_NET);
	if (!conn_bts || !conn_net)
		return;

	struct sockaddr_in addr = {
		.sin_addr = conn_bts->end.addr,
		.sin_port = conn_bts->end.rtp_port,
	};

	rate_ctr_inc(&conn_net->rate_ctr_group->ctr[RTP_PACKETS_TX_CTR]);
	rate_ctr_add(&conn_net->rate_ctr_group->ctr[RTP_OCTETS_TX_CTR], msg->len);

	/* Send RTP data to BTS */
	/* FIXME: Get rid of conn_bts and conn_net! */
	mgcp_send(endp, 1, &addr, (char *)msg->data, msg->len,
		  conn_net, conn_bts);
	msgb_free(msg);
}

static struct msgb *osmux_recv(struct osmo_fd *ofd, struct sockaddr_in *addr)
{
	struct msgb *msg;
	socklen_t slen = sizeof(*addr);
	int ret;

	msg = msgb_alloc(4096, "OSMUX");
	if (!msg) {
		LOGP(DLMGCP, LOGL_ERROR, "cannot allocate message\n");
		return NULL;
	}
	ret = recvfrom(ofd->fd, msg->data, msg->data_len, 0,
			(struct sockaddr *)addr, &slen);
	if (ret <= 0) {
		msgb_free(msg);
		LOGP(DLMGCP, LOGL_ERROR, "cannot receive message\n");
		return NULL;
	}
	msgb_put(msg, ret);

	return msg;
}

#define osmux_chunk_length(msg, rem) (rem - msg->len);

int osmux_read_from_bsc_nat_cb(struct osmo_fd *ofd, unsigned int what)
{
	struct msgb *msg;
	struct osmux_hdr *osmuxh;
	struct sockaddr_in addr;
	struct mgcp_config *cfg = ofd->data;
	uint32_t rem;
	struct mgcp_conn_rtp *conn_bts = NULL;

	msg = osmux_recv(ofd, &addr);
	if (!msg)
		return -1;

	if (!cfg->osmux) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "bsc-nat wants to use Osmux but bsc did not request it\n");
		goto out;
	}

	/* not any further processing dummy messages */
	if (msg->data[0] == MGCP_DUMMY_LOAD)
		goto out;

	rem = msg->len;
	while((osmuxh = osmux_xfrm_output_pull(msg)) != NULL) {
		struct mgcp_endpoint *endp;

		/* Yes, we use MGCP_DEST_NET to locate the origin */
		endp = endpoint_lookup(cfg, osmuxh->circuit_id,
				       &addr.sin_addr, MGCP_DEST_NET);

		/* FIXME: Get rid of CONN_ID_XXX! */
		conn_bts = mgcp_conn_get_rtp(endp, CONN_ID_BTS);
		if (!conn_bts)
			goto out;

		if (!endp) {
			LOGP(DLMGCP, LOGL_ERROR,
			     "Cannot find an endpoint for circuit_id=%d\n",
			     osmuxh->circuit_id);
			goto out;
		}
		conn_bts->osmux.stats.octets += osmux_chunk_length(msg, rem);
		conn_bts->osmux.stats.chunks++;
		rem = msg->len;

		osmux_xfrm_output_sched(&conn_bts->osmux.out, osmuxh);
	}
out:
	msgb_free(msg);
	return 0;
}

/* This is called from the bsc-nat */
static int osmux_handle_dummy(struct mgcp_config *cfg, struct sockaddr_in *addr,
			      struct msgb *msg)
{
	struct mgcp_endpoint *endp;
	uint8_t osmux_cid;
	struct mgcp_conn_rtp *conn_net = NULL;

	if (msg->len < 1 + sizeof(osmux_cid)) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "Discarding truncated Osmux dummy load\n");
		goto out;
	}

	LOGP(DLMGCP, LOGL_DEBUG, "Received Osmux dummy load from %s\n",
	     inet_ntoa(addr->sin_addr));

	/* extract the osmux CID from the dummy message */
	memcpy(&osmux_cid, &msg->data[1], sizeof(osmux_cid));

	endp = endpoint_lookup(cfg, osmux_cid, &addr->sin_addr, MGCP_DEST_BTS);
	if (!endp) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "Cannot find endpoint for Osmux CID %d\n", osmux_cid);
		goto out;
	}

	conn_net = mgcp_conn_get_rtp(endp, CONN_ID_NET);
	if (!conn_net)
		goto out;

	if (conn_net->osmux.state == OSMUX_STATE_ENABLED)
		goto out;

	if (osmux_enable_conn(endp, conn_net, &addr->sin_addr, addr->sin_port) < 0 ) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "Could not enable osmux in endpoint 0x%x\n",
		     ENDPOINT_NUMBER(endp));
		goto out;
	}

	LOGP(DLMGCP, LOGL_INFO, "Enabling osmux in endpoint 0x%x for %s:%u\n",
	     ENDPOINT_NUMBER(endp), inet_ntoa(addr->sin_addr),
	     ntohs(addr->sin_port));
out:
	msgb_free(msg);
	return 0;
}

int osmux_read_from_bsc_cb(struct osmo_fd *ofd, unsigned int what)
{
	struct msgb *msg;
	struct osmux_hdr *osmuxh;
	struct sockaddr_in addr;
	struct mgcp_config *cfg = ofd->data;
	uint32_t rem;
	struct mgcp_conn_rtp *conn_net = NULL;

	msg = osmux_recv(ofd, &addr);
	if (!msg)
		return -1;

	if (!cfg->osmux) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "bsc wants to use Osmux but bsc-nat did not request it\n");
		goto out;
	}

	/* not any further processing dummy messages */
	if (msg->data[0] == MGCP_DUMMY_LOAD)
		return osmux_handle_dummy(cfg, &addr, msg);

	rem = msg->len;
	while((osmuxh = osmux_xfrm_output_pull(msg)) != NULL) {
		struct mgcp_endpoint *endp;

		/* Yes, we use MGCP_DEST_BTS to locate the origin */
		endp = endpoint_lookup(cfg, osmuxh->circuit_id,
				       &addr.sin_addr, MGCP_DEST_BTS);

		/* FIXME: Get rid of CONN_ID_XXX! */
		conn_net = mgcp_conn_get_rtp(endp, CONN_ID_NET);
		if (!conn_net)
			goto out;

		if (!endp) {
			LOGP(DLMGCP, LOGL_ERROR,
			     "Cannot find an endpoint for circuit_id=%d\n",
			     osmuxh->circuit_id);
			goto out;
		}
		conn_net->osmux.stats.octets += osmux_chunk_length(msg, rem);
		conn_net->osmux.stats.chunks++;
		rem = msg->len;

		osmux_xfrm_output_sched(&conn_net->osmux.out, osmuxh);
	}
out:
	msgb_free(msg);
	return 0;
}

int osmux_init(int role, struct mgcp_config *cfg)
{
	int ret;

	switch(role) {
	case OSMUX_ROLE_BSC:
		osmux_fd.cb = osmux_read_from_bsc_nat_cb;
		break;
	case OSMUX_ROLE_BSC_NAT:
		osmux_fd.cb = osmux_read_from_bsc_cb;
		break;
	default:
		LOGP(DLMGCP, LOGL_ERROR, "wrong role for OSMUX\n");
		return -1;
	}
	osmux_fd.data = cfg;

	ret = mgcp_create_bind(cfg->osmux_addr, &osmux_fd, cfg->osmux_port);
	if (ret < 0) {
		LOGP(DLMGCP, LOGL_ERROR, "cannot bind OSMUX socket\n");
		return ret;
	}
	mgcp_set_ip_tos(osmux_fd.fd, cfg->endp_dscp);
	osmux_fd.when |= BSC_FD_READ;

	ret = osmo_fd_register(&osmux_fd);
	if (ret < 0) {
		LOGP(DLMGCP, LOGL_ERROR, "cannot register OSMUX socket\n");
		return ret;
	}
	cfg->osmux_init = 1;

	return 0;
}

/*! enable OSXMUX circuit for a specified connection.
 *  \param[in] endp mgcp endpoint (configuration)
 *  \param[in] conn connection to disable
 *  \param[in] addr IP address of remote OSMUX endpoint
 *  \param[in] port portnumber of the remote OSMUX endpoint
 *  \returns 0 on success, -1 on ERROR */
int osmux_enable_conn(struct mgcp_endpoint *endp, struct mgcp_conn_rtp *conn,
		      struct in_addr *addr, uint16_t port)
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
	static const uint32_t rtp_ssrc_winlen = UINT32_MAX / (OSMUX_CID_MAX + 1);
	uint16_t osmux_dummy = endp->cfg->osmux_dummy;

	/* Check if osmux is enabled for the specified connection */
	if (conn->osmux.state == OSMUX_STATE_DISABLED) {
		LOGP(DLMGCP, LOGL_ERROR, "OSMUX not enabled for conn:%s\n",
		     mgcp_conn_dump(conn->conn));
		return -1;
	}

	conn->osmux.in = osmux_handle_lookup(endp->cfg, addr, port);
	if (!conn->osmux.in) {
		LOGP(DLMGCP, LOGL_ERROR, "Cannot allocate input osmux handle for conn:%s\n",
		     mgcp_conn_dump(conn->conn));
		return -1;
	}
	if (!osmux_xfrm_input_open_circuit(conn->osmux.in, conn->osmux.cid, osmux_dummy)) {
		LOGP(DLMGCP, LOGL_ERROR, "Cannot open osmux circuit %u for conn:%s\n",
		     conn->osmux.cid, mgcp_conn_dump(conn->conn));
		return -1;
	}

	osmux_xfrm_output_init(&conn->osmux.out,
			       (conn->osmux.cid * rtp_ssrc_winlen) +
			       (random() % rtp_ssrc_winlen));

	switch (endp->cfg->role) {
		case MGCP_BSC_NAT:
			conn->type = MGCP_OSMUX_BSC_NAT;
			osmux_xfrm_output_set_tx_cb(&conn->osmux.out,
							scheduled_tx_net_cb, endp);
			break;
		case MGCP_BSC:
			conn->type = MGCP_OSMUX_BSC;
			osmux_xfrm_output_set_tx_cb(&conn->osmux.out,
							scheduled_tx_bts_cb, endp);
			break;
	}

	conn->osmux.state = OSMUX_STATE_ENABLED;

	return 0;
}

/*! disable OSXMUX circuit for a specified connection.
 *  \param[in] conn connection to disable */
void osmux_disable_conn(struct mgcp_conn_rtp *conn)
{
	if (!conn)
		return;

	if (conn->osmux.state != OSMUX_STATE_ENABLED)
		return;

	LOGP(DLMGCP, LOGL_INFO, "Releasing connection %s using Osmux CID %u\n",
	     conn->conn->id, conn->osmux.cid);

	/* We are closing, we don't need pending RTP packets to be transmitted */
	osmux_xfrm_output_set_tx_cb(&conn->osmux.out, NULL, NULL);
	osmux_xfrm_output_flush(&conn->osmux.out);

	osmux_xfrm_input_close_circuit(conn->osmux.in, conn->osmux.cid);
	conn->osmux.state = OSMUX_STATE_DISABLED;
	conn->osmux.cid = -1;
	osmux_handle_put(conn->osmux.in);
}

/*! relase OSXMUX cid, that had been allocated to this connection.
 *  \param[in] conn connection with OSMUX cid to release */
void osmux_release_cid(struct mgcp_conn_rtp *conn)
{
	if (!conn)
		return;

	if (conn->osmux.state != OSMUX_STATE_ENABLED)
		return;

	if (conn->osmux.allocated_cid >= 0)
		osmux_put_cid(conn->osmux.allocated_cid);
	conn->osmux.allocated_cid = -1;
}

/*! allocate OSXMUX cid to connection.
 *  \param[in] conn connection for which we allocate the OSMUX cid*/
void osmux_allocate_cid(struct mgcp_conn_rtp *conn)
{
	osmux_release_cid(conn);
	conn->osmux.allocated_cid = osmux_get_cid();
}

/*! send RTP dummy packet to OSMUX connection port.
 *  \param[in] endp mcgp endpoint that holds the RTP connection
 *  \param[in] conn associated RTP connection
 *  \returns bytes sent, -1 on error */
int osmux_send_dummy(struct mgcp_endpoint *endp, struct mgcp_conn_rtp *conn)
{
	char buf[1 + sizeof(uint8_t)];
	struct in_addr addr_unset = {};

	/*! The dummy packet will not be sent via the actual OSMUX connection,
	 *  instead it is sent out of band to port where the remote OSMUX
	 *  multplexer is listening. The goal is to ensure that the connection
	 *  is kept open */

	/*! We don't need to send the dummy load for osmux so often as another
	 *  endpoint may have already punched the hole in the firewall. This
	 *  approach is simple though. */

	buf[0] = MGCP_DUMMY_LOAD;
	memcpy(&buf[1], &conn->osmux.cid, sizeof(conn->osmux.cid));

	/* Wait until we have the connection information from MDCX */
	if (memcmp(&conn->end.addr, &addr_unset, sizeof(addr_unset)) == 0)
		return 0;

	if (conn->osmux.state == OSMUX_STATE_ACTIVATING) {
		if (osmux_enable_conn(endp, conn, &conn->end.addr,
				      htons(endp->cfg->osmux_port)) < 0) {
			LOGP(DLMGCP, LOGL_ERROR,
			     "Could not activate osmux for conn:%s\n",
			     mgcp_conn_dump(conn->conn));
			return 0;
		}
		LOGP(DLMGCP, LOGL_ERROR,
		     "Osmux CID %u for %s:%u is now enabled\n",
		     conn->osmux.cid, inet_ntoa(conn->end.addr),
		     endp->cfg->osmux_port);
	}
	if(conn->osmux.state != OSMUX_STATE_ENABLED) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "OSMUX dummy to %s CID %u: Osmux not enabled on endpoint 0x%x state %d\n",
		     inet_ntoa(conn->end.addr), conn->osmux.cid,
		     ENDPOINT_NUMBER(endp), conn->osmux.state);
		     return 0;
	}
	LOGP(DLMGCP, LOGL_DEBUG,
	     "sending OSMUX dummy load to %s CID %u\n",
	     inet_ntoa(conn->end.addr), conn->osmux.cid);

	return mgcp_udp_send(osmux_fd.fd, &conn->end.addr,
			     htons(endp->cfg->osmux_port), buf, sizeof(buf));
}

/* bsc-nat allocates/releases the Osmux circuit ID. +7 to round up to 8 bit boundary. */
static uint8_t osmux_cid_bitmap[(OSMUX_CID_MAX + 1 + 7) / 8];

/*! count the number of taken OSMUX cids.
 *  \returns number of OSMUX cids in use */
int osmux_used_cid(void)
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
int osmux_get_cid(void)
{
	int i, j;

	for (i = 0; i < sizeof(osmux_cid_bitmap); i++) {
		for (j = 0; j < 8; j++) {
			if (osmux_cid_bitmap[i] & (1 << j))
				continue;

			osmux_cid_bitmap[i] |= (1 << j);
			LOGP(DLMGCP, LOGL_DEBUG,
			     "Allocating Osmux CID %u from pool\n", (i * 8) + j);
			return (i * 8) + j;
		}
	}

	LOGP(DLMGCP, LOGL_ERROR, "All Osmux circuits are in use!\n");
	return -1;
}

/*! put back a no longer used OSMUX cid.
 *  \param[in] osmux_cid OSMUX cid */
void osmux_put_cid(uint8_t osmux_cid)
{
	LOGP(DLMGCP, LOGL_DEBUG, "Osmux CID %u is back to the pool\n", osmux_cid);
	osmux_cid_bitmap[osmux_cid / 8] &= ~(1 << (osmux_cid % 8));
}

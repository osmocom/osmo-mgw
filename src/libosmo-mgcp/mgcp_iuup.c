/*
 * (C) 2021 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * All rights not specifically granted under this license are reserved.
 *
 * Author: Pau Espin Pedrol
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Affero General Public License as published by the
 * Free Software Foundation; either version 3 of the License, or (at your
 * option) any later version.
 */

#include <stdint.h>

#include <osmocom/core/byteswap.h>

#include <osmocom/gsm/iuup.h>

#include <osmocom/netif/rtp.h>
#include <osmocom/netif/amr.h>

#include <osmocom/mgcp/mgcp_conn.h>
#include <osmocom/mgcp/mgcp_iuup.h>
#include <osmocom/mgcp/mgcp_endp.h>
#include <osmocom/mgcp/mgcp_codec.h>
#include <osmocom/mgcp/mgcp_network.h>
#include <osmocom/mgcp/debug.h>

#define MGW_IUUP_MSGB_SIZE 4096

static const struct osmo_iuup_rnl_config def_configure_req = {
	.transparent = false,
	.active = true,
	.supported_versions_mask = 0x0003,
	.num_rfci = 0,
	.num_subflows = 0,
	.IPTIs_present = false,
	.t_init = { .t_ms = IUUP_TIMER_INIT_T_DEFAULT, .n_max = IUUP_TIMER_INIT_N_DEFAULT },
	.t_ta = { .t_ms = IUUP_TIMER_TA_T_DEFAULT, .n_max = IUUP_TIMER_TA_N_DEFAULT },
	.t_rc = { .t_ms = IUUP_TIMER_RC_T_DEFAULT, .n_max = IUUP_TIMER_RC_N_DEFAULT },
};

/* Find a destination connection. */
static struct mgcp_conn *_find_dst_conn(struct mgcp_conn *conn)
{
	/* NOTE: This code path runs every time an RTP packet is received. The
	 * function mgcp_find_dst_conn() we use to determine the detination
	 * connection will iterate the connection list inside the endpoint.
	 * Since list iterations are quite costly, we will figure out the
	 * destination only once and use the optional private data pointer of
	 * the connection to cache the destination connection pointer. */

	struct mgcp_conn *conn_dst;
	if (!conn->priv) {
		conn_dst = mgcp_find_dst_conn(conn);
		conn->priv = conn_dst;
	} else {
		conn_dst = (struct mgcp_conn *)conn->priv;
	}
	return conn_dst;
}

/* Find RFCI containing all 0 sizes, -1 if not found. irp is an Initialization.ind prim */
static int _find_rfci_no_data(struct osmo_iuup_rnl_prim *irp)
{
	int i;
	uint8_t rfci_cnt = 0;
	/* Find RFCI containing NO_DATA: */
	for (i = 0; i < ARRAY_SIZE(irp->u.status.u.initialization.rfci); i++) {
		struct osmo_iuup_rfci *rfci = &irp->u.status.u.initialization.rfci[i];
		int j;
		bool is_no_data;
		if (!rfci->used)
			continue;
		rfci_cnt++;

		is_no_data = true;
		for (j = 0; j < irp->u.status.u.initialization.num_subflows; j++) {
			if (rfci->subflow_sizes[j]) {
				is_no_data = false;
				break;
			}
		}
		if (is_no_data)
			return rfci->id;

		/* early loop termination: */
		if (rfci_cnt == irp->u.status.u.initialization.num_subflows)
			break;
	}
	return -1;
}

/* Lookup RFCI to use for specific AMR codec type. -1 if none found */
static int8_t _conn_iuup_amr_ft_2_rfci(struct mgcp_conn_rtp *conn_rtp, uint8_t ft)
{
	int8_t i;
	uint8_t rfci_cnt = 0;
	unsigned match_bytes = (unsigned)osmo_amr_bytes(ft);
	struct osmo_iuup_rnl_prim *irp = conn_rtp->iuup.init_ind;
	if (!irp) {
		/* No IuUP Initialization has occured on the IuUP side yet. Return error and drop the RTP data, until
		 * the IuUP Initialization has configured the link. */
		return -1;
	}

	/* TODO: cache this somehow */
	for (i = 0; i < ARRAY_SIZE(irp->u.status.u.initialization.rfci); i++) {
		struct osmo_iuup_rfci *rfci = &irp->u.status.u.initialization.rfci[i];
		int j;
		unsigned num_bits;
		if (!rfci->used)
			continue;
		rfci_cnt++;

		num_bits = 0;
		for (j = 0; j < irp->u.status.u.initialization.num_subflows; j++)
			num_bits += rfci->subflow_sizes[j];
		if (match_bytes == (num_bits + 7)/8)
			return rfci->id;

		/* early loop termination: */
		if (rfci_cnt == irp->u.status.u.initialization.num_subflows)
			break;
	}
	return -1;
}

/* Helper function to configure IuUP layer FSM as Init-Passive, based on default config */
static int _conn_iuup_configure_as_passive(struct mgcp_conn_rtp *conn_rtp)
{
	struct osmo_iuup_rnl_prim *irp;
	int rc;

	conn_rtp->iuup.active_init = false;

	/* Tx CONFIG.req */
	irp = osmo_iuup_rnl_prim_alloc(conn_rtp->conn, OSMO_IUUP_RNL_CONFIG, PRIM_OP_REQUEST, MGW_IUUP_MSGB_SIZE);
	irp->u.config = def_configure_req;
	irp->u.config.active = conn_rtp->iuup.active_init;
	if ((rc = osmo_iuup_rnl_prim_down(conn_rtp->iuup.iui, irp)) == 0)
		conn_rtp->iuup.configured = true;
	else
		LOG_CONN_RTP(conn_rtp, LOGL_ERROR, "Failed configuring IuUP layer\n");
	return rc;
}

/* Helper function to configure IuUP layer FSM as Init-Active, based on received
 * RNL Status-Init primitive from the sister IuUP connection we will bridge to. */
static int _conn_iuup_configure_as_active(struct mgcp_conn_rtp *conn_rtp, struct osmo_iuup_rnl_prim *init_ind)
{
	struct osmo_iuup_rnl_prim *irp = init_ind;
	struct osmo_iuup_rnl_prim *irp2;
	struct msgb *msg;
	bool prev_output_enabled;
	int rc;

	conn_rtp->iuup.active_init = true;

	/* Find RFCI containing NO_DATA: */
	conn_rtp->iuup.rfci_id_no_data = _find_rfci_no_data(init_ind);

	/* Copy over the rfci_id_no_data, since we reuse the same subflow set: */
	msg = msgb_copy_c(conn_rtp->conn, irp->oph.msg, "iuup-init-copy");
	conn_rtp->iuup.init_ind = (struct osmo_iuup_rnl_prim *)msgb_data(msg);
	conn_rtp->iuup.init_ind->oph.msg = msg;

	/* Tx CONFIG.req */
	irp2 = osmo_iuup_rnl_prim_alloc(conn_rtp->conn, OSMO_IUUP_RNL_CONFIG, PRIM_OP_REQUEST, MGW_IUUP_MSGB_SIZE);
	irp2->u.config.transparent = false;
	irp2->u.config.active = conn_rtp->iuup.active_init;
	irp2->u.config.data_pdu_type = irp->u.status.u.initialization.data_pdu_type;
	irp2->u.config.supported_versions_mask = def_configure_req.supported_versions_mask;
	irp2->u.config.num_rfci = irp->u.status.u.initialization.num_rfci;
	irp2->u.config.num_subflows = irp->u.status.u.initialization.num_subflows;
	irp2->u.config.IPTIs_present = irp->u.status.u.initialization.IPTIs_present;
	memcpy(irp2->u.config.rfci, irp->u.status.u.initialization.rfci, sizeof(irp2->u.config.rfci));
	irp2->u.config.t_init = def_configure_req.t_init;
	irp2->u.config.t_ta = def_configure_req.t_ta;
	irp2->u.config.t_rc = def_configure_req.t_rc;

	/* We need to force allowance of RTP containing Init-ACK back: */
	prev_output_enabled = conn_rtp->end.output_enabled;
	conn_rtp->end.output_enabled = true;

	if ((rc = osmo_iuup_rnl_prim_down(conn_rtp->iuup.iui, irp2)) == 0)
		conn_rtp->iuup.configured = true;
	else
		LOG_CONN_RTP(conn_rtp, LOGL_ERROR, "Failed configuring IuUP layer\n");

	conn_rtp->end.output_enabled = prev_output_enabled;
	return rc;
}

/* Helper function to push an RTP+IuUP pkt up to the IuUP layer FSM through the
 * TNL primitive interface. */
static int _conn_iuup_rtp_pl_up(struct mgcp_conn_rtp *conn_rtp, struct msgb *msg)
{
	/* Send RTP payload (IuUP) up the stack: */
	struct osmo_iuup_tnl_prim *itp;
	int rc;

	msg->l2h = msgb_data(msg) + sizeof(struct rtp_hdr);

	itp = osmo_iuup_tnl_prim_alloc(conn_rtp->conn, OSMO_IUUP_TNL_UNITDATA, PRIM_OP_INDICATION, MGW_IUUP_MSGB_SIZE);
	itp->oph.msg->l2h = msgb_put(itp->oph.msg, msgb_l2len(msg));
	memcpy(itp->oph.msg->l2h, msgb_l2(msg), msgb_l2len(msg));
	if ((rc = osmo_iuup_tnl_prim_up(conn_rtp->iuup.iui, itp)) != 0) {
		LOG_CONN_RTP(conn_rtp, LOGL_ERROR, "Failed passing IuUP-Init to IuUP layer\n");
	}
	return rc;
}

static int check_rtp_iuup(const struct mgcp_conn_rtp *conn_rtp, struct msgb *msg)
{
	size_t min_size = sizeof(struct rtp_hdr);
	/* Check there's at least 2 bytes of RTP payload (IuUP header). This is
	 ** mainly to avoid 0-byte payload copy cases */
	if (msgb_length(msg) < sizeof(struct rtp_hdr) + 2) {
		LOG_CONN_RTP(conn_rtp, LOGL_ERROR, "RTP-IuUP packet too short (%u < %zu)\n",
			     msgb_length(msg), min_size);
		return -1;
	}
	return 0;
}

/* Bridge received IuUP packet in conn_rtp_src to conn_rtp_dst, an IuUP sister
 * conn in the endpoint. The function takes ownsership of the irp */
static int bridge_iuup_to_iuup_peer(struct mgcp_conn_rtp *conn_rtp_src, struct mgcp_conn_rtp *conn_rtp_dst, struct osmo_iuup_rnl_prim *irp)
{
	int rc;

	/* If we are not configured and we received bridged data, it means
	 * conn_rtp_src is already configured and INITed, and we can infer
	 * conn_rtp_src is Init-passive (RNC side), so conn_rtp_dst needs to be
	 * configured as INIT-active: */
	if (!conn_rtp_dst->iuup.configured) {
		OSMO_ASSERT(conn_rtp_src->iuup.init_ind);
		rc = _conn_iuup_configure_as_active(conn_rtp_dst, conn_rtp_src->iuup.init_ind);
		if (rc < 0) {
			msgb_free(irp->oph.msg);
			return rc;
		}
	}

	/* We simply forward the msg, without freeing it: */
	talloc_steal(conn_rtp_dst->conn, irp->oph.msg);
	irp->oph.operation = PRIM_OP_REQUEST;
	if ((rc = osmo_iuup_rnl_prim_down(conn_rtp_dst->iuup.iui, irp)) != 0)
		LOG_CONN_RTP(conn_rtp_dst, LOGL_ERROR, "Failed Tx data down to IuUP layer\n");
	return rc;
}

/* Bridge received IuUP packet in conn_rtp_src to conn_rtp_dst, an RTP (no IuUP)
 * sister conn in the endpoint. The function takes ownsership of the irp */
static int bridge_iuup_to_rtp_peer(struct mgcp_conn_rtp *conn_rtp_src, struct mgcp_conn_rtp *conn_rtp_dst, struct osmo_iuup_rnl_prim *irp)
{
	/* FIXME: We probably need transcoding here?! Or at least look up AMR modes and translate to related RFCI */
	uint8_t frame_nr = irp->u.data.frame_nr;
	uint8_t fqc = irp->u.data.fqc;
	struct msgb *msg = irp->oph.msg;
	ssize_t amr_length = 0;
	int ft;
	uint8_t *amr_data;
	struct rtp_hdr *rtp_hdr;
	struct amr_hdr *amr_hdr;
	struct mgcp_rtp_codec *dst_codec;
	int rc;

	ft = osmo_amr_bytes_to_ft(msgb_l3len(msg));
	if (ft < 0) {
		LOGPCONN(conn_rtp_src->conn, DRTP, LOGL_ERROR,
			 "Unknown AMR format for size %u\n", msgb_l3len(msg));
		msgb_free(msg);
		return ft;
	}
	msgb_pull_to_l3(msg);

	dst_codec = conn_rtp_dst->end.cset.codec;
	if (mgcp_codec_amr_is_octet_aligned(dst_codec)) {
		LOGP(DLMGCP, LOGL_DEBUG, "Convert IuUP -> AMR OA: ft %d, len %d\n", ft, msgb_length(msg));
		amr_hdr = (struct amr_hdr *) msgb_push(msg, sizeof(struct amr_hdr));
		amr_hdr->cmr = 15; /* no change */
		amr_hdr->f = 0;
		amr_hdr->q = !fqc;
		amr_hdr->ft = ft & 0xff;
		amr_hdr->pad1 = 0;
		amr_hdr->pad2 = 0;
	} else {
		OSMO_ASSERT(msgb_tailroom(msg) >= 2);
		msgb_put(msg, 2);
		osmo_amr_iuup_to_bwe(msgb_data(msg), msgb_length(msg) - 2, msgb_length(msg) + 2);
		/* fill bwe header */
		amr_data = msgb_data(msg);
		/* CMR no change      | follow bit | ft (3 of 4 bits) */
		amr_data[0] = 15 << 4 | (0 << 3) | (ft >> 1);
		amr_data[1] |= ((ft & 0x1) << 7) | (((!fqc) & 0x1) << 6);
		amr_length = (osmo_amr_bits(ft) + 10 + 7) / 8;
		msgb_trim(msg, amr_length);
		LOGP(DLMGCP, LOGL_DEBUG, "Convert IuUP -> AMR BE: ft %d, len %zd\n", ft, amr_length);
	}
	rtp_hdr = (struct rtp_hdr *) msgb_push(msg, sizeof(*rtp_hdr));
	*rtp_hdr = (struct rtp_hdr){
		.csrc_count = 0,
		.extension = 0,
		.padding = 0,
		.version = 0,
		.payload_type = dst_codec->payload_type,
		.marker = 0,
		.sequence = frame_nr,
		.timestamp = 0,
		.ssrc = 0
	};

	rc = mgcp_send(conn_rtp_dst->conn->endp, true, NULL, msg, conn_rtp_src, conn_rtp_dst);
	return rc;
}

/* Handle RNL Data primitive received from the IuUP layer FSM: Bridge it to the
 * sister connection in the endpoint: */
static int _conn_iuup_rx_rnl_data(struct mgcp_conn_rtp *conn_rtp_src, struct osmo_iuup_rnl_prim *irp)
{
	struct mgcp_conn *conn_dst;
	struct mgcp_conn_rtp *conn_rtp_dst;
	int rc;

	conn_dst = _find_dst_conn(conn_rtp_src->conn);

	/* There is no destination conn, stop here */
	if (!conn_dst) {
		LOGPCONN(conn_rtp_src->conn, DRTP, LOGL_DEBUG,
			 "no connection to forward an incoming IuUP payload to\n");
		rc = -1;
		goto free_ret;
	}

	/* The destination conn is not an RTP/IuUP connection */
	if (conn_dst->type != MGCP_CONN_TYPE_RTP) {
		LOGPCONN(conn_rtp_src->conn, DRTP, LOGL_ERROR,
			 "unable to find suitable destination conn\n");
		 rc = -1;
		goto free_ret;
	}
	conn_rtp_dst = &conn_dst->u.rtp;

	switch (conn_rtp_dst->type) {
	case MGCP_RTP_IUUP:
		return bridge_iuup_to_iuup_peer(conn_rtp_src, conn_rtp_dst, irp);
	case MGCP_RTP_DEFAULT:
		return bridge_iuup_to_rtp_peer(conn_rtp_src, conn_rtp_dst, irp);
	case MGCP_RTP_OSMUX:
	default:
		LOGPCONN(conn_rtp_src->conn, DRTP, LOGL_ERROR,
			 "Forward of IuUP payload to RTP connection type %u not supported!\n",
			 conn_rtp_dst->type);
		rc = 0;
	}

free_ret:
	msgb_free(irp->oph.msg);
	return rc;
}

/* Handle RNL Status-Init primitive received from the IuUP layer FSM.
 * Potentially configure sister conn as IuUP Init-Active: */
static int _conn_iuup_rx_rnl_status_init(struct mgcp_conn_rtp *conn_rtp_src, struct osmo_iuup_rnl_prim *irp)
{
	struct mgcp_conn *conn_dst;
	struct mgcp_conn_rtp *conn_rtp_dst;
	int rc = 0;
	struct msgb *msg;

	if (conn_rtp_src->iuup.init_ind) {
		/* We received more than one IuUP Initialization. It's probably
		 * a retransmission, so simply ignore it (lower layers take care
		 * of ACKing it). */
		LOGPCONN(conn_rtp_src->conn, DRTP, LOGL_INFO,
		  "Ignoring potential IuUP Initialization retrans\n");
		return 0;
	}

	msg = msgb_copy_c(conn_rtp_src->conn, irp->oph.msg, "iuup-init-copy");
	conn_rtp_src->iuup.init_ind = (struct osmo_iuup_rnl_prim *)msgb_data(msg);
	conn_rtp_src->iuup.init_ind->oph.msg = msg;

	/* Find RFCI containing NO_DATA: */
	conn_rtp_src->iuup.rfci_id_no_data = _find_rfci_no_data(irp);

	conn_dst = _find_dst_conn(conn_rtp_src->conn);
	/* If not yet there, peer will potentially be IuUP-Initialized later
	 * when we attempt to bridge audio towards it. See bridge_iuup_to_iuup_peer() */
	if (!conn_dst)
		return 0;
	conn_rtp_dst = &conn_dst->u.rtp;
	if (!mgcp_conn_rtp_is_iuup(conn_rtp_dst))
		return 0; /* Nothing to do */

	/* We received IuUP parameters on the peer (RNC), Init actively this conn (against CN): */
	if (!conn_rtp_dst->iuup.configured)
		rc = _conn_iuup_configure_as_active(conn_rtp_dst, irp);

	return rc;
}

/* Handle RNL Status primitives received from the IuUP layer FSM: */
static int _conn_iuup_rx_rnl_status(struct mgcp_conn_rtp *conn_rtp_src, struct osmo_iuup_rnl_prim *irp)
{
	int rc;

	switch (irp->u.status.procedure) {
	case IUUP_PROC_INIT:
		rc = _conn_iuup_rx_rnl_status_init(conn_rtp_src, irp);
		break;
	case IUUP_PROC_RATE_CTRL:
	case IUUP_PROC_TIME_ALIGN:
	case IUUP_PROC_ERR_EVENT:
	default:
		LOG_CONN_RTP(conn_rtp_src, LOGL_ERROR,
			     "Received IuUP RNL STATUS procedure type %u not handled\n",
			     irp->u.status.procedure);
		rc = 0;
	}

	return rc;
}

/* Received RNL primitive from the IuUP layer FSM containing IuUP Status or
 * data. Continue pushing it up the stack, either IuUP Status or Data: */
static int _conn_iuup_user_prim_cb(struct osmo_prim_hdr *oph, void *ctx)
{
	struct mgcp_conn_rtp *conn_rtp_src = ctx;
	struct osmo_iuup_rnl_prim *irp = (struct osmo_iuup_rnl_prim *)oph;
	struct msgb *msg = oph->msg;
	int rc;

	switch (OSMO_PRIM_HDR(&irp->oph)) {
	case OSMO_PRIM(OSMO_IUUP_RNL_DATA, PRIM_OP_INDICATION):
		/* we pass ownsership of msg here: */
		rc = _conn_iuup_rx_rnl_data(conn_rtp_src, irp);
		break;
	case OSMO_PRIM(OSMO_IUUP_RNL_STATUS, PRIM_OP_INDICATION):
		rc = _conn_iuup_rx_rnl_status(conn_rtp_src, irp);
		msgb_free(msg);
		break;
	default:
		msgb_free(msg);
		OSMO_ASSERT(false);
	}

	return rc;
}

/*! Send |RTP+IuUP| data down the stack of the specified destination connection.
 *  \param[in] endp associated endpoint (for configuration, logging).
 *  \param[in] buf buffer that contains the |RTP+IuUP| data.
 *  \param[in] len length of the buffer that contains the |RTP+IuUP| data.
 *  \param[in] conn_src associated source connection.
 *  \param[in] conn_dst associated destination connection.
 *  \returns 0 on success, -1 on ERROR. */
static int mgcp_send_iuup(struct mgcp_endpoint *endp, struct msgb *msg,
		   struct mgcp_conn_rtp *conn_src, struct mgcp_conn_rtp *conn_dst)
{
	/*! When no destination connection is available (e.g. when only one
	 *  connection in loopback mode exists), then the source connection
	 *  shall be specified as destination connection */

	struct mgcp_rtp_end *rtp_end;
	struct mgcp_rtp_state *rtp_state;
	char ipbuf[INET6_ADDRSTRLEN];
	struct rtp_hdr *hdr = (struct rtp_hdr *)msgb_data(msg);
	int buflen = msgb_length(msg);
	char *dest_name;
	int rc;

	OSMO_ASSERT(conn_src);
	OSMO_ASSERT(conn_dst);

	LOGPENDP(endp, DRTP, LOGL_DEBUG, "delivering IuUP packet...\n");

	/* Note: In case of loopback configuration, both, the source and the
	 * destination will point to the same connection. */
	rtp_end = &conn_dst->end;
	rtp_state = &conn_src->state;
	dest_name = conn_dst->conn->name;

	/* Ensure we have an alternative SSRC in case we need it, see also
	 * gen_rtp_header() */
	if (rtp_state->alt_rtp_tx_ssrc == 0)
		rtp_state->alt_rtp_tx_ssrc = rand();

	if (!rtp_end->output_enabled) {
		rtpconn_rate_ctr_add(conn_dst, endp, RTP_DROPPED_PACKETS_CTR, 1);
		LOGPENDP(endp, DRTP, LOGL_DEBUG,
			 "output disabled, drop to %s %s "
			 "rtp_port:%u rtcp_port:%u\n",
			 dest_name,
			 osmo_sockaddr_ntop(&rtp_end->addr.u.sa, ipbuf),
			 osmo_sockaddr_port(&rtp_end->addr.u.sa), ntohs(rtp_end->rtcp_port)
			);
		return 0;
	}

	/* Specs say, in IuUP, the RTP seqnum and timestamp should actually be
	 * ignored by the receiver, but still it's useful for debug purposes
	 * to set it. Moreover, it seems ip.access nano3g produces much worse
	 * audio output on the air side if timestamp is not set properly. */
	hdr->timestamp = osmo_htonl(mgcp_get_current_ts(rtp_end->cset.codec->rate));
	hdr->sequence = osmo_htons(rtp_state->alt_rtp_tx_sequence);
	hdr->ssrc = rtp_state->alt_rtp_tx_ssrc;
	rtp_state->alt_rtp_tx_sequence++;

	LOGPENDP(endp, DRTP, LOGL_DEBUG,
		 "process/send IuUP to %s %s rtp_port:%u rtcp_port:%u\n",
		 dest_name, osmo_sockaddr_ntop(&rtp_end->addr.u.sa, ipbuf),
		 osmo_sockaddr_port(&rtp_end->addr.u.sa), ntohs(rtp_end->rtcp_port));

	/* Forward a copy of the RTP data to a debug ip/port */
	forward_data_tap(rtp_end->rtp, &conn_src->tap_out, msg);

	rc = mgcp_udp_send(rtp_end->rtp, &rtp_end->addr, (char *)hdr, buflen);

	if (rc < 0)
		return rc;

	rtpconn_rate_ctr_add(conn_dst, endp, RTP_PACKETS_TX_CTR, 1);
	rtpconn_rate_ctr_add(conn_dst, endp, RTP_OCTETS_TX_CTR, buflen);

	return 0;
}

/* Received TNL primitive from IuUP layer FSM, transmit it further down to the
 * socket towards destination peer. */
static int _conn_iuup_transport_prim_cb(struct osmo_prim_hdr *oph, void *ctx)
{
	struct mgcp_conn_rtp *conn_rtp_dst = ctx;
	struct mgcp_conn *conn_dst = conn_rtp_dst->conn;
	struct osmo_iuup_tnl_prim *itp = (struct osmo_iuup_tnl_prim *)oph;
	struct mgcp_conn *conn_src;
	struct msgb *msg;
	struct rtp_hdr *rtph;

	OSMO_ASSERT(OSMO_PRIM_HDR(&itp->oph) == OSMO_PRIM(OSMO_IUUP_TNL_UNITDATA, PRIM_OP_REQUEST));

	msg = oph->msg;
	talloc_steal(conn_rtp_dst->conn, msg);

	msgb_pull_to_l2(msg);
	rtph = (struct rtp_hdr *)msgb_push(msg, sizeof(*rtph));
	/* rtph is further filled in mgcp_send_iuup() below. */
	*rtph = (struct rtp_hdr){
		.csrc_count = 0,
		.extension = 0,
		.padding = 0,
		.version = 2,
		.payload_type = conn_rtp_dst->end.cset.codec->payload_type,
		.marker = 0,
		.sequence = 0,
		.timestamp = 0,
		.ssrc = 0
	};

	/* The destination of the destination conn is the source conn, right? */
	conn_src = _find_dst_conn(conn_dst);
	if (!conn_src) {
		LOG_CONN_RTP(conn_rtp_dst, LOGL_NOTICE,
			     "Couldn't find source conn for IuUP dst conn\n");
		/* If there's no sister connection we are either still
		 * initializing (so we want to send back Init (ACK)), or we are
		 * probably in loopback mode anyway, so use dst as src. */
		conn_src = conn_dst;
	}

	return mgcp_send_iuup(conn_dst->endp, msg, &conn_src->u.rtp, conn_rtp_dst);
}

/* Used to upgrade a regular RTP connection (MGCP_RTP_DEFAULT) to become a IuUP
 * connection (MGCP_RTP_IUUP) */
int mgcp_conn_iuup_init(struct mgcp_conn_rtp *conn_rtp)
{
	conn_rtp->type = MGCP_RTP_IUUP;
	conn_rtp->iuup.iui = osmo_iuup_instance_alloc(conn_rtp->conn, conn_rtp->conn->id);
	OSMO_ASSERT(conn_rtp->iuup.iui);
	osmo_iuup_instance_set_user_prim_cb(conn_rtp->iuup.iui, _conn_iuup_user_prim_cb, conn_rtp);
	osmo_iuup_instance_set_transport_prim_cb(conn_rtp->iuup.iui, _conn_iuup_transport_prim_cb, conn_rtp);
	conn_rtp->iuup.rfci_id_no_data = -1;
	return 0;
}

/* Cleanup specific IuUP connection (MGCP_RTP_IUUP) state, allocated by mgcp_conn_iuup_init() */
void mgcp_conn_iuup_cleanup(struct mgcp_conn_rtp *conn_rtp)
{
	osmo_iuup_instance_free(conn_rtp->iuup.iui);
	conn_rtp->iuup.iui = NULL;
}

/* Received RTP+IuUP pkt from socket of conn_rtp_src, build a TNL primitive to
 * push it further up the stack to the IuUP layer FSM to handle and/or bridge it */
int mgcp_conn_iuup_dispatch_rtp(struct msgb *msg)
{
	struct osmo_rtp_msg_ctx *mc = OSMO_RTP_MSG_CTX(msg);
	struct mgcp_conn_rtp *conn_rtp_src = mc->conn_src;
	int rc = 0;
	bool force_output_enabled = false;
	bool prev_output_enabled;
	struct osmo_sockaddr prev_rem_addr;
	uint16_t prev_rem_rtp_port;

	OSMO_ASSERT(mgcp_conn_rtp_is_iuup(conn_rtp_src));

	if ((rc = check_rtp_iuup(conn_rtp_src, msg)) < 0)
		goto free_ret;

	if (!conn_rtp_src->iuup.configured) {
		/* We received the first message without sending any, the peer is the active side (RNC). */
		rc = _conn_iuup_configure_as_passive(conn_rtp_src);
		if (rc < 0)
			goto free_ret;
		/* We need to force allowance of RTP containing Init-ACK back: */
		prev_output_enabled = conn_rtp_src->end.output_enabled;
		conn_rtp_src->end.output_enabled = true;
		force_output_enabled = true;
		/* Fill in the peer address so that we can send Init-ACK back: */
		prev_rem_addr = conn_rtp_src->end.addr;
		prev_rem_rtp_port = osmo_sockaddr_port(&conn_rtp_src->end.addr.u.sa);
		conn_rtp_src->end.addr = *mc->from_addr;
	}

	rc = _conn_iuup_rtp_pl_up(conn_rtp_src, msg);

	if (force_output_enabled) {
		conn_rtp_src->end.output_enabled = prev_output_enabled;
		conn_rtp_src->end.addr = prev_rem_addr;
		osmo_sockaddr_set_port(&conn_rtp_src->end.addr.u.sa, prev_rem_rtp_port);
	}

	return rc;
free_ret:
	msgb_free(msg);
	return rc;
}

/* Build IuUP RNL Data primitive from msg containing an incoming RTP pkt from
 * peer and send it down the IuUP layer towards the destination as IuUP/RTP. Takes ownership of msg. */
int mgcp_conn_iuup_send_rtp(struct mgcp_conn_rtp *conn_src_rtp, struct mgcp_conn_rtp *conn_dest_rtp, struct msgb *msg)
{
	struct osmo_iuup_rnl_prim *irp;
	struct rtp_hdr *rtph;
	int rc = -1;
	int iuup_length = 0;
	struct mgcp_rtp_codec *src_codec;
	int8_t rfci;

	/* Tx RNL-DATA.req */
	rtph = (struct rtp_hdr *)msgb_data(msg);
	msgb_pull(msg, sizeof(*rtph));

	/* FIXME: validate amr packets */
	irp = osmo_iuup_rnl_prim_alloc(conn_dest_rtp->conn, OSMO_IUUP_RNL_DATA, PRIM_OP_REQUEST, MGW_IUUP_MSGB_SIZE);
	irp->u.data.frame_nr = htons(rtph->sequence) % 16;

	/* TODO: CMR handling & multiple frames handling */

	src_codec = conn_src_rtp->end.cset.codec;
	if (strcmp(src_codec->subtype_name, "AMR") != 0) {
		LOG_CONN_RTP(conn_src_rtp, LOGL_ERROR,
			     "Bridge RTP=>IuUP: Bridging src codec %s to IuUP AMR not supported\n",
			     src_codec->subtype_name);
		goto free_ret;
	}
	if (mgcp_codec_amr_is_octet_aligned(src_codec)) {
		struct amr_hdr *amr_hdr = (struct amr_hdr *) msgb_data(msg);
		if (msgb_length(msg) < (sizeof(*amr_hdr))) {
			LOG_CONN_RTP(conn_src_rtp, LOGL_NOTICE,
				     "Bridge RTP=>IuUP: too short for AMR OA hdr (%u)\n", msgb_length(msg));
			goto free_ret;
		}
		if (!osmo_amr_ft_valid(amr_hdr->ft)) {
			LOG_CONN_RTP(conn_src_rtp, LOGL_NOTICE, "Bridge RTP=>IuUP: wrong AMR OA ft=%u\n", amr_hdr->ft);
			goto free_ret;
		}
		if ((rfci =  _conn_iuup_amr_ft_2_rfci(conn_dest_rtp, amr_hdr->ft)) < 0) {
			LOG_CONN_RTP(conn_dest_rtp, LOGL_NOTICE, "Bridge RTP=>IuUP: No RFCI found for AMR OA ft=%u\n", amr_hdr->ft);
			goto free_ret;
		}
		irp->u.data.fqc = amr_hdr->q ? IUUP_FQC_FRAME_GOOD : IUUP_FQC_FRAME_BAD;
		irp->u.data.rfci = rfci;
		msgb_pull(msg, 2);
		LOGP(DLMGCP, LOGL_DEBUG, "Convert AMR OA -> IuUP: ft %d -> rfci %d len %d\n",
		     amr_hdr->ft, rfci, msgb_length(msg));
	} else {
		uint8_t *amr_bwe_hdr = (uint8_t *) msgb_data(msg);
		int8_t ft;
		uint8_t q;
		if (msgb_length(msg) < 2) {
			LOG_CONN_RTP(conn_src_rtp, LOGL_NOTICE,
				     "Bridge RTP=>IuUP: too short for AMR BE hdr (%u)\n", msgb_length(msg));
			goto free_ret;
		}
		ft = ((amr_bwe_hdr[0] & 0x07) << 1) | ((amr_bwe_hdr[1] & 0x80) >> 7);
		if (!osmo_amr_ft_valid(ft)) {
			LOG_CONN_RTP(conn_src_rtp, LOGL_NOTICE, "Bridge RTP=>IuUP: wrong AMR BE ft=%u\n", ft);
			goto free_ret;
		}
		if ((rfci =  _conn_iuup_amr_ft_2_rfci(conn_dest_rtp, ft)) < 0) {
			LOG_CONN_RTP(conn_dest_rtp, LOGL_NOTICE, "Bridge RTP=>IuUP: No RFCI found for AMR BE ft=%u\n", ft);
			goto free_ret;
		}
		q = amr_bwe_hdr[1] & 0x40;
		irp->u.data.fqc = q ? IUUP_FQC_FRAME_GOOD : IUUP_FQC_FRAME_BAD;
		irp->u.data.rfci = rfci;
		rc = iuup_length = osmo_amr_bwe_to_iuup(msgb_data(msg), msgb_length(msg));
		if (rc < 0) {
			LOG_CONN_RTP(conn_dest_rtp, LOGL_ERROR, "Bridge RTP=>IuUP: Failed convert the RTP/AMR to IuUP payload\n");
			return rc;
		}
		msgb_trim(msg, iuup_length);
		LOGP(DLMGCP, LOGL_DEBUG, "Convert AMR BE -> IuUP: ft %d -> rfci %d len %d\n",
		     ft, rfci, msgb_length(msg));
	}

	irp->oph.msg->l3h = msgb_put(irp->oph.msg, msgb_length(msg));
	memcpy(irp->oph.msg->l3h, msgb_data(msg), msgb_length(msg));
	if ((rc = osmo_iuup_rnl_prim_down(conn_dest_rtp->iuup.iui, irp)) != 0)
		LOG_CONN_RTP(conn_dest_rtp, LOGL_ERROR, "Bridge RTP=>IuUP: Failed Tx RTP payload down the IuUP layer\n");
	return rc;

free_ret:
	msgb_free(irp->oph.msg);
	return -1;
}

/* Build IuUP RNL Data primitive from msg containing dummy content and send it
 * down the IuUP layer towards the destination as IuUP/RTP: */
int mgcp_conn_iuup_send_dummy(struct mgcp_conn_rtp *conn_rtp)
{
	struct osmo_iuup_rnl_prim *irp;
	int rc;

	if (conn_rtp->iuup.rfci_id_no_data == -1) {
		LOG_CONN_RTP(conn_rtp, LOGL_NOTICE, "No RFCI NO_DATA found, unable to send dummy packet\n");
		return -ENOTSUP;
	}

	irp = osmo_iuup_rnl_prim_alloc(conn_rtp->conn, OSMO_IUUP_RNL_DATA, PRIM_OP_REQUEST, MGW_IUUP_MSGB_SIZE);
	irp->u.data.frame_nr = 0;
	irp->u.data.fqc = IUUP_FQC_FRAME_GOOD;
	irp->u.data.rfci = conn_rtp->iuup.rfci_id_no_data;
	irp->oph.msg->l3h = irp->oph.msg->tail;
	if ((rc = osmo_iuup_rnl_prim_down(conn_rtp->iuup.iui, irp)) != 0) {
		LOG_CONN_RTP(conn_rtp, LOGL_ERROR, "Failed Tx RTP dummy payload down the IuUP layer\n");
		return -EINVAL;
	}

	return 0;
}

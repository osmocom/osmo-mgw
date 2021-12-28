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

#include <osmocom/gsm/iuup.h>

#include <osmocom/netif/amr.h>
#include <osmocom/netif/rtp.h>

#include <osmocom/mgcp/mgcp_codec.h>
#include <osmocom/mgcp/mgcp_conn.h>
#include <osmocom/mgcp/mgcp_iuup.h>
#include <osmocom/mgcp/mgcp_endp.h>
#include <osmocom/mgcp/debug.h>

#define MGW_IUUP_MSGB_SIZE 4096

static struct osmo_iuup_rnl_config def_configure_req = {
	.transparent = false,
	.active = true,
	.supported_versions_mask = 0x0003,
	.num_rfci = 0,
	.num_subflows = 0,
	/* .delivery_err_sdu = All set to 0 (YES) by default, */
	.IPTIs_present = false,
	.t_init = { .t_ms = IUUP_TIMER_INIT_T_DEFAULT, .n_max = IUUP_TIMER_INIT_N_DEFAULT },
	.t_ta = { .t_ms = IUUP_TIMER_TA_T_DEFAULT, .n_max = IUUP_TIMER_TA_N_DEFAULT },
	.t_rc = { .t_ms = IUUP_TIMER_RC_T_DEFAULT, .n_max = IUUP_TIMER_RC_N_DEFAULT },
};

static struct mgcp_conn *_find_dst_conn(struct mgcp_conn *conn)
{
	/* Find a destination connection. */
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

static int _conn_iuup_configure_as_passive(struct mgcp_conn_rtp *conn_rtp, struct msgb *msg)
{
	struct osmo_iuup_rnl_prim *irp;
	int rc;

	conn_rtp->iuup.active_init = false;

	/* Tx CONFIG.req */
	irp = osmo_iuup_rnl_prim_alloc(conn_rtp->conn, OSMO_IUUP_RNL_CONFIG, PRIM_OP_REQUEST, MGW_IUUP_MSGB_SIZE);
	irp->u.config = def_configure_req;
	irp->u.config.active = conn_rtp->iuup.active_init;
	if ((rc = osmo_iuup_rnl_prim_down(conn_rtp->iuup.iui, irp)) != 0)
		LOG_CONN_RTP(conn_rtp, LOGL_ERROR, "Failed configuring IuUP layer\n");
	return rc;
}

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

static int _conn_iuup_rx_rnl_data(struct mgcp_conn_rtp *conn_rtp_src, struct osmo_iuup_rnl_prim *irp)
{
	struct mgcp_conn *conn_src, *conn_dst;
	struct mgcp_conn_rtp *conn_src_rtp, *conn_rtp_dst;
	int rc;
	uint8_t rfci, frame_nr, fqc;
	int ft;
	struct msgb *msg;
	struct amr_hdr *amr_hdr;
	uint8_t *amr_data;
	ssize_t amr_length = 0;
	struct rtp_hdr *rtp_hdr;

	conn_dst = _find_dst_conn(conn_rtp_src->conn);

	/* There is no destination conn, stop here */
	if (!conn_dst) {
		LOGPCONN(conn_rtp_src->conn, DRTP, LOGL_DEBUG,
			 "no connection to forward an incoming IuUP payload to\n");
		rc= -1;
		goto free_ret;
	}

	/* The destination conn is not an RTP/IuUP connection */
	if (conn_dst->type != MGCP_CONN_TYPE_RTP) {
		LOGPCONN(conn_rtp_src->conn, DRTP, LOGL_ERROR,
			 "unable to find suitable destination conn\n");
		 rc= -1;
		goto free_ret;
	}
	conn_rtp_dst = &conn_dst->u.rtp;

	switch (conn_rtp_dst->type) {
	case MGCP_RTP_IUUP:
		/* We simply forward the msg, without freeing it: */
		talloc_steal(conn_dst, irp->oph.msg);
		irp->oph.operation = PRIM_OP_REQUEST;
		if ((rc = osmo_iuup_rnl_prim_down(conn_rtp_dst->iuup.iui, irp)) != 0)
			LOG_CONN_RTP(conn_rtp_dst, LOGL_ERROR, "Failed Tx data down to IuUP layer\n");
		return rc;
		break;
	case MGCP_RTP_DEFAULT:
		/* FIXME: We probably need transcoding here?! Or at least look up AMR modes and translate to related RFCI */
		rfci = irp->u.data.rfci;
		frame_nr = irp->u.data.frame_nr;
		fqc = irp->u.data.fqc;
		msg = irp->oph.msg;
		ft = osmo_amr_bytes_to_ft(msgb_l3len(msg));
		if (ft < 0) {
			/* FIXME LOGP */
			return ft;
		}
		msgb_pull_to_l3(msg);
		LOGP(DLMGCP, LOGL_ERROR, "Convert Iuup -> AMR: ft %d, len %d\n", ft, msgb_l3len(msg));

		if (mgcp_codec_amr_is_octet_aligned(conn_rtp_dst->end.codec)) {
			amr_hdr = (struct amr_hdr *) msgb_push(msg, sizeof(struct amr_hdr));
			amr_hdr->cmr = 15; /* no change */
			amr_hdr->f = 0;
			amr_hdr->q = !fqc;
			amr_hdr->ft = ft & 0xff;
			amr_hdr->pad1 = 0;
			amr_hdr->pad2 = 0;
		} else {
			if (msgb_tailroom(msg) < 2) {
				/* FIXME not enought tailroom */
				return -4;
			}
			msgb_put(msg, 2);
			osmo_amr_iuup_to_bwe(msgb_data(msg), msgb_length(msg) - 2, msgb_length(msg) + 2);
			/* fill bwe header */
			amr_data = msgb_data(msg);
			/* CMR no change      | follow bit | ft (3 of 4 bits) */
			amr_data[0] = 15 << 4 | (0 << 3) | (ft >> 1);
			LOGP(DLMGCP, LOGL_ERROR, "Convert Iuup -> AMR bwe: amr[0] 0x%x 0x%x\n", amr_data[0], amr_data[1]);
			amr_data[1] |= ((ft & 0x1) << 7) | (((!fqc) & 0x1) << 6);
			LOGP(DLMGCP, LOGL_ERROR, "Convert Iuup -> AMR bwe: amr[0] 0x%x 0x%x\n", amr_data[0], amr_data[1]);
			amr_length = (osmo_amr_bits(ft) + 10 + 7) / 8;
			msgb_trim(msg, amr_length);
		}
		rtp_hdr = (struct rtp_hdr *) msgb_push(msg, sizeof(struct rtp_hdr));
		*rtp_hdr = (struct rtp_hdr){
			.csrc_count = 0,
			.extension = 0,
			.padding = 0,
			.version = 0,
			.payload_type = 0,
			.marker = 0,
			.sequence = 0,
			.timestamp = 0,
			.ssrc = 0
		};

		conn_src = _find_dst_conn(conn_dst);
		if (conn_src)
			conn_src_rtp = &conn_src->u.rtp;
		else
			conn_src_rtp = &conn_dst->u.rtp;

		rc = mgcp_send(conn_dst->endp, 1,
			 NULL, msg, conn_src_rtp, conn_rtp_dst);
		break;
	case MGCP_OSMUX_BSC:
	case MGCP_OSMUX_BSC_NAT:
	default:
		LOGPCONN(conn_rtp_src->conn, DRTP, LOGL_ERROR,
			 "Forward of IuUP payload to RTP connection type %u not supported!\n",
			 conn_rtp_dst->type);
	}

free_ret:
	msgb_free(irp->oph.msg);
	return rc;
}

static int _conn_iuup_rx_rnl_status_init(struct mgcp_conn_rtp *conn_rtp_src, struct osmo_iuup_rnl_prim *irp)
{
	struct mgcp_conn *conn_dst;
	struct mgcp_conn_rtp *conn_rtp_dst;
	int rc = 0;

	conn_dst = _find_dst_conn(conn_rtp_src->conn);
	if (!conn_dst)
		return 0; /* FIXME: that probably means we potentially need to Init the peer dst later! */
	conn_rtp_dst = &conn_dst->u.rtp;
	if (!mgcp_conn_rtp_is_iuup(conn_rtp_dst))
		return 0; /* Nothing to do */

	if (conn_rtp_dst->iuup.first_rtp_pkt_received) {
		/* Note: This could actually happen if INIT is rentransmitted, etc: */
		LOG_CONN_RTP(conn_rtp_dst, LOGL_ERROR, "Unexpected: Peer conn received IuUP INIT-ACK but RTP packets already received on this conn!\n");
	}
	/* We received IuUP parameters on the peer (RNC), Init actively this conn (against CN): */

	/* TODO: we still don't send this INIT INDICATION from IuUP FSM! Once we
	   do, we copy RFCI, etc. and send CONFIGURE.req(init=active) to
	   conn_rtp_dst->iuup.iui  */
	return rc;
}

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

static int _conn_iuup_transport_prim_cb(struct osmo_prim_hdr *oph, void *ctx)
{
	struct mgcp_conn_rtp *conn_src_rtp = NULL, *conn_rtp_dst = ctx;
	struct mgcp_conn *conn_dst = conn_rtp_dst->conn;
	struct osmo_iuup_tnl_prim *itp = (struct osmo_iuup_tnl_prim *)oph;
	struct mgcp_conn *conn_src;
	struct msgb *msg;
	struct rtp_hdr *rtph;
	struct osmo_sockaddr from_addr = {0}; /* FIXME: what to do with this one? */


	OSMO_ASSERT(OSMO_PRIM_HDR(&itp->oph) == OSMO_PRIM(OSMO_IUUP_TNL_UNITDATA, PRIM_OP_REQUEST));

	msg = oph->msg;
	talloc_steal(conn_rtp_dst->conn, msg);

	msgb_pull_to_l2(msg);
	rtph = (struct rtp_hdr *)msgb_push(msg, sizeof(*rtph));
	/* TODO: fill rtph properly: */
	*rtph = (struct rtp_hdr){
		.csrc_count = 0,
		.extension = 0,
		.padding = 0,
		.version = 0,
		.payload_type = conn_rtp_dst->end.codec->payload_type,
		.marker = 0,
		.sequence = 0,
		.timestamp = 0,
		.ssrc = 0
	};

	/* TODO: mgcp_send_rtp() expects msg to have OSMO_RTP_MSG_CTX filled */
	// 	struct osmo_rtp_msg_ctx *mc = OSMO_RTP_MSG_CTX(msg);
	// how to handle an early init packet which need to be answered correct! */


	/* The destination of the destination conn is the source conn, right? */
	conn_src = _find_dst_conn(conn_dst);
	if (conn_src)
		conn_src_rtp = &conn_src->u.rtp;
	else
		conn_src_rtp = &conn_dst->u.rtp;

	/* FIXME: set from_addr = NULL */
	return mgcp_send(conn_dst->endp, 1,
			 &from_addr, msg, conn_src_rtp, conn_rtp_dst);
}

int mgcp_conn_iuup_init(struct mgcp_conn_rtp *conn_rtp)
{
	conn_rtp->type = MGCP_RTP_IUUP;
	conn_rtp->iuup.iui = osmo_iuup_instance_alloc(conn_rtp->conn, conn_rtp->conn->id);
	OSMO_ASSERT(conn_rtp->iuup.iui);
	osmo_iuup_instance_set_user_prim_cb(conn_rtp->iuup.iui, _conn_iuup_user_prim_cb, conn_rtp);
	osmo_iuup_instance_set_transport_prim_cb(conn_rtp->iuup.iui, _conn_iuup_transport_prim_cb, conn_rtp);
	return 0;
}

void mgcp_conn_iuup_cleanup(struct mgcp_conn_rtp *conn_rtp)
{
	osmo_iuup_instance_free(conn_rtp->iuup.iui);
	conn_rtp->iuup.iui = NULL;
}

int mgcp_conn_iuup_dispatch_rtp(struct msgb *msg)
{
	struct osmo_rtp_msg_ctx *mc = OSMO_RTP_MSG_CTX(msg);
	struct mgcp_conn_rtp *conn_rtp_src = mc->conn_src;
	struct mgcp_conn *conn_dst;
	int rc = 0;
	bool force_output_enabled = false;
	int prev_output_enabled;

	OSMO_ASSERT(mgcp_conn_rtp_is_iuup(conn_rtp_src));

	if ((rc = check_rtp_iuup(conn_rtp_src, msg)) < 0)
		goto free_ret;

	if (!conn_rtp_src->iuup.active_init && !conn_rtp_src->iuup.first_rtp_pkt_received) {
		conn_rtp_src->iuup.first_rtp_pkt_received = true;
		/* We received the first message without sending any, the peer is the active side (RNC). */
		conn_dst = _find_dst_conn(conn_rtp_src->conn);
		if (conn_dst && mgcp_conn_rtp_is_iuup(&conn_dst->u.rtp) &&
		    !conn_dst->u.rtp.iuup.first_rtp_pkt_received) {
			conn_dst->u.rtp.iuup.active_init = true;
			/* TODO: start Init as active there */
		}
		rc = _conn_iuup_configure_as_passive(conn_rtp_src, msg);
		if (rc < 0)
			goto free_ret;
		/* We need to force allowance of RTP containing Init-ACK back: */
		prev_output_enabled = conn_rtp_src->end.output_enabled;
		conn_rtp_src->end.output_enabled = 1;
		force_output_enabled = true;
	}

	rc = _conn_iuup_rtp_pl_up(conn_rtp_src, msg);

	if (force_output_enabled)
		conn_rtp_src->end.output_enabled = prev_output_enabled;

	return rc;
free_ret:
	msgb_free(msg);
	return rc;
}

/* Build IuUP RNL Data primitive from msg containing an incoming RTP pkt from
 * peer and send it down the IuUP layer towards the destination as IuUP/RTP: */
int mgcp_conn_iuup_send_rtp(struct mgcp_conn_rtp *conn_src_rtp, struct mgcp_conn_rtp *conn_dest_rtp, struct msgb *msg)
{
	struct osmo_iuup_rnl_prim *irp;
	struct rtp_hdr *rtph;
	struct amr_hdr *amr_hdr;
	int rc = -1;
	int iuup_length = 0;

	/* Tx RNL-DATA.req */
	rtph = (struct rtp_hdr *)msgb_data(msg);
	msgb_pull(msg, sizeof(*rtph));

	/* FIXME: validate amr packets */
	irp = osmo_iuup_rnl_prim_alloc(conn_dest_rtp->conn, OSMO_IUUP_RNL_DATA, PRIM_OP_REQUEST, MGW_IUUP_MSGB_SIZE);

	/* FIXME: We probably need transcoding here?! Or at least look up AMR modes and translate to related RFCI */
	irp->u.data.frame_nr = htons(rtph->sequence) % 16;

	if (msgb_length(msg) < (sizeof(struct amr_hdr))) {
		return -1;
	}

	amr_hdr = (struct amr_hdr *) msgb_data(msg);
	if (mgcp_codec_amr_is_octet_aligned(conn_src_rtp->end.codec)) {
		/* FIXME: CMR handling & multiple frames handling */
		irp->u.data.fqc = IUUP_FQC_FRAME_GOOD;
		irp->u.data.rfci = amr_hdr->ft < 8 ? 0 : 1;
		msgb_pull(msg, 2);
	} else {
		irp->u.data.fqc = amr_hdr->q;
		irp->u.data.rfci = amr_hdr->ft < 8 ? 0 : 1;
		rc = iuup_length = osmo_amr_bwe_to_iuup(msgb_data(msg), msgb_length(msg));
		if (rc < 0) {
			LOG_CONN_RTP(conn_dest_rtp, LOGL_ERROR, "Failed convert the RTP/AMR to IuUP payload\n");
			return rc;
		}
		msgb_trim(msg, iuup_length);
	}

	irp->oph.msg->l3h = msgb_put(irp->oph.msg, msgb_length(msg));
	memcpy(irp->oph.msg->l3h, msgb_data(msg), msgb_length(msg));
	if ((rc = osmo_iuup_rnl_prim_down(conn_dest_rtp->iuup.iui, irp)) != 0) {
		LOG_CONN_RTP(conn_dest_rtp, LOGL_ERROR, "Failed Tx RTP payload down the IuUP layer\n");
		return rc;
	}

	return rc;
}

/* A Media Gateway Control Protocol Media Gateway: RFC 3435 */
/* IuUP Core Network side protocol handling, minimal implementation */

/*
 * (C) 2018 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Neels Hofmeyr <neels@hofmeyr.de>
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

#include <talloc.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/msgb.h>

#include <osmocom/netif/rtp.h>

#include <osmocom/mgcp/iuup_cn_node.h>
#include <osmocom/mgcp/iuup_protocol.h>

#include <osmocom/mgcp/debug.h>

#define LOG_IUUP_CN(cn, level, fmt, args...) \
		LOGP(DIUUP, level, "(%s) " fmt, (cn)->name, ## args)

struct osmo_iuup_cn {
	struct osmo_iuup_cn_cfg cfg;
	char *name;
	uint8_t next_frame_nr;
	int rtp_payload_type;
};

struct osmo_iuup_cn *osmo_iuup_cn_init(void *ctx, struct osmo_iuup_cn_cfg *cfg,
				       const char *name_fmt, ...)
{
	va_list ap;
	struct osmo_iuup_cn *cn = talloc_zero(ctx, struct osmo_iuup_cn);
	OSMO_ASSERT(cn);

	cn->cfg = *cfg;

	if (!name_fmt)
		name_fmt = "-";

	va_start(ap, name_fmt);
	cn->name = talloc_vasprintf(cn, name_fmt, ap);
	va_end(ap);

	LOGP(DIUUP, LOGL_INFO, "(%s) Initializing IuUP node\n", cn->name);

	if (!osmo_identifier_valid(cn->name)) {
		LOGP(DIUUP, LOGL_ERROR, "Attempting to set illegal id for IuUP CN instance: %s\n",
		     osmo_quote_str(cn->name, -1));
		talloc_free(cn);
		return NULL;
	}

	return cn;
}

void osmo_iuup_cn_free(struct osmo_iuup_cn *cn)
{
	talloc_free(cn);
}

static int rx_data(struct osmo_iuup_cn *cn, struct msgb *pdu,
		   struct osmo_iuup_hdr_data *hdr)
{
	/* Remove the IuUP bit from the middle of the buffer by writing the RTP header forward. */
	/* And append AMR 12.2k header "0xf03c". - AD HOC fix */
	unsigned int pre_hdr_len = ((uint8_t*)hdr) - pdu->data;

	int is_comfort_noise = ((pdu->len - pre_hdr_len) == 9);

	memmove(pdu->data + sizeof(*hdr) - 2, pdu->data, pre_hdr_len);
	((uint8_t*)hdr)[2] = 0xf0;
	((uint8_t*)hdr)[3] = is_comfort_noise ? 0x44 : 0x3c;
	msgb_pull(pdu, sizeof(*hdr) - 2);

	LOGP(DIUUP, LOGL_DEBUG, "(%s) IuUP stripping IuUP header from RTP data\n", cn->name);
	cn->cfg.rx_payload(pdu, cn->cfg.node_priv);

	return 0;
}

static int tx_init_ack(struct osmo_iuup_cn *cn, struct msgb *src_pdu)
{
	/* Send Initialization Ack PDU back to the sender */
	int rc;
	struct msgb *ack = msgb_alloc(4096, "IuUP Initialization Ack");
	OSMO_ASSERT(ack);
	ack->dst = src_pdu->dst;

	/* Just copy the RTP header that was sent... TODO: tweak some RTP values?? */
	memcpy(msgb_put(ack, sizeof(struct rtp_hdr)), src_pdu->data, sizeof(struct rtp_hdr));

	osmo_iuup_make_init_ack(ack);

	LOGP(DIUUP, LOGL_DEBUG, "(%s) Sending Initialization ACK %p\n", cn->name, cn->cfg.node_priv);
	rc = cn->cfg.tx_msg(ack, cn->cfg.node_priv);
	msgb_free(ack);
	return rc;
}

static int rx_control(struct osmo_iuup_cn *cn, struct msgb *pdu,
		      struct osmo_iuup_hdr_ctrl *hdr)
{
	switch (hdr->procedure) {
	case OSMO_IUUP_PROC_INITIALIZATION:
		switch (hdr->ack_nack) {
		case OSMO_IUUP_ACKNACK_PROCEDURE:
			LOGP(DIUUP, LOGL_INFO, "(%s) Rx IuUP Initialization, sending ACK\n", cn->name);
			cn->rtp_payload_type = ((struct rtp_hdr*)pdu->data)->payload_type;
			return tx_init_ack(cn, pdu);

		default:
			LOGP(DIUUP, LOGL_DEBUG, "(%s) Rx IuUP Initialization, unhandled ack_nack = %d\n",
			     cn->name, hdr->ack_nack);
			break;
		}
		/* Continue to log "unexpected procedure" below. */
		break;

	case OSMO_IUUP_PROC_ERROR_EVENT:
		{
			union osmo_iuup_hdr_ctrl_payload *p = (void*)hdr->payload;
			LOGP(DIUUP, LOGL_ERROR,
			     "(%s) Rx IuUP Error Event: distance=%u, cause=%u=\"%s\"\n",
			     cn->name, p->error_event.error_distance, p->error_event.error_cause,
			     osmo_iuup_error_cause_name(p->error_event.error_cause));
			return 0;
		}

	default:
		break;
	}
	LOG_IUUP_CN(cn, LOGL_ERROR,
		    "Rx control PDU with unexpected procedure: 0x%x acknack=0x%x\n",
		    hdr->procedure, hdr->ack_nack);
	return -EINVAL;
}

/* Feed a received PDU to the IuUP CN node. This function takes ownership of the msgb, it must not be
 * freed by the caller. */
int osmo_iuup_cn_rx_pdu(struct osmo_iuup_cn *cn, struct msgb *pdu)
{
	struct osmo_iuup_hdr_ctrl *is_ctrl;
	struct osmo_iuup_hdr_data *is_data;
	int rc;

	rc = osmo_iuup_classify(true, cn->name, pdu, &is_ctrl, &is_data);
	if (rc)
		return rc;

	if (is_ctrl)
		return rx_control(cn, pdu, is_ctrl);
	if (is_data)
		return rx_data(cn, pdu, is_data);
	return rc;
}

static uint8_t next_frame_nr(struct osmo_iuup_cn *cn)
{
	uint8_t frame_nr = cn->next_frame_nr;
	cn->next_frame_nr = (frame_nr + 1) & 0x0f;
	return frame_nr;
}

/* Send this RTP packet to the IuUP peer: add IuUP header and call the tx_msg() to transmit the resulting
 * message to the IuUP peer.
 * Returns 0 on success, negative on error. */
int osmo_iuup_cn_tx_payload(struct osmo_iuup_cn *cn, struct msgb *pdu)
{
	struct rtp_hdr *rtp_was, *rtp;
	struct osmo_iuup_hdr_data *iuup_hdr;

	/* Splice an IuUP header in between RTP header and payload data */
	rtp_was = (void*)pdu->data;

	/* copy the RTP header part backwards by the size needed for the IuUP header */
	/* also strips 2 bytes from the front of RTP payload - AMR header - AD HOC fix */
	rtp = (void*)msgb_push(pdu, sizeof(*iuup_hdr) - 2);
	memmove(rtp, rtp_was, sizeof(*rtp));

	/* Send the same payload type to the peer (erm...) */
	rtp->payload_type = cn->rtp_payload_type;

	iuup_hdr = (void*)rtp->data;

	*iuup_hdr = (struct osmo_iuup_hdr_data){
		.pdu_type = OSMO_IUUP_PDU_DATA_WITH_CRC,
		.frame_nr = next_frame_nr(cn),
		.frame_good = OSMO_IUUP_FRAME_GOOD,
	};

	osmo_iuup_set_checksums((uint8_t*)iuup_hdr, pdu->tail - (uint8_t*)iuup_hdr);
	LOGP(DIUUP, LOGL_DEBUG, "(%s) IuUP inserting IuUP header in RTP data (frame nr %u)\n",
	     cn->name, iuup_hdr->frame_nr);

	return cn->cfg.tx_msg(pdu, cn->cfg.node_priv);
}

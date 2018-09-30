/* A Media Gateway Control Protocol Media Gateway: RFC 3435 */
/* IuUP CN node, minimal implementation */

/*                                            _____IuUP_CN_____
 *                                            |               |
 * UE <--> RNC --PDU-> osmo_iuup_cn_rx_pdu() -+->           ---+-> rx_payload()
 *          |                                 |               |
 *          |  <-PDU-- tx_msg() <-------------+--           <-+--- osmo_iuup_cn_tx_payload()
 *                                            |               |
 *                                            -----------------
 */

#pragma once

struct msgb;

typedef int (*osmo_iuup_data_cb_t)(struct msgb *msg, void *node_priv);

struct osmo_iuup_cn_cfg {
	void *node_priv;

	/* When the IuUP peer sent a voice packet, the clean RTP without the IuUP header is fed to this
	 * callback. */
	osmo_iuup_data_cb_t rx_payload;

	/* IuUP handler requests that a PDU shall be sent to the IuUP peer (e.g. the RNC).
	 * It is guaranteed that the msgb->dst pointer is preserved or copied from the msgb that
	 * originated the request. */
	osmo_iuup_data_cb_t tx_msg;
};

struct osmo_iuup_cn {
	struct osmo_iuup_cn_cfg cfg;
	char *name;
	uint8_t next_frame_nr;
	int rtp_payload_type;
};

bool osmo_iuup_cn_is_iuup_init(struct msgb *msg);

struct osmo_iuup_cn *osmo_iuup_cn_init(void *ctx, struct osmo_iuup_cn_cfg *cfg,
				       const char *name_fmt, ...);
void osmo_iuup_cn_free(struct osmo_iuup_cn *cn);

int osmo_iuup_cn_tx_payload(struct osmo_iuup_cn *cn, struct msgb *payload);

int osmo_iuup_cn_rx_pdu(struct osmo_iuup_cn *cn, struct msgb *pdu);

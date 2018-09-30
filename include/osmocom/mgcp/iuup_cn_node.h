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

struct osmo_iuup_cn;
struct msgb;

typedef int (*osmo_iuup_data_cb_t)(struct msgb *msg, void *node_priv, void *pdu_priv);

struct osmo_iuup_cn_cfg {
	void *node_priv;

	/* When an IuUP PDU containing voice payload has been received, this callback is invoked to pass
	 * the voice payload towards the Core Network, msgb_l3() pointing at the payload. */
	osmo_iuup_data_cb_t rx_payload;

	/* IuUP handler sends a PDU to the IuUP peer (e.g. the RNC) */
	osmo_iuup_data_cb_t tx_msg;
};

bool osmo_iuup_cn_is_iuup_init(struct msgb *msg);

struct osmo_iuup_cn *osmo_iuup_cn_init(void *ctx, struct osmo_iuup_cn_cfg *cfg,
				       const char *name_fmt, ...);
void osmo_iuup_cn_free(struct osmo_iuup_cn *cn);

/* Encapsulate voice stream payload in IuUP and, if appropriate, call the tx_msg() to transmit the
 * resulting message to the IuUP peer. msgb_l3() should point at the payload data.
 * pdu_priv is transparently passed on to tx_msg().
 * Returns 0 on success, negative on error. */
int osmo_iuup_cn_tx_payload(struct osmo_iuup_cn *cn, struct msgb *payload, void *pdu_priv);

/* Feed a received PDU to the IuUP CN node. This function takes ownership of the msgb, it must not be
 * freed by the caller. */
int osmo_iuup_cn_rx_pdu(struct osmo_iuup_cn *cn, struct msgb *pdu, void *pdu_priv);

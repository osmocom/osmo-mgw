#pragma once

struct msgb;
struct gprs_ra_id;

struct ue_conn_ctx {
	struct llist_head list;
	struct osmo_sua_link *link;
	uint32_t conn_id;
};

typedef int (* iu_recv_cb_t )(struct msgb *msg, struct gprs_ra_id *ra_id,
			      /* TODO is ra_id only used for gprs? ^ */
			      uint16_t *sai);

int iu_tx(struct msgb *msg, uint8_t sapi);

int iu_rab_act_cs(struct ue_conn_ctx *ue_ctx, uint32_t rtp_ip, uint16_t rtp_port);
int iu_rab_act_ps(struct ue_conn_ctx *ue_ctx, uint32_t gtp_ip, uint32_t gtp_tei);
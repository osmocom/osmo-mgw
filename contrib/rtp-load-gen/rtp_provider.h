#pragma once
#include <stdint.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/utils.h>

enum codec_type {
	CODEC_ULAW,
	CODEC_ALAW,
	CODEC_GSM_FR,
	CODEC_GSM_EFR,
	CODEC_GSM_HR,
	CODEC_AMR_4_75,
	CODEC_AMR_5_15,
	CODEC_AMR_5_90,
	CODEC_AMR_6_70,
	CODEC_AMR_7_40,
	CODEC_AMR_7_95,
	CODEC_AMR_10_2,
	CODEC_AMR_12_2,
	CODEC_AMR_SID,
	_NUM_CODECS
};

extern const struct value_string codec_type_names[];

struct rtp_provider_instance;

struct rtp_provider {
	/* global list of RTP providers */
	struct llist_head list;
	const char *name;

	/* create/initialie a RTP provider with specified argument string */
	int (*setup)(struct rtp_provider_instance *inst, const char *arg);

	/* generate the next RTP packet; return length in octests or negative on error */
	int (*rtp_gen)(struct rtp_provider_instance *inst, uint8_t *out, size_t out_size);
};

struct rtp_provider_instance {
	/* entry in global list of RTP provider instances */
	struct llist_head list;
	/* pointer to provider of which we are an instance */
	const struct rtp_provider *provider;
	/* codec payload we are to generate */
	enum codec_type codec;

	/* private user data */
	void *priv;
};

void rtp_provider_register(struct rtp_provider *prov);
const struct rtp_provider *rtp_provider_find(const char *name);

struct rtp_provider_instance *rtp_provider_instance_alloc(void *ctx, const struct rtp_provider *provider, enum codec_type codec);
void rtp_provider_instance_free(struct rtp_provider_instance *pi);
int rtp_provider_instance_gen_frame(struct rtp_provider_instance *pi, uint8_t *out, size_t out_size);

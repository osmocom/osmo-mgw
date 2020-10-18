#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/logging.h>

#include "rtp_provider.h"
#include "internal.h"


static LLIST_HEAD(g_providers);

const struct value_string codec_type_names[] = {
	{ CODEC_ULAW,		"ULAW" },
	{ CODEC_ALAW,		"ALAW" },
	{ CODEC_GSM_FR,		"GSM_FR" },
	{ CODEC_GSM_EFR,	"GSM_EFR" },
	{ CODEC_GSM_HR,		"GSM_HR" },
	{ CODEC_AMR_4_75,	"AMR_4_75" },
	{ CODEC_AMR_5_15,	"AMR_5_15" },
	{ CODEC_AMR_5_90,	"AMR_5_90" },
	{ CODEC_AMR_6_70,	"AMR_6_70" },
	{ CODEC_AMR_7_40,	"AMR_7_40" },
	{ CODEC_AMR_7_95,	"AMR_7_95" },
	{ CODEC_AMR_10_2,	"AMR_10_2" },
	{ CODEC_AMR_12_2,	"AMR_12_2" },
	{ CODEC_AMR_SID,	"AMR_SID" },
	{ 0, NULL }
};

void rtp_provider_register(struct rtp_provider *prov)
{
	llist_add_tail(&prov->list, &g_providers);
}

const struct rtp_provider *rtp_provider_find(const char *name)
{
	struct rtp_provider *p;
	llist_for_each_entry(p, &g_providers, list) {
		if (!strcmp(name, p->name))
			return p;
	}
	LOGP(DMAIN, LOGL_ERROR, "Couldn't find RTP provider '%s'\n", name);
	return NULL;
}

struct rtp_provider_instance *
rtp_provider_instance_alloc(void *ctx, const struct rtp_provider *provider, enum codec_type codec)
{
	struct rtp_provider_instance *pi;

	pi = talloc_zero(ctx, struct rtp_provider_instance);
	if (!pi)
		return NULL;

	pi->provider = provider;
	pi->codec = codec;

	return pi;
}

void rtp_provider_instance_free(struct rtp_provider_instance *pi)
{
	llist_del(&pi->list);
	talloc_free(pi);
}

int rtp_provider_instance_gen_frame(struct rtp_provider_instance *pi, uint8_t *out, size_t out_size)
{
	OSMO_ASSERT(pi->provider);
	return pi->provider->rtp_gen(pi, out, out_size);
}

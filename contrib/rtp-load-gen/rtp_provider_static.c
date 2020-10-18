
#include <errno.h>
#include <osmocom/codec/codec.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/logging.h>

#include "rtp_provider.h"
#include "internal.h"

static struct rtp_provider static_provider;

static const uint8_t len4codec[_NUM_CODECS] = {
    [CODEC_ULAW] = 160,
    [CODEC_ALAW] = 160,
    [CODEC_GSM_FR] = GSM_FR_BYTES,
    [CODEC_GSM_EFR] = GSM_EFR_BYTES,
    [CODEC_GSM_HR] = GSM_HR_BYTES,
    [CODEC_AMR_4_75] = 12,
    [CODEC_AMR_5_15] = 13,
    [CODEC_AMR_5_90] = 15,
    [CODEC_AMR_6_70] = 17,
    [CODEC_AMR_7_40] = 19,
    [CODEC_AMR_7_95] = 20,
    [CODEC_AMR_10_2] = 26,
    [CODEC_AMR_12_2] = 31,
    [CODEC_AMR_SID] = 5,
};

/* generate a static / fixed RTP payload of matching codec/mode */
static int rtp_gen_static(struct rtp_provider_instance *pi, uint8_t *out, size_t out_size)
{
	uint8_t len;

	OSMO_ASSERT(pi->provider == &static_provider);

	len = len4codec[pi->codec];
	if (out_size < len) {
		LOGP(DMAIN, LOGL_ERROR, "out_size %zu < %u\n", out_size, len);
		return -EINVAL;
	}

	memset(out, 0, len);

	switch (pi->codec) {
	case CODEC_ULAW:
	case CODEC_ALAW:
		break;
	case CODEC_GSM_FR:
		out[0] = (out[0] & 0x0f) | 0xD0; /* mask in first four bit for FR */
		break;
	case CODEC_GSM_EFR:
		out[0] = (out[0] & 0x0f) | 0xC0; /* mask in first four bit for EFR */
		break;
	case CODEC_GSM_HR:
		break;
	case CODEC_AMR_4_75:
		out[0] = 0 << 4;
		out[1] = 0 << 3;
		break;
	case CODEC_AMR_5_15:
		out[0] = 1 << 4;
		out[1] = 1 << 3;
		break;
	case CODEC_AMR_5_90:
		out[0] = 2 << 4;
		out[1] = 2 << 3;
		break;
	case CODEC_AMR_6_70:
		out[0] = 3 << 4;
		out[1] = 3 << 3;
		break;
	case CODEC_AMR_7_40:
		out[0] = 4 << 4;
		out[1] = 4 << 3;
		break;
	case CODEC_AMR_7_95:
		out[0] = 5 << 4;
		out[1] = 5 << 3;
		break;
	case CODEC_AMR_10_2:
		out[0] = 6 << 4;
		out[1] = 6 << 3;
		break;
	case CODEC_AMR_12_2:
		out[0] = 7 << 4;
		out[1] = 7 << 3;
		break;
	case CODEC_AMR_SID:
		out[0] = 2 << 4; /* CMR: 5.90 */
		out[0] = 8 << 3;
		break;
	default:
		OSMO_ASSERT(0);
	}

	return len;
}


static struct rtp_provider static_provider = {
	.name = "static",
	.rtp_gen = &rtp_gen_static,
};

static void __attribute__((constructor)) rtp_provider_static_constr(void)
{
	rtp_provider_register(&static_provider);
}

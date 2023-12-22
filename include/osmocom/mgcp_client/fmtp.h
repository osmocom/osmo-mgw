#pragma once

#include <stddef.h>
#include <stdbool.h>

#define OSMO_SDP_NAME_A "a"
#define OSMO_SDP_NAME_FMTP "fmtp"
#define OSMO_SDP_NAME_AMR_OCTET_ALIGN "octet-align"

#define OSMO_SDP_VAL_AMR_OCTET_ALIGN_0 OSMO_SDP_NAME_AMR_OCTET_ALIGN "=0"
#define OSMO_SDP_VAL_AMR_OCTET_ALIGN_1 OSMO_SDP_NAME_AMR_OCTET_ALIGN "=1"

/* "fmtp:" */
#define OSMO_SDP_PREFIX_FMTP OSMO_SDP_NAME_FMTP ":"
/* "a=fmtp:" */
#define OSMO_SDP_PREFIX_A_FMTP OSMO_SDP_NAME_A "=" OSMO_SDP_PREFIX_FMTP

bool osmo_sdp_fmtp_get_val(char *val, size_t val_size, const char *fmtp, const char *option_name);
int osmo_sdp_fmtp_get_int(const char *fmtp, const char *option_name, int default_value);

/* Some AMR related fmtp parameters as in https://www.rfc-editor.org/rfc/rfc4867#section-8.1 that osmo-mgw needs.*/
bool osmo_sdp_fmtp_amr_is_octet_aligned(const char *fmtp);

/*! To compose AMR related fmtp indicating octet-align.
 * Usage:
 *   printf("%s", OSMO_SDP_AMR_SET_OCTET_ALIGN(oa_flag));
 */
#define OSMO_SDP_AMR_SET_OCTET_ALIGN(VAL) \
	((VAL) ? OSMO_SDP_VAL_AMR_OCTET_ALIGN_1 : OSMO_SDP_VAL_AMR_OCTET_ALIGN_0 )

/* Central definition of string tokens used for parsing and composing SDP messages */
#pragma once

#define OSMO_SDP_STR_MEDIA "m"
#define OSMO_SDP_STR_ATTRIB "a"
#define OSMO_SDP_STR_TIME_ACTIVE "t"

#define OSMO_SDP_STR_RTPMAP "rtpmap"
#define OSMO_SDP_STR_FMTP "fmtp"
#define OSMO_SDP_STR_PTIME "ptime"

/*! "a=foo:" */
#define OSMO_SDP_A_PREFIX(STR) OSMO_SDP_STR_ATTRIB "=" STR ":"

/*! "a=fmtp:" */
#define OSMO_SDP_STR_A_FMTP OSMO_SDP_A_PREFIX(OSMO_SDP_STR_FMTP)

/* Media Direction Attributes "a=recvonly", "a=sendrecv", "a=sendonly", "a=inactive" RFC-8866 6.7. */
#define OSMO_SDP_STR_RECVONLY "recvonly"
#define OSMO_SDP_STR_SENDRECV "sendrecv"
#define OSMO_SDP_STR_SENDONLY "sendonly"
#define OSMO_SDP_STR_INACTIVE "inactive"

/* AMR related tokens */

#define OSMO_SDP_STR_AMR_OCTET_ALIGN "octet-align"

/*! "octet-align=1" */
#define OSMO_SDP_STR_AMR_OCTET_ALIGN_1  OSMO_SDP_STR_AMR_OCTET_ALIGN "=1"

/*! "octet-align=0".
 * According to spec [1], "octet-align=0" is identical to omitting 'octet-align' entirely. In Osmocom practice, whether
 * or not "octet-align=0" is present can make a big difference for osmo-mgw versions 1.12 and older, which do not heed
 * [1].
 *
 * spec [1]: RFC4867, see details in description of osmo_sdp_fmtp_amr_is_octet_aligned().
 */
#define OSMO_SDP_STR_AMR_OCTET_ALIGN_0  OSMO_SDP_STR_AMR_OCTET_ALIGN "=0"


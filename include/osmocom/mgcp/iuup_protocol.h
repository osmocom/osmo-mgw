/* A Media Gateway Control Protocol Media Gateway: RFC 3435 */
/* IuUP protocol handling, minimal implementation */

#pragma once

#include <osmocom/core/endian.h>
#include <osmocom/core/msgb.h>

#define OSMO_IUUP_HEADROOM 32

enum osmo_iuup_pdu_type {
	OSMO_IUUP_PDU_DATA_WITH_CRC = 0,
	OSMO_IUUP_PDU_CONTROL_PROCEDURE = 14,
};

enum osmo_iuup_acknack {
	OSMO_IUUP_ACKNACK_PROCEDURE = 0,
	OSMO_IUUP_ACKNACK_ACK = 1,
	OSMO_IUUP_ACKNACK_NACK = 2,
};

enum osmo_iuup_procedure {
	OSMO_IUUP_PROC_INITIALIZATION = 0,
	OSMO_IUUP_PROC_RATE_CONTROL = 1,
	OSMO_IUUP_PROC_TIME_ALIGNMENT = 2,
	OSMO_IUUP_PROC_ERROR_EVENT = 3,
};

enum osmo_iuup_frame_good {
	OSMO_IUUP_FRAME_GOOD = 0,
	OSMO_IUUP_FRAME_BAD = 1,
	OSMO_IUUP_FRAME_BAD_DUE_TO_RADIO = 2,
};

struct osmo_iuup_hdr_ctrl {
#if OSMO_IS_BIG_ENDIAN
	uint8_t pdu_type:4,
		ack_nack:2,
		frame_nr:2;
	uint8_t mode_version:4,
		procedure:4;
	uint8_t header_crc:6,
		payload_crc_hi:2;
	uint8_t payload_crc_lo;
	uint8_t payload[0];
#elif OSMO_IS_LITTLE_ENDIAN
	uint8_t frame_nr:2,
		ack_nack:2,
		pdu_type:4;
	uint8_t procedure:4,
		mode_version:4;
	uint8_t payload_crc_hi:2,
		header_crc:6;
	uint8_t payload_crc_lo;
	uint8_t payload[0];
#endif
} __attribute__((packed));

union osmo_iuup_hdr_ctrl_payload {
	struct {
#if OSMO_IS_BIG_ENDIAN
	uint8_t spare:3,
		iptis_present:1,
		subflows:3,
		chain:1;
#elif OSMO_IS_LITTLE_ENDIAN
	uint8_t spare:3,
		iptis_present:1,
		subflows:3,
		chain:1;
#endif
	} initialization;

	struct {
#if OSMO_IS_BIG_ENDIAN
	uint8_t error_distance:2,
		error_cause:6;
#elif OSMO_IS_LITTLE_ENDIAN
	uint8_t error_cause:6,
		error_distance:2;
#endif
	} error_event;
};

extern const struct value_string osmo_iuup_error_cause_names[];
static inline const char *osmo_iuup_error_cause_name(uint8_t val)
{ return get_value_string(osmo_iuup_error_cause_names, val); }

struct osmo_iuup_hdr_data {
#if OSMO_IS_BIG_ENDIAN
	uint8_t pdu_type:4,
		frame_nr:4;
	uint8_t frame_good:2,
		rfci:6;
	uint8_t header_crc:6,
		payload_crc_hi:2;
	uint8_t payload_crc_lo;
#elif OSMO_IS_LITTLE_ENDIAN
	uint8_t frame_nr:4,
		pdu_type:4;
	uint8_t rfci:6,
		frame_good:2;
	uint8_t payload_crc_hi:2,
		header_crc:6;
	uint8_t payload_crc_lo;
#endif
	uint8_t payload[0];
} __attribute__((packed));

int osmo_iuup_classify(bool log_errors,
		       const char *log_label,
		       struct msgb *pdu,
		       struct osmo_iuup_hdr_ctrl **is_ctrl,
		       struct osmo_iuup_hdr_data **is_data);
bool osmo_iuup_is_init(struct msgb *pdu);
void osmo_iuup_make_init_ack(struct msgb *ack);
void osmo_iuup_set_checksums(uint8_t *iuup_header_and_payload, unsigned int header_and_payload_len);

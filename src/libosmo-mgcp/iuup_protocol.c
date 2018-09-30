/* A Media Gateway Control Protocol Media Gateway: RFC 3435 */
/* IuUP Core Network side protocol, minimal implementation */

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

#include <errno.h>
#include <osmocom/mgcp/iuup_protocol.h>
#include <osmocom/mgcp/debug.h>
#include <osmocom/netif/rtp.h>

/* Calculating two bytes of CRC is ok to do by a loop */
static uint8_t header_crc6(const uint8_t *hdr)
{
    int bit;
    /* Polynomial: D^6 + D^5 + D^3 + D^2 + D^1 + 1
     * that's 1101111 or 0x6f;
     * align its lowest bit with a uint16_t's highest bit: */
    uint32_t polynomial = 0x6f << 15; // 00110111 10000000 00000000
    uint32_t remainder = ( ((uint32_t)hdr[0]) << 8 | hdr[1] ) << 6;

    for (bit = 15; bit >= 0; bit--)
    {
        if (remainder & (0x40 << bit))
            remainder ^= polynomial;
        polynomial >>= 1;
    }

    return remainder;
}

/*
 * Charles Michael Heard's CRC-10 code, from
 *
 *      http://web.archive.org/web/20061005231950/http://cell-relay.indiana.edu/cell-relay/publications/software/CRC/crc10.html
 *
 * with the CRC table initialized with values computed by
 * his "gen_byte_crc10_table()" routine, rather than by calling that
 * routine at run time, and with various data type cleanups.
 */
static const uint16_t byte_crc10_table[256] = {
	0x0000, 0x0233, 0x0255, 0x0066, 0x0299, 0x00aa, 0x00cc, 0x02ff,
	0x0301, 0x0132, 0x0154, 0x0367, 0x0198, 0x03ab, 0x03cd, 0x01fe,
	0x0031, 0x0202, 0x0264, 0x0057, 0x02a8, 0x009b, 0x00fd, 0x02ce,
	0x0330, 0x0103, 0x0165, 0x0356, 0x01a9, 0x039a, 0x03fc, 0x01cf,
	0x0062, 0x0251, 0x0237, 0x0004, 0x02fb, 0x00c8, 0x00ae, 0x029d,
	0x0363, 0x0150, 0x0136, 0x0305, 0x01fa, 0x03c9, 0x03af, 0x019c,
	0x0053, 0x0260, 0x0206, 0x0035, 0x02ca, 0x00f9, 0x009f, 0x02ac,
	0x0352, 0x0161, 0x0107, 0x0334, 0x01cb, 0x03f8, 0x039e, 0x01ad,
	0x00c4, 0x02f7, 0x0291, 0x00a2, 0x025d, 0x006e, 0x0008, 0x023b,
	0x03c5, 0x01f6, 0x0190, 0x03a3, 0x015c, 0x036f, 0x0309, 0x013a,
	0x00f5, 0x02c6, 0x02a0, 0x0093, 0x026c, 0x005f, 0x0039, 0x020a,
	0x03f4, 0x01c7, 0x01a1, 0x0392, 0x016d, 0x035e, 0x0338, 0x010b,
	0x00a6, 0x0295, 0x02f3, 0x00c0, 0x023f, 0x000c, 0x006a, 0x0259,
	0x03a7, 0x0194, 0x01f2, 0x03c1, 0x013e, 0x030d, 0x036b, 0x0158,
	0x0097, 0x02a4, 0x02c2, 0x00f1, 0x020e, 0x003d, 0x005b, 0x0268,
	0x0396, 0x01a5, 0x01c3, 0x03f0, 0x010f, 0x033c, 0x035a, 0x0169,
	0x0188, 0x03bb, 0x03dd, 0x01ee, 0x0311, 0x0122, 0x0144, 0x0377,
	0x0289, 0x00ba, 0x00dc, 0x02ef, 0x0010, 0x0223, 0x0245, 0x0076,
	0x01b9, 0x038a, 0x03ec, 0x01df, 0x0320, 0x0113, 0x0175, 0x0346,
	0x02b8, 0x008b, 0x00ed, 0x02de, 0x0021, 0x0212, 0x0274, 0x0047,
	0x01ea, 0x03d9, 0x03bf, 0x018c, 0x0373, 0x0140, 0x0126, 0x0315,
	0x02eb, 0x00d8, 0x00be, 0x028d, 0x0072, 0x0241, 0x0227, 0x0014,
	0x01db, 0x03e8, 0x038e, 0x01bd, 0x0342, 0x0171, 0x0117, 0x0324,
	0x02da, 0x00e9, 0x008f, 0x02bc, 0x0043, 0x0270, 0x0216, 0x0025,
	0x014c, 0x037f, 0x0319, 0x012a, 0x03d5, 0x01e6, 0x0180, 0x03b3,
	0x024d, 0x007e, 0x0018, 0x022b, 0x00d4, 0x02e7, 0x0281, 0x00b2,
	0x017d, 0x034e, 0x0328, 0x011b, 0x03e4, 0x01d7, 0x01b1, 0x0382,
	0x027c, 0x004f, 0x0029, 0x021a, 0x00e5, 0x02d6, 0x02b0, 0x0083,
	0x012e, 0x031d, 0x037b, 0x0148, 0x03b7, 0x0184, 0x01e2, 0x03d1,
	0x022f, 0x001c, 0x007a, 0x0249, 0x00b6, 0x0285, 0x02e3, 0x00d0,
	0x011f, 0x032c, 0x034a, 0x0179, 0x0386, 0x01b5, 0x01d3, 0x03e0,
	0x021e, 0x002d, 0x004b, 0x0278, 0x0087, 0x02b4, 0x02d2, 0x00e1
};

static uint16_t crc10(uint16_t crc10_accum, const uint8_t *payload, unsigned int payload_len)
{
	int i;

	for (i = 0; i < payload_len; i++) {
		crc10_accum = ((crc10_accum << 8) & 0x300)
			^ byte_crc10_table[(crc10_accum >> 2) & 0xff]
			^ payload[i];
	}
	return crc10_accum;
}

/* When a payload of a multiple of bytes has run through, we need to still feed 10 bits of zeros into the
 * CRC10 to get the payload's checksum result that we can send to a peer. That can't be done with above
 * table, because it acts as if full 16 bits are fed. This stops after 10 bits. */
static uint16_t crc10_remainder(uint16_t crc10_accum)
{
    int bit;
    /* Polynomial: D^10 + D^9 + D^5 + D^4 + D^1 + 1
     * that's 11000110011 or 0x633;
     * align its lowest bit with a 10bit value's highest bit: */
    uint32_t polynomial = 0x633 << 9; // 1100 01100110 00000000
    uint32_t remainder = ((uint32_t)crc10_accum) << 10;

    /* Run on 10 bits */
    for (bit = 9; bit >= 0; bit--)
    {
        if (remainder & ((1 << 10) << bit))
            remainder ^= polynomial;
        polynomial >>= 1;
    }

    return remainder & 0x3ff;
}

static uint16_t payload_crc10(const uint8_t *payload, unsigned int payload_len)
{
	uint16_t crc10_accum = crc10(0, payload, payload_len);
	return crc10_remainder(crc10_accum);
}

/* Given an IuUP PDU data block, write the correct header and payload CRC checksums at the right places.
 */
void osmo_iuup_set_checksums(uint8_t *iuup_header_and_payload, unsigned int header_and_payload_len)
{
	/* For both data and ctrl, the checksums and payload are at the same offset */
	struct osmo_iuup_hdr_data *hdr = (void*)iuup_header_and_payload;
	uint16_t crc;
	unsigned int payload_len;

	hdr->header_crc = header_crc6(iuup_header_and_payload);

	payload_len = iuup_header_and_payload + header_and_payload_len - hdr->payload;
	crc = payload_crc10(hdr->payload, payload_len);
	hdr->payload_crc_hi = (crc >> 8) & 0x3;
	hdr->payload_crc_lo = crc & 0xff;

}

/* Validate minimum message sizes, IuUP PDU type, header- and payload checksums. If it is a Control
 * Procedure PDU, return the header position in is_ctrl, if it is a Data PDU, return the header position
 * in is_data. If log_errors is true, log on DIUUP with the given log label for context. Return NULL in
 * both is_ctrl and is_data, and return a negative error code if the PDU could not be identified as a
 * valid RTP PDU containing an IuUP part. */
int osmo_iuup_classify(bool log_errors,
		       const char *log_label,
		       struct msgb *pdu,
		       struct osmo_iuup_hdr_ctrl **is_ctrl,
		       struct osmo_iuup_hdr_data **is_data)
{
	struct rtp_hdr *rtp = (void*)pdu->data;
	struct osmo_iuup_hdr_ctrl *hdr = (void*)rtp->data;
	unsigned int payload_len;
	uint16_t crc_calculated;
	uint16_t crc_from_peer;

#define ERR(fmt, args...) do { \
			if (log_errors) \
				LOGP(DIUUP, LOGL_ERROR, "(%s) " fmt, log_label? : "-", ## args); \
			return -EINVAL; \
		} while (0)

	if (is_ctrl)
		*is_ctrl = NULL;
	if (is_data)
		*is_data = NULL;

	/* We need at least a header of 4 bytes. The osmo_iuup_hdr_ctrl already includes a byte of
	 * payload, so use osmo_iuup_hdr_data to check the minimum here. */
	if (pdu->len < (sizeof(*rtp) + sizeof(struct osmo_iuup_hdr_data)))
		ERR("IuUP PDU too short: %u\n", pdu->len);

	/* Let's not validate checksums if the header type isn't sane */
	switch (hdr->pdu_type) {
	case OSMO_IUUP_PDU_DATA_WITH_CRC:
		/* If the caller isn't interested in data PDUs, cut short here. */
		if (!is_data)
			return 0;
		break;
	case OSMO_IUUP_PDU_CONTROL_PROCEDURE:
		/* If the caller isn't interested in control PDUs, cut short here. */
		if (!is_ctrl)
			return 0;
		if (pdu->len < (sizeof(*rtp) + sizeof(struct osmo_iuup_hdr_ctrl)))
			ERR("IuUP control PDU too short: %u\n", pdu->len);
		break;
	default:
		ERR("IuUP with invalid type: %u\n", hdr->pdu_type);
	}

	/* For both data and ctrl, the checksums and payload are at the same offset */

	crc_calculated = header_crc6((uint8_t*)hdr);
	if (crc_calculated != hdr->header_crc)
		ERR("IuUP PDU with invalid header CRC (peer sent 0x%x, calculated 0x%x)\n",
		    hdr->header_crc, crc_calculated);

	payload_len = pdu->tail - hdr->payload;
	crc_calculated = payload_crc10(hdr->payload, payload_len);
	crc_from_peer = (((uint16_t)hdr->payload_crc_hi) << 8) | hdr->payload_crc_lo;
	if (crc_from_peer != crc_calculated)
		ERR("IuUP PDU with invalid payload CRC (peer sent 0x%x, calculated 0x%x)\n",
		    crc_from_peer, crc_calculated);

	switch (hdr->pdu_type) {
	case OSMO_IUUP_PDU_DATA_WITH_CRC:
		if (is_data)
			*is_data = (void*)hdr;
		return 0;
	case OSMO_IUUP_PDU_CONTROL_PROCEDURE:
		if (is_ctrl)
			*is_ctrl = hdr;
		return 0;
	default:
		ERR("IuUP with invalid type: %u\n", hdr->pdu_type);
	}
#undef ERR
}

/* Return true if this RTP packet contains an IuUP Initialization header (detect IuUP peer). */
bool osmo_iuup_is_init(struct msgb *pdu)
{
	struct osmo_iuup_hdr_ctrl *is_ctrl;
	osmo_iuup_classify(false, NULL, pdu, &is_ctrl, NULL);
	return is_ctrl
		&& is_ctrl->procedure == OSMO_IUUP_PROC_INITIALIZATION
		&& is_ctrl->ack_nack == OSMO_IUUP_ACKNACK_PROCEDURE;
}

/* Append an IuUP Initialization ACK message */
void osmo_iuup_make_init_ack(struct msgb *ack)
{
	/* Send Initialization Ack PDU back to the sender */
	struct osmo_iuup_hdr_ctrl *hdr;
	OSMO_ASSERT(ack);

	hdr = (void*)msgb_put(ack, sizeof(*hdr));

	*hdr = (struct osmo_iuup_hdr_ctrl){
		.pdu_type = OSMO_IUUP_PDU_CONTROL_PROCEDURE,
		.ack_nack = OSMO_IUUP_ACKNACK_ACK,
		.procedure = OSMO_IUUP_PROC_INITIALIZATION,
	};

	osmo_iuup_set_checksums((uint8_t*)hdr, sizeof(*hdr));
}

const struct value_string osmo_iuup_error_cause_names[] = {
	{ 0, "CRC error of frame header" },
	{ 1, "CRC error of frame payload" },
	{ 2, "Unexpected frame number" },
	{ 3, "Frame loss" },
	{ 4, "PDU type unknown" },
	{ 5, "Unknown procedure" },
	{ 6, "Unknown reserved value" },
	{ 7, "Unknown field" },
	{ 8, "Frame too short" },
	{ 9, "Missing fields" },
	{ 16, "Unexpected PDU type" },
	{ 17, "spare" },
	{ 18, "Unexpected procedure" },
	{ 19, "Unexpected RFCI" },
	{ 20, "Unexpected value" },
	{ 42, "Initialisation failure" },
	{ 43, "Initialisation failure (network error, timer expiry)" },
	{ 44, "Initialisation failure (Iu UP function error, repeated NACK)" },
	{ 45, "Rate control failure" },
	{ 46, "Error event failure" },
	{ 47, "Time Alignment not supported" },
	{ 48, "Requested Time Alignment not possible" },
	{ 49, "Iu UP Mode version not supported" },
	{}
};

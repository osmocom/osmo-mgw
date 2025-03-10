#pragma once

/* A 64k timeslot on an E1 line can be subdevied into the following
 * subslot combinations:
 *
 * subslot:                                          offset:
 * [          ][          ][   16k    ][8k_subslot]  0
 * [          ][   32k    ][_subslot__][8k_subslot]  1
 * [          ][ subslot  ][   16k    ][8k_subslot]  2
 * [   64k    ][__________][_subslot__][8k_subslot]  3
 * [ timeslot ][          ][   16k    ][8k_subslot]  4
 * [          ][   32K    ][_subslot__][8k_subslot]  5
 * [          ][ subslot  ][   16k    ][8k_subslot]  6
 * [          ][          ][ subslot  ][8k_subslot]  7
 *
 * Since overlapping assignment of subslots is not possible there is a limited
 * set of subslot assignments possible. The e1_rates array lists the possible
 * assignments as depicted above. Also each subslot assignment comes along with
 * a bit offset in the E1 bitstream. The e1_offsets arrays lists the bit
 * offsets. */
static const uint8_t e1_rates[] = { 64, 32, 32, 16, 16, 16, 16, 8, 8, 8, 8, 8, 8, 8, 8 };
static const uint8_t e1_offsets[] = { 0, 0, 4, 0, 2, 4, 6, 0, 1, 2, 3, 4, 5, 6, 7 };

int mgcp_e1_endp_equip(struct mgcp_endpoint *endp, uint8_t ts, uint8_t ss, uint8_t offs);
int mgcp_e1_endp_update(struct mgcp_endpoint *endp);
void mgcp_e1_endp_release(struct mgcp_endpoint *endp, uint8_t ts);
int mgcp_e1_send_rtp(struct mgcp_endpoint *endp, struct mgcp_rtp_codec *codec, struct msgb *msg);

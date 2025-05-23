/* E1 traffic handling */

/*
 * (C) 2020 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Philipp Maier
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

#include <inttypes.h>

#include <osmocom/mgcp/mgcp_protocol.h>
#include <osmocom/mgcp/mgcp.h>
#include <osmocom/mgcp/mgcp_endp.h>
#include <osmocom/mgcp/mgcp_trunk.h>
#include <osmocom/mgcp/mgcp_conn.h>
#include <osmocom/core/msgb.h>
#include <osmocom/abis/e1_input.h>
#include <osmocom/abis/abis.h>

#include <osmocom/trau/trau_sync.h>
#include <osmocom/trau/trau_frame.h>
#include <osmocom/trau/trau_rtp.h>
#include <osmocom/mgcp/mgcp_conn.h>
#include <osmocom/netif/rtp.h>
#include <osmocom/mgcp/debug.h>
#include <osmocom/mgcp/mgcp_e1.h>
#include <osmocom/codec/codec.h>
#include <osmocom/gsm/rtp_extensions.h>

#define DEBUG_BITS_MAX 80
#define DEBUG_BYTES_MAX 40
#define DEBUG_E1_TS 0
#define E1_TS_BYTES 160
#define E1_TRAU_BITS 320
#define E1_TRAU_BITS_MSGB 2048

static struct mgcp_config *cfg;

static const struct e1inp_line_ops dummy_e1_line_ops = {
	.sign_link_up = NULL,
	.sign_link_down = NULL,
	.sign_link = NULL,
};

/* If the RTP transmission has dropouts for some reason the I.460 TX-Queue may
 * run empty. In order to make sure that the TRAU frame transmission continues
 * we generate idle TRAU frames here. */
static void e1_i460_mux_empty_cb(struct osmo_i460_subchan *schan, void *user_data)
{
	struct mgcp_endpoint *endp = user_data;
	struct rate_ctr_group *rate_ctrs = endp->trunk->ratectr.e1_stats;
	struct msgb *msg = msgb_alloc_c(endp->trunk, E1_TRAU_BITS_MSGB, "E1-I.460-IDLE-TX-TRAU-frame");
	const uint8_t *dummy_fill_pl;
	unsigned dummy_fill_pl_len;
	struct osmo_trau_frame tf;
	int rc;

	rate_ctr_inc(rate_ctr_group_get_ctr(rate_ctrs, E1_I460_TRAU_MUX_EMPTY_CTR));

	/* choose dummy fill frame payload based on current codec */
	switch (endp->e1.trau_rtp_st->type) {
	case OSMO_TRAU16_FT_FR:
		dummy_fill_pl = osmo_gsm611_silence_frame;
		dummy_fill_pl_len = GSM_FR_BYTES;
		break;
	case OSMO_TRAU16_FT_EFR:
		dummy_fill_pl = osmo_gsm660_homing_frame;
		dummy_fill_pl_len = GSM_EFR_BYTES;
		break;
	case OSMO_TRAU16_FT_HR:
	case OSMO_TRAU8_SPEECH:
		dummy_fill_pl = osmo_gsm620_silence_frame;
		dummy_fill_pl_len = GSM_HR_BYTES;
		break;
	default:
		LOGPENDP(endp, DE1, LOGL_ERROR, "E1-I.460-IDLE-TX: unsupported frame type\n");
		goto skip;
	}

	/* turn it into a TRAU-DL frame */
	memset(&tf, 0, sizeof(tf));
	tf.dir = OSMO_TRAU_DIR_DL;
	rc = osmo_rtp2trau(&tf, dummy_fill_pl, dummy_fill_pl_len, endp->e1.trau_rtp_st);
	if (rc < 0) {
		LOGPENDP(endp, DE1, LOGL_ERROR,
			 "E1-I.460-IDLE-TX: error converting dummy fill frame!\n");
		goto skip;
	}
	rc = osmo_trau_frame_encode(msgb_data(msg), msg->data_len, &tf);
	if (rc < 0) {
		LOGPENDP(endp, DE1, LOGL_ERROR,
			 "E1-I.460-IDLE-TX: error encoding dummy fill frame!\n");
		goto skip;
	}
	msgb_put(msg, rc);

	/* enqueue it into the I.460 multiplexer */
	LOGPENDP(endp, DE1, LOGL_DEBUG, "E1-I.460-IDLE-TX: enquing %u trau frame bits: %s...\n", msgb_length(msg),
		 osmo_ubit_dump(msgb_data(msg), msgb_length(msg) > DEBUG_BITS_MAX ? DEBUG_BITS_MAX : msgb_length(msg)));
	osmo_i460_mux_enqueue(endp->e1.schan, msg);
	return;

skip:
	rate_ctr_inc(rate_ctr_group_get_ctr(rate_ctrs, E1_I460_TRAU_TX_FAIL_CTR));
	msgb_free(msg);
}

/* called by I.460 de-multiplexer; feed output of I.460 demux into TRAU frame sync */
static void e1_i460_demux_bits_cb(struct osmo_i460_subchan *schan, void *user_data, const ubit_t *bits,
				  unsigned int num_bits)
{
	struct mgcp_endpoint *endp = user_data;
	LOGPENDP(endp, DE1, LOGL_DEBUG, "E1-I.460-RX: receiving %u bits from subslot: %s...\n", num_bits,
		 osmo_ubit_dump(bits, num_bits > DEBUG_BITS_MAX ? DEBUG_BITS_MAX : num_bits));

	OSMO_ASSERT(endp->e1.trau_sync_fi);
	osmo_trau_sync_rx_ubits(endp->e1.trau_sync_fi, bits, num_bits);
}

/* called for each synchronized TRAU frame received; decode frame + convert to RTP
 * (the resulting frame will be prepended with an all-zero (12-byte) rtp header) */
static void sync_frame_out_cb(void *user_data, const ubit_t *bits, unsigned int num_bits)
{
	unsigned int rtp_hdr_len = sizeof(struct rtp_hdr);
	struct mgcp_endpoint *endp = user_data;
	struct msgb *msg = msgb_alloc_c(endp->trunk, RTP_BUF_SIZE, "RTP-rx-from-E1");
	struct rate_ctr_group *rate_ctrs = endp->trunk->ratectr.e1_stats;
	struct mgcp_conn *conn_dst;
	struct osmo_trau_frame fr;
	int rc;

	if (!bits || num_bits == 0)
		goto skip;

	LOGPENDP(endp, DE1, LOGL_DEBUG, "E1-I.460-RX: receiving %u TRAU frame bits from E1 subslot: %s...\n",
		 num_bits, osmo_ubit_dump(bits, num_bits > DEBUG_BITS_MAX ? DEBUG_BITS_MAX : num_bits));

	/* Decode TRAU frame */
	switch (endp->e1.scd.rate) {
	case OSMO_I460_RATE_8k:
		LOGPENDP(endp, DE1, LOGL_DEBUG, "E1-I.460-RX: decoding 8k trau frame...\n");
		rc = osmo_trau_frame_decode_8k(&fr, bits, OSMO_TRAU_DIR_UL);
		break;
	case OSMO_I460_RATE_16k:
		LOGPENDP(endp, DE1, LOGL_DEBUG, "E1-I.460-RX: decoding 16k trau frame...\n");
		rc = osmo_trau_frame_decode_16k(&fr, bits, OSMO_TRAU_DIR_UL);
		break;
	default:
		/* TRAU frames only exist in 8K or 16K subslots. */
		OSMO_ASSERT(false);
		break;
	}
	if (rc != 0) {
		LOGPENDP(endp, DE1, LOGL_DEBUG, "E1-I.460-RX: unable to decode trau frame\n");
		goto skip;
	}

	/* Check if the payload type is supported and what the expected lenth
	 * of the RTP payload will be. */
	LOGPENDP(endp, DE1, LOGL_DEBUG, "E1-I.460-RX: decoded trau frame type: %s\n",
		 osmo_trau_frame_type_name(fr.type));

	/* Convert decoded trau frame to RTP frame */
	struct osmo_trau2rtp_state t2rs = {
		.type = fr.type,
		.rtp_extensions = endp->e1.rtp_extensions,
	};
	rc = osmo_trau2rtp(msgb_data(msg) + rtp_hdr_len, msg->data_len - rtp_hdr_len, &fr, &t2rs);
	if (rc <= 0) {
		LOGPENDP(endp, DE1, LOGL_DEBUG, "E1-I.460-RX: unable to convert trau frame to RTP audio\n");
		goto skip;
	}
	msgb_put(msg, rtp_hdr_len + rc);
	LOGPENDP(endp, DE1, LOGL_DEBUG, "E1-I.460-RX: encoded %u bytes of RTP audio: %s\n", rc,
		 osmo_hexdump(msgb_data(msg) + rtp_hdr_len, msgb_length(msg) - rtp_hdr_len));

	/* Forward RTP data to IP */
	conn_dst = llist_first_entry(&endp->conns, struct mgcp_conn, entry);
	if (!conn_dst) {
		LOGPENDP(endp, DE1, LOGL_DEBUG,
			 "E1-I.460-RX: unable to forward RTP audio data from E1: no connection to forward an incoming RTP packet to\n");
		goto skip;
	}
	OSMO_ASSERT(conn_dst->type == MGCP_CONN_TYPE_RTP);

	mgcp_send(endp, 1, NULL, msg, &conn_dst->u.rtp, &conn_dst->u.rtp);

	return;
skip:
	rate_ctr_inc(rate_ctr_group_get_ctr(rate_ctrs, E1_I460_TRAU_RX_FAIL_CTR));
	msgb_free(msg);
	return;
}

/* handle outgoing E1 traffic */
static void e1_send_ts_frame(struct e1inp_ts *ts, struct mgcp_trunk *trunk)
{
	struct msgb *msg = msgb_alloc_c(trunk, E1_TS_BYTES, "E1-TX-timeslot-bytes");
	uint8_t *ptr;

	/* Get E1 frame from I.460 multiplexer */
	ptr = msgb_put(msg, E1_TS_BYTES);
	osmo_i460_mux_out(&trunk->e1.i460_ts[ts->num - 1], ptr, E1_TS_BYTES);

#if DEBUG_E1_TS == 1
	LOGPTRUNK(trunk, DE1, LOGL_DEBUG, "E1-TX: (ts:%u) sending %u bytes: %s...\n", ts->num, msgb_length(msg),
		  osmo_hexdump_nospc(msgb_data(msg),
				     msgb_length(msg) > DEBUG_BYTES_MAX ? DEBUG_BYTES_MAX : msgb_length(msg)));
#endif
	/* Hand data over to the E1 stack */
	e1inp_ts_send_raw(ts, msg);
	return;
}

/* Callback function to handle incoming E1 traffic */
static void e1_recv_cb(struct e1inp_ts *ts, struct msgb *msg)
{
	struct mgcp_trunk *trunk;

	/* Find associated trunk */
	trunk = mgcp_trunk_by_line_num(cfg, ts->line->num);
	if (!trunk) {
		LOGP(DE1, LOGL_ERROR, "E1-RX: unable to find a trunk for E1-line %u!\n", ts->line->num);
		msgb_free(msg);
		return;
	}

	/* Check if the incoming data looks sane */
	if (msgb_length(msg) != E1_TS_BYTES) {
		LOGPTRUNK(trunk, DE1, LOGL_NOTICE,
			  "E1-RX: (ts:%u) expected length is %u, actual length is %u!\n", ts->num, E1_TS_BYTES,
			  msgb_length(msg));
	}
#if DEBUG_E1_TS == 1
	LOGPTRUNK(trunk, DE1, LOGL_DEBUG, "E1-RX: (ts:%u) receiving %u bytes: %s...\n", ts->num,
		  msgb_length(msg), osmo_hexdump_nospc(msgb_data(msg),
						       msgb_length(msg) >
						       DEBUG_BYTES_MAX ? DEBUG_BYTES_MAX : msgb_length(msg)));
#endif

	/* Hand data over to the I.460 demultiplexer. */
	osmo_i460_demux_in(&trunk->e1.i460_ts[ts->num - 1], msgb_data(msg), msgb_length(msg));

	/* Trigger sending of pending E1 traffic */
	e1_send_ts_frame(ts, trunk);

	/* e1inp_rx_ts(), the caller of this callback does not free() msgb. */
	msgb_free(msg);
}

static int e1_open(struct mgcp_trunk *trunk, uint8_t ts_nr)
{
	/*! One E1 timeslot may serve multiple I.460 subslots. The timeslot is opened as soon as an I.460 subslot is
	 *  opened and will stay open until the last I.460 subslot is closed (see e1_close below). This function must
	 *  be called any time a new I.460 subslot is opened in order to maintain constancy of the ts_usecount counter. */

	struct e1inp_line *e1_line;
	int rc;

	OSMO_ASSERT(ts_nr > 0 || ts_nr < NUM_E1_TS);
	cfg = trunk->cfg;

	if (trunk->e1.ts_usecount[ts_nr - 1] > 0) {
		LOGPTRUNK(trunk, DE1, LOGL_INFO, "E1 timeslot %u already set up and in use by %u subslot(s), using it as it is...\n",
			  ts_nr, trunk->e1.ts_usecount[ts_nr - 1]);
		trunk->e1.ts_usecount[ts_nr - 1]++;
		return 0;
	}

	/* Find E1 line */
	e1_line = e1inp_line_find(trunk->e1.vty_line_nr);
	if (!e1_line) {
		LOGPTRUNK(trunk, DE1, LOGL_ERROR, "no such E1 line %u - check VTY config!\n",
			  trunk->e1.vty_line_nr);
		return -EINVAL;
	}
	e1inp_line_bind_ops(e1_line, &dummy_e1_line_ops);

	/* Configure E1 timeslot */
	rc = e1inp_ts_config_raw(&e1_line->ts[ts_nr - 1], e1_line, e1_recv_cb);
	if (rc < 0) {
		LOGPTRUNK(trunk, DE1, LOGL_ERROR, "failed to put E1 timeslot %u in raw mode.\n", ts_nr);
		return -EINVAL;
	}
	rc = e1inp_line_update(e1_line);
	if (rc < 0) {
		LOGPTRUNK(trunk, DE1, LOGL_ERROR, "failed to update E1 line %u.\n", ts_nr);
		return -EINVAL;
	}

	LOGPTRUNK(trunk, DE1, LOGL_INFO, "E1 timeslot %u set up successfully.\n", ts_nr);
	trunk->e1.ts_usecount[ts_nr - 1]++;
	OSMO_ASSERT(trunk->e1.ts_usecount[ts_nr - 1] == 1);

	return 0;
}

static int e1_close(struct mgcp_trunk *trunk, uint8_t ts_nr)
{
	/* See also comment above (e1_open). This function must be called any time an I.460 subslot is closed */

	struct e1inp_line *e1_line;
	int rc;

	OSMO_ASSERT(ts_nr > 0 || ts_nr < NUM_E1_TS);
	cfg = trunk->cfg;

	if (trunk->e1.ts_usecount[ts_nr - 1] > 1) {
		trunk->e1.ts_usecount[ts_nr - 1]--;
		LOGPTRUNK(trunk, DE1, LOGL_INFO, "E1 timeslot %u still in use by %u other subslot(s), leaving it open...\n",
			  ts_nr, trunk->e1.ts_usecount[ts_nr - 1]);
		return 0;
	} else if (trunk->e1.ts_usecount[ts_nr - 1] == 0) {
		/* This should not be as it means we close the timeslot too often. */
		LOGPTRUNK(trunk, DE1, LOGL_ERROR, "E1 timeslot %u already closed, leaving it as it is...\n", ts_nr);
		return -EINVAL;
	}

	/* Find E1 line */
	e1_line = e1inp_line_find(trunk->e1.vty_line_nr);
	if (!e1_line) {
		LOGPTRUNK(trunk, DE1, LOGL_ERROR, "no such E1 line %u - check VTY config!\n",
			  trunk->e1.vty_line_nr);
		return -EINVAL;
	}

	/* Release E1 timeslot */
	rc = e1inp_ts_config_none(&e1_line->ts[ts_nr - 1], e1_line);
	if (rc < 0) {
		LOGPTRUNK(trunk, DE1, LOGL_ERROR, "failed to disable E1 timeslot %u.\n", ts_nr);
		return -EINVAL;
	}
	rc = e1inp_line_update(e1_line);
	if (rc < 0) {
		LOGPTRUNK(trunk, DE1, LOGL_ERROR, "failed to update E1 line %u.\n", trunk->e1.vty_line_nr);
		return -EINVAL;
	}

	LOGPTRUNK(trunk, DE1, LOGL_INFO, "E1 timeslot %u closed.\n", ts_nr);
	trunk->e1.ts_usecount[ts_nr - 1]--;
	OSMO_ASSERT(trunk->e1.ts_usecount[ts_nr - 1] == 0);

	return 0;
}

/* Determine a suitable TRAU frame type for a given codec */
static enum osmo_trau_frame_type determine_trau_fr_type(char *sdp_subtype_name, enum osmo_i460_rate i460_rate,
							uint8_t amr_ft, struct mgcp_endpoint *endp)
{
	if (strcmp(sdp_subtype_name, "GSM") == 0)
		return OSMO_TRAU16_FT_FR;

	if (strcmp(sdp_subtype_name, "GSM-EFR") == 0)
		return OSMO_TRAU16_FT_EFR;

	if (strcmp(sdp_subtype_name, "GSM-HR-08") == 0) {
		if (i460_rate == OSMO_I460_RATE_16k)
			return OSMO_TRAU16_FT_HR;
		if (i460_rate == OSMO_I460_RATE_8k)
			return OSMO_TRAU8_SPEECH;
		LOGPENDP(endp, DE1, LOGL_ERROR,
			 "E1-TRAU-TX: unsupported or illegal I.460 rate for HR\n");
		return OSMO_TRAU_FT_NONE;
	}

	if (strcmp(sdp_subtype_name, "AMR") == 0) {
		if (i460_rate == OSMO_I460_RATE_8k) {
			switch (amr_ft) {
			case AMR_4_75:
			case AMR_5_15:
			case AMR_5_90:
				return OSMO_TRAU8_AMR_LOW;
			case AMR_6_70:
				return OSMO_TRAU8_AMR_6k7;
			case AMR_7_40:
				return OSMO_TRAU8_AMR_7k4;
			default:
				LOGPENDP(endp, DE1, LOGL_ERROR,
					 "E1-TRAU-TX: unsupported or illegal AMR frame type: %u\n", amr_ft);
				return OSMO_TRAU_FT_NONE;
			}
		}
		return OSMO_TRAU16_FT_AMR;
	}

	LOGPENDP(endp, DE1, LOGL_ERROR, "E1-TRAU-TX: unsupported or illegal codec subtype name: %s\n",
		 sdp_subtype_name);
	return OSMO_TRAU_FT_NONE;
}

/* Determine a suitable TRAU frame type for a given codec */
static enum osmo_tray_sync_pat_id determine_trau_sync_pat(char *sdp_subtype_name, enum osmo_i460_rate i460_rate,
							  uint8_t amr_ft, struct mgcp_endpoint *endp)
{
	if (strcmp(sdp_subtype_name, "GSM") == 0)
		return OSMO_TRAU_SYNCP_16_FR_EFR;

	if (strcmp(sdp_subtype_name, "GSM-EFR") == 0)
		return OSMO_TRAU_SYNCP_16_FR_EFR;

	if (strcmp(sdp_subtype_name, "GSM-HR-08") == 0) {
		if (i460_rate == OSMO_I460_RATE_16k)
			return OSMO_TRAU_SYNCP_16_FR_EFR;
		if (i460_rate == OSMO_I460_RATE_8k)
			return OSMO_TRAU_SYNCP_8_HR;
		LOGPENDP(endp, DE1, LOGL_ERROR,
			 "E1-TRAU-TX: unsupported or illegal I.460 rate for HR\n");
		return OSMO_TRAU_SYNCP_16_FR_EFR;
	}

	if (strcmp(sdp_subtype_name, "AMR") == 0) {
		if (i460_rate == OSMO_I460_RATE_8k) {
			switch (amr_ft) {
			case AMR_4_75:
			case AMR_5_15:
			case AMR_5_90:
				return OSMO_TRAU_SYNCP_8_AMR_LOW;
			case AMR_6_70:
				return OSMO_TRAU_SYNCP_8_AMR_6K7;
			case AMR_7_40:
				return OSMO_TRAU_SYNCP_8_AMR_7K4;
			default:
				LOGPENDP(endp, DE1, LOGL_ERROR,
					 "E1-TRAU-TX: unsupported or illegal AMR frame type: %u\n", amr_ft);
				return OSMO_TRAU_SYNCP_16_FR_EFR;
			}
		}
		return OSMO_TRAU_SYNCP_16_FR_EFR;
	}

	LOGPENDP(endp, DE1, LOGL_ERROR, "E1-TRAU-TX: unsupported or illegal codec subtype name: %s\n",
		 sdp_subtype_name);
	return OSMO_TRAU_SYNCP_16_FR_EFR;
}

/* Find out if a given TRAU frame type is AMR */
static bool tf_type_is_amr(enum osmo_trau_frame_type ft)
{

	switch (ft) {
	case OSMO_TRAU16_FT_AMR:
	case OSMO_TRAU8_AMR_LOW:
	case OSMO_TRAU8_AMR_6k7:
	case OSMO_TRAU8_AMR_7k4:
		return true;
	default:
		return false;
	}
}

/*! Equip E1 endpoint with I.460 mux and E1 timeslot resources.
 *  \param[in] endp endpoint to equip
 *  \param[in] ts E1 timeslot number.
 *  \param[in] ss E1 subslot number.
 *  \param[in] offset E1 bit offset.
 *  \returns 0 on success, -EINVAL on error. */
int mgcp_e1_endp_equip(struct mgcp_endpoint *endp, uint8_t ts, uint8_t ss, uint8_t offs)
{
	int rc;
	enum osmo_tray_sync_pat_id sync_pat_id = OSMO_TRAU_SYNCP_16_FR_EFR;

	OSMO_ASSERT(ts != 0);
	OSMO_ASSERT(ts != 0xFF);
	OSMO_ASSERT(ss != 0xFF);
	OSMO_ASSERT(offs != 0xFF);

	memset(&endp->e1, 0, sizeof(endp->e1));

	endp->e1.last_amr_ft = AMR_4_75;

	/* Set up E1 line / timeslot */
	rc = e1_open(endp->trunk, ts);
	if (rc != 0)
		return -EINVAL;

	/* Set up I.460 mux */
	switch (e1_rates[ss]) {
	case 64:
		endp->e1.scd.rate = OSMO_I460_RATE_64k;
		endp->e1.scd.demux.num_bits = 160 * 8;
		break;
	case 32:
		endp->e1.scd.rate = OSMO_I460_RATE_32k;
		endp->e1.scd.demux.num_bits = 80 * 8;
		break;
	case 16:
		endp->e1.scd.rate = OSMO_I460_RATE_16k;
		endp->e1.scd.demux.num_bits = 40 * 8;
		sync_pat_id = OSMO_TRAU_SYNCP_16_FR_EFR;
		break;
	case 8:
		endp->e1.scd.rate = OSMO_I460_RATE_8k;
		endp->e1.scd.demux.num_bits = 20 * 8;
		sync_pat_id = OSMO_TRAU_SYNCP_8_HR;
		break;
	}
	endp->e1.scd.bit_offset = offs;
	endp->e1.scd.demux.out_cb_bits = e1_i460_demux_bits_cb;
	endp->e1.scd.demux.out_cb_bytes = NULL;
	endp->e1.scd.demux.user_data = endp;
	endp->e1.scd.mux.in_cb_queue_empty = e1_i460_mux_empty_cb;
	endp->e1.scd.mux.user_data = endp;

	LOGPENDP(endp, DE1, LOGL_INFO, "adding I.460 subchannel: ts=%u, bit_offset=%u, rate=%uk, num_bits=%lu\n", ts,
		 offs, e1_rates[ss], endp->e1.scd.demux.num_bits);
	endp->e1.schan = osmo_i460_subchan_add(endp, &endp->trunk->e1.i460_ts[ts - 1], &endp->e1.scd);
	if (!endp->e1.schan) {
		LOGPENDP(endp, DE1, LOGL_ERROR, "adding I.460 subchannel: failed!\n");
		return -EINVAL;
	}

	if (endp->e1.scd.rate == OSMO_I460_RATE_16k || endp->e1.scd.rate == OSMO_I460_RATE_8k) {
		/* TRAU frames are only specified for 16k and 8k subslots. For all other subslot
		 * types the concept of TRAU frames does not apply. However, at the moment this
		 * is the only format we currently support in osmo-mgw */
		endp->e1.trau_sync_fi = osmo_trau_sync_alloc(endp, "trau-sync", sync_frame_out_cb, sync_pat_id, endp);
		if (!endp->e1.trau_sync_fi) {
			LOGPENDP(endp, DE1, LOGL_ERROR, "adding I.460 TRAU frame sync: failed!\n");
			return -EINVAL;
		}
		endp->e1.trau_rtp_st = talloc_zero(endp->e1.trau_sync_fi, struct osmo_trau2rtp_state);
		endp->e1.trau_rtp_st->type = OSMO_TRAU_FT_NONE;
	} else {
		LOGPENDP(endp, DE1, LOGL_ERROR,
			 "osmo-mgw currently only supports 16K and 8K subslots (TRAU frames)!\n");
		return -EINVAL;
	}

	return 0;
}

/*! Update E1 related parameters (codec and sync pattern).
 *  \param[in] endp endpoint to update. */
int mgcp_e1_endp_update(struct mgcp_endpoint *endp)
{
	struct mgcp_conn *conn;
	struct mgcp_conn_rtp *conn_rtp;
	struct mgcp_rtp_codec *codec;
	enum osmo_tray_sync_pat_id sync_pat_id;

	/* In order to determine the codec, find the oldest connection on
	 * the endpoint and use its codec information. Normally on an E1
	 * endpoint no more than one connection should exist. */
	conn = mgcp_endp_get_conn_oldest(endp);
	OSMO_ASSERT(conn);
	conn_rtp = mgcp_conn_get_conn_rtp(conn);
	codec = conn_rtp->end.cset.codec;
	OSMO_ASSERT(codec);

	/* Update codec information */
	endp->e1.trau_rtp_st->type =
	    determine_trau_fr_type(codec->subtype_name, endp->e1.scd.rate, endp->e1.last_amr_ft, endp);
	endp->e1.last_codec = codec;

	/* possible RTP extensions, codec-associated */
	endp->e1.rtp_extensions = 0;
	if (codec->param_present && codec->param.fr_efr_twts001)
		endp->e1.rtp_extensions |= OSMO_RTP_EXT_TWTS001;
	if (codec->param_present && codec->param.hr_twts002)
		endp->e1.rtp_extensions |= OSMO_RTP_EXT_TWTS002;

	/* Update sync pattern */
	sync_pat_id = determine_trau_sync_pat(codec->subtype_name, endp->e1.scd.rate, endp->e1.last_amr_ft, endp);
	osmo_trau_sync_set_pat(endp->e1.trau_sync_fi, sync_pat_id);
	return 0;
}

/*! Remove E1 resources from endpoint
 *  \param[in] endp endpoint to release.
 *  \param[in] ts E1 timeslot number. */
void mgcp_e1_endp_release(struct mgcp_endpoint *endp, uint8_t ts)
{
	/* Guard against multiple calls. In case we don't see a subchannel anymore we can safely assume that all work
	 * is done. */
	if (!(endp->e1.schan || endp->e1.trau_rtp_st || endp->e1.trau_sync_fi))
		return;

	LOGPENDP(endp, DE1, LOGL_DEBUG, "removing I.460 subchannel and sync...\n");

	if (endp->e1.schan)
		osmo_i460_subchan_del(endp->e1.schan);
	if (endp->e1.trau_rtp_st)
		talloc_free(endp->e1.trau_rtp_st);
	if (endp->e1.trau_sync_fi)
		osmo_fsm_inst_term(endp->e1.trau_sync_fi, OSMO_FSM_TERM_REGULAR, NULL);
	memset(&endp->e1, 0, sizeof(endp->e1));

	/* Close E1 timeslot */
	e1_close(endp->trunk, ts);
}

/*! Accept RTP message buffer with RTP data and enqueue voice data for E1 transmit.
 *  \param[in] endp related endpoint (does not take ownership).
 *  \param[in] codec configuration.
 *  \param[in] msg RTP message buffer (including RTP header).
 *  \returns 0 on success, -1 on ERROR. */
int mgcp_e1_send_rtp(struct mgcp_endpoint *endp, struct mgcp_rtp_codec *codec, struct msgb *msg)
{
	struct msgb *msg_tf = msgb_alloc_c(endp->trunk, E1_TRAU_BITS_MSGB, "E1-I.460-TX-TRAU-frame");
	struct rate_ctr_group *rate_ctrs = endp->trunk->ratectr.e1_stats;
	unsigned int rtp_hdr_len = sizeof(struct rtp_hdr);
	struct osmo_trau_frame tf;
	uint8_t amr_ft;
	int rc;

	/* Extract AMR frame type from AMR head (if AMR is used) */
	if (tf_type_is_amr(endp->e1.trau_rtp_st->type))
		amr_ft = (msgb_data(msg)[rtp_hdr_len + 1] >> 3) & 0xf;
	else
		amr_ft = 0xff;

	/* Adapt TRAU frame type on codec changes */
	OSMO_ASSERT(endp->e1.last_codec);
	if (codec != endp->e1.last_codec || (amr_ft != 0xff && amr_ft != endp->e1.last_amr_ft)) {
		endp->e1.trau_rtp_st->type =
		    determine_trau_fr_type(codec->subtype_name, endp->e1.scd.rate, amr_ft, endp);
		endp->e1.last_codec = codec;
		endp->e1.last_amr_ft = amr_ft;
	}
	if (endp->e1.trau_rtp_st->type == OSMO_TRAU_FT_NONE)
		goto skip;
	LOGPENDP(endp, DE1, LOGL_DEBUG, "E1-I.460-TX: using trau frame type for encoding: %s\n",
		 osmo_trau_frame_type_name(endp->e1.trau_rtp_st->type));

	/* Convert from RTP to TRAU format */
	msg->l2h = msgb_data(msg) + rtp_hdr_len;
	LOGPENDP(endp, DE1, LOGL_DEBUG, "E1-I.460-TX: decoding %u bytes of RTP audio to TRAU format: %s\n",
		 msgb_length(msg), osmo_hexdump(msgb_l2(msg), msgb_l2len(msg)));
	memset(&tf, 0, sizeof(tf));
	tf.dir = OSMO_TRAU_DIR_DL;
	rc = osmo_rtp2trau(&tf, msgb_l2(msg), msgb_l2len(msg), endp->e1.trau_rtp_st);
	if (rc < 0) {
		LOGPENDP(endp, DE1, LOGL_DEBUG,
			 "E1-I.460-TX: failed to decode from RTP payload format to TRAU format\n");
		goto skip;
	}
	rc = osmo_trau_frame_encode(msgb_data(msg_tf), msg_tf->data_len, &tf);
	if (rc < 0) {
		LOGPENDP(endp, DE1, LOGL_DEBUG, "E1-I.460-TX: failed to encode TRAU frame\n");
		goto skip;
	}
	msgb_put(msg_tf, rc);
	LOGPENDP(endp, DE1, LOGL_DEBUG, "E1-I.460-TX: enquing %u trau frame bits: %s...\n", msgb_length(msg_tf),
		 osmo_ubit_dump(msgb_data(msg_tf),
				msgb_length(msg_tf) > DEBUG_BITS_MAX ? DEBUG_BITS_MAX : msgb_length(msg_tf)));

	/* Enqueue data to I.460 multiplexer */
	OSMO_ASSERT(endp->e1.schan);
	OSMO_ASSERT(endp->e1.trau_sync_fi);

	osmo_i460_mux_enqueue(endp->e1.schan, msg_tf);
	LOGPENDP(endp, DE1, LOGL_DEBUG, "E1-I.460-TX: %u bits of audio enqued for E1 tx\n", msgb_length(msg_tf));

	return 0;
skip:
	rate_ctr_inc(rate_ctr_group_get_ctr(rate_ctrs, E1_I460_TRAU_TX_FAIL_CTR));
	msgb_free(msg_tf);
	return -1;
}

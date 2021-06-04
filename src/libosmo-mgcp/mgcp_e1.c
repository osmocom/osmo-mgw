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

/* EFR idle frame */
static const ubit_t idle_tf_efr[] = { 0, 0, 0, 0, 0, 0, 0, 0,
				      0, 0, 0, 0, 0, 0, 0, 0,
				      1, 1, 1, 0, 1, 0, 0, 0,
				      0, 0, 0, 0, 1, 0, 0, 0,
				      1, 0, 0, 0, 0, 0, 0, 0,
				      0, 0, 0, 0, 0, 0, 0, 0,
				      1, 0, 0, 0, 0, 0, 0, 0,
				      0, 0, 0, 0, 0, 0, 0, 0,
				      1, 0, 0, 0, 0, 0, 0, 0,
				      0, 0, 0, 0, 0, 0, 0, 0,
				      1, 0, 0, 0, 0, 0, 0, 0,
				      0, 0, 0, 0, 0, 0, 0, 0,
				      1, 0, 0, 0, 0, 0, 0, 0,
				      0, 0, 0, 0, 0, 0, 0, 0,
				      1, 0, 0, 0, 0, 0, 0, 0,
				      0, 0, 0, 0, 0, 0, 0, 0,
				      1, 0, 0, 0, 0, 0, 0, 0,
				      0, 0, 0, 0, 0, 0, 0, 0,
				      1, 0, 0, 0, 0, 0, 0, 0,
				      0, 0, 0, 0, 0, 0, 0, 0,
				      1, 0, 0, 0, 0, 0, 0, 0,
				      0, 0, 0, 0, 0, 0, 0, 0,
				      1, 0, 0, 0, 0, 0, 0, 0,
				      0, 0, 0, 0, 0, 0, 0, 0,
				      1, 0, 0, 0, 0, 0, 0, 0,
				      0, 0, 0, 0, 0, 0, 0, 0,
				      1, 0, 0, 0, 0, 0, 0, 0,
				      0, 0, 0, 0, 0, 0, 0, 0,
				      1, 0, 0, 0, 0, 0, 0, 0,
				      0, 0, 0, 0, 0, 0, 0, 0,
				      1, 0, 0, 0, 0, 0, 0, 0,
				      0, 0, 0, 0, 0, 0, 0, 0,
				      1, 0, 0, 0, 0, 0, 0, 0,
				      0, 0, 0, 0, 0, 0, 0, 0,
				      1, 0, 0, 0, 0, 0, 0, 0,
				      0, 0, 0, 0, 0, 0, 0, 0,
				      1, 0, 0, 0, 0, 0, 0, 0,
				      0, 0, 0, 0, 0, 0, 0, 0,
				      1, 0, 0, 0, 0, 0, 1, 0,
				      1, 1, 1, 1, 1, 1, 1, 1,
};

/* FR idle frame */
static const ubit_t idle_tf_fr[] = { 0, 0, 0, 0, 0, 0, 0, 0,
				     0, 0, 0, 0, 0, 0, 0, 0,
				     1, 1, 1, 1, 0, 0, 0, 0,
				     0, 0, 0, 0, 1, 0, 0, 0,
				     1, 0, 0, 0, 0, 0, 0, 0,
				     0, 0, 0, 0, 0, 0, 0, 0,
				     1, 0, 0, 0, 0, 0, 0, 0,
				     0, 0, 0, 0, 0, 0, 0, 0,
				     1, 0, 0, 0, 0, 0, 0, 0,
				     0, 0, 0, 0, 0, 0, 0, 0,
				     1, 0, 0, 0, 0, 0, 0, 0,
				     0, 0, 0, 0, 0, 0, 0, 0,
				     1, 0, 0, 0, 0, 0, 0, 0,
				     0, 0, 0, 0, 0, 0, 0, 0,
				     1, 0, 0, 0, 0, 0, 0, 0,
				     0, 0, 0, 0, 0, 0, 0, 0,
				     1, 0, 0, 0, 0, 0, 0, 0,
				     0, 0, 0, 0, 0, 0, 0, 0,
				     1, 0, 0, 0, 0, 0, 0, 0,
				     0, 0, 0, 0, 0, 0, 0, 0,
				     1, 0, 0, 0, 0, 0, 0, 0,
				     0, 0, 0, 0, 0, 0, 0, 0,
				     1, 0, 0, 0, 0, 0, 0, 0,
				     0, 0, 0, 0, 0, 0, 0, 0,
				     1, 0, 0, 0, 0, 0, 0, 0,
				     0, 0, 0, 0, 0, 0, 0, 0,
				     1, 0, 0, 0, 0, 0, 0, 0,
				     0, 0, 0, 0, 0, 0, 0, 0,
				     1, 0, 0, 0, 0, 0, 0, 0,
				     0, 0, 0, 0, 0, 0, 0, 0,
				     1, 0, 0, 0, 0, 0, 0, 0,
				     0, 0, 0, 0, 0, 0, 0, 0,
				     1, 0, 0, 0, 0, 0, 0, 0,
				     0, 0, 0, 0, 0, 0, 0, 0,
				     1, 0, 0, 0, 0, 0, 0, 0,
				     0, 0, 0, 0, 0, 0, 0, 0,
				     1, 0, 0, 0, 0, 0, 0, 0,
				     0, 0, 0, 0, 0, 0, 0, 0,
				     1, 0, 0, 0, 0, 0, 1, 0,
				     1, 1, 1, 1, 1, 1, 1, 1,
};

/* Idle speech frame, see also GSM 08.60, chapter 3.4 */
static const ubit_t idle_tf_spch[] = { 0, 0, 0, 0, 0, 0, 0, 0,
				       0, 0, 0, 0, 0, 0, 0, 0,
				       1, 0, 1, 1, 1, 0, 0, 0,
				       0, 0, 0, 0, 1, 0, 0, 0,
				       1, 1, 1, 1, 1, 1, 1, 1,
				       1, 1, 1, 1, 1, 1, 1, 1,
				       1, 1, 1, 1, 1, 1, 1, 1,
				       1, 1, 1, 1, 1, 1, 1, 1,
				       1, 1, 1, 1, 1, 1, 1, 1,
				       1, 1, 1, 1, 1, 1, 1, 1,
				       1, 1, 1, 1, 1, 1, 1, 1,
				       1, 1, 1, 1, 1, 1, 1, 1,
				       1, 1, 1, 1, 1, 1, 1, 1,
				       1, 1, 1, 1, 1, 1, 1, 1,
				       1, 1, 1, 1, 1, 1, 1, 1,
				       1, 1, 1, 1, 1, 1, 1, 1,
				       1, 1, 1, 1, 1, 1, 1, 1,
				       1, 1, 1, 1, 1, 1, 1, 1,
				       1, 1, 1, 1, 1, 1, 1, 1,
				       1, 1, 1, 1, 1, 1, 1, 1,
				       1, 1, 1, 1, 1, 1, 1, 1,
				       1, 1, 1, 1, 1, 1, 1, 1,
				       1, 1, 1, 1, 1, 1, 1, 1,
				       1, 1, 1, 1, 1, 1, 1, 1,
				       1, 1, 1, 1, 1, 1, 1, 1,
				       1, 1, 1, 1, 1, 1, 1, 1,
				       1, 1, 1, 1, 1, 1, 1, 1,
				       1, 1, 1, 1, 1, 1, 1, 1,
				       1, 1, 1, 1, 1, 1, 1, 1,
				       1, 1, 1, 1, 1, 1, 1, 1,
				       1, 1, 1, 1, 1, 1, 1, 1,
				       1, 1, 1, 1, 1, 1, 1, 1,
				       1, 1, 1, 1, 1, 1, 1, 1,
				       1, 1, 1, 1, 1, 1, 1, 1,
				       1, 1, 1, 1, 1, 1, 1, 1,
				       1, 1, 1, 1, 1, 1, 1, 1,
				       1, 1, 1, 1, 1, 1, 1, 1,
				       1, 1, 1, 1, 1, 1, 1, 1,
				       1, 1, 1, 1, 1, 1, 1, 0,
				       1, 1, 1, 1, 1, 1, 1, 1,
};

/* If the RTP transmission has dropouts for some reason the I.460 TX-Queue may
 * run empty. In order to make sure that the TRAU frame transmission continues
 * we generate idle TRAU frames here. */
static void e1_i460_mux_empty_cb(struct osmo_i460_subchan *schan, void *user_data)
{
	struct mgcp_endpoint *endp = user_data;
	struct rate_ctr_group *rate_ctrs = endp->trunk->ratectr.e1_stats;
	struct msgb *msg = msgb_alloc(E1_TRAU_BITS_MSGB, "E1-I.460-IDLE-TX-TRAU-frame");
	uint8_t *ptr;
	const uint8_t *ptr_ft;
	enum osmo_trau_frame_type ft;

	rate_ctr_inc(rate_ctr_group_get_ctr(rate_ctrs, E1_I460_TRAU_MUX_EMPTY_CTR));

	/* Choose an appropiate idle frame type */
	ft = endp->e1.trau_rtp_st->type;
	switch (ft) {
	case OSMO_TRAU16_FT_FR:
		ptr_ft = idle_tf_fr;
		break;
	case OSMO_TRAU16_FT_EFR:
		ptr_ft = idle_tf_efr;
		break;
	default:
		/* FIXME: What about 8k subslots and AMR frames? */
		ptr_ft = idle_tf_spch;
	}

	/* Put the replacement into a message buffer and enqueue it into the
	 * I.460 multiplexer */
	ptr = msgb_put(msg, E1_TRAU_BITS);
	memcpy(ptr, ptr_ft, E1_TRAU_BITS);
	LOGPENDP(endp, DE1, LOGL_DEBUG, "E1-I.460-IDLE-TX: enquing %u trau frame bits: %s...\n", msgb_length(msg),
		 osmo_ubit_dump(msgb_data(msg), msgb_length(msg) > DEBUG_BITS_MAX ? DEBUG_BITS_MAX : msgb_length(msg)));
	osmo_i460_mux_enqueue(endp->e1.schan, msg);
}

/* called by I.460 de-multeiplexer; feed output of I.460 demux into TRAU frame sync */
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
	struct msgb *msg = msgb_alloc(RTP_BUF_SIZE, "RTP-rx-from-E1");
	unsigned int rtp_hdr_len = sizeof(struct rtp_hdr);
	struct mgcp_endpoint *endp = user_data;
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

	msgb_free(msg);
	return;
skip:
	rate_ctr_inc(rate_ctr_group_get_ctr(rate_ctrs, E1_I460_TRAU_RX_FAIL_CTR));
	msgb_free(msg);
	return;
}

/* Function to handle outgoing E1 traffic */
static void e1_send(struct e1inp_ts *ts, struct mgcp_trunk *trunk)
{
	struct msgb *msg = msgb_alloc(E1_TS_BYTES, "E1-TX-timeslot-bytes");
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
	msgb_enqueue(&ts->raw.tx_queue, msg);
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
	e1_send(ts, trunk);
}

static int e1_init(struct mgcp_trunk *trunk, uint8_t ts_nr)
{
	/*! Each timeslot needs only to be configured once. The Timeslot then
	 *  stays open and permanently receives data. It is then up to the
	 *  I.460 demultiplexer to add/remove subchannels as needed. It is
	 *  allowed to call this function multiple times since we check if the
	 *  timeslot is already configured. */

	struct e1inp_line *e1_line;
	int rc;

	OSMO_ASSERT(ts_nr > 0 || ts_nr < NUM_E1_TS);
	cfg = trunk->cfg;

	if (trunk->e1.ts_in_use[ts_nr - 1]) {
		LOGPTRUNK(trunk, DE1, LOGL_INFO, "E1 timeslot %u already set up, skipping...\n", ts_nr);
		return 0;
	}

	/* Get E1 line */
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
		LOGPTRUNK(trunk, DE1, LOGL_ERROR, "failed to update E1 timeslot %u.\n", ts_nr);
		return -EINVAL;
	}

	LOGPTRUNK(trunk, DE1, LOGL_INFO, "E1 timeslot %u set up successfully.\n", ts_nr);
	trunk->e1.ts_in_use[ts_nr - 1] = true;

	return 0;
}

/* Determine a suitable TRAU frame type for a given codec */
static enum osmo_trau_frame_type determine_trau_fr_type(char *sdp_subtype_name, enum osmo_i460_rate i460_rate,
							uint8_t amr_ft, struct mgcp_endpoint *endp)
{
	if (strcmp(sdp_subtype_name, "GSM") == 0)
		return OSMO_TRAU16_FT_FR;
	else if (strcmp(sdp_subtype_name, "GSM-EFR") == 0)
		return OSMO_TRAU16_FT_EFR;
	else if (strcmp(sdp_subtype_name, "GSM-HR-08") == 0)
		return OSMO_TRAU16_FT_HR;
	else if (strcmp(sdp_subtype_name, "AMR") == 0) {
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
	} else {
		LOGPENDP(endp, DE1, LOGL_ERROR, "E1-TRAU-TX: unsupported or illegal codec subtype name: %s\n",
			 sdp_subtype_name);
		return OSMO_TRAU_FT_NONE;
	}
}

/* Determine a suitable TRAU frame type for a given codec */
static enum osmo_tray_sync_pat_id determine_trau_sync_pat(char *sdp_subtype_name, enum osmo_i460_rate i460_rate,
							  uint8_t amr_ft, struct mgcp_endpoint *endp)
{
	if (strcmp(sdp_subtype_name, "GSM") == 0)
		return OSMO_TRAU_SYNCP_16_FR_EFR;
	else if (strcmp(sdp_subtype_name, "GSM-EFR") == 0)
		return OSMO_TRAU_SYNCP_16_FR_EFR;
	else if (strcmp(sdp_subtype_name, "GSM-HR-08") == 0)
		return OSMO_TRAU_SYNCP_8_HR;
	else if (strcmp(sdp_subtype_name, "AMR") == 0) {
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
	} else {
		LOGPENDP(endp, DE1, LOGL_ERROR, "E1-TRAU-TX: unsupported or illegal codec subtype name: %s\n",
			 sdp_subtype_name);
		return OSMO_TRAU_SYNCP_16_FR_EFR;
	}
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

/* !Equip E1 endpoint with I.460 mux resources.
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
	rc = e1_init(endp->trunk, ts);
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
void mgcp_e1_endp_update(struct mgcp_endpoint *endp)
{
	struct mgcp_conn *conn;
	struct mgcp_rtp_codec *codec;
	enum osmo_tray_sync_pat_id sync_pat_id;

	/* In order to determine the codec, find the oldest connection on
	 * the endpoint and use its codec information. Normally on an E1
	 * endpoint no more than one connection should exist. */
	conn = mgcp_conn_get_oldest(endp);
	OSMO_ASSERT(conn);
	codec = conn->u.rtp.end.codec;
	OSMO_ASSERT(codec);

	/* Update codec information */
	endp->e1.trau_rtp_st->type =
	    determine_trau_fr_type(codec->subtype_name, endp->e1.scd.rate, endp->e1.last_amr_ft, endp);
	endp->e1.last_codec = codec;

	/* Update sync pattern */
	sync_pat_id = determine_trau_sync_pat(codec->subtype_name, endp->e1.scd.rate, endp->e1.last_amr_ft, endp);
	osmo_trau_sync_set_pat(endp->e1.trau_sync_fi, sync_pat_id);
}

/*! Remove E1 resources from endpoint
 *  \param[in] endp endpoint to release. */
void mgcp_e1_endp_release(struct mgcp_endpoint *endp)
{
	LOGPENDP(endp, DE1, LOGL_DEBUG, "removing I.460 subchannel and sync...\n");

	if (endp->e1.schan)
		osmo_i460_subchan_del(endp->e1.schan);
	if (endp->e1.trau_rtp_st)
		talloc_free(endp->e1.trau_rtp_st);
	if (endp->e1.trau_sync_fi)
		osmo_fsm_inst_term(endp->e1.trau_sync_fi, OSMO_FSM_TERM_REGULAR, NULL);

	memset(&endp->e1, 0, sizeof(endp->e1));
}

/*! Accept RTP message buffer with RTP data and enqueue voice data for E1 transmit.
 *  \param[in] endp related endpoint (does not take ownership).
 *  \param[in] codec configuration.
 *  \param[in] msg RTP message buffer (including RTP header).
 *  \returns 0 on success, -1 on ERROR. */
int mgcp_e1_send_rtp(struct mgcp_endpoint *endp, struct mgcp_rtp_codec *codec, struct msgb *msg)
{
	struct msgb *msg_tf = msgb_alloc(E1_TRAU_BITS_MSGB, "E1-I.460-TX-TRAU-frame");
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

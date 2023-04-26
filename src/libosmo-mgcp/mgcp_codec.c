/*
 * (C) 2009-2015 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009-2014 by On-Waves
 * All Rights Reserved
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
#include <osmocom/mgcp/mgcp.h>
#include <osmocom/mgcp/osmux.h>
#include <osmocom/mgcp/mgcp_conn.h>
#include <osmocom/mgcp/mgcp_protocol.h>
#include <osmocom/mgcp/mgcp_endp.h>
#include <osmocom/mgcp/mgcp_trunk.h>
#include <osmocom/mgcp/mgcp_codec.h>
#include <errno.h>

/* Helper function to dump codec information of a specified codec to a printable
 * string, used by dump_codec_summary() */
static char *dump_codec(struct mgcp_rtp_codec *codec)
{
	static char str[256];
	char *pt_str;

	if (codec->payload_type > 76)
		pt_str = "DYNAMIC";
	else if (codec->payload_type > 72)
		pt_str = "RESERVED <!>";
	else if (codec->payload_type != PTYPE_UNDEFINED)
		pt_str = codec->subtype_name;
	else
		pt_str = "INVALID <!>";

	snprintf(str, sizeof(str), "(pt:%i=%s, audio:%s subt=%s, rate=%u, ch=%i, t=%u/%u)", codec->payload_type, pt_str,
		 codec->audio_name, codec->subtype_name, codec->rate, codec->channels, codec->frame_duration_num,
		 codec->frame_duration_den);
	return str;
}

/*! Dump a summary of all negotiated codecs to debug log
 *  \param[in] conn related rtp-connection. */
void mgcp_codec_summary(struct mgcp_conn_rtp *conn)
{
	struct mgcp_rtp_end *rtp;
	unsigned int i;
	struct mgcp_rtp_codec *codec;
	struct mgcp_endpoint *endp;

	rtp = &conn->end;
	endp = conn->conn->endp;

	if (rtp->codecs_assigned == 0) {
		LOGPENDP(endp, DLMGCP, LOGL_ERROR, "conn:%s no codecs available\n",
			 mgcp_conn_dump(conn->conn));
		return;
	}

	/* Store parsed codec information */
	for (i = 0; i < rtp->codecs_assigned; i++) {
		codec = &rtp->codecs[i];

		LOGPENDP(endp, DLMGCP, LOGL_DEBUG, "conn:%s codecs[%u]:%s",
			 mgcp_conn_dump(conn->conn), i, dump_codec(codec));

		if (codec == rtp->codec)
			LOGPC(DLMGCP, LOGL_DEBUG, " [selected]");

		LOGPC(DLMGCP, LOGL_DEBUG, "\n");
	}
}

/* Initalize or reset codec information with default data. */
static void codec_init(struct mgcp_rtp_codec *codec)
{
	*codec = (struct mgcp_rtp_codec){
		.payload_type = -1,
		.frame_duration_num = DEFAULT_RTP_AUDIO_FRAME_DUR_NUM,
		.frame_duration_den = DEFAULT_RTP_AUDIO_FRAME_DUR_DEN,
		.rate = DEFAULT_RTP_AUDIO_DEFAULT_RATE,
		.channels = DEFAULT_RTP_AUDIO_DEFAULT_CHANNELS,
		.subtype_name = "",
		.audio_name = "",
	};
}

static void codec_free(struct mgcp_rtp_codec *codec)
{
	*codec = (struct mgcp_rtp_codec){};
}

/*! Initalize or reset codec information with default data.
 *  \param[out] conn related rtp-connection. */
void mgcp_codec_reset_all(struct mgcp_conn_rtp *conn)
{
	int i;
	for (i = 0; i < conn->end.codecs_assigned; i++)
		codec_free(&conn->end.codecs[i]);
	conn->end.codecs_assigned = 0;
	conn->end.codec = NULL;
}

/*! Add codec configuration depending on payload type and/or codec name. This
 *  function uses the input parameters to extrapolate the full codec information.
 *  \param[out] codec configuration (caller provided memory).
 *  \param[out] conn related rtp-connection.
 *  \param[in] payload_type codec type id (e.g. 3 for GSM, -1 when undefined).
 *  \param[in] audio_name audio codec name, in uppercase (e.g. "GSM/8000/1").
 *  \param[in] param optional codec parameters (set to NULL when unused).
 *  \returns 0 on success, -EINVAL on failure. */
int mgcp_codec_add(struct mgcp_conn_rtp *conn, int payload_type, const char *audio_name, const struct mgcp_codec_param *param)
{
	int rate;
	int channels;
	struct mgcp_rtp_codec *codec;
	unsigned int pt_offset = conn->end.codecs_assigned;

	/* The amount of codecs we can store is limited, make sure we do not
	 * overrun this limit. */
	if (conn->end.codecs_assigned >= MGCP_MAX_CODECS)
		return -EINVAL;

	/* First unused entry */
	codec = &conn->end.codecs[conn->end.codecs_assigned];

	/* Initalize the codec struct with some default data to begin with */
	codec_init(codec);

	if (payload_type != PTYPE_UNDEFINED) {
		/* Make sure we do not get any reserved or undefined type numbers */
		/* See also: https://www.iana.org/assignments/rtp-parameters/rtp-parameters.xhtml */
		if ((payload_type == 1 || payload_type == 2 || payload_type == 19)
		    || (payload_type >= 72 && payload_type <= 76)
		    || (payload_type >= 127)) {
			LOGP(DLMGCP, LOGL_ERROR, "Cannot add codec, payload type number %d is reserved\n",
			     payload_type);
			goto error;
		}

		codec->payload_type = payload_type;
	}

	/* When no audio name is given, we are forced to use the payload
	 * type to generate the audio name. This is only possible for
	 * non dynamic payload types, which are statically defined */
	if (!audio_name) {
		switch (payload_type) {
		case 0:
			strcpy(codec->audio_name, "PCMU/8000/1");
			break;
		case 3:
			strcpy(codec->audio_name, "GSM/8000/1");
			break;
		case 8:
			strcpy(codec->audio_name, "PCMA/8000/1");
			break;
		case 18:
			strcpy(codec->audio_name, "G729/8000/1");
			break;
		default:
			/* The given payload type is not known to us, or it
			 * it is a dynamic payload type for which we do not
			 * know the audio name. We must give up here */
			LOGP(DLMGCP, LOGL_ERROR, "No audio codec name given, and payload type %d unknown\n",
			     payload_type);
			goto error;
		}
	} else {
		OSMO_STRLCPY_ARRAY(codec->audio_name, audio_name);
	}

	/* Now we extract the codec subtype name, rate and channels. The latter
	 * two are optional. If they are not present we use the safe defaults
	 * above. */
	if (strlen(codec->audio_name) >= sizeof(codec->subtype_name)) {
		LOGP(DLMGCP, LOGL_ERROR, "Audio codec too long: %s\n", osmo_quote_str(codec->audio_name, -1));
		goto error;
	}
	channels = DEFAULT_RTP_AUDIO_DEFAULT_CHANNELS;
	rate = DEFAULT_RTP_AUDIO_DEFAULT_RATE;
	if (sscanf(codec->audio_name, "%63[^/]/%d/%d", codec->subtype_name, &rate, &channels) < 1) {
		LOGP(DLMGCP, LOGL_ERROR, "Invalid audio codec: %s\n", osmo_quote_str(codec->audio_name, -1));
		goto error;
	}

	/* Note: We only accept configurations with one audio channel! */
	if (channels != 1) {
		LOGP(DLMGCP, LOGL_ERROR, "Cannot handle audio codec with more than one channel: %s\n",
		     osmo_quote_str(codec->audio_name, -1));
		goto error;
	}

	codec->rate = rate;
	codec->channels = channels;
	codec->payload_type = payload_type;

	if (!strcmp(codec->subtype_name, "G729")) {
		codec->frame_duration_num = 10;
		codec->frame_duration_den = 1000;
	} else {
		codec->frame_duration_num = DEFAULT_RTP_AUDIO_FRAME_DUR_NUM;
		codec->frame_duration_den = DEFAULT_RTP_AUDIO_FRAME_DUR_DEN;
	}

	/* Derive the payload type if it is unknown */
	if (codec->payload_type == PTYPE_UNDEFINED) {
		/* TODO: This is semi dead code, see OS#4150 */

		/* For the known codecs from the static range we restore
		 * the IANA or 3GPP assigned payload type number */
		if (codec->rate == 8000 && codec->channels == 1) {
			/* See also: https://www.iana.org/assignments/rtp-parameters/rtp-parameters.xhtml */
			if (!strcmp(codec->subtype_name, "GSM"))
				codec->payload_type = 3;
			else if (!strcmp(codec->subtype_name, "PCMA"))
				codec->payload_type = 8;
			else if (!strcmp(codec->subtype_name, "PCMU"))
				codec->payload_type = 0;
			else if (!strcmp(codec->subtype_name, "G729"))
				codec->payload_type = 18;

			/* See also: 3GPP TS 48.103, chapter 5.4.2.2 RTP Payload
			 * Note: These are not fixed payload types as the IANA
			 * defined once, they still remain dymanic payload
			 * types, but with a payload type number preference. */
			else if (!strcmp(codec->subtype_name, "GSM-EFR"))
				codec->payload_type = 110;
			else if (!strcmp(codec->subtype_name, "GSM-HR-08"))
				codec->payload_type = 111;
			else if (!strcmp(codec->subtype_name, "AMR"))
				codec->payload_type = 112;
			else if (!strcmp(codec->subtype_name, "AMR-WB"))
				codec->payload_type = 113;
		}

		/* If we could not determine a payload type we assume that
		 * we are dealing with a codec from the dynamic range. We
		 * choose a fixed identifier from 96-109. (Note: normally,
		 * the dynamic payload type rante is from 96-127, but from
		 * 110 onwards 3gpp defines prefered codec types, which are
		 * also fixed, see above)  */
		if (codec->payload_type < 0) {
			/* FIXME: pt_offset is completely unrelated and useless here, any of those numbers may already
			 * have been added to the codecs. Instead, there should be an iterator checking for an actually
			 * unused dynamic payload type number. */
			codec->payload_type = 96 + pt_offset;
			if (codec->payload_type > 109) {
				LOGP(DLMGCP, LOGL_ERROR, "Ran out of payload type numbers to assign dynamically\n");
				goto error;
			}
		}
	}

	/* Copy over optional codec parameters */
	if (param) {
		codec->param = *param;
		codec->param_present = true;
	} else
		codec->param_present = false;

	conn->end.codecs_assigned++;
	return 0;
error:
	/* Make sure we leave a clean codec entry on error. */
	codec_free(codec);
	return -EINVAL;
}

/* Return true if octet-aligned is set in the given codec. Default to octet-aligned=0, i.e. bandwidth-efficient mode.
 * See RFC4867 "RTP Payload Format for AMR and AMR-WB" sections "8.1. AMR Media Type Registration" and "8.2. AMR-WB
 * Media Type Registration":
 *
 *    octet-align: Permissible values are 0 and 1.  If 1, octet-aligned
 *                 operation SHALL be used.  If 0 or if not present,
 *                 bandwidth-efficient operation is employed.
 *
 * https://tools.ietf.org/html/rfc4867
 */
bool mgcp_codec_amr_is_octet_aligned(const struct mgcp_rtp_codec *codec)
{
	if (!codec->param_present)
		return false;
	if (!codec->param.amr_octet_aligned_present)
		return false;
	return codec->param.amr_octet_aligned;
}

/* Compare two codecs, all parameters must match up */
static bool codecs_same(struct mgcp_rtp_codec *codec_a, struct mgcp_rtp_codec *codec_b)
{
	/* All codec properties must match up, except the payload type number. Even though standardisd payload numbers
	 * exist for certain situations, the call agent may still assign them freely. Hence we must not insist on equal
	 * payload type numbers. Also the audio_name is not checked since it is already parsed into subtype_name, rate,
	 * and channels, which are checked. */
	if (strcmp(codec_a->subtype_name, codec_b->subtype_name))
		return false;
	if (codec_a->rate != codec_b->rate)
		return false;
	if (codec_a->channels != codec_b->channels)
		return false;
	if (codec_a->frame_duration_num != codec_b->frame_duration_num)
		return false;
	if (codec_a->frame_duration_den != codec_b->frame_duration_den)
		return false;

	/* AMR payload may be formatted in two different payload formats, it is still the same codec but since the
	 * formatting of the payload is different, conversation is required, so we must treat it as a different
	 * codec here. */
	if (strcmp(codec_a->subtype_name, "AMR") == 0) {
		if (mgcp_codec_amr_is_octet_aligned(codec_a) != mgcp_codec_amr_is_octet_aligned(codec_b))
			return false;
	}

	return true;
}

/* Compare two codecs, all parameters must match up, except parameters related to payload formatting (not checked). */
static bool codecs_convertible(struct mgcp_rtp_codec *codec_a, struct mgcp_rtp_codec *codec_b)
{
	/* OsmoMGW currently has no ability to transcode from one codec to another. However OsmoMGW is still able to
	 * translate between different payload formats as long as the encoded voice data itself does not change.
	 * Therefore we must insist on equal codecs but still allow different payload formatting. */
	if (strcmp(codec_a->subtype_name, codec_b->subtype_name))
		return false;
	if (codec_a->rate != codec_b->rate)
		return false;
	if (codec_a->channels != codec_b->channels)
		return false;
	if (codec_a->frame_duration_num != codec_b->frame_duration_num)
		return false;
	if (codec_a->frame_duration_den != codec_b->frame_duration_den)
		return false;

	return true;
}

struct mgcp_rtp_codec *mgcp_codec_find_same(struct mgcp_conn_rtp *conn, struct mgcp_rtp_codec *codec)
{
	struct mgcp_rtp_end *rtp_end;
	unsigned int i;
	unsigned int codecs_assigned;

	rtp_end = &conn->end;

	/* Use the codec information from the source and try to find the equivalent of it on the destination side. In
	 * the first run we will look for an exact match. */
	codecs_assigned = rtp_end->codecs_assigned;
	OSMO_ASSERT(codecs_assigned <= MGCP_MAX_CODECS);
	for (i = 0; i < codecs_assigned; i++) {
		if (codecs_same(codec, &rtp_end->codecs[i])) {
			return &rtp_end->codecs[i];
			break;
		}
	}

	return NULL;
}

/* For a given codec, find a convertible codec in the given connection. */
static struct mgcp_rtp_codec *codec_find_convertible(struct mgcp_conn_rtp *conn, struct mgcp_rtp_codec *codec)
{
	struct mgcp_rtp_end *rtp_end;
	unsigned int i;
	unsigned int codecs_assigned;
	struct mgcp_rtp_codec *codec_convertible = NULL;

	rtp_end = &conn->end;

	/* Use the codec information from the source and try to find the equivalent of it on the destination side. In
	 * the first run we will look for an exact match. */
	codec_convertible = mgcp_codec_find_same(conn, codec);
	if (codec_convertible)
		return codec_convertible;

	/* In case we weren't able to find an exact match, we will try to find a match that is the same codec, but the
	 * payload format may be different. This alternative will require a frame format conversion (i.e. AMR bwe->oe) */
	codecs_assigned = rtp_end->codecs_assigned;
	OSMO_ASSERT(codecs_assigned <= MGCP_MAX_CODECS);
	for (i = 0; i < codecs_assigned; i++) {
		if (codecs_convertible(codec, &rtp_end->codecs[i])) {
			codec_convertible = &rtp_end->codecs[i];
			break;
		}
	}

	return codec_convertible;
}

/*! Decide for one suitable codec on both of the given connections. In case a destination connection is not available,
 *  a tentative decision is made.
 *  \param[inout] conn_src related rtp-connection.
 *  \param[inout] conn_dst related destination rtp-connection (NULL if not present).
 *  \returns 0 on success, -EINVAL on failure. */
int mgcp_codec_decide(struct mgcp_conn_rtp *conn_src, struct mgcp_conn_rtp *conn_dst)
{
	unsigned int i;

	/* In case no destination connection is available (yet), or in case the destination connection exists but has
	 * no codecs assigned, we are forced to make a simple tentative decision:
	 * We just use the first codec of the source connection (conn_src) */
	OSMO_ASSERT(conn_src->end.codecs_assigned <= MGCP_MAX_CODECS);
	if (!conn_dst || conn_dst->end.codecs_assigned == 0) {
		if (conn_src->end.codecs_assigned >= 1) {
			conn_src->end.codec = &conn_src->end.codecs[0];
			return 0;
		} else
			return -EINVAL;
	}

	/* Compare all codecs of the source connection (conn_src) to the codecs of the destination connection (conn_dst). In case
	 * of a match set this codec on both connections. This would be an ideal selection since no codec conversion would be
	 * required. */
	for (i = 0; i < conn_src->end.codecs_assigned; i++) {
		struct mgcp_rtp_codec *codec_conn_dst = mgcp_codec_find_same(conn_dst, &conn_src->end.codecs[i]);
		if (codec_conn_dst) {
			/* We found the a codec that is exactly the same (same codec, same payload format etc.) on both
			 * sides. We now set this codec on both connections. */
			conn_dst->end.codec = codec_conn_dst;
			conn_src->end.codec = mgcp_codec_find_same(conn_src, codec_conn_dst);
			OSMO_ASSERT(conn_src->end.codec);
			return 0;
		}
	}

	/* In case we could not find a codec that is exactly the same, let's at least try to find a codec that we are able
	 * to convert. */
	for (i = 0; i < conn_src->end.codecs_assigned; i++) {
		struct mgcp_rtp_codec *codec_conn_dst = codec_find_convertible(conn_dst, &conn_src->end.codecs[i]);
		if (codec_conn_dst) {
			/* We found the a codec that we are able to convert on both sides. We now set this codec on both
			 * connections. */
			conn_dst->end.codec = codec_conn_dst;
			conn_src->end.codec = codec_find_convertible(conn_src, codec_conn_dst);
			OSMO_ASSERT(conn_src->end.codec);
			return 0;
		}
	}

	return -EINVAL;
}

/* Check if the codec has a specific AMR mode (octet-aligned or bandwith-efficient) set. */
bool mgcp_codec_amr_align_mode_is_indicated(const struct mgcp_rtp_codec *codec)
{
	if (codec->param_present == false)
		return false;
	if (!codec->param.amr_octet_aligned_present)
		return false;
	if (strcmp(codec->subtype_name, "AMR") != 0)
		return false;
	return true;
}

/* Find the payload type number configured for a specific codec by SDP.
 * For example, IuUP gets assigned a payload type number, and the endpoint needs to translate that to the number
 * assigned to "AMR" on the other conn (by a=rtpmap:N).
 * \param conn  The side of an endpoint to get the payload type number for (to translate the payload type number to).
 * \param subtype_name  SDP codec name without parameters (e.g. "AMR").
 * \param match_nr  Index for the match found, first being match_nr == 0. Iterate all matches by calling multiple times
 *                  with incrementing match_nr.
 * \return codec definition for that conn matching the subtype_name, or NULL if no such match_nr is found. */
const struct mgcp_rtp_codec *mgcp_codec_pt_find_by_subtype_name(struct mgcp_conn_rtp *conn,
								const char *subtype_name, unsigned int match_nr)
{
	int i;
	for (i = 0; i < conn->end.codecs_assigned; i++) {
		if (!strcmp(conn->end.codecs[i].subtype_name, subtype_name)) {
			if (match_nr) {
				match_nr--;
				continue;
			}
			return &conn->end.codecs[i];
		}
	}
	return NULL;
}

/*! Lookup a codec that is assigned to a connection by its payload type number.
 *  \param[in] conn related rtp-connection.
 *  \param[in] payload_type number of the codec to look up.
 *  \returns pointer to codec struct on success, NULL on failure. */
struct mgcp_rtp_codec *mgcp_codec_from_pt(struct mgcp_conn_rtp *conn, int payload_type)
{
	struct mgcp_rtp_end *rtp_end = &conn->end;
	unsigned int codecs_assigned = rtp_end->codecs_assigned;
	struct mgcp_rtp_codec *codec = NULL;
	size_t i;

	OSMO_ASSERT(codecs_assigned <= MGCP_MAX_CODECS);

	for (i = 0; i < codecs_assigned; i++) {
		if (payload_type == rtp_end->codecs[i].payload_type) {
			codec = &rtp_end->codecs[i];
			break;
		}
	}

	return codec;
}

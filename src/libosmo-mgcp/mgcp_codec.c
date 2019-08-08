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
#include <osmocom/mgcp/mgcp_internal.h>
#include <osmocom/mgcp/mgcp_endp.h>
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
void codec_init(struct mgcp_rtp_codec *codec)
{
	if (codec->subtype_name)
		talloc_free(codec->subtype_name);
	if (codec->audio_name)
		talloc_free(codec->audio_name);
	memset(codec, 0, sizeof(*codec));
	codec->payload_type = -1;
	codec->frame_duration_num = DEFAULT_RTP_AUDIO_FRAME_DUR_NUM;
	codec->frame_duration_den = DEFAULT_RTP_AUDIO_FRAME_DUR_DEN;
	codec->rate = DEFAULT_RTP_AUDIO_DEFAULT_RATE;
	codec->channels = DEFAULT_RTP_AUDIO_DEFAULT_CHANNELS;
}

/*! Initalize or reset codec information with default data.
 *  \param[out] conn related rtp-connection. */
void mgcp_codec_reset_all(struct mgcp_conn_rtp *conn)
{
	memset(conn->end.codecs, 0, sizeof(conn->end.codecs));
	conn->end.codecs_assigned = 0;
	conn->end.codec = NULL;
}

/* Set members of struct mgcp_rtp_codec, extrapolate in missing information. Param audio_name is expected in uppercase. */
static int codec_set(void *ctx, struct mgcp_rtp_codec *codec, int payload_type, const char *audio_name,
		     unsigned int pt_offset, const struct mgcp_codec_param *param)
{
	int rate;
	int channels;
	char audio_codec[64];

	/* Initalize the codec struct with some default data to begin with */
	codec_init(codec);

	if (payload_type != PTYPE_UNDEFINED) {
		/* Make sure we do not get any reserved or undefined type numbers */
		/* See also: https://www.iana.org/assignments/rtp-parameters/rtp-parameters.xhtml */
		if (payload_type == 1 || payload_type == 2 || payload_type == 19)
			goto error;
		if (payload_type >= 72 && payload_type <= 76)
			goto error;
		if (payload_type >= 127)
			goto error;

		codec->payload_type = payload_type;
	}

	/* When no audio name is given, we are forced to use the payload
	 * type to generate the audio name. This is only possible for
	 * non dynamic payload types, which are statically defined */
	if (!audio_name) {
		switch (payload_type) {
		case 0:
			audio_name = talloc_strdup(ctx, "PCMU/8000/1");
			break;
		case 3:
			audio_name = talloc_strdup(ctx, "GSM/8000/1");
			break;
		case 8:
			audio_name = talloc_strdup(ctx, "PCMA/8000/1");
			break;
		case 18:
			audio_name = talloc_strdup(ctx, "G729/8000/1");
			break;
		default:
			/* The given payload type is not known to us, or it
			 * it is a dynamic payload type for which we do not
			 * know the audio name. We must give up here */
			goto error;
		}
	}

	/* Now we extract the codec subtype name, rate and channels. The latter
	 * two are optional. If they are not present we use the safe defaults
	 * above. */
	if (strlen(audio_name) > sizeof(audio_codec))
		goto error;
	channels = DEFAULT_RTP_AUDIO_DEFAULT_CHANNELS;
	rate = DEFAULT_RTP_AUDIO_DEFAULT_RATE;
	if (sscanf(audio_name, "%63[^/]/%d/%d", audio_codec, &rate, &channels) < 1)
		goto error;

	/* Note: We only accept configurations with one audio channel! */
	if (channels != 1)
		goto error;

	codec->rate = rate;
	codec->channels = channels;
	codec->subtype_name = talloc_strdup(ctx, audio_codec);
	codec->audio_name = talloc_strdup(ctx, audio_name);
	codec->payload_type = payload_type;

	if (!strcmp(audio_codec, "G729")) {
		codec->frame_duration_num = 10;
		codec->frame_duration_den = 1000;
	} else {
		codec->frame_duration_num = DEFAULT_RTP_AUDIO_FRAME_DUR_NUM;
		codec->frame_duration_den = DEFAULT_RTP_AUDIO_FRAME_DUR_DEN;
	}

	/* Derive the payload type if it is unknown */
	if (codec->payload_type == PTYPE_UNDEFINED) {

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
			codec->payload_type = 96 + pt_offset;
			if (codec->payload_type > 109)
				goto error;
		}
	}

	/* Copy over optional codec parameters */
	if (param) {
		codec->param = *param;
		codec->param_present = true;
	} else
		codec->param_present = false;

	return 0;
error:
	/* Make sure we leave a clean codec entry on error. */
	codec_init(codec);
	memset(codec, 0, sizeof(*codec));
	return -EINVAL;
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
	int rc;

	/* The amount of codecs we can store is limited, make sure we do not
	 * overrun this limit. */
	if (conn->end.codecs_assigned >= MGCP_MAX_CODECS)
		return -EINVAL;

	rc = codec_set(conn->conn, &conn->end.codecs[conn->end.codecs_assigned], payload_type, audio_name,
		       conn->end.codecs_assigned, param);
	if (rc != 0)
		return -EINVAL;

	conn->end.codecs_assigned++;

	return 0;
}

/* Check if the given codec is applicable on the specified endpoint
 * Helper function for mgcp_codec_decide() */
static bool is_codec_compatible(const struct mgcp_endpoint *endp, const struct mgcp_rtp_codec *codec)
{
	char codec_name[64];

	/* A codec name must be set, if not, this might mean that the codec
	 * (payload type) that was assigned is unknown to us so we must stop
	 * here. */
	if (!codec->subtype_name)
		return false;

	/* We now extract the codec_name (letters before the /, e.g. "GSM"
	 * from the audio name that is stored in the trunk configuration.
	 * We do not compare to the full audio_name because we expect that
	 * "GSM", "GSM/8000" and "GSM/8000/1" are all compatible when the
	 * audio name of the codec is set to "GSM" */
	if (sscanf(endp->tcfg->audio_name, "%63[^/]/%*d/%*d", codec_name) < 1)
		return false;

	/* Finally we check if the subtype_name we have generated from the
	 * audio_name in the trunc struct patches the codec_name of the
	 * given codec */
	if (strcasecmp(codec_name, codec->subtype_name) == 0)
		return true;

	/* FIXME: It is questinable that the method to pick a compatible
	 * codec can work properly. Since this useses tcfg->audio_name, as
	 * a reference, which is set to "AMR/8000" permanently.
	 * tcfg->audio_name must be updated by the first connection that
	 * has been made on an endpoint, so that the second connection
	 * can make a meaningful decision here */

	return false;
}

/*! Decide for one suitable codec
 *  \param[in] conn related rtp-connection.
 *  \returns 0 on success, -EINVAL on failure. */
int mgcp_codec_decide(struct mgcp_conn_rtp *conn)
{
	struct mgcp_rtp_end *rtp;
	unsigned int i;
	struct mgcp_endpoint *endp;
	bool codec_assigned = false;

	endp = conn->conn->endp;
	rtp = &conn->end;

	/* This function works on the results the SDP/LCO parser has extracted
	 * from the MGCP message. The goal is to select a suitable codec for
	 * the given connection. When transcoding is available, the first codec
	 * from the codec list is taken without further checking. When
	 * transcoding is not available, then the choice must be made more
	 * carefully. Each codec in the list is checked until one is found that
	 * is rated compatible. The rating is done by the helper function
	 * is_codec_compatible(), which does the actual checking. */
	for (i = 0; i < rtp->codecs_assigned; i++) {
		/* When no transcoding is available, avoid codecs that would
		 * require transcoding. */
		if (endp->tcfg->no_audio_transcoding && !is_codec_compatible(endp, &rtp->codecs[i])) {
			LOGP(DLMGCP, LOGL_NOTICE, "transcoding not available, skipping codec: %d/%s\n",
			     rtp->codecs[i].payload_type, rtp->codecs[i].subtype_name);
			continue;
		}

		rtp->codec = &rtp->codecs[i];
		codec_assigned = true;
		break;
	}

	/* FIXME: To the reviewes: This is problematic. I do not get why we
	 * need to reset the packet_duration_ms depending on the codec
	 * selection. I thought it were all 20ms? Is this to address some
	 * cornercase. (This piece of code was in the code path before,
	 * together with the note: "TODO/XXX: Store this per codec and derive
	 * it on use" */
	if (codec_assigned) {
		if (rtp->maximum_packet_time >= 0
		    && rtp->maximum_packet_time * rtp->codec->frame_duration_den >
		    rtp->codec->frame_duration_num * 1500)
			rtp->packet_duration_ms = 0;

		return 0;
	}

	return -EINVAL;
}

/* Compare two codecs, all parameters must match up, except for the payload type
 * number. */
static bool codecs_same(struct mgcp_rtp_codec *codec_a, struct mgcp_rtp_codec *codec_b)
{
	if (codec_a->rate != codec_b->rate)
		return false;
	if (codec_a->channels != codec_b->channels)
		return false;
	if (codec_a->frame_duration_num != codec_b->frame_duration_num)
		return false;
	if (codec_a->frame_duration_den != codec_b->frame_duration_den)
		return false;
	if (strcmp(codec_a->audio_name, codec_b->audio_name))
		return false;
	if (strcmp(codec_a->subtype_name, codec_b->subtype_name))
		return false;

	return true;
}

/*! Translate a given payload type number that belongs to the packet of a
 *  source connection to the equivalent payload type number that matches the
 *  configuration of a destination connection.
 *  \param[in] conn_src related source rtp-connection.
 *  \param[in] conn_dst related destination rtp-connection.
 *  \param[in] payload_type number from the source packet or source connection.
 *  \returns translated payload type number on success, -EINVAL on failure. */
int mgcp_codec_pt_translate(struct mgcp_conn_rtp *conn_src, struct mgcp_conn_rtp *conn_dst, int payload_type)
{
	struct mgcp_rtp_end *rtp_src;
	struct mgcp_rtp_end *rtp_dst;
	struct mgcp_rtp_codec *codec_src = NULL;
	struct mgcp_rtp_codec *codec_dst = NULL;
	unsigned int i;
	unsigned int codecs_assigned;

	rtp_src = &conn_src->end;
	rtp_dst = &conn_dst->end;

	/* Find the codec information that is used on the source side */
	codecs_assigned = rtp_src->codecs_assigned;
	OSMO_ASSERT(codecs_assigned <= MGCP_MAX_CODECS);
	for (i = 0; i < codecs_assigned; i++) {
		if (payload_type == rtp_src->codecs[i].payload_type) {
			codec_src = &rtp_src->codecs[i];
			break;
		}
	}
	if (!codec_src)
		return -EINVAL;

	/* Use the codec infrmation from the source and try to find the
	 * equivalent of it on the destination side */
	codecs_assigned = rtp_dst->codecs_assigned;
	OSMO_ASSERT(codecs_assigned <= MGCP_MAX_CODECS);
	for (i = 0; i < codecs_assigned; i++) {
		if (codecs_same(codec_src, &rtp_dst->codecs[i])) {
			codec_dst = &rtp_dst->codecs[i];
			break;
		}
	}
	if (!codec_dst)
		return -EINVAL;

	return codec_dst->payload_type;
}

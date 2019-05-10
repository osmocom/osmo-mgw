/*
 * (C) 2016 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Neels Hofmeyr
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
 */

#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

#include <string.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/application.h>
#include <osmocom/mgcp_client/mgcp_client.h>
#include <osmocom/mgcp_client/mgcp_client_internal.h>
#include <errno.h>

void *ctx;

#define buf_len 4096

#if 0
static struct msgb *from_hex(const char *hex)
{
	struct msgb *msg = msgb_alloc(buf_len, "mgcpgw_test_from_hex");
	unsigned int l = osmo_hexparse(hex, msg->data, buf_len);
	msg->l2h = msgb_put(msg, l);
	return msg;
}

static struct msgb *mgcp_from_str(const char *head, const char *params)
{
	struct msgb *msg = msgb_alloc(buf_len, "mgcp_from_str");
	unsigned int l;
	char *data;
	l = strlen(head);
	msg->l2h = msgb_put(msg, l);
	data = (char*)msgb_l2(msg);
	osmo_strlcpy(data, head, l);

	data = (char*)msgb_put(msg, 1);
	*data = '\n';

	l = strlen(params);
	data = (char*)msgb_put(msg, l);
	osmo_strlcpy(data, params, l);

	return msg;
}
#endif

static struct msgb *from_str(const char *str)
{
	struct msgb *msg = msgb_alloc(buf_len, "from_str");
	unsigned int l = strlen(str);
	char *data;
	msg->l2h = msgb_put(msg, l);
	data = (char*)msgb_l2(msg);
	osmo_strlcpy(data, str, l);
	return msg;
}

static struct mgcp_client_conf conf;
struct mgcp_client *mgcp = NULL;

static int reply_to(mgcp_trans_id_t trans_id, int code, const char *comment,
		    const char *params)
{
	static char compose[4096 - 128];
	int len;

	len = snprintf(compose, sizeof(compose),
		       "%d %u %s\r\n%s",
		       code, trans_id, comment, params);
	OSMO_ASSERT(len < sizeof(compose));
	OSMO_ASSERT(len > 0);

	printf("composed response:\n-----\n%s\n-----\n",
	       compose);
	return mgcp_client_rx(mgcp, from_str(compose));
}

void test_response_cb(struct mgcp_response *response, void *priv)
{
	unsigned int i;
	OSMO_ASSERT(priv == mgcp);
	mgcp_response_parse_params(response);

	printf("response cb received:\n");
	printf("  head.response_code = %d\n", response->head.response_code);
	printf("  head.trans_id = %u\n", response->head.trans_id);
	printf("  head.conn_id = %s\n", response->head.conn_id);
	printf("  head.comment = %s\n", response->head.comment);
	printf("  audio_port = %u\n", response->audio_port);
	printf("  audio_ip = %s\n", response->audio_ip);
	printf("  ptime = %u\n", response->ptime);
	printf("  codecs_len = %u\n", response->codecs_len);
	for(i=0;i<response->codecs_len;i++)
		printf("  codecs[%u] = %u\n", i, response->codecs[i]);
	printf("  ptmap_len = %u\n", response->ptmap_len);
	for(i=0;i<response->ptmap_len;i++) {
		printf("  ptmap[%u].codec = %u\n", i, response->ptmap[i].codec);
		printf("  ptmap[%u].pt = %u\n", i, response->ptmap[i].pt);
	}

}

mgcp_trans_id_t dummy_mgcp_send(struct msgb *msg)
{
	mgcp_trans_id_t trans_id;
	trans_id = msg->cb[MSGB_CB_MGCP_TRANS_ID];
	char *end;

	OSMO_ASSERT(mgcp_client_pending_add(mgcp, trans_id, test_response_cb, mgcp));

	end = (char*)msgb_put(msg, 1);
	*end = '\0';
	printf("composed:\n-----\n%s\n-----\n",
	       (char*)msgb_l2(msg));

	talloc_free(msg);
	return trans_id;
}

void test_mgcp_msg(void)
{
	struct msgb *msg;
	char audio_ip_overflow[5000];

	/* A message struct prefilled with some arbitary values */
	struct mgcp_msg mgcp_msg = {
		.audio_ip = "192.168.100.23",
		.endpoint = "23@mgw",
		.audio_port = 1234,
		.call_id = 47,
		.conn_id = "11",
		.conn_mode = MGCP_CONN_RECV_SEND,
		.ptime = 20,
		.codecs[0] = CODEC_GSM_8000_1,
		.codecs[1] = CODEC_AMR_8000_1,
		.codecs[2] = CODEC_GSMEFR_8000_1,
		.codecs_len = 1,
		.ptmap[0].codec = CODEC_GSMEFR_8000_1,
		.ptmap[0].pt = 96,
		.ptmap_len = 1,
		.x_osmo_ign = MGCP_X_OSMO_IGN_CALLID,
		.x_osmo_osmux_cid = -1, /* wildcard */
	};

	if (mgcp)
		talloc_free(mgcp);
	mgcp = mgcp_client_init(ctx, &conf);

	printf("\n");

	printf("Generated CRCX message:\n");
	mgcp_msg.verb = MGCP_VERB_CRCX;
	mgcp_msg.presence =
	    (MGCP_MSG_PRESENCE_ENDPOINT | MGCP_MSG_PRESENCE_CALL_ID |
	     MGCP_MSG_PRESENCE_CONN_ID | MGCP_MSG_PRESENCE_CONN_MODE);
	msg = mgcp_msg_gen(mgcp, &mgcp_msg);
	printf("%s\n", (char *)msg->data);

	printf("Generated CRCX message (two codecs):\n");
	mgcp_msg.verb = MGCP_VERB_CRCX;
	mgcp_msg.presence =
	    (MGCP_MSG_PRESENCE_ENDPOINT | MGCP_MSG_PRESENCE_CALL_ID |
	     MGCP_MSG_PRESENCE_CONN_ID | MGCP_MSG_PRESENCE_CONN_MODE);
	mgcp_msg.codecs_len = 2;
	msg = mgcp_msg_gen(mgcp, &mgcp_msg);
	mgcp_msg.codecs_len = 1;
	printf("%s\n", (char *)msg->data);

	printf("Generated CRCX message (three codecs, one with custom pt):\n");
	mgcp_msg.verb = MGCP_VERB_CRCX;
	mgcp_msg.presence =
	    (MGCP_MSG_PRESENCE_ENDPOINT | MGCP_MSG_PRESENCE_CALL_ID |
	     MGCP_MSG_PRESENCE_CONN_ID | MGCP_MSG_PRESENCE_CONN_MODE);
	mgcp_msg.codecs_len = 3;
	msg = mgcp_msg_gen(mgcp, &mgcp_msg);
	mgcp_msg.codecs_len = 1;
	printf("%s\n", (char *)msg->data);

	printf("Generated MDCX message:\n");
	mgcp_msg.verb = MGCP_VERB_MDCX;
	mgcp_msg.presence =
	    (MGCP_MSG_PRESENCE_ENDPOINT | MGCP_MSG_PRESENCE_CALL_ID |
	     MGCP_MSG_PRESENCE_CONN_ID | MGCP_MSG_PRESENCE_CONN_MODE |
	     MGCP_MSG_PRESENCE_AUDIO_IP | MGCP_MSG_PRESENCE_AUDIO_PORT);
	msg = mgcp_msg_gen(mgcp, &mgcp_msg);
	printf("%s\n", (char *)msg->data);

	printf("Generated MDCX message (two codecs):\n");
	mgcp_msg.verb = MGCP_VERB_MDCX;
	mgcp_msg.presence =
	    (MGCP_MSG_PRESENCE_ENDPOINT | MGCP_MSG_PRESENCE_CALL_ID |
	     MGCP_MSG_PRESENCE_CONN_ID | MGCP_MSG_PRESENCE_CONN_MODE |
	     MGCP_MSG_PRESENCE_AUDIO_IP | MGCP_MSG_PRESENCE_AUDIO_PORT);
	mgcp_msg.codecs_len = 2;
	msg = mgcp_msg_gen(mgcp, &mgcp_msg);
	mgcp_msg.codecs_len = 1;
	printf("%s\n", (char *)msg->data);

	printf("Generated MDCX message (three codecs, one with custom pt):\n");
	mgcp_msg.verb = MGCP_VERB_MDCX;
	mgcp_msg.presence =
	    (MGCP_MSG_PRESENCE_ENDPOINT | MGCP_MSG_PRESENCE_CALL_ID |
	     MGCP_MSG_PRESENCE_CONN_ID | MGCP_MSG_PRESENCE_CONN_MODE |
	     MGCP_MSG_PRESENCE_AUDIO_IP | MGCP_MSG_PRESENCE_AUDIO_PORT);
	mgcp_msg.codecs_len = 3;
	msg = mgcp_msg_gen(mgcp, &mgcp_msg);
	mgcp_msg.codecs_len = 1;
	printf("%s\n", (char *)msg->data);

	printf("Generated DLCX message:\n");
	mgcp_msg.verb = MGCP_VERB_DLCX;
	mgcp_msg.presence =
	    (MGCP_MSG_PRESENCE_ENDPOINT | MGCP_MSG_PRESENCE_CALL_ID |
	     MGCP_MSG_PRESENCE_CONN_ID);
	msg = mgcp_msg_gen(mgcp, &mgcp_msg);
	printf("%s\n", (char *)msg->data);

	printf("Generated AUEP message:\n");
	mgcp_msg.verb = MGCP_VERB_AUEP;
	mgcp_msg.presence = (MGCP_MSG_PRESENCE_ENDPOINT);
	msg = mgcp_msg_gen(mgcp, &mgcp_msg);
	printf("%s\n", msg->data);

	printf("Generated RSIP message:\n");
	mgcp_msg.verb = MGCP_VERB_RSIP;
	mgcp_msg.presence = (MGCP_MSG_PRESENCE_ENDPOINT);
	msg = mgcp_msg_gen(mgcp, &mgcp_msg);
	printf("%s\n", (char *)msg->data);

	printf("Generate X-Osmo-IGN message:\n");
	msg = mgcp_msg_gen(mgcp, &mgcp_msg);
	mgcp_msg.verb = MGCP_VERB_CRCX;
	mgcp_msg.presence =
	    (MGCP_MSG_PRESENCE_ENDPOINT | MGCP_MSG_PRESENCE_CALL_ID |
	     MGCP_MSG_PRESENCE_CONN_ID | MGCP_MSG_PRESENCE_CONN_MODE
	     | MGCP_MSG_PRESENCE_X_OSMO_IGN);
	msg = mgcp_msg_gen(mgcp, &mgcp_msg);
	printf("%s\n", (char *)msg->data);

	printf("Generate X-Osmo-Osmux message:\n");
	msg = mgcp_msg_gen(mgcp, &mgcp_msg);
	mgcp_msg.verb = MGCP_VERB_CRCX;
	mgcp_msg.presence =
	    (MGCP_MSG_PRESENCE_ENDPOINT | MGCP_MSG_PRESENCE_CALL_ID |
	     MGCP_MSG_PRESENCE_CONN_ID | MGCP_MSG_PRESENCE_CONN_MODE
	     | MGCP_MSG_PRESENCE_X_OSMO_OSMUX_CID);
	msg = mgcp_msg_gen(mgcp, &mgcp_msg);
	printf("%s\n", (char *)msg->data);

	printf("Generate X-Osmo-Osmux message (fixed CID 2):\n");
	msg = mgcp_msg_gen(mgcp, &mgcp_msg);
	mgcp_msg.verb = MGCP_VERB_CRCX;
	mgcp_msg.x_osmo_osmux_cid = 2;
	mgcp_msg.presence =
	    (MGCP_MSG_PRESENCE_ENDPOINT | MGCP_MSG_PRESENCE_CALL_ID |
	     MGCP_MSG_PRESENCE_CONN_ID | MGCP_MSG_PRESENCE_CONN_MODE
	     | MGCP_MSG_PRESENCE_X_OSMO_OSMUX_CID);
	msg = mgcp_msg_gen(mgcp, &mgcp_msg);
	printf("%s\n", (char *)msg->data);

	printf("Generate X-Osmo-Osmux message (MDCX):\n");
	msg = mgcp_msg_gen(mgcp, &mgcp_msg);
	mgcp_msg.verb = MGCP_VERB_MDCX;
	mgcp_msg.x_osmo_osmux_cid = 2;
	mgcp_msg.presence =
	    (MGCP_MSG_PRESENCE_ENDPOINT | MGCP_MSG_PRESENCE_CALL_ID |
	     MGCP_MSG_PRESENCE_CONN_ID | MGCP_MSG_PRESENCE_CONN_MODE
	     | MGCP_MSG_PRESENCE_X_OSMO_OSMUX_CID);
	msg = mgcp_msg_gen(mgcp, &mgcp_msg);
	printf("%s\n", (char *)msg->data);

	printf("Overfolow test:\n");
	mgcp_msg.verb = MGCP_VERB_MDCX;
	mgcp_msg.presence =
	    (MGCP_MSG_PRESENCE_ENDPOINT | MGCP_MSG_PRESENCE_CALL_ID |
	     MGCP_MSG_PRESENCE_CONN_ID | MGCP_MSG_PRESENCE_CONN_MODE |
	     MGCP_MSG_PRESENCE_AUDIO_IP | MGCP_MSG_PRESENCE_AUDIO_PORT);
	memset(audio_ip_overflow, 'X', sizeof(audio_ip_overflow));
	audio_ip_overflow[sizeof(audio_ip_overflow) - 1] = '\0';
	mgcp_msg.audio_ip = audio_ip_overflow;
	msg = mgcp_msg_gen(mgcp, &mgcp_msg);
	OSMO_ASSERT(msg == NULL);

	printf("\n");
	msgb_free(msg);
}

void test_mgcp_client_cancel()
{
	mgcp_trans_id_t trans_id;
	struct msgb *msg;
	struct mgcp_msg mgcp_msg = {
		.verb = MGCP_VERB_CRCX,
		.audio_ip = "192.168.100.23",
		.endpoint = "23@mgw",
		.audio_port = 1234,
		.call_id = 47,
		.conn_id = "11",
		.conn_mode = MGCP_CONN_RECV_SEND,
		.presence = (MGCP_MSG_PRESENCE_ENDPOINT | MGCP_MSG_PRESENCE_CALL_ID
			     | MGCP_MSG_PRESENCE_CONN_ID | MGCP_MSG_PRESENCE_CONN_MODE),
		.ptime = 20,
		.codecs[0] = CODEC_AMR_8000_1,
		.codecs_len = 1
	};

	printf("\n%s():\n", __func__);
	fprintf(stderr, "\n%s():\n", __func__);

	if (mgcp)
		talloc_free(mgcp);
	mgcp = mgcp_client_init(ctx, &conf);

	msg = mgcp_msg_gen(mgcp, &mgcp_msg);
	trans_id = mgcp_msg_trans_id(msg);
	fprintf(stderr, "- composed msg with trans_id=%u\n", trans_id);

	fprintf(stderr, "- not in queue yet, cannot cancel yet\n");
	OSMO_ASSERT(mgcp_client_cancel(mgcp, trans_id) == -ENOENT);

	fprintf(stderr, "- enqueue\n");
	dummy_mgcp_send(msg);

	fprintf(stderr, "- cancel succeeds\n");
	OSMO_ASSERT(mgcp_client_cancel(mgcp, trans_id) == 0);

	fprintf(stderr, "- late response gets discarded\n");
	OSMO_ASSERT(reply_to(trans_id, 200, "OK", "I: 1\r\n\r\nv=0\r\n") == -ENOENT);

	fprintf(stderr, "- canceling again does nothing\n");
	OSMO_ASSERT(mgcp_client_cancel(mgcp, trans_id) == -ENOENT);

	fprintf(stderr, "%s() done\n", __func__);
}

struct sdp_section_start_test {
	const char *body;
	int expect_rc;
	struct mgcp_response expect_params;
};

static struct sdp_section_start_test sdp_section_start_tests[] = {
	{
		.body = "",
		.expect_rc = -EINVAL,
	},
	{
		.body = "\n\n",
	},
	{
		.body = "\r\n\r\n",
	},
	{
		.body = "\n\r\n\r",
	},
	{
		.body = "some mgcp header data\r\nand header params"
			"\n\n"
			"m=audio 23\r\n",
		.expect_params = {
			.audio_port = 23,
		},
	},
	{
		.body = "some mgcp header data\r\nand header params"
			"\r\n\r\n"
			"m=audio 23\r\n",
		.expect_params = {
			.audio_port = 23,
		},
	},
	{
		.body = "some mgcp header data\r\nand header params"
			"\n\r\n\r"
			"m=audio 23\r\n",
		.expect_params = {
			.audio_port = 23,
		},
	},
	{
		.body = "some mgcp header data\r\nand header params"
			"\n\r\n"
			"m=audio 23\r\n",
		.expect_rc = -EINVAL,
	},
	{
		.body = "some mgcp header data\r\nand header params"
			"\r\n\r"
			"m=audio 23\r\n",
		.expect_rc = -EINVAL,
	},
	{
		.body = "some mgcp header data\r\nand header params"
			"\n\r\r"
			"m=audio 23\r\n",
		.expect_rc = -EINVAL,
	},
};

void test_sdp_section_start()
{
	int i;
	int failures = 0;

	for (i = 0; i < ARRAY_SIZE(sdp_section_start_tests); i++) {
		int rc;
		struct sdp_section_start_test *t = &sdp_section_start_tests[i];
		struct mgcp_response *r = talloc_zero(ctx, struct mgcp_response);

		r->body = talloc_strdup(r, t->body);

		printf("\n%s() test [%d]:\n", __func__, i);
		fprintf(stderr, "\n%s() test [%d]:\n", __func__, i);
		fprintf(stderr, "body: \"%s\"\n", osmo_escape_str(r->body, -1));

		rc = mgcp_response_parse_params(r);

		fprintf(stderr, "got rc=%d\n", rc);
		if (rc != t->expect_rc) {
			fprintf(stderr, "FAIL: Expected rc=%d\n", t->expect_rc);
			failures++;
		}
		if (rc) {
			talloc_free(r);
			continue;
		}

		fprintf(stderr, "got audio_port=%u\n", t->expect_params.audio_port);
		if (r->audio_port != t->expect_params.audio_port) {
			fprintf(stderr, "FAIL: Expected audio_port=%u\n", t->expect_params.audio_port);
			failures++;
		}
		talloc_free(r);
	}

	OSMO_ASSERT(!failures);
}

static void test_map_pt_to_codec(void)
{
	/* Full form */
	OSMO_ASSERT(map_str_to_codec("PCMU/8000/1") == CODEC_PCMU_8000_1);
	OSMO_ASSERT(map_str_to_codec("GSM/8000/1") == CODEC_GSM_8000_1);
	OSMO_ASSERT(map_str_to_codec("PCMA/8000/1") == CODEC_PCMA_8000_1);
	OSMO_ASSERT(map_str_to_codec("G729/8000/1") == CODEC_G729_8000_1);
	OSMO_ASSERT(map_str_to_codec("GSM-EFR/8000/1") == CODEC_GSMEFR_8000_1);
	OSMO_ASSERT(map_str_to_codec("GSM-HR-08/8000/1") == CODEC_GSMHR_8000_1);
	OSMO_ASSERT(map_str_to_codec("AMR/8000/1") == CODEC_AMR_8000_1);
	OSMO_ASSERT(map_str_to_codec("AMR-WB/16000/1") == CODEC_AMRWB_16000_1);

	/* Short form */
	OSMO_ASSERT(map_str_to_codec("GSM-EFR") == CODEC_GSMEFR_8000_1);
	OSMO_ASSERT(map_str_to_codec("G729") == CODEC_G729_8000_1);
	OSMO_ASSERT(map_str_to_codec("GSM-HR-08") == CODEC_GSMHR_8000_1);

	/* We do not care about what is after the first delimiter */
	OSMO_ASSERT(map_str_to_codec("AMR-WB/123///456") == CODEC_AMRWB_16000_1);
	OSMO_ASSERT(map_str_to_codec("PCMA/asdf") == CODEC_PCMA_8000_1);
	OSMO_ASSERT(map_str_to_codec("GSM/qwertz") == CODEC_GSM_8000_1);

	/* A trailing delimiter should not hurt */
	OSMO_ASSERT(map_str_to_codec("AMR/") == CODEC_AMR_8000_1);
	OSMO_ASSERT(map_str_to_codec("G729/") == CODEC_G729_8000_1);
	OSMO_ASSERT(map_str_to_codec("GSM/") == CODEC_GSM_8000_1);

	/* This is expected to fail */
	OSMO_ASSERT(map_str_to_codec("INVALID/1234/7") == -1);
	OSMO_ASSERT(map_str_to_codec(NULL) == -1);
	OSMO_ASSERT(map_str_to_codec("") == -1);
	OSMO_ASSERT(map_str_to_codec("/////") == -1);

	/* The buffers are 64 bytes long, check what happens with overlong
	 * strings as input (This schould still work.) */
	OSMO_ASSERT(map_str_to_codec("AMR-WB/16000/1############################################################################################################") == CODEC_AMRWB_16000_1);

	/* This should not work, as there is no delimiter after the codec
	 * name */
	OSMO_ASSERT(map_str_to_codec("AMR-WB####################################################################################################################") == -1);
}

static void test_map_codec_to_pt_and_map_pt_to_codec(void)
{
	struct ptmap ptmap[10];
	unsigned int ptmap_len;
	unsigned int i;

	ptmap[0].codec = CODEC_GSMEFR_8000_1;
	ptmap[0].pt = 96;
	ptmap[1].codec = CODEC_GSMHR_8000_1;
	ptmap[1].pt = 97;
	ptmap[2].codec = CODEC_AMR_8000_1;
	ptmap[2].pt = 98;
	ptmap[3].codec = CODEC_AMRWB_16000_1;
	ptmap[3].pt = 99;
	ptmap_len = 4;

	/* Mappings that are covered by the table */
	for (i = 0; i < ptmap_len; i++)
		printf(" %u => %u\n", ptmap[i].codec, map_codec_to_pt(ptmap, ptmap_len, ptmap[i].codec));
	for (i = 0; i < ptmap_len; i++)
		printf(" %u <= %u\n", ptmap[i].pt, map_pt_to_codec(ptmap, ptmap_len, ptmap[i].pt));
	printf("\n");

	/* Map some codecs/payload types from the static range, result must
	 * always be a 1:1 mapping */
	printf(" %u => %u\n", CODEC_PCMU_8000_1, map_codec_to_pt(ptmap, ptmap_len, CODEC_PCMU_8000_1));
	printf(" %u => %u\n", CODEC_GSM_8000_1, map_codec_to_pt(ptmap, ptmap_len, CODEC_GSM_8000_1));
	printf(" %u => %u\n", CODEC_PCMA_8000_1, map_codec_to_pt(ptmap, ptmap_len, CODEC_PCMA_8000_1));
	printf(" %u => %u\n", CODEC_G729_8000_1, map_codec_to_pt(ptmap, ptmap_len, CODEC_G729_8000_1));
	printf(" %u <= %u\n", CODEC_PCMU_8000_1, map_pt_to_codec(ptmap, ptmap_len, CODEC_PCMU_8000_1));
	printf(" %u <= %u\n", CODEC_GSM_8000_1, map_pt_to_codec(ptmap, ptmap_len, CODEC_GSM_8000_1));
	printf(" %u <= %u\n", CODEC_PCMA_8000_1, map_pt_to_codec(ptmap, ptmap_len, CODEC_PCMA_8000_1));
	printf(" %u <= %u\n", CODEC_G729_8000_1, map_pt_to_codec(ptmap, ptmap_len, CODEC_G729_8000_1));
	printf("\n");

	/* Try to do mappings from statically defined range to danymic range and vice versa. This
	 * is illegal and should result into a 1:1 mapping */
	ptmap[3].codec = CODEC_AMRWB_16000_1;
	ptmap[3].pt = 2;
	ptmap[4].codec = CODEC_PCMU_8000_1;
	ptmap[4].pt = 100;
	ptmap_len = 5;

	/* Apply all mappings again, the illegal ones we defined should result into 1:1 mappings */
	for (i = 0; i < ptmap_len; i++)
		printf(" %u => %u\n", ptmap[i].codec, map_codec_to_pt(ptmap, ptmap_len, ptmap[i].codec));
	for (i = 0; i < ptmap_len; i++)
		printf(" %u <= %u\n", ptmap[i].pt, map_pt_to_codec(ptmap, ptmap_len, ptmap[i].pt));
	printf("\n");
}

static const struct log_info_cat log_categories[] = {
};

const struct log_info log_info = {
        .cat = log_categories,
        .num_cat = ARRAY_SIZE(log_categories),
};


int main(int argc, char **argv)
{
	ctx = talloc_named_const(NULL, 1, "mgcp_client_test");
	msgb_talloc_ctx_init(ctx, 0);
	osmo_init_logging2(ctx, &log_info);
	log_set_print_filename(osmo_stderr_target, 0);
	log_set_print_timestamp(osmo_stderr_target, 0);
	log_set_use_color(osmo_stderr_target, 0);
	log_set_print_category(osmo_stderr_target, 1);

	log_set_category_filter(osmo_stderr_target, DLMGCP, 1, LOGL_DEBUG);

	mgcp_client_conf_init(&conf);

	test_mgcp_msg();
	test_mgcp_client_cancel();
	test_sdp_section_start();
	test_map_codec_to_pt_and_map_pt_to_codec();
	test_map_pt_to_codec();

	printf("Done\n");
	fprintf(stderr, "Done\n");
	return EXIT_SUCCESS;
}

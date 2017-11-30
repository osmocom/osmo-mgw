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
		     int conn_id, const char *params)
{
	static char compose[4096 - 128];
	int len;

	len = snprintf(compose, sizeof(compose),
		       "%d %u %s\r\nI: %d\n\n%s",
		       code, trans_id, comment, conn_id, params);
	OSMO_ASSERT(len < sizeof(compose));
	OSMO_ASSERT(len > 0);

	printf("composed response:\n-----\n%s\n-----\n",
	       compose);
	return mgcp_client_rx(mgcp, from_str(compose));
}

void test_response_cb(struct mgcp_response *response, void *priv)
{
	OSMO_ASSERT(priv == mgcp);
	mgcp_response_parse_params(response);

	printf("response cb received:\n"
	       "  head.response_code = %d\n"
	       "  head.trans_id = %u\n"
	       "  head.comment = %s\n"
	       "  audio_port = %u\n"
	       "  audio_ip = %s\n",
	       response->head.response_code,
	       response->head.trans_id,
	       response->head.comment,
	       response->audio_port,
	       response->audio_ip
	      );
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

void test_crcx(void)
{
	struct msgb *msg;
	mgcp_trans_id_t trans_id;

	printf("\n===== %s =====\n", __func__);

	if (mgcp)
		talloc_free(mgcp);
	mgcp = mgcp_client_init(ctx, &conf);

	msg = mgcp_msg_crcx(mgcp, 23, 42, MGCP_CONN_LOOPBACK);
	trans_id = dummy_mgcp_send(msg);

	reply_to(trans_id, 200, "OK", 1,
		"v=0\r\n"
		"o=- 1 23 IN IP4 10.9.1.120\r\n"
		"s=-\r\n"
		"c=IN IP4 10.9.1.120\r\n"
		"t=0 0\r\n"
		"m=audio 16002 RTP/AVP 98\r\n"
		"a=rtpmap:98 AMR/8000\r\n"
		"a=ptime:20\r\n");
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
		.conn_mode = MGCP_CONN_RECV_SEND
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

	printf("Generated MDCX message:\n");
	mgcp_msg.verb = MGCP_VERB_MDCX;
	mgcp_msg.presence =
	    (MGCP_MSG_PRESENCE_ENDPOINT | MGCP_MSG_PRESENCE_CALL_ID |
	     MGCP_MSG_PRESENCE_CONN_ID | MGCP_MSG_PRESENCE_CONN_MODE |
	     MGCP_MSG_PRESENCE_AUDIO_IP | MGCP_MSG_PRESENCE_AUDIO_PORT);
	msg = mgcp_msg_gen(mgcp, &mgcp_msg);
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
		.conn_id = 11,
		.conn_mode = MGCP_CONN_RECV_SEND,
		.presence = (MGCP_MSG_PRESENCE_ENDPOINT | MGCP_MSG_PRESENCE_CALL_ID
			     | MGCP_MSG_PRESENCE_CONN_ID | MGCP_MSG_PRESENCE_CONN_MODE),
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
	OSMO_ASSERT(reply_to(trans_id, 200, "OK", 1, "v=0\r\n") == -ENOENT);

	fprintf(stderr, "- canceling again does nothing\n");
	OSMO_ASSERT(mgcp_client_cancel(mgcp, trans_id) == -ENOENT);

	fprintf(stderr, "%s() done\n", __func__);
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
	osmo_init_logging(&log_info);
	log_set_print_filename(osmo_stderr_target, 0);
	log_set_print_timestamp(osmo_stderr_target, 0);
	log_set_use_color(osmo_stderr_target, 0);
	log_set_print_category(osmo_stderr_target, 1);

	log_set_category_filter(osmo_stderr_target, DLMGCP, 1, LOGL_DEBUG);

	mgcp_client_conf_init(&conf);

	test_crcx();
	test_mgcp_msg();
	test_mgcp_client_cancel();

	printf("Done\n");
	fprintf(stderr, "Done\n");
	return EXIT_SUCCESS;
}

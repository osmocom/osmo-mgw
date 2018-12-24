#include <stdint.h>
#include <string.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/application.h>
#include <osmocom/core/logging.h>

#include <osmocom/mgcp/iuup_cn_node.h>
#include <osmocom/mgcp/iuup_protocol.h>

void *ctx = NULL;

static const char *dump(struct msgb *msg)
{
	return osmo_hexdump_nospc(msg->data, msg->len);
}

struct msgb *msgb_from_hex(const char *label, const char *hex)
{
	struct msgb *msg = msgb_alloc_headroom(4096 + OSMO_IUUP_HEADROOM,
					       OSMO_IUUP_HEADROOM, label);
	unsigned char *rc;
	msg->l2h = msg->data;
	rc = msgb_put(msg, osmo_hexparse(hex, msg->data, msgb_tailroom(msg)));
	OSMO_ASSERT(rc == msg->l2h);
	return msg;
}

const char *expect_rx_payload = NULL;
int rx_payload(struct msgb *msg, void *node_priv)
{
	printf("rx_payload() invoked by iuup_cn!\n");
	printf("        [IuUP] -RTP->\n");
	printf("%s\n", dump(msg));
	printf("node_priv=%p\n", node_priv);
	if (!expect_rx_payload) {
		printf("ERROR: did not expect rx_payload()\n");
		exit(-1);
	} else if (strcmp(expect_rx_payload, dump(msg))) {
		printf("ERROR: mismatches expected msg %s\n", expect_rx_payload);
		exit(-1);
	} else
		printf("ok: matches expected msg\n");
	expect_rx_payload = NULL;
	return 0;
}

const char *expect_tx_msg = NULL;
int tx_msg(struct msgb *msg, void *node_priv)
{
	printf("tx_msg() invoked by iuup_cn!\n");
	printf(" <-PDU- [IuUP]\n");
	printf("%s\n", dump(msg));
	printf("node_priv=%p\n", node_priv);
	if (!expect_tx_msg) {
		printf("ERROR: did not expect tx_msg()\n");
		exit(-1);
	} else if (strcmp(expect_tx_msg, dump(msg))) {
		printf("ERROR: mismatches expected msg %s\n", expect_tx_msg);
		exit(-1);
	} else
		printf("ok: matches expected msg\n");
	expect_tx_msg = NULL;
	return 0;
}

static int rx_pdu(struct osmo_iuup_cn *cn, struct msgb *msg)
{
	int rc;
	printf(" -PDU-> [IuUP]\n");
	printf("%s\n", dump(msg));
	rc = osmo_iuup_cn_rx_pdu(cn, msg);
	printf("rc=%d\n", rc);
	return rc;
}

static int tx_payload(struct osmo_iuup_cn *cn, struct msgb *msg)
{
	int rc;
	printf("        [IuUP] <-RTP-\n");
	printf("%s\n", dump(msg));
	rc = osmo_iuup_cn_tx_payload(cn, msg);
	printf("rc=%d\n", rc);
	return rc;
}

void test_cn_session()
{
	void *node_priv = (void*)0x2342;

	struct osmo_iuup_cn_cfg cfg = {
		.node_priv = node_priv,
		.rx_payload = rx_payload,
		.tx_msg = tx_msg,
	};

	struct osmo_iuup_cn *cn = osmo_iuup_cn_init(ctx, &cfg, __func__);
	OSMO_ASSERT(cn);

	printf("\nSend IuUP Initialization. Expecting direct tx_msg() of the Initialization Ack\n");
	expect_tx_msg = "8060dc5219495e3f00010111" /* RTP header */
			"e4002400"; /* IuUP Init Ack */
	rx_pdu(cn,
	       msgb_from_hex("IuUP-Init",
			     "8060dc5219495e3f00010111" /* <- RTP header */
			     "e000df99" /* <- IuUP header */
			     "160051673c01270000820000001710000100" /* IuUP params */));

#define RTP_HEADER "8060944c6256042c00010102"
#define IUUP_HEADER "0100e2b3"
#define RTP_PAYLOAD "6cfb23bc46d18180c3e5ffe040045600005a7d35b625b80005fff03214ced0"
	printf("\nReceive payload encapsulated in IuUP. Expecting rx_payload() of just RTP packet\n");
	printf("i.e. should strip away " IUUP_HEADER "\n");
	expect_rx_payload = RTP_HEADER "703c" RTP_PAYLOAD;
	rx_pdu(cn,
	       msgb_from_hex("IuUP-Data",
			     RTP_HEADER IUUP_HEADER RTP_PAYLOAD));

	printf("\nReceive payload encapsulated in IuUP. Expecting rx_payload() of just RTP packet\n");
	printf("i.e. should strip away " "0401479e" "\n");
	expect_rx_payload = RTP_HEADER "7044" "26e9b851ee";
	rx_pdu(cn,
	       msgb_from_hex("IuUP-Data",
			     RTP_HEADER "0401479e" "26e9b851ee"));

	printf("\nTransmit RTP. Expecting tx_msg() with inserted IuUP header\n");
	expect_tx_msg = RTP_HEADER "000002b3" RTP_PAYLOAD;
	tx_payload(cn,
		   msgb_from_hex("RTP data", RTP_HEADER "703c" RTP_PAYLOAD));

	printf("\nMore RTP, each time the Frame Nr advances, causing a new header CRC.\n");
	expect_tx_msg = RTP_HEADER "0100e2b3" RTP_PAYLOAD;
	tx_payload(cn,
		   msgb_from_hex("RTP data", RTP_HEADER "703c" RTP_PAYLOAD));
	expect_tx_msg = RTP_HEADER "02007eb3" RTP_PAYLOAD;
	tx_payload(cn,
		   msgb_from_hex("RTP data", RTP_HEADER "703c" RTP_PAYLOAD));
	expect_tx_msg = RTP_HEADER "03009eb3" RTP_PAYLOAD;
	tx_payload(cn,
		   msgb_from_hex("RTP data", RTP_HEADER "703c" RTP_PAYLOAD));

	printf("All done.\n");
}

static const struct log_info_cat log_categories[] = {
};

const struct log_info log_info = {
	.cat = log_categories,
	.num_cat = ARRAY_SIZE(log_categories),
};

int main(void)
{
	ctx = talloc_named_const(NULL, 0, __FILE__);
	void *msgb_ctx = msgb_talloc_ctx_init(ctx, 0);
	osmo_init_logging2(ctx, &log_info);

	test_cn_session();

	talloc_free(msgb_ctx);
	return 0;
}

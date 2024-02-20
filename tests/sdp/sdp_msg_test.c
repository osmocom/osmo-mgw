#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/linuxlist.h>

#include <osmocom/sdp/sdp_msg.h>

void *test_ctx = NULL;

static void report_callback(const void *ptr, int depth, int max_depth, int is_ref, void *priv)
{
        const char *name = talloc_get_name(ptr);
	printf(" |%*s%3zu %s\n", depth, "", talloc_total_blocks(ptr), name);
}

/* Print a talloc report that is reproducible for test output verification. It contains no pointer addresses. */
#define report(CTX) _report(CTX, #CTX)
static void _report(void *ctx, const char *label)
{
	fflush(stdout);
	fflush(stderr);
	printf("%s\n", label);
        talloc_report_depth_cb(ctx, 0, 100, report_callback, NULL);
	fflush(stdout);
}

static void dump_sdp(const char *str, const char *prefix)
{
	while (str && *str) {
		const char *line_end = str;
		while (*line_end && *line_end != '\r' && *line_end != '\n')
			line_end++;
		while (*line_end == '\r' || *line_end == '\n')
			line_end++;
		printf("%s%s\n", prefix, osmo_escape_str(str, line_end - str));
		str = line_end;
	}
}

struct sdp_msg_test_data {
	const char *sdp_input;
	const char *expect_sdp_str;
};

static const struct sdp_msg_test_data sdp_msg_tests[] = {
	{
		"v=0\r\n"
		"o=- 5628250 5628250 IN IP4 192.168.11.121\r\n"
		"s=-\r\n"
		"c=IN IP4 192.168.11.121\r\n"
		"t=0 0\r\n"
		"m=audio 10020 RTP/AVP 18 0 2 4 8 96 97 98 100 101\r\n"
		"a=rtpmap:18 G729/8000\r\n"
		"a=rtpmap:0 PCMU/8000\r\n"
		"a=rtpmap:2 G726-32/8000\r\n"
		"a=rtpmap:4 G723/8000\r\n"
		"a=rtpmap:8 PCMA/8000\r\n"
		"a=rtpmap:96 G726-40/8000\r\n"
		"a=rtpmap:97 G726-24/8000\r\n"
		"a=rtpmap:98 G726-16/8000\r\n"
		"a=rtpmap:100 NSE/8000\r\n"
		"a=fmtp:100 192-193\r\n"
		"a=rtpmap:101 telephone-event/8000\r\n"
		"a=fmtp:101 0-15\r\n"
		"a=ptime:20\r\n"
		"a=sendrecv\r\n"
		,
	},
	{
		"v=0\r\n"
		"o=FooBar 1565090289 1565090290 IN IP4 192.168.11.151\r\n"
		"s=FooBar\r\n"
		"c=IN IP4 192.168.11.151\r\n"
		"t=0 0\r\n"
		"m=audio 16398 RTP/AVP 98\r\n"
		"a=rtpmap:98 AMR/8000\r\n"
		"a=fmtp:98 octet-align=1; mode-set=4\r\n"
		"a=ptime:20\r\n"
		"a=rtcp:16399 IN IP4 192.168.11.151\r\n"
		,
		"v=0\r\n"
		"o=FooBar 1565090289 1565090290 IN IP4 192.168.11.151\r\n"
		"s=FooBar\r\n"
		"c=IN IP4 192.168.11.151\r\n"
		"t=0 0\r\n"
		"m=audio 16398 RTP/AVP 98\r\n"
		"a=rtpmap:98 AMR/8000\r\n"
		"a=fmtp:98 octet-align=1; mode-set=4\r\n"
		"a=ptime:20\r\n"
		/* The rtcp line is dropped, not supported yet */
	},
	{
		"v=0\r\n"
		"o=FooBar 1565090289 1565090290 IN IP4 192.168.11.151\r\n"
		"s=FooBar\r\n"
		"c=IN IP4 192.168.11.140\r\n"
		"t=0 0\r\n"
		"m=audio 30436 RTP/AVP 18 0 4 8 101\r\n"
		"a=rtpmap:18 G729/8000\r\n"
		"a=rtpmap:0 PCMU/8000\r\n"
		"a=rtpmap:4 G723/8000\r\n"
		"a=rtpmap:8 PCMA/8000\r\n"
		"a=rtpmap:101 telephone-event/8000\r\n"
		"a=fmtp:101 0-15\r\n"
		"a=sendrecv\r\n"
		"a=rtcp:30437\r\n"
		"a=ptime:20\r\n"
		,
		"v=0\r\n"
		"o=FooBar 1565090289 1565090290 IN IP4 192.168.11.151\r\n"
		"s=FooBar\r\n"
		"c=IN IP4 192.168.11.140\r\n"
		"t=0 0\r\n"
		"m=audio 30436 RTP/AVP 18 0 4 8 101\r\n"
		"a=rtpmap:18 G729/8000\r\n"
		"a=rtpmap:0 PCMU/8000\r\n"
		"a=rtpmap:4 G723/8000\r\n"
		"a=rtpmap:8 PCMA/8000\r\n"
		"a=rtpmap:101 telephone-event/8000\r\n"
		"a=fmtp:101 0-15\r\n"
		/* a=sendrecv ends up further below */
		/* The rtcp line is dropped, not supported yet */
		"a=ptime:20\r\n"
		"a=sendrecv\r\n"
		,
	},
	{
		"v=0\r\n"
		"o=FooBar 1565090289 1565090290 IN IP4 192.168.11.151\r\n"
		"s=FooBar\r\n"
		"c=IN IP4 192.168.11.140\r\n"
		"t=0 0\r\n"
		"m=audio 30436 RTP/AVP 18 0 4 8 101\r\n"
		"a=rtpmap:18 G729/8000\r\n"
		"a=rtpmap:0 PCMU/8000\r\n"
		"a=rtpmap:4 G723/8000\r\n"
		"a=rtpmap:8 PCMA/8000\r\n"
		"a=rtpmap:101 telephone-event/8000\r\n"
		"a=fmtp:101 0-15\r\n"
		"a=recvonly\r\n"
		"a=rtcp:30437\r\n"
		"a=ptime:20\r\n"
		,
		"v=0\r\n"
		"o=FooBar 1565090289 1565090290 IN IP4 192.168.11.151\r\n"
		"s=FooBar\r\n"
		"c=IN IP4 192.168.11.140\r\n"
		"t=0 0\r\n"
		"m=audio 30436 RTP/AVP 18 0 4 8 101\r\n"
		"a=rtpmap:18 G729/8000\r\n"
		"a=rtpmap:0 PCMU/8000\r\n"
		"a=rtpmap:4 G723/8000\r\n"
		"a=rtpmap:8 PCMA/8000\r\n"
		"a=rtpmap:101 telephone-event/8000\r\n"
		"a=fmtp:101 0-15\r\n"
		/* a=recvonly ends up further below */
		/* The rtcp line is dropped, not supported yet */
		"a=ptime:20\r\n"
		"a=recvonly\r\n"
		,
	},
	{
		"v=0\r\n"
		"o=FooBar 1565090289 1565090290 IN IP4 192.168.11.151\r\n"
		"s=FooBar\r\n"
		"c=IN IP4 192.168.11.140\r\n"
		"t=0 0\r\n"
		"m=audio 30436 RTP/AVP 18 0 4 8 101\r\n"
		"a=rtpmap:18 G729/8000\r\n"
		"a=rtpmap:0 PCMU/8000\r\n"
		"a=rtpmap:4 G723/8000\r\n"
		"a=rtpmap:8 PCMA/8000\r\n"
		"a=rtpmap:101 telephone-event/8000\r\n"
		"a=fmtp:101 0-15\r\n"
		"a=ptime:20\r\n"
		"a=sendonly\r\n"
		,
	},
	{
		"v=0\r\n"
		"o=FooBar 1565090289 1565090290 IN IP4 192.168.11.151\r\n"
		"s=FooBar\r\n"
		"c=IN IP4 192.168.11.140\r\n"
		"t=0 0\r\n"
		"m=audio 30436 RTP/AVP 18 0 4 8 101\r\n"
		"a=rtpmap:18 G729/8000\r\n"
		"a=rtpmap:0 PCMU/8000\r\n"
		"a=rtpmap:4 G723/8000\r\n"
		"a=rtpmap:8 PCMA/8000\r\n"
		"a=rtpmap:101 telephone-event/8000\r\n"
		"a=fmtp:101 0-15\r\n"
		"a=ptime:20\r\n"
		"a=inactive\r\n"
		,
	},
};

static void test_parse_and_compose(void)
{
	void *ctx = talloc_named_const(test_ctx, 0, __func__);
	void *print_ctx = talloc_named_const(test_ctx, 0, "print");
	int i;
	bool ok = true;

	printf("\n\n%s\n", __func__);

	for (i = 0; i < ARRAY_SIZE(sdp_msg_tests); i++) {
		const struct sdp_msg_test_data *t = &sdp_msg_tests[i];
		struct osmo_sdp_msg *sdp_msg;
		char str[1024];
		const char *expect;
		struct osmo_sdp_msg_decode_ret ret;

		printf("\n[%d]\n", i);
		dump_sdp(t->sdp_input, "sdp input: ");

		sdp_msg = osmo_sdp_msg_decode(ctx, t->sdp_input, -1, &ret);

		if (ret.rc) {
			printf("ERROR: %s at %s\n", strerror(abs(ret.rc)),
			       osmo_quote_cstr_c(print_ctx, ret.error.at_input_str, ret.error.at_input_str_len));
			ok = false;
		}
		printf("parsed SDP message %s\n", osmo_sdp_msg_to_str_c(print_ctx, sdp_msg, false));

		osmo_sdp_msg_encode_buf(str, sizeof(str), sdp_msg);
		dump_sdp(str, "osmo_sdp_msg_encode_buf: ");
		expect = t->expect_sdp_str ? : t->sdp_input;
		if (strcmp(str, expect)) {
			int j;
			ok = false;
			printf("ERROR:\n");
			dump_sdp(expect, "expect: ");
			for (j = 0; expect[j]; j++) {
				if (expect[j] != str[j]) {
					printf("ERROR at position %d, at:\n", j);
					dump_sdp(str + j, "     mismatch: ");
					break;
				}
			}
		} else
			printf("[%d] ok\n", i);

		report(ctx);
		printf("talloc_free(sdp_msg)\n");
		talloc_free(sdp_msg);
		report(ctx);

		if (talloc_total_blocks(ctx) != 1) {
			printf("ERROR: memleak\n");
			talloc_free_children(ctx);
		}
		printf("\n");
	}

	OSMO_ASSERT(ok);
	talloc_free(ctx);
	talloc_free(print_ctx);
}

struct intersect_test_data {
	const char *descr;
	const char *sdp_msg_a;
	const char *sdp_msg_b;
	const char *expect_intersection;
};

#define SDP_1 \
		"v=0\r\n" \
		"o=libosmo-sdp 0 0 IN IP4 23.42.23.42\r\n" \
		"s=GSM Call\r\n" \
		"c=IN IP4 23.42.23.42\r\n" \
		"t=0 0\r\n" \
		"m=audio 30436 RTP/AVP 112 3 111 110\r\n" \
		"a=rtpmap:112 AMR/8000\r\n" \
		"a=fmtp:112 octet-align=1\r\n" \
		"a=rtpmap:3 GSM/8000\r\n" \
		"a=rtpmap:111 GSM-HR-08/8000\r\n" \
		"a=rtpmap:110 GSM-EFR/8000\r\n" \
		"a=ptime:20\r\n"

#define SDP_2 \
		"v=0\r\n" \
		"o=libosmo-sdp 0 0 IN IP4 23.42.23.42\r\n" \
		"s=GSM Call\r\n" \
		"c=IN IP4 23.42.23.42\r\n" \
		"t=0 0\r\n" \
		"m=audio 30436 RTP/AVP 112 110\r\n" \
		"a=rtpmap:112 AMR/8000\r\n" \
		"a=fmtp:112 octet-align=1\r\n" \
		"a=rtpmap:110 GSM-EFR/8000\r\n" \
		"a=ptime:20\r\n"

#define SDP_3 \
		"v=0\r\n" \
		"o=libosmo-sdp 0 0 IN IP4 23.42.23.42\r\n" \
		"s=GSM Call\r\n" \
		"c=IN IP4 23.42.23.42\r\n" \
		"t=0 0\r\n" \
		"m=audio 30436 RTP/AVP 3 111 123\r\n" \
		"a=rtpmap:3 GSM/8000\r\n" \
		"a=rtpmap:111 GSM-HR-08/8000\r\n" \
		"a=rtpmap:123 FOO/8000\r\n" \
		"a=ptime:20\r\n"

#define SDP_4 \
		"v=0\r\n" \
		"o=libosmo-sdp 0 0 IN IP4 23.42.23.42\r\n" \
		"s=GSM Call\r\n" \
		"c=IN IP4 23.42.23.42\r\n" \
		"t=0 0\r\n" \
		"m=audio 30436 RTP/AVP 3 111\r\n" \
		"a=rtpmap:3 GSM/8000\r\n" \
		"a=rtpmap:111 GSM-HR-08/8000\r\n" \
		"a=ptime:20\r\n"

#define SDP_5 \
		"v=0\r\n" \
		"o=libosmo-sdp 0 0 IN IP4 0.0.0.0\r\n" \
		"s=GSM Call\r\n" \
		"c=IN IP4 0.0.0.0\r\n" \
		"t=0 0\r\n" \
		"m=audio 0 RTP/AVP 112 113 110 3 111\r\n" \
		"a=rtpmap:112 AMR/8000\r\n" \
		"a=fmtp:112 octet-align=1;mode-set=0,1,2,3\r\n" \
		"a=rtpmap:113 AMR-WB/8000\r\n" \
		"a=fmtp:113 octet-align=1\r\n" \
		"a=rtpmap:110 GSM-EFR/8000\r\n" \
		"a=rtpmap:3 GSM/8000\r\n" \
		"a=rtpmap:111 GSM-HR-08/8000\r\n" \
		"a=ptime:20\r\n"

static const struct intersect_test_data intersect_tests[] = {
	{
		.descr = "identical codecs lead to no change",
		.sdp_msg_a = SDP_1,
		.sdp_msg_b =
			"v=0\r\n"
			"c=IN IP4 5.6.7.8\r\n"
			"m=audio 12345 RTP/AVP 112 3 111 110\r\n"
			"a=rtpmap:112 AMR/8000\r\n"
			"a=fmtp:112 octet-align=1\r\n"
			"a=rtpmap:3 GSM/8000\r\n"
			"a=rtpmap:111 GSM-HR-08/8000\r\n"
			"a=rtpmap:110 GSM-EFR/8000\r\n"
			,
		.expect_intersection = SDP_1,
	},
	{
		.descr = "identical codecs in different order also lead to no change",
		.sdp_msg_a = SDP_1,
		.sdp_msg_b =
			"v=0\r\n"
			"c=IN IP4 5.6.7.8\r\n" \
			"m=audio 12345 RTP/AVP 3 110 111 112\r\n"
			"a=rtpmap:3 GSM/8000\r\n"
			"a=rtpmap:110 GSM-EFR/8000\r\n"
			"a=rtpmap:111 GSM-HR-08/8000\r\n"
			"a=rtpmap:112 AMR/8000\r\n"
			"a=fmtp:112 octet-align=1\r\n"
			,
		.expect_intersection = SDP_1,
	},
	{
		.descr = "identical codecs with mismatching payload type numbers also lead to no change",
		.sdp_msg_a = SDP_1,
		.sdp_msg_b =
			"v=0\r\n"
			"c=IN IP4 5.6.7.8\r\n" \
			"m=audio 12345 RTP/AVP 96 97 98 99\r\n"
			"a=rtpmap:96 GSM/8000\r\n"
			"a=rtpmap:97 GSM-EFR/8000\r\n"
			"a=rtpmap:98 GSM-HR-08/8000\r\n"
			"a=rtpmap:99 AMR/8000\r\n"
			"a=fmtp:99 octet-align=1\r\n"
			,
		.expect_intersection = SDP_1,
	},
	{
		.descr = "identical codecs plus some extra codecs also lead to no change" ,
		.sdp_msg_a = SDP_1,
		.sdp_msg_b =
			"v=0\r\n"
			"c=IN IP4 5.6.7.8\r\n" \
			"m=audio 12345 RTP/AVP 8 0 96 97 98 99\r\n"
			"a=rtpmap:8 PCMA/8000\r\n"
			"a=rtpmap:0 PCMU/8000\r\n"
			"a=rtpmap:96 GSM/8000\r\n"
			"a=rtpmap:97 GSM-EFR/8000\r\n"
			"a=rtpmap:98 GSM-HR-08/8000\r\n"
			"a=rtpmap:99 AMR/8000\r\n"
			"a=fmtp:99 octet-align=1\r\n"
			,
		.expect_intersection = SDP_1,
	},
	{
		.descr = "some codecs removed",
		.sdp_msg_a = SDP_1,
		.sdp_msg_b = SDP_2,
		.expect_intersection = SDP_2,
	},
	{
		.descr = "other codecs removed",
		.sdp_msg_a = SDP_1,
		.sdp_msg_b = SDP_3,
		.expect_intersection = SDP_4,
	},
	{
		.descr = "all codecs removed",
		.sdp_msg_a = SDP_1,
		.sdp_msg_b =
			"v=0\r\n"
			"s=empty"
			,
		.expect_intersection =
			"v=0\r\n"
			"o=libosmo-sdp 0 0 IN IP4 23.42.23.42\r\n"
			"s=GSM Call\r\n"
			"c=IN IP4 23.42.23.42\r\n"
			"t=0 0\r\n"
			"m=audio 30436 RTP/AVP\r\n"
			"a=ptime:20\r\n"
	},
	{
		.descr = "some real world test case",
		.sdp_msg_a = SDP_5,
		.sdp_msg_b = SDP_5,
		.expect_intersection = SDP_5,
	},
};

static const char *sdp_msg_logstr(const struct osmo_sdp_msg *sdp_msg)
{
	static char buf[1024];
	osmo_sdp_msg_encode_buf(buf, sizeof(buf), sdp_msg);
	return buf;
}

static void test_intersect(void)
{
	int i;
	bool ok = true;
	void *ctx = talloc_named_const(test_ctx, 0, __func__);

	printf("\n\n%s\n", __func__);

	for (i = 0; i < ARRAY_SIZE(intersect_tests); i++) {
		const struct intersect_test_data *t = &intersect_tests[i];
		struct osmo_sdp_msg *sdp_msg_a = NULL;
		struct osmo_sdp_msg *sdp_msg_b = NULL;
		char str[1024];
		printf("\n[%d] %s\n", i, t->descr);
		dump_sdp(t->sdp_msg_a, "SDP A: ");
		dump_sdp(t->sdp_msg_b, " SDP B: ");

		sdp_msg_a = osmo_sdp_msg_decode(ctx, t->sdp_msg_a, -1, NULL);
		if (!sdp_msg_a) {
			printf("ERROR parsing SDP A\n");
			break;
		}
		dump_sdp(sdp_msg_logstr(sdp_msg_a), "parsed SDP A: ");

		struct osmo_sdp_msg_decode_ret r;
		sdp_msg_b = osmo_sdp_msg_decode(ctx, t->sdp_msg_b, -1, &r);
		if (!sdp_msg_b) {
			printf("ERROR parsing SDP B\n");
			break;
		}
		dump_sdp(sdp_msg_logstr(sdp_msg_b), "parsed SDP B: ");

		osmo_sdp_codec_list_intersection(sdp_msg_a->codecs, sdp_msg_b->codecs,
						 &osmo_sdp_codec_cmp_equivalent,
						 false);
		osmo_sdp_msg_encode_buf(str, sizeof(str), sdp_msg_a);
		dump_sdp(str, "intersection(a,b): ");
		if (strcmp(str, t->expect_intersection)) {
			int j;
			ok = false;
			printf("ERROR:\n");
			dump_sdp(t->expect_intersection, "expect_intersection: ");
			for (j = 0; t->expect_intersection[j]; j++) {
				if (t->expect_intersection[j] != str[j]) {
					printf("ERROR at position %d, at:\n", j);
					dump_sdp(str + j, "     mismatch: ");
					break;
				}
			}
		} else
			printf("[%d] ok\n", i);

		report(ctx);
		printf("talloc_free(sdp_msg_a)\n");
		talloc_free(sdp_msg_a);
		report(ctx);
		printf("talloc_free(sdp_msg_b)\n");
		talloc_free(sdp_msg_b);
		report(ctx);

		if (talloc_total_blocks(ctx) != 1) {
			printf("ERROR: memleak\n");
			talloc_free_children(ctx);
		}
		printf("\n");
	}

	OSMO_ASSERT(ok);
	talloc_free(ctx);
}

struct sdp_select_test_data {
	const char *sdp;
	const struct osmo_sdp_codec_cmp_flags *cmpf;
	const struct osmo_sdp_codec select;
	const char *expect_sdp;
};

static const struct osmo_sdp_codec_cmp_flags pt_only = { .payload_type = true };

static const struct sdp_select_test_data sdp_select_tests[] = {
	{
		"v=0\r\n"
		"o=libosmo-sdp 0 0 IN IP4 23.42.23.42\r\n"
		"s=GSM Call\r\n"
		"c=IN IP4 23.42.23.42\r\n"
		"t=0 0\r\n"
		"m=audio 30436 RTP/AVP 112 3 111 110\r\n"
		"a=rtpmap:112 AMR/8000\r\n"
		"a=fmtp:112 octet-align=1\r\n"
		"a=rtpmap:3 GSM/8000\r\n"
		"a=rtpmap:111 GSM-HR-08/8000\r\n"
		"a=rtpmap:110 GSM-EFR/8000\r\n"
		"a=ptime:20\r\n"
		,
		&pt_only,
		{ .payload_type = 112, },
		NULL
	},
	{
		"v=0\r\n"
		"o=libosmo-sdp 0 0 IN IP4 23.42.23.42\r\n"
		"s=GSM Call\r\n"
		"c=IN IP4 23.42.23.42\r\n"
		"t=0 0\r\n"
		"m=audio 30436 RTP/AVP 112 3 111 110\r\n"
		"a=rtpmap:112 AMR/8000\r\n"
		"a=fmtp:112 octet-align=1\r\n"
		"a=rtpmap:3 GSM/8000\r\n"
		"a=rtpmap:111 GSM-HR-08/8000\r\n"
		"a=rtpmap:110 GSM-EFR/8000\r\n"
		"a=ptime:20\r\n"
		,
		&pt_only,
		{ .payload_type = 3, },
		"v=0\r\n"
		"o=libosmo-sdp 0 0 IN IP4 23.42.23.42\r\n"
		"s=GSM Call\r\n"
		"c=IN IP4 23.42.23.42\r\n"
		"t=0 0\r\n"
		"m=audio 30436 RTP/AVP 3 112 111 110\r\n"
		"a=rtpmap:3 GSM/8000\r\n"
		"a=rtpmap:112 AMR/8000\r\n"
		"a=fmtp:112 octet-align=1\r\n"
		"a=rtpmap:111 GSM-HR-08/8000\r\n"
		"a=rtpmap:110 GSM-EFR/8000\r\n"
		"a=ptime:20\r\n"
	},
	{
		"v=0\r\n"
		"o=libosmo-sdp 0 0 IN IP4 23.42.23.42\r\n"
		"s=GSM Call\r\n"
		"c=IN IP4 23.42.23.42\r\n"
		"t=0 0\r\n"
		"m=audio 30436 RTP/AVP 112 3 111 110\r\n"
		"a=rtpmap:112 AMR/8000\r\n"
		"a=fmtp:112 octet-align=1\r\n"
		"a=rtpmap:3 GSM/8000\r\n"
		"a=rtpmap:111 GSM-HR-08/8000\r\n"
		"a=rtpmap:110 GSM-EFR/8000\r\n"
		"a=ptime:20\r\n"
		,
		&pt_only,
		{ .payload_type = 111, },
		"v=0\r\n"
		"o=libosmo-sdp 0 0 IN IP4 23.42.23.42\r\n"
		"s=GSM Call\r\n"
		"c=IN IP4 23.42.23.42\r\n"
		"t=0 0\r\n"
		"m=audio 30436 RTP/AVP 111 112 3 110\r\n"
		"a=rtpmap:111 GSM-HR-08/8000\r\n"
		"a=rtpmap:112 AMR/8000\r\n"
		"a=fmtp:112 octet-align=1\r\n"
		"a=rtpmap:3 GSM/8000\r\n"
		"a=rtpmap:110 GSM-EFR/8000\r\n"
		"a=ptime:20\r\n"
	},
	{
		"v=0\r\n"
		"o=libosmo-sdp 0 0 IN IP4 23.42.23.42\r\n"
		"s=GSM Call\r\n"
		"c=IN IP4 23.42.23.42\r\n"
		"t=0 0\r\n"
		"m=audio 30436 RTP/AVP 112 3 111 110\r\n"
		"a=rtpmap:112 AMR/8000\r\n"
		"a=fmtp:112 octet-align=1\r\n"
		"a=rtpmap:3 GSM/8000\r\n"
		"a=rtpmap:111 GSM-HR-08/8000\r\n"
		"a=rtpmap:110 GSM-EFR/8000\r\n"
		"a=ptime:20\r\n"
		,
		&pt_only,
		{ .payload_type = 110, },
		"v=0\r\n"
		"o=libosmo-sdp 0 0 IN IP4 23.42.23.42\r\n"
		"s=GSM Call\r\n"
		"c=IN IP4 23.42.23.42\r\n"
		"t=0 0\r\n"
		"m=audio 30436 RTP/AVP 110 112 3 111\r\n"
		"a=rtpmap:110 GSM-EFR/8000\r\n"
		"a=rtpmap:112 AMR/8000\r\n"
		"a=fmtp:112 octet-align=1\r\n"
		"a=rtpmap:3 GSM/8000\r\n"
		"a=rtpmap:111 GSM-HR-08/8000\r\n"
		"a=ptime:20\r\n"
	},

};

static void test_select(void)
{
	int i;
	bool ok = true;
	void *ctx = talloc_named_const(test_ctx, 0, __func__);
	void *print_ctx = talloc_named_const(test_ctx, 0, "print");

	printf("\n\n%s\n", __func__);

	for (i = 0; i < ARRAY_SIZE(sdp_select_tests); i++) {
		const struct sdp_select_test_data *t = &sdp_select_tests[i];
		struct osmo_sdp_msg *sdp_msg;
		char buf[1024];
		const char *expect_sdp;

		printf("\n[%d]\n", i);
		sdp_msg = osmo_sdp_msg_decode(ctx, t->sdp, -1, NULL);
		if (!sdp_msg) {
			printf("ERROR parsing SDP\n");
			break;
		}
		printf("SDP: %s\n", osmo_sdp_codec_list_to_str_c(print_ctx, sdp_msg->codecs, false));

		printf("Select: %s\n", osmo_sdp_codec_to_str_c(print_ctx, &t->select));
		osmo_sdp_codec_list_move_to_first(sdp_msg->codecs, &t->select, t->cmpf);

		printf("SDP: %s\n", osmo_sdp_codec_list_to_str_c(print_ctx, sdp_msg->codecs, false));
		osmo_sdp_msg_encode_buf(buf, sizeof(buf), sdp_msg);

		expect_sdp = t->expect_sdp ? : t->sdp;
		if (strcmp(buf, expect_sdp)) {
			int j;
			ok = false;
			printf("ERROR:\n");
			dump_sdp(buf, "selection result: ");
			dump_sdp(expect_sdp, "expect result: ");
			for (j = 0; expect_sdp[j]; j++) {
				if (expect_sdp[j] != buf[j]) {
					printf("ERROR at position %d, at:\n", j);
					dump_sdp(buf + j, "     mismatch: ");
					break;
				}
			}
		} else
			printf("[%d] ok\n", i);

		report(ctx);
		printf("talloc_free(sdp_msg)\n");
		talloc_free(sdp_msg);
		report(ctx);
		if (talloc_total_blocks(ctx) != 1) {
			printf("ERROR: memleak\n");
			talloc_free_children(ctx);
		}
		printf("\n");
		talloc_free_children(print_ctx);
	}

	OSMO_ASSERT(ok);
	talloc_free(ctx);
	talloc_free(print_ctx);
}


struct my_obj {
	struct osmo_sdp_msg *sdp_msg;
};

static struct my_obj *my_obj_alloc(void *ctx)
{
	struct my_obj *o = talloc_zero(ctx, struct my_obj);
	return o;
}

static void test_obj_members(void)
{
	void *ctx = talloc_named_const(test_ctx, 0, __func__);
	void *print_ctx = talloc_named_const(test_ctx, 0, "print");
	int i;

	struct my_obj *o;

	printf("\n\n--- %s()\n", __func__);
	o = my_obj_alloc(ctx);

	o->sdp_msg = osmo_sdp_msg_alloc(o);

	printf("o->sdp_msg = '%s'\n", osmo_sdp_msg_encode_c(print_ctx, o->sdp_msg));
	report(ctx);

	const struct osmo_sdp_codec all_codecs[] = {
		{ .payload_type = 112, .encoding_name = "AMR", .rate = 8000, .fmtp = "octet-align=1;mode-set=0,2,4" },
		{ .payload_type = 3, .encoding_name = "GSM", .rate = 8000 },
		{ .payload_type = 111, .encoding_name = "GSM-HR-08", .rate = 8000 },
	};

	for (i = 0; i < ARRAY_SIZE(all_codecs); i++)
		osmo_sdp_codec_list_add(o->sdp_msg->codecs, &all_codecs[i], false, false);

	printf("o->sdp_msg = '%s'\n", osmo_sdp_msg_encode_c(print_ctx, o->sdp_msg));

	report(ctx);
	printf("talloc_free(o)\n");
	talloc_free(o);
	report(ctx);
	talloc_free(ctx);
	talloc_free(print_ctx);
}

typedef void (*test_func_t)(void);

static const test_func_t test_func[] = {
	test_parse_and_compose,
	test_intersect,
	test_select,
	test_obj_members,
};

int main(void)
{
	int i;
	test_ctx = talloc_named_const(NULL, 0, "sdp_codec_test");

	for (i = 0; i < ARRAY_SIZE(test_func); i++) {

		test_func[i]();

		if (talloc_total_blocks(test_ctx) != 1) {
			talloc_report_full(test_ctx, stderr);
			printf("ERROR after test %d: memory leak\n", i);
			return -1;
		}
	}

	talloc_free(test_ctx);
	return 0;
}

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/linuxlist.h>

#include <osmocom/sdp/sdp_codec.h>
#include <osmocom/sdp/fmtp.h>

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

struct codec_test {
	struct osmo_sdp_codec set;
	int expect_rc;
	const char *expect_str;
	bool expect_is_set;
};

struct codec_test codec_tests[] = {
	{
		.set = { 23, "encoding-name", 8000, NULL },
		.expect_str = "encoding-name#23",
		.expect_is_set = true,
	},
	{
		.set = { 112, "AMR", 8000, "octet-align=1;mode-set=0,2,4" },
		.expect_str = "AMR:octet-align=1;mode-set=0,2,4#112",
		.expect_is_set = true,
	},
	{
		.set = { 96, "AMR", 8000, "mode-set=0,2,4;octet-align=1" },
		.expect_str = "AMR:mode-set=0,2,4;octet-align=1#96",
		.expect_is_set = true,
	},
	{
		.set = { 114, "AMR", 8000, "mode-set=0,2,4" },
		.expect_str = "AMR:mode-set=0,2,4#114",
		.expect_is_set = true,
	},
	{
		.set = { 97, "AMR", 8000, "mode-set=0,2,4;octet-align=0" },
		.expect_str = "AMR:mode-set=0,2,4;octet-align=0#97",
		.expect_is_set = true,
	},
	{
		.set = { 98, "AMR", 8000, "octet-align=1" },
		.expect_str = "AMR:octet-align=1#98",
		.expect_is_set = true,
	},
	{
		.set = { 96, "AMR-WB", 16000 },
		.expect_str = "AMR-WB/16000#96",
		.expect_is_set = true,
	},
	{
		.set = { 3, "GSM", 8000 },
		.expect_str = "GSM#3",
		.expect_is_set = true,
	},
	{
		.set = { },
		.expect_str = "/0#0",
		.expect_is_set = false,
	},
	{
		.set = { 112, NULL, 8000, "octet-align=1" },
		.expect_str = ":octet-align=1#112",
		.expect_is_set = false,
	},
	{
		.set = { 112, "", 8000, "octet-align=1" },
		.expect_str = ":octet-align=1#112",
		.expect_is_set = false,
	},
};

void test_codec(void)
{
	void *ctx = talloc_named_const(test_ctx, 0, __func__);

	struct codec_test *t;
	struct codec_test *t2;

	printf("\n\n--- %s()\n", __func__);
	printf("- osmo_sdp_codec_set():\n");
	for (t = codec_tests; (t - codec_tests) < ARRAY_SIZE(codec_tests); t++) {
		struct osmo_sdp_codec *codec = osmo_sdp_codec_alloc(ctx);
		char *str;
		bool is_set;

		osmo_sdp_codec_set(codec, t->set.payload_type, t->set.encoding_name, t->set.rate, t->set.fmtp);

		str = osmo_sdp_codec_to_str_c(ctx, codec);
		printf("osmo_sdp_codec_set [%d] '%s'\n", (int)(t - codec_tests), str);
		if (strcmp(str, t->expect_str))
			printf("  *** ERROR: expected '%s'\n", t->expect_str);

		if (!osmo_sdp_codec_cmp(codec, &t->set, &osmo_sdp_codec_cmp_exact))
			printf("  osmo_sdp_codec_cmp() ok\n");
		else
			printf("  osmo_sdp_codec_cmp() *** ERROR: mismatches original values\n");

		is_set = osmo_sdp_codec_is_set(codec);
		printf("  osmo_sdp_codec_is_set() = %s\n", is_set ? "true" : "false");
		if (is_set != t->expect_is_set)
			printf("    *** ERROR: expected is_set = %s\n", t->expect_is_set ? "true" : "false");

		if (is_set != osmo_sdp_codec_is_set(&t->set))
			printf("    *** ERROR: is_set(copy) != is_set(orig)\n");

		talloc_free(str);
		talloc_free(codec);
		if (talloc_total_blocks(ctx) != 1)
			printf("  *** ERROR: ctx has %zu items, should be 1\n", talloc_total_blocks(ctx));
	}

	printf("\n- osmo_sdp_codec_cmp(equivalent):\n");
	for (t = codec_tests; (t - codec_tests) < ARRAY_SIZE(codec_tests); t++) {
		for (t2 = codec_tests; (t2 - codec_tests) < ARRAY_SIZE(codec_tests); t2++) {
			int cmp = osmo_sdp_codec_cmp(&t->set, &t2->set, &osmo_sdp_codec_cmp_equivalent);
			int reverse_cmp = osmo_sdp_codec_cmp(&t2->set, &t->set, &osmo_sdp_codec_cmp_equivalent);
			printf("  %s %s %s %s %s\n",
			       osmo_sdp_codec_to_str_c(ctx, &t->set),
			       (cmp == 0) ? "=="
			       : ((cmp < 0) ? "<" : ">"),
			       osmo_sdp_codec_to_str_c(ctx, &t2->set),
			       (reverse_cmp == 0) ? "=="
			       : ((reverse_cmp < 0) ? "<" : ">"),
			       osmo_sdp_codec_to_str_c(ctx, &t->set));

			if (reverse_cmp != -cmp)
				printf("    *** ERROR: osmo_sdp_codec_cmp(reverse args) == %d, expected %d\n",
				       reverse_cmp, -cmp);

			talloc_free_children(ctx);
		}
	}

	printf("\n- osmo_sdp_codec_from_str():\n");
	for (t = codec_tests; (t - codec_tests) < ARRAY_SIZE(codec_tests); t++) {
		struct osmo_sdp_codec *codec = osmo_sdp_codec_alloc(ctx);
		int rc = osmo_sdp_codec_from_str(codec, t->expect_str, -1);
		printf("  osmo_sdp_codec_from_str('%s') rc=%d",
		       t->expect_str, rc);
		if (!rc) {
			printf(" res=%s", osmo_sdp_codec_to_str_c(ctx, codec));
			rc = osmo_sdp_codec_cmp(codec, &t->set, &osmo_sdp_codec_cmp_exact);
			if (rc)
				printf(" *** ERROR: osmo_sdp_codec_cmp(res,orig) = %d", rc);
		}
		printf("\n");
		talloc_free_children(ctx);
	}

	talloc_free(ctx);
}


struct my_obj {
	struct osmo_sdp_codec *codec;
};

struct my_obj *my_obj_alloc(void *ctx)
{
	struct my_obj *o = talloc_zero(ctx, struct my_obj);
	return o;
}

void test_obj_members(void)
{
	void *ctx = talloc_named_const(test_ctx, 0, __func__);
	void *print_ctx = talloc_named_const(test_ctx, 0, "print");

	struct my_obj *o;

	printf("\n\n--- %s()\n", __func__);
	o = my_obj_alloc(ctx);

	o->codec = osmo_sdp_codec_alloc(o);
	osmo_sdp_codec_set(o->codec, 96, "AMR", 8000, "octet-align=1");

	printf("o->codec = %s\n", osmo_sdp_codec_to_str_c(print_ctx, o->codec));

	report(ctx);
	printf("talloc_free(o)\n");
	talloc_free(o);
	report(ctx);
	talloc_free(ctx);
	talloc_free(print_ctx);
}

typedef void (*test_func_t)(void);
test_func_t test_func[] = {
	test_codec,
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

#include <inttypes.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/application.h>
#include <osmocom/core/logging.h>

#include <osmocom/sdp/fmtp.h>

struct get_val_test {
	const char *fmtp_string;
	const char *val_name;
	bool expect_rc;
	const char *expect_val;
};

const struct get_val_test get_val_tests[] = {
	{
		"foo=123;bar=success;baz=456", "foo",
		true, "123"
	},
	{
		"foo=123;bar=success;baz=456", "bar",
		true, "success"
	},
	{
		"foo=123;bar=success;baz=456", "baz",
		true, "456"
	},
};

void test_get_val(void)
{
	int i;
	printf("\n--- %s()\n", __func__);

	for (i = 0; i < ARRAY_SIZE(get_val_tests); i++) {
		const struct get_val_test *t = &get_val_tests[i];
		char val[128] = {};
		bool rc = osmo_sdp_fmtp_get_val(val, sizeof(val), t->fmtp_string, t->val_name);
		bool ok;
		printf("osmo_sdp_fmtp_get_val('%s', '%s') rc=%s",
		       t->fmtp_string, t->val_name,
		       rc ? "true" : "false");
		if (rc)
			printf(" val='%s'", val);
		ok = true;
		if (rc != t->expect_rc) {
			printf(" ERROR: expected rc=%s", t->expect_rc ? "true" : "false");
			ok = false;
		}
		if (t->expect_val && strcmp(val, t->expect_val)) {
			printf(" ERROR: expected val='%s'", t->expect_val);
			ok = false;
		}
		if (ok)
			printf(" ok");
		printf("\n");
	}
	printf("\n--- %s() DONE\n", __func__);
}

struct get_int_test {
	const char *fmtp_string;
	const char *val_name;
	int64_t defval;
	int64_t expect_rc;
};

const struct get_int_test get_int_tests[] = {
	{
		"foo=123;bar=success;baz=456", "foo", -1,
		123
	},
	{
		"foo=123;bar=success;baz=456", "bar", -1,
		-1
	},
	{
		"foo=123;bar=success;baz=456", "baz", -1,
		456
	},
};

void test_get_int(void)
{
	int i;
	printf("\n--- %s()\n", __func__);

	for (i = 0; i < ARRAY_SIZE(get_int_tests); i++) {
		const struct get_int_test *t = &get_int_tests[i];
		int64_t rc = osmo_sdp_fmtp_get_int(t->fmtp_string, t->val_name, t->defval);
		printf("osmo_sdp_fmtp_get_int('%s', '%s') rc=%"PRId64,
		       t->fmtp_string, t->val_name, rc);
		if (rc != t->expect_rc) {
			printf(" ERROR: expected rc=%"PRId64, t->expect_rc);
		}
		else {
			printf(" ok");
		}
		printf("\n");
	}
	printf("\n--- %s() DONE\n", __func__);
}

static const struct log_info_cat log_categories[] = {
};

const struct log_info log_info = {
        .cat = log_categories,
        .num_cat = ARRAY_SIZE(log_categories),
};

int main(void)
{
	void *ctx = talloc_named_const(NULL, 1, "sdp_fmtp_test");

	osmo_init_logging2(ctx, &log_info);
	log_set_print_filename2(osmo_stderr_target, LOG_FILENAME_NONE);
	log_set_print_timestamp(osmo_stderr_target, 0);
	log_set_use_color(osmo_stderr_target, 0);
	log_set_print_category_hex(osmo_stderr_target, 0);
	log_set_print_category(osmo_stderr_target, 1);

	test_get_val();
	test_get_int();
	return 0;
}

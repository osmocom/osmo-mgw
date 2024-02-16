AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/include \
	-I$(top_srcdir) \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	-ggdb3 \
	$(LIBOSMOCORE_CFLAGS) \
	$(COVERAGE_CFLAGS) \
	$(NULL)

AM_LDFLAGS = \
	$(LIBOSMOCORE_LIBS) \
	$(COVERAGE_LDFLAGS) \
	-no-install \
	$(NULL)

EXTRA_DIST = \
	sdp_fmtp_test.ok \
	sdp_fmtp_test.err \
	sdp_codec_test.ok \
	sdp_codec_test.err \
	$(NULL)

check_PROGRAMS = \
	sdp_fmtp_test \
	sdp_codec_test \
	$(NULL)

sdp_fmtp_test_SOURCES = \
	sdp_fmtp_test.c \
	$(NULL)

sdp_fmtp_test_LDADD = \
	$(top_builddir)/src/libosmo-sdp/libosmo-sdp.la \
	$(NULL)

sdp_codec_test_SOURCES = \
	sdp_codec_test.c \
	$(NULL)

sdp_codec_test_LDADD = \
	$(top_builddir)/src/libosmo-sdp/libosmo-sdp.la \
	$(LIBOSMOCORE_LIBS) \
	$(NULL)

update_exp:
	$(builddir)/sdp_fmtp_test >$(srcdir)/sdp_fmtp_test.ok 2>$(srcdir)/sdp_fmtp_test.err
	$(builddir)/sdp_codec_test >$(srcdir)/sdp_codec_test.ok 2>$(srcdir)/sdp_codec_test.err

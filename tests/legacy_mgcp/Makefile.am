AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	-I$(top_srcdir) \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	-ggdb3 \
	$(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMONETIF_CFLAGS) \
	$(LIBBCG729_CFLAGS) \
	$(COVERAGE_CFLAGS) \
	$(NULL)

AM_LDFLAGS = \
	$(COVERAGE_LDFLAGS) \
	$(NULL)

EXTRA_DIST = \
	mgcp_test.ok \
	mgcp_transcoding_test.ok \
	mgcpgw_client_test.ok \
	$(NULL)

noinst_PROGRAMS = \
	mgcp_test \
	mgcpgw_client_test \
	$(NULL)
if BUILD_MGCP_TRANSCODING
noinst_PROGRAMS += \
	mgcp_transcoding_test \
	$(NULL)
endif

mgcp_test_SOURCES = \
	mgcp_test.c \
	$(NULL)

mgcp_test_LDADD = \
	$(top_builddir)/src/libosmo-legacy-mgcp/libosmo-legacy-mgcp.la \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOVTY_LIBS) \
	$(LIBRARY_DL) \
	$(LIBOSMONETIF_LIBS) \
	$(LIBRARY_GSM) \
	-lm  \
	$(NULL)

mgcp_transcoding_test_SOURCES = \
	mgcp_transcoding_test.c \
	$(NULL)

mgcp_transcoding_test_LDADD = \
	$(top_builddir)/src/libosmo-legacy-mgcp/libosmo-legacy-mgcp.la \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOVTY_LIBS) \
	$(LIBBCG729_LIBS) \
	$(LIBRARY_DL) \
	$(LIBOSMONETIF_LIBS) \
	$(LIBRARY_GSM) \
	-lm \
	$(NULL)

mgcpgw_client_test_SOURCES = \
	mgcpgw_client_test.c \
	$(NULL)

mgcpgw_client_test_LDADD = \
	$(top_builddir)/src/libosmo-legacy-mgcp/libosmo-legacy-mgcp.la \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOVTY_LIBS) \
	$(LIBRARY_DL) \
	$(LIBOSMONETIF_LIBS) \
	$(LIBRARY_GSM) \
	$(NULL)

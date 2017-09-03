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
	$(COVERAGE_CFLAGS) \
	$(NULL)

AM_LDFLAGS = \
	$(COVERAGE_LDFLAGS) \
	$(NULL)

EXTRA_DIST = \
	mgcpgw_client_test.ok \
	mgcpgw_client_test.err \
	$(NULL)

noinst_PROGRAMS = \
	mgcpgw_client_test \
	$(NULL)

mgcpgw_client_test_SOURCES = \
	mgcpgw_client_test.c \
	$(NULL)

mgcpgw_client_test_LDADD = \
	$(top_builddir)/src/libosmo-mgcp-client/libosmo-mgcp-client.la \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOVTY_LIBS) \
	$(LIBRARY_DL) \
	$(LIBOSMONETIF_LIBS) \
	$(NULL)

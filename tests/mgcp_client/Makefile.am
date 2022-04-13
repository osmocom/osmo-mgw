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
	$(LIBOSMONETIF_CFLAGS) \
	$(COVERAGE_CFLAGS) \
	$(NULL)

AM_LDFLAGS = \
	$(COVERAGE_LDFLAGS) \
	$(NULL)

EXTRA_DIST = \
	mgcp_client_test.ok \
	mgcp_client_test.err \
	$(NULL)

check_PROGRAMS = \
	mgcp_client_test \
	$(NULL)

mgcp_client_test_SOURCES = \
	mgcp_client_test.c \
	$(NULL)

mgcp_client_test_LDADD = \
	$(top_builddir)/src/libosmo-mgcp-client/libosmo-mgcp-client.la \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOVTY_LIBS) \
	$(LIBRARY_DL) \
	$(LIBRARY_DLSYM) \
	$(LIBOSMONETIF_LIBS) \
	$(NULL)

update_exp:
	$(builddir)/mgcp_client_test >$(srcdir)/mgcp_client_test.ok 2>$(srcdir)/mgcp_client_test.err

AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	-I$(top_srcdir) \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	-ggdb3 \
	$(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOVTY_CFLAGS) \
	$(LIBOSMOGSM_CFLAGS) \
	$(LIBOSMONETIF_CFLAGS) \
	$(LIBOSMOABIS_CFLAGS) \
	$(LIBOSMOTRAU_CFLAGS) \
	$(COVERAGE_CFLAGS) \
	$(NULL)

AM_LDFLAGS = \
	$(COVERAGE_LDFLAGS) \
	-no-install \
	$(NULL)

EXTRA_DIST = \
	mgcp_test.ok \
	$(NULL)

check_PROGRAMS = \
	mgcp_test \
	$(NULL)

mgcp_test_SOURCES = \
	mgcp_test.c \
	$(NULL)

mgcp_test_LDADD = \
	$(top_builddir)/src/libosmo-mgcp/libosmo-mgcp.a \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOCODEC_LIBS) \
	$(LIBOSMOVTY_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOABIS_LIBS) \
	$(LIBOSMOTRAU_LIBS) \
	$(LIBRARY_DL) \
	$(LIBRARY_DLSYM) \
	$(LIBOSMONETIF_LIBS) \
	-lm  \
	$(NULL)

update_exp:
	$(builddir)/mgcp_test >$(srcdir)/mgcp_test.ok

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
	$(COVERAGE_CFLAGS) \
	$(NULL)

AM_LDFLAGS = \
	$(COVERAGE_LDFLAGS) \
	$(NULL)

EXTRA_DIST = \
	mgcp_test.ok \
	$(NULL)

noinst_PROGRAMS = \
	mgcp_test \
	$(NULL)

mgcp_test_SOURCES = \
	mgcp_test.c \
	$(NULL)

mgcp_test_LDADD = \
	$(top_builddir)/src/libosmo-mgcp/libosmo-mgcp.a \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOVTY_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBRARY_DL) \
	$(LIBOSMONETIF_LIBS) \
	-lm  \
	$(NULL)

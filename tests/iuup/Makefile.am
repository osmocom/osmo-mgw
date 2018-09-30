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
	iuup_test.ok \
	iuup_test.err \
	$(NULL)

noinst_PROGRAMS = \
	iuup_test \
	$(NULL)

iuup_test_SOURCES = \
	iuup_test.c \
	$(NULL)

iuup_test_LDADD = \
	$(top_builddir)/src/libosmo-mgcp/libosmo-mgcp.a \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOVTY_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBRARY_DL) \
	$(LIBOSMONETIF_LIBS) \
	-lm  \
	$(NULL)

update_exp:
	$(builddir)/iuup_test >$(srcdir)/iuup_test.ok 2>$(srcdir)/iuup_test.err

AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	-I$(top_builddir) \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	$(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOVTY_CFLAGS) \
	$(LIBOSMONETIF_CFLAGS) \
	$(LIBBCG729_CFLAGS) \
	$(COVERAGE_CFLAGS) \
	$(NULL)

bin_PROGRAMS = \
	osmo-bsc_mgcp \
	$(NULL)

osmo_bsc_mgcp_SOURCES = \
	mgcp_main.c \
	$(NULL)

osmo_bsc_mgcp_LDADD = \
	$(top_builddir)/src/libosmo-legacy-mgcp/libosmo-legacy-mgcp.la \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMONETIF_LIBS) \
	$(LIBOSMOVTY_LIBS) \
	$(LIBBCG729_LIBS) \
	$(LIBRARY_GSM) \
	$(NULL)

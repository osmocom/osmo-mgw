AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	-I$(top_builddir) \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	$(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOVTY_CFLAGS) \
	$(LIBOSMOGSM_CFLAGS) \
	$(LIBOSMOCTRL_CFLAGS) \
	$(LIBOSMONETIF_CFLAGS) \
	$(LIBOSMOABIS_CFLAGS) \
	$(LIBOSMOTRAU_CFLAGS) \
	$(COVERAGE_CFLAGS) \
	$(NULL)

bin_PROGRAMS = \
	osmo-mgw \
	$(NULL)

osmo_mgw_SOURCES = \
	mgw_main.c \
	$(NULL)

osmo_mgw_LDADD = \
	$(top_builddir)/src/libosmo-mgcp/libosmo-mgcp.a \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOCODEC_LIBS) \
	$(LIBOSMOVTY_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOCTRL_LIBS) \
	$(LIBOSMONETIF_LIBS) \
	$(LIBOSMOABIS_LIBS) \
	$(LIBOSMOTRAU_LIBS) \
	$(NULL)

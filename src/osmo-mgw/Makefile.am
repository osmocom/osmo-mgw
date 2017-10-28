AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	-I$(top_builddir) \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	$(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOVTY_CFLAGS) \
	$(COVERAGE_CFLAGS) \
	$(NULL)

bin_PROGRAMS = \
	osmo-mgw \
	$(NULL)

osmo_mgw_SOURCES = \
	mgw_main.c \
	$(NULL)

osmo_mgw_LDADD = \
	$(top_builddir)/src/libosmo-mgcp/libosmo-mgcp.la \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOVTY_LIBS) \
	$(NULL)

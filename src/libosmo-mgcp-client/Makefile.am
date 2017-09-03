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
	$(COVERAGE_CFLAGS) \
	$(NULL)

AM_LDFLAGS = \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMONETIF_LIBS) \
	$(COVERAGE_LDFLAGS) \
	$(NULL)

# This is _NOT_ the library release version, it's an API version.
# Please read Chapter 6 "Library interface versions" of the libtool
# documentation before making any modification
MGCP_CLIENT_LIBVERSION=1:0:0

lib_LTLIBRARIES = \
	libosmo-mgcp-client.la \
	$(NULL)

libosmo_mgcp_client_la_SOURCES = \
	mgcp_client.c \
	mgcp_client_vty.c \
	../libosmo-legacy-mgcp/mgcp_common.c \
	$(NULL)

libosmo_mgcp_client_la_LDFLAGS = $(AM_LDFLAGS) -version-info $(MGCP_CLIENT_LIBVERSION)

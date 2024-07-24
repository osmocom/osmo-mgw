AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/include \
	-I$(top_builddir) \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	$(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOVTY_CFLAGS) \
	$(LIBOSMOABIS_CFLAGS) \
	$(COVERAGE_CFLAGS) \
	$(NULL)

AM_LDFLAGS = \
	$(COVERAGE_LDFLAGS) \
	$(NULL)

# This is not at all related to the release version, but a range of supported
# API versions. Read TODO_RELEASE in the source tree's root!
MGCP_CLIENT_LIBVERSION=14:0:0

lib_LTLIBRARIES = \
	libosmo-mgcp-client.la \
	$(NULL)

libosmo_mgcp_client_la_SOURCES = \
	mgcp_client.c \
	mgcp_client_vty.c \
	mgcp_client_fsm.c \
	mgcp_client_endpoint_fsm.c \
	mgcp_client_pool.c \
	$(NULL)

libosmo_mgcp_client_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	-version-info $(MGCP_CLIENT_LIBVERSION) \
	-no-undefined \
	$(NULL)

libosmo_mgcp_client_la_LIBADD = \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOVTY_LIBS) \
	$(NULL)

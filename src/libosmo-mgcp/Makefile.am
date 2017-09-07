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
	$(LIBBCG729_CFLAGS) \
	$(NULL)

AM_LDFLAGS = \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMONETIF_LIBS) \
	$(COVERAGE_LDFLAGS) \
	$(LIBBCG729_LIBS) \
	$(NULL)

# This is not at all related to the release version, but a range of supported
# API versions. Read TODO_RELEASE in the source tree's root!
LEGACY_MGCP_LIBVERSION=0:0:0

lib_LTLIBRARIES = \
	libosmo-legacy-mgcp.la \
	$(NULL)

noinst_HEADERS = \
	g711common.h \
	$(NULL)

libosmo_legacy_mgcp_la_SOURCES = \
	mgcp_common.c \
	mgcp_protocol.c \
	mgcp_network.c \
	mgcp_vty.c \
	mgcp_osmux.c \
	mgcp_sdp.c \
	$(NULL)
if BUILD_MGCP_TRANSCODING
libosmo_legacy_mgcp_la_SOURCES += \
	mgcp_transcode.c \
	$(NULL)
endif

libosmo_legacy_mgcp_la_LDFLAGS = $(AM_LDFLAGS) -version-info $(LEGACY_MGCP_LIBVERSION)

AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	-I$(top_builddir) \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	$(LIBOSMOCORE_CFLAGS) \
	$(TALLOC_CFLAGS) \
	$(NULL)

SDP_LIBVERSION=1:0:0

# This is not at all related to the release version, but a range of supported
# API versions. Read TODO_RELEASE in the source tree's root!
lib_LTLIBRARIES = \
	libosmo-sdp.la \
	$(NULL)

libosmo_sdp_la_SOURCES = \
	fmtp.c \
	$(NULL)

libosmo_sdp_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	-version-info $(SDP_LIBVERSION) \
	-no-undefined \
	-export-symbols-regex '^osmo_' \
	$(NULL)

libosmo_sdp_la_LIBADD = \
	$(LIBOSMOCORE_LIBS) \
	$(NULL)

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

noinst_LTLIBRARIES = \
	libosmo-sdp.la \
	$(NULL)

libosmo_sdp_la_SOURCES = \
	sdp_codec.c \
	sdp_codec_list.c \
	sdp_msg.c \
	sdp_internal.c \
	fmtp.c \
	$(NULL)

libosmo_sdp_la_LIBADD = \
	$(LIBOSMOCORE_LIBS) \
	$(TALLOC_LIBS) \
	$(NULL)

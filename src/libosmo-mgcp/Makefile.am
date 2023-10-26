AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	-I$(top_builddir) \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	$(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOGSM_CFLAGS) \
	$(LIBOSMOVTY_CFLAGS) \
	$(LIBOSMONETIF_CFLAGS) \
	$(LIBOSMOABIS_CFLAGS) \
	$(LIBOSMOTRAU_CFLAGS) \
	$(COVERAGE_CFLAGS) \
	$(NULL)

AM_LDFLAGS = \
	$(COVERAGE_LDFLAGS) \
	$(NULL)

noinst_LTLIBRARIES = \
	libosmo-mgcp.la \
	$(NULL)

noinst_HEADERS = \
	g711common.h \
	$(NULL)

libosmo_mgcp_la_SOURCES = \
	mgcp_protocol.c \
	mgcp_network.c \
	mgcp_vty.c \
	mgcp_osmux.c \
	mgcp_sdp.c \
	mgcp_codec.c \
	mgcp_msg.c \
	mgcp_conn.c \
	mgcp_stat.c \
	mgcp_endp.c \
	mgcp_trunk.c \
	mgcp_ratectr.c \
	mgcp_e1.c \
	mgcp_iuup.c \
	$(NULL)

libosmo_mgcp_la_LIBADD = \
	$(top_builddir)/src/libosmo-sdp/libosmo-sdp.la \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOVTY_LIBS) \
	$(LIBOSMONETIF_LIBS) \
	$(LIBOSMOABIS_LIBS) \
	$(LIBOSMOTRAU_LIBS) \
	$(NULL)

EXTRA_DIST = osmomgw-usermanual.adoc \
    osmomgw-usermanual-docinfo.xml \
    osmomgw-vty-reference.xml \
    chapters \
    vty

if BUILD_MANUALS
  ASCIIDOC = osmomgw-usermanual.adoc
  ASCIIDOC_DEPS = $(srcdir)/chapters/*.adoc
  include $(OSMO_GSM_MANUALS_DIR)/build/Makefile.asciidoc.inc

  VTY_REFERENCE = osmomgw-vty-reference.xml
  include $(OSMO_GSM_MANUALS_DIR)/build/Makefile.vty-reference.inc

  OSMO_REPOSITORY = osmo-mgw
  include $(OSMO_GSM_MANUALS_DIR)/build/Makefile.common.inc
endif

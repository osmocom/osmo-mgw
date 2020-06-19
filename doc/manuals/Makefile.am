EXTRA_DIST = osmomgw-usermanual.adoc \
    osmomgw-usermanual-docinfo.xml \
    osmomgw-vty-reference.xml \
    regen_doc.sh \
    chapters \
    vty

if BUILD_MANUALS
  ASCIIDOC = osmomgw-usermanual.adoc
  ASCIIDOC_DEPS = $(srcdir)/chapters/*.adoc
  include $(OSMO_GSM_MANUALS_DIR)/build/Makefile.asciidoc.inc

  VTY_REFERENCE = osmomgw-vty-reference.xml
  include $(OSMO_GSM_MANUALS_DIR)/build/Makefile.vty-reference.inc

  BUILT_REFERENCE_XML = $(builddir)/vty/mgw_vty_reference.xml
  $(builddir)/vty/mgw_vty_reference.xml: $(top_builddir)/src/osmo-mgw/osmo-mgw
	mkdir -p $(builddir)/vty
	$(top_builddir)/src/osmo-mgw/osmo-mgw --vty-ref-xml > $@

  OSMO_REPOSITORY = osmo-mgw
  include $(OSMO_GSM_MANUALS_DIR)/build/Makefile.common.inc
endif

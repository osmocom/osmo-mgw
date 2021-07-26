SUBDIRS = \
	osmocom \
	$(NULL)

nobase_include_HEADERS = \
	osmocom/mgcp_client/mgcp_client.h \
	osmocom/mgcp_client/mgcp_client_endpoint_fsm.h \
	osmocom/mgcp_client/mgcp_client_fsm.h \
	osmocom/mgcp_client/mgcp_client_pool.h \
	osmocom/mgcp/mgcp.h \
	osmocom/mgcp/mgcp_common.h \
	osmocom/mgcp/osmux.h \
	$(NULL)

# This gets copied during make from osmocom/mgcp/mgcp_common.h. Therefore it is not included in the source tree and we
# don't need to distribute it (OS#4084).
nobase_nodist_include_HEADERS = \
	osmocom/mgcp_client/mgcp_common.h \
	$(NULL)

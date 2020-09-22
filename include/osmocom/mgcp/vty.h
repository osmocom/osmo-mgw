#pragma once

#include <osmocom/vty/command.h>

enum mgcp_vty_node {
	MGCP_NODE = _LAST_OSMOVTY_NODE + 1,
	TRUNK_NODE,
};

enum mgw_vty_cmd_attr {
	MGW_CMD_ATTR_NEWCONN = 0,
};

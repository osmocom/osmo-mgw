#pragma once

#include <osmocom/vty/command.h>

enum mgcp_vty_node {
	MGCP_NODE = _LAST_OSMOVTY_NODE + 1,
	TRUNK_NODE,
};

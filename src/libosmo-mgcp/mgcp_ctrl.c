/*
 * (C) 2020 by Harald Welte <laforge@gnumonks.org>
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <osmocom/ctrl/control_if.h>
#include <osmocom/mgcp/mgcp.h>


static int mgw_ctrl_node_lookup(void *data, vector vline, int *node_type,
				void **node_data, int *i)
{
	return 0;
}


struct ctrl_handle *mgw_ctrl_interface_setup(struct mgcp_config *cfg,
					     const char *bind_addr, uint16_t port)
{
	return ctrl_interface_setup_dynip2(cfg, bind_addr, port, mgw_ctrl_node_lookup,
					   _LAST_CTRL_NODE);
}

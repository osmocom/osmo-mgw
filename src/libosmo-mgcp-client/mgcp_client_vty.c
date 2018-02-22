/* MGCP client interface to quagga VTY */
/* (C) 2016 by sysmocom s.m.f.c. GmbH <info@sysmocom.de>
 * Based on OpenBSC interface to quagga VTY (libmsc/vty_interface_layer3.c)
 * (C) 2009 by Harald Welte <laforge@gnumonks.org>
 * (C) 2009-2011 by Holger Hans Peter Freyther
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <inttypes.h>
#include <stdlib.h>
#include <talloc.h>

#include <osmocom/vty/command.h>
#include <osmocom/vty/misc.h>
#include <osmocom/core/utils.h>

#include <osmocom/mgcp_client/mgcp_client.h>

#define MGW_STR "Configure MGCP connection to Media Gateway\n"

void *global_mgcp_client_ctx = NULL;
struct mgcp_client_conf *global_mgcp_client_conf = NULL;

DEFUN(cfg_mgw_local_ip, cfg_mgw_local_ip_cmd,
      "mgw local-ip A.B.C.D",
      MGW_STR "local bind to connect to MGW from\n"
      "local bind IP address\n")
{
	if (!global_mgcp_client_conf)
		return CMD_ERR_NOTHING_TODO;
	OSMO_ASSERT(global_mgcp_client_ctx);
	global_mgcp_client_conf->local_addr =
		talloc_strdup(global_mgcp_client_ctx, argv[0]);
	return CMD_SUCCESS;
}
ALIAS_DEPRECATED(cfg_mgw_local_ip, cfg_mgcpgw_local_ip_cmd,
		 "mgcpgw local-ip A.B.C.D",
		 MGW_STR "local bind to connect to MGCP gateway with\n"
		 "local bind IP address\n")

DEFUN(cfg_mgw_local_port, cfg_mgw_local_port_cmd,
      "mgw local-port <0-65535>",
      MGW_STR "local port to connect to MGW from\n"
      "local bind port\n")
{
	if (!global_mgcp_client_conf)
		return CMD_ERR_NOTHING_TODO;
	global_mgcp_client_conf->local_port = atoi(argv[0]);
	return CMD_SUCCESS;
}
ALIAS_DEPRECATED(cfg_mgw_local_port, cfg_mgcpgw_local_port_cmd,
		 "mgcpgw local-port <0-65535>",
		 MGW_STR "local bind to connect to MGCP gateway with\n"
		 "local bind port\n")

DEFUN(cfg_mgw_remote_ip, cfg_mgw_remote_ip_cmd,
      "mgw remote-ip A.B.C.D",
      MGW_STR "remote IP address to reach the MGW at\n"
      "remote IP address\n")
{
	if (!global_mgcp_client_conf)
		return CMD_ERR_NOTHING_TODO;
	OSMO_ASSERT(global_mgcp_client_ctx);
	global_mgcp_client_conf->remote_addr =
		talloc_strdup(global_mgcp_client_ctx, argv[0]);
	return CMD_SUCCESS;
}
ALIAS_DEPRECATED(cfg_mgw_remote_ip, cfg_mgcpgw_remote_ip_cmd,
		 "mgcpgw remote-ip A.B.C.D",
		 MGW_STR "remote bind to connect to MGCP gateway with\n"
		 "remote bind IP address\n")

DEFUN(cfg_mgw_remote_port, cfg_mgw_remote_port_cmd,
      "mgw remote-port <0-65535>",
      MGW_STR "remote port to reach the MGW at\n"
      "remote port\n")
{
	if (!global_mgcp_client_conf)
		return CMD_ERR_NOTHING_TODO;
	global_mgcp_client_conf->remote_port = atoi(argv[0]);
	return CMD_SUCCESS;
}
ALIAS_DEPRECATED(cfg_mgw_remote_port, cfg_mgcpgw_remote_port_cmd,
		 "mgcpgw remote-port <0-65535>",
		 MGW_STR "remote bind to connect to MGCP gateway with\n"
		 "remote bind port\n")

DEFUN(cfg_mgw_endpoint_range, cfg_mgw_endpoint_range_cmd,
      "mgw endpoint-range <1-65534> <1-65534>",
      MGW_STR "usable range of endpoint identifiers\n"
      "set first usable endpoint identifier\n"
      "set last usable endpoint identifier\n")
{
	uint16_t first_endpoint = atoi(argv[0]);
	uint16_t last_endpoint = atoi(argv[1]);

	if (last_endpoint < first_endpoint) {
		vty_out(vty, "last endpoint must be greater than first endpoint!%s",
			VTY_NEWLINE);
		return CMD_SUCCESS;
	}

	global_mgcp_client_conf->first_endpoint = first_endpoint;
	global_mgcp_client_conf->last_endpoint = last_endpoint;
	return CMD_SUCCESS;
}
ALIAS_DEPRECATED(cfg_mgw_endpoint_range, cfg_mgcpgw_endpoint_range_cmd,
      "mgcpgw endpoint-range <1-65534> <1-65534>",
      MGW_STR "usable range of endpoint identifiers\n"
      "set first useable endpoint identifier\n"
      "set the last useable endpoint identifier\n")

#define BTS_START_STR "First UDP port allocated for the BTS side\n"
#define UDP_PORT_STR "UDP Port number\n"
DEFUN(cfg_mgw_rtp_bts_base_port,
      cfg_mgw_rtp_bts_base_port_cmd,
      "mgw bts-base <0-65534>",
      MGW_STR
      BTS_START_STR
      UDP_PORT_STR)
{
	global_mgcp_client_conf->bts_base = atoi(argv[0]);
	return CMD_SUCCESS;
}
ALIAS_DEPRECATED(cfg_mgw_rtp_bts_base_port,
      cfg_mgcpgw_rtp_bts_base_port_cmd,
      "mgcpgw bts-base <0-65534>",
      MGW_STR
      BTS_START_STR
      UDP_PORT_STR)

int mgcp_client_config_write(struct vty *vty, const char *indent)
{
	const char *addr;
	int port;
	uint16_t first_endpoint;
	uint16_t last_endpoint;
	uint16_t bts_base;

	addr = global_mgcp_client_conf->local_addr;
	if (addr)
		vty_out(vty, "%smgw local-ip %s%s", indent, addr,
			VTY_NEWLINE);
	port = global_mgcp_client_conf->local_port;
	if (port >= 0)
		vty_out(vty, "%smgw local-port %u%s", indent,
			(uint16_t)port, VTY_NEWLINE);

	addr = global_mgcp_client_conf->remote_addr;
	if (addr)
		vty_out(vty, "%smgw remote-ip %s%s", indent, addr,
			VTY_NEWLINE);
	port = global_mgcp_client_conf->remote_port;
	if (port >= 0)
		vty_out(vty, "%smgw remote-port %u%s", indent,
			(uint16_t)port, VTY_NEWLINE);

	first_endpoint = global_mgcp_client_conf->first_endpoint;
	last_endpoint = global_mgcp_client_conf->last_endpoint;
	if (last_endpoint != 0) {
		vty_out(vty, "%smgw endpoint-range %u %u%s", indent,
			first_endpoint, last_endpoint, VTY_NEWLINE);
	}

	bts_base = global_mgcp_client_conf->bts_base;
	if (bts_base) {
		vty_out(vty, "%smgw bts-base %u%s", indent,
			bts_base, VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}

void mgcp_client_vty_init(void *talloc_ctx, int node, struct mgcp_client_conf *conf)
{
	global_mgcp_client_ctx = talloc_ctx;
	global_mgcp_client_conf = conf;

	install_element(node, &cfg_mgw_local_ip_cmd);
	install_element(node, &cfg_mgw_local_port_cmd);
	install_element(node, &cfg_mgw_remote_ip_cmd);
	install_element(node, &cfg_mgw_remote_port_cmd);
	install_element(node, &cfg_mgw_endpoint_range_cmd);
	install_element(node, &cfg_mgw_rtp_bts_base_port_cmd);

	/* deprecated 'mgcpgw' commands */
	install_element(node, &cfg_mgcpgw_local_ip_cmd);
	install_element(node, &cfg_mgcpgw_local_port_cmd);
	install_element(node, &cfg_mgcpgw_remote_ip_cmd);
	install_element(node, &cfg_mgcpgw_remote_port_cmd);
	install_element(node, &cfg_mgcpgw_endpoint_range_cmd);
	install_element(node, &cfg_mgcpgw_rtp_bts_base_port_cmd);

	osmo_fsm_vty_add_cmds();
}

/* MGCP client interface to quagga VTY */
/* (C) 2016 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
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

#include <osmocom/vty/vty.h>
#include <osmocom/vty/command.h>
#include <osmocom/vty/misc.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/timer.h>

#include <osmocom/mgcp_client/mgcp_client.h>
#include <osmocom/mgcp_client/mgcp_client_internal.h>
#include <osmocom/mgcp_client/mgcp_client_pool_internal.h>
#include <osmocom/mgcp_client/mgcp_client_pool.h>

#define MGW_STR MGCP_CLIENT_MGW_STR

/* Only common (non-pooled) VTY commands will use this talloc context. All
 * pooled VTY commands will use the pool (global_mgcp_client_pool) as
 * talloc context. */
static void *global_mgcp_client_ctx = NULL;

/* MGCP Client configuration used with mgcp_client_vty_init(). (This pointer
 * points to user provided memory, so it cannot be used as talloc context.) */
static struct mgcp_client_conf *global_mgcp_client_conf = NULL;

/* Pointer to the MGCP pool that is managed by mgcp_client_pool_vty_init() */
static struct mgcp_client_pool *global_mgcp_client_pool = NULL;

static struct mgcp_client_conf *get_mgcp_client_config(struct vty *vty)
{
	if (global_mgcp_client_pool && vty->node == global_mgcp_client_pool->vty_node->node)
		return vty->index;

	/* Global single MGCP config, deprecated: */
	vty_out(vty, "%% MGCP commands outside of 'mgw' nodes are deprecated. "
		"You should consider reading the User Manual and migrating to 'mgw' node.%s",
		VTY_NEWLINE);

	return global_mgcp_client_conf;
}

static struct mgcp_client *get_mgcp_client(struct vty *vty)
{
	struct mgcp_client_conf *conf = get_mgcp_client_config(vty);
	struct mgcp_client_pool_member *pool_member;

	if (global_mgcp_client_pool && vty->node == global_mgcp_client_pool->vty_node->node) {
		llist_for_each_entry(pool_member, &global_mgcp_client_pool->member_list, list) {
			/* Find matching the conf pointer: */
			if (&pool_member->conf != conf)
				continue;
			return pool_member->client;
		}
	}

	/* Global single MGCP config, deprecated: */
	vty_out(vty, "%% MGCP commands outside of 'mgw' nodes are deprecated. "
		"You should consider reading the User Manual and migrating to 'mgw' node.%s",
		VTY_NEWLINE);

	/* There's no way to obtain the struct mgcp_client in old interface, but anyway it's deprecated. */
	return NULL;
}


DEFUN(cfg_mgw_local_ip, cfg_mgw_local_ip_cmd,
      "local-ip " VTY_IPV46_CMD,
      "local bind to connect to MGW from\n"
      "local bind IPv4 address\n"
      "local bind IPv6 address\n")
{
	struct mgcp_client_conf *conf = get_mgcp_client_config(vty);

	osmo_talloc_replace_string(global_mgcp_client_ctx,
				   (char **)&conf->local_addr,
				   argv[0]);
	return CMD_SUCCESS;
}
ALIAS_DEPRECATED(cfg_mgw_local_ip, cfg_mgcpgw_local_ip_cmd,
		 "mgcpgw local-ip A.B.C.D",
		 MGW_STR "local bind to connect to MGCP gateway with\n"
		 "local bind IP address\n")
ALIAS_DEPRECATED(cfg_mgw_local_ip,
		 cfg_mgw_mgw_local_ip_cmd,
		 "mgw local-ip " VTY_IPV46_CMD,
		 MGW_STR "local bind to connect to MGW from\n"
		 "local bind IPv4 address\n"
		 "local bind IPv6 address\n")

DEFUN(cfg_mgw_local_port, cfg_mgw_local_port_cmd,
      "local-port <0-65535>",
      "local port to connect to MGW from\n"
      "local bind port\n")
{
	struct mgcp_client_conf *conf = get_mgcp_client_config(vty);

	conf->local_port = atoi(argv[0]);
	return CMD_SUCCESS;
}
ALIAS_DEPRECATED(cfg_mgw_local_port, cfg_mgcpgw_local_port_cmd,
		 "mgcpgw local-port <0-65535>",
		 MGW_STR "local bind to connect to MGCP gateway with\n"
		 "local bind port\n")
ALIAS_DEPRECATED(cfg_mgw_local_port,
		 cfg_mgw_mgw_local_port_cmd,
		 "mgw local-port <0-65535>",
		 MGW_STR "local port to connect to MGW from\n"
		 "local bind port\n")

DEFUN(cfg_mgw_remote_ip, cfg_mgw_remote_ip_cmd,
      "remote-ip " VTY_IPV46_CMD,
      "remote IP address to reach the MGW at\n"
      "remote IPv4 address\n"
      "remote IPv6 address\n")
{
	struct mgcp_client_conf *conf = get_mgcp_client_config(vty);

	osmo_talloc_replace_string(global_mgcp_client_ctx,
				   (char **)&conf->remote_addr, argv[0]);
	return CMD_SUCCESS;
}
ALIAS_DEPRECATED(cfg_mgw_remote_ip, cfg_mgcpgw_remote_ip_cmd,
		 "mgcpgw remote-ip A.B.C.D",
		 MGW_STR "remote bind to connect to MGCP gateway with\n"
		 "remote bind IP address\n")
ALIAS_DEPRECATED(cfg_mgw_remote_ip,
		 cfg_mgw_mgw_remote_ip_cmd,
		 "mgw remote-ip " VTY_IPV46_CMD,
		 MGW_STR "remote IP address to reach the MGW at\n"
		 "remote IPv4 address\n"
		 "remote IPv6 address\n")

DEFUN(cfg_mgw_remote_port, cfg_mgw_remote_port_cmd,
      "remote-port <0-65535>",
      "remote port to reach the MGW at\n"
      "remote port\n")
{
	struct mgcp_client_conf *conf = get_mgcp_client_config(vty);

	conf->remote_port = atoi(argv[0]);
	return CMD_SUCCESS;
}
ALIAS_DEPRECATED(cfg_mgw_remote_port, cfg_mgcpgw_remote_port_cmd,
		 "mgcpgw remote-port <0-65535>",
		 MGW_STR "remote bind to connect to MGCP gateway with\n"
		 "remote bind port\n")
ALIAS_DEPRECATED(cfg_mgw_remote_port,
		 cfg_mgw_mgw_remote_port_cmd,
		 "mgw remote-port <0-65535>",
		 MGW_STR "remote port to reach the MGW at\n"
		 "remote port\n")

DEFUN_DEPRECATED(cfg_mgw_mgw_endpoint_range, cfg_mgw_mgw_endpoint_range_cmd,
      "mgw endpoint-range <1-65534> <1-65534>",
      MGW_STR "DEPRECATED: the endpoint range cannot be defined by the client\n"
      "-\n" "-\n")
{
	vty_out(vty, "Please do not use legacy config 'mgw endpoint-range'"
		" (the range can no longer be defined by the MGCP client)%s",
		VTY_NEWLINE);
	return CMD_SUCCESS;
}
ALIAS_DEPRECATED(cfg_mgw_mgw_endpoint_range, cfg_mgcpgw_endpoint_range_cmd,
      "mgcpgw endpoint-range <1-65534> <1-65534>",
      MGW_STR "usable range of endpoint identifiers\n"
      "set first useable endpoint identifier\n"
      "set the last useable endpoint identifier\n")

#define BTS_START_STR "First UDP port allocated for the BTS side\n"
#define UDP_PORT_STR "UDP Port number\n"
DEFUN_DEPRECATED(cfg_mgw_rtp_bts_base_port,
      cfg_mgw_rtp_bts_base_port_cmd,
      "mgw bts-base <0-65534>",
      MGW_STR
      "DEPRECATED: there is no explicit BTS side in current osmo-mgw\n" "-\n")
{
	vty_out(vty, "Please do not use legacy config 'mgw bts-base'"
		" (there is no explicit BTS side in an MGW anymore)%s",
		VTY_NEWLINE);
	return CMD_SUCCESS;
}
ALIAS_DEPRECATED(cfg_mgw_rtp_bts_base_port,
      cfg_mgcpgw_rtp_bts_base_port_cmd,
      "mgcpgw bts-base <0-65534>",
      MGW_STR
      BTS_START_STR
      UDP_PORT_STR)

DEFUN(cfg_mgw_endpoint_domain_name,
      cfg_mgw_endpoint_domain_name_cmd,
      "endpoint-domain NAME",
      "Set the domain name to send in MGCP messages, e.g. the part 'foo' in 'rtpbridge/*@foo'.\n"
      "Domain name, should be alphanumeric.\n")
{
	struct mgcp_client_conf *conf = get_mgcp_client_config(vty);

	if (osmo_strlcpy(conf->endpoint_domain_name, argv[0], sizeof(conf->endpoint_domain_name))
	    >= sizeof(conf->endpoint_domain_name)) {
		vty_out(vty, "%% Error: 'mgw endpoint-domain' name too long, max length is %zu: '%s'%s",
			sizeof(conf->endpoint_domain_name) - 1, argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}
	return CMD_SUCCESS;
}
ALIAS_DEPRECATED(cfg_mgw_endpoint_domain_name,
      cfg_mgw_mgw_endpoint_domain_name_cmd,
      "mgw endpoint-domain NAME",
      MGW_STR "Set the domain name to send in MGCP messages, e.g. the part 'foo' in 'rtpbridge/*@foo'.\n"
      "Domain name, should be alphanumeric.\n")

DEFUN(cfg_mgw_reset_ep_name,
      cfg_mgw_reset_ep_name_cmd,
      "reset-endpoint NAME",
      "Add an endpoint name that should be reset (DLCX) on connect to the reset-endpoint list,"
      "e.g. 'rtpbridge/*'\n"
      "Endpoint name, e.g. 'rtpbridge/*' or 'ds/e1-0/s-3/su16-4'.\n")
{
	int rc;
	struct reset_ep *reset_ep;
	struct mgcp_client_conf *conf = get_mgcp_client_config(vty);

	/* stop when the address is already in the list */
	llist_for_each_entry(reset_ep, &conf->reset_epnames, list) {
		if (strcmp(argv[0], reset_ep->name) == 0) {
			vty_out(vty, "%% duplicate endpoint name configured ('%s')%s", argv[0], VTY_NEWLINE);
			return CMD_WARNING;
		}
	}

	/* the domain name is not part of the actual endpoint name */
	if (strchr(argv[0], '@')) {
		vty_out(vty, "%% the endpoint name must be given without domain name ('%s')%s",
			argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	reset_ep = talloc_zero(global_mgcp_client_ctx, struct reset_ep);
	OSMO_ASSERT(reset_ep);

	rc = osmo_strlcpy(reset_ep->name, argv[0], sizeof(reset_ep->name));
	if (rc >= sizeof(reset_ep->name)) {
		vty_out(vty, "%% Error: 'mgw reset-endpoint' name too long, max length is %zu: '%s'%s",
			sizeof(reset_ep->name) - 1, argv[0], VTY_NEWLINE);
		talloc_free(reset_ep);
		return CMD_WARNING;
	}

	llist_add_tail(&reset_ep->list, &conf->reset_epnames);

	return CMD_SUCCESS;
}
ALIAS_DEPRECATED(cfg_mgw_reset_ep_name,
      cfg_mgw_mgw_reset_ep_name_cmd,
      "mgw reset-endpoint NAME",
      MGW_STR "Add an endpoint name that should be reset (DLCX) on connect to the reset-endpoint list,"
      "e.g. 'rtpbridge/*'\n"
      "Endpoint name, e.g. 'rtpbridge/*' or 'ds/e1-0/s-3/su16-4'.\n")

DEFUN(cfg_mgw_no_reset_ep_name,
      cfg_mgw_no_reset_ep_name_cmd,
      "no reset-endpoint NAME",
      NO_STR "remove an endpoint name from the reset-endpoint list, e.g. 'rtpbridge/*'\n"
      "Endpoint name, e.g. 'rtpbridge/*' or 'ds/e1-0/s-3/su16-4'.\n")
{
	struct reset_ep *reset_ep;
	struct mgcp_client_conf *conf = get_mgcp_client_config(vty);

	llist_for_each_entry(reset_ep, &conf->reset_epnames, list) {
		if (strcmp(argv[0], reset_ep->name) == 0) {
			llist_del(&reset_ep->list);
			talloc_free(reset_ep);
			return CMD_SUCCESS;
		}
	}

	vty_out(vty, "%% no such endpoint name configured ('%s')%s", argv[0], VTY_NEWLINE);
	return CMD_WARNING;
}
ALIAS_DEPRECATED(cfg_mgw_no_reset_ep_name,
      cfg_mgw_mgw_no_reset_ep_name_cmd,
      "no mgw reset-endpoint NAME",
      NO_STR MGW_STR "remove an endpoint name from the reset-endpoint list, e.g. 'rtpbridge/*'\n"
      "Endpoint name, e.g. 'rtpbridge/*' or 'ds/e1-0/s-3/su16-4'.\n")

DEFUN(cfg_mgw_mgw_keepalive_req_interval,
      cfg_mgw_mgw_keepalive_req_interval_cmd,
      "keepalive request-interval <0-4294967295>",
      "Monitor if the MGCP link against MGW is still usable\n"
      "Send an MGCP command to the MGW at given interval if no other commands are sent\n"
      "The interval at which send MGCP commands (s), 0 to disable\n")
{
	struct mgcp_client_conf *conf = get_mgcp_client_config(vty);
	struct mgcp_client *mgcp = get_mgcp_client(vty);

	conf->keepalive.req_interval_sec = atoi(argv[0]);

	if (!mgcp)
		return CMD_SUCCESS;

	/* If client already exists, apply the change immediately if possible: */
	mgcp->actual.keepalive.req_interval_sec = atoi(argv[0]);
	if (mgcp->iofd) { /* UDP MGCP socket connected */
		if (mgcp->actual.keepalive.req_interval_sec > 0) {
			/* Re-schedule: */
			osmo_timer_schedule(&mgcp->keepalive_tx_timer, mgcp->actual.keepalive.req_interval_sec, 0);
		} else {
			if (osmo_timer_pending(&mgcp->keepalive_tx_timer))
				osmo_timer_del(&mgcp->keepalive_tx_timer);
			/* Assume link is UP by default, so that this MGW can be selected: */
			mgcp->conn_up = true;
		}
	} /* else: wait until connect() to do first scheduling */

	return CMD_SUCCESS;
}

DEFUN(cfg_mgw_mgw_keepalive_req_endpoint,
      cfg_mgw_mgw_keepalive_req_endpoint_cmd,
      "keepalive request-endpoint NAME",
      "Monitor if the MGCP link against MGW is still usable\n"
      "Use a given endpoint name when sending an MGCP command to the MGW for keepalive purposes\n"
      "The name of the endpoint to use\n")
{
	struct mgcp_client_conf *conf = get_mgcp_client_config(vty);
	struct mgcp_client *mgcp = get_mgcp_client(vty);

	OSMO_STRLCPY_ARRAY(conf->keepalive.req_endpoint_name, argv[0]);

	if (!mgcp)
		return CMD_SUCCESS;

	/* If client already exists, apply the change immediately if possible: */
	OSMO_STRLCPY_ARRAY(mgcp->actual.keepalive.req_endpoint_name, argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_mgw_mgw_keepalive_timeout,
      cfg_mgw_mgw_keepalive_timeout_cmd,
      "keepalive timeout <0-4294967295>",
      "Monitor if the MGCP link against MGW is still usable\n"
      "Consider the link to the MGW to be down after time without receiving any message from it\n"
      "The timeout (s), 0 to disable\n")
{
	struct mgcp_client_conf *conf = get_mgcp_client_config(vty);
	struct mgcp_client *mgcp = get_mgcp_client(vty);

	conf->keepalive.timeout_sec = atoi(argv[0]);

	if (!mgcp)
		return CMD_SUCCESS;

	/* If client already exists, apply the change immediately if possible: */
	mgcp->actual.keepalive.timeout_sec = atoi(argv[0]);
	if (mgcp->iofd) { /* UDP MGCP socket connected */
		if (mgcp->actual.keepalive.timeout_sec > 0) {
			/* Re-schedule: */
			osmo_timer_schedule(&mgcp->keepalive_rx_timer, mgcp->actual.keepalive.timeout_sec, 0);
		} else {
			if (osmo_timer_pending(&mgcp->keepalive_rx_timer))
				osmo_timer_del(&mgcp->keepalive_rx_timer);
			/* Assume link is UP by default, so that this MGW can be selected: */
			mgcp->conn_up = true;
		}
	} /* else: wait until connect() to do first scheduling */

	return CMD_SUCCESS;
}

static int config_write(struct vty *vty, const char *indent, struct mgcp_client_conf *conf)
{
	const char *addr;
	int port;
	struct reset_ep *reset_ep;

	/* If caller doesn't the MGW pool API (mgcp_client_pool_vty_init was never called),
	 * then the "mgw" cmd prefix must be added since the old node always contained it.
	 */
	const char *mgw_prefix = global_mgcp_client_pool ? "" : "mgw ";

	if (conf->description) /* description never had "mgw" prefix even on old node: */
		vty_out(vty, "%sdescription %s%s", indent, conf->description, VTY_NEWLINE);

	addr = conf->local_addr;
	if (addr)
		vty_out(vty, "%s%slocal-ip %s%s", indent, mgw_prefix, addr, VTY_NEWLINE);
	port = conf->local_port;
	if (port >= 0)
		vty_out(vty, "%s%slocal-port %u%s", indent, mgw_prefix,
			(uint16_t)port, VTY_NEWLINE);

	addr = conf->remote_addr;
	if (addr)
		vty_out(vty, "%s%sremote-ip %s%s", indent, mgw_prefix, addr, VTY_NEWLINE);
	port = conf->remote_port;
	if (port >= 0)
		vty_out(vty, "%s%sremote-port %u%s", indent, mgw_prefix,
			(uint16_t)port, VTY_NEWLINE);

	if (conf->endpoint_domain_name[0])
		vty_out(vty, "%s%sendpoint-domain %s%s", indent, mgw_prefix,
			conf->endpoint_domain_name, VTY_NEWLINE);

	llist_for_each_entry(reset_ep, &conf->reset_epnames, list)
		vty_out(vty, "%s%sreset-endpoint %s%s", indent, mgw_prefix, reset_ep->name, VTY_NEWLINE);

	if (conf->keepalive.req_interval_sec != 0)
		vty_out(vty, "%s%skeepalive request-interval %u%s", indent, mgw_prefix,
			conf->keepalive.req_interval_sec, VTY_NEWLINE);
	if (strncmp(conf->keepalive.req_endpoint_name, MGCP_CLIENT_KEEPALIVE_DEFAULT_ENDP,
		    sizeof(conf->keepalive.req_endpoint_name)) != 0)
		vty_out(vty, "%s%skeepalive request-endpoint %s%s", indent,  mgw_prefix,
			conf->keepalive.req_endpoint_name, VTY_NEWLINE);
	if (conf->keepalive.timeout_sec != 0)
		vty_out(vty, "%s%skeepalive timeout %u%s", indent,  mgw_prefix,
			conf->keepalive.timeout_sec, VTY_NEWLINE);

	return CMD_SUCCESS;
}

/*! Write out MGCP client config to VTY.
 *  \param[in] vty VTY to which we should print.
 *  \param[in] string used for indentation (e.g. " ").
 *  \returns CMD_SUCCESS on success, CMD_WARNING on error */
int mgcp_client_config_write(struct vty *vty, const char *indent)
{
	/* If caller supports MGW pool API (mgcp_client_pool_vty_init was
	 * called), then skip printing any config in this node and print it when
	 * the whole 'mgw' node is printed. */
	if (global_mgcp_client_pool)
		return CMD_SUCCESS;
	return config_write(vty, indent, global_mgcp_client_conf);
}

static void vty_init_common(void *talloc_ctx, int node)
{
	global_mgcp_client_ctx = talloc_ctx;

	/* deprecated 'mgw' commands ('mgw' prepended as first arg) */
	install_lib_element(node, &cfg_mgw_mgw_local_ip_cmd);
	install_lib_element(node, &cfg_mgw_mgw_local_port_cmd);
	install_lib_element(node, &cfg_mgw_mgw_remote_ip_cmd);
	install_lib_element(node, &cfg_mgw_mgw_remote_port_cmd);
	install_lib_element(node, &cfg_mgw_mgw_endpoint_range_cmd);
	install_lib_element(node, &cfg_mgw_mgw_endpoint_domain_name_cmd);
	install_lib_element(node, &cfg_mgw_mgw_reset_ep_name_cmd);
	install_lib_element(node, &cfg_mgw_mgw_no_reset_ep_name_cmd);
	install_lib_element(node, &cfg_mgw_mgw_keepalive_req_interval_cmd);
	install_lib_element(node, &cfg_mgw_mgw_keepalive_req_endpoint_cmd);
	install_lib_element(node, &cfg_mgw_mgw_keepalive_timeout_cmd);

	osmo_fsm_vty_add_cmds();
}

/*! Set up MGCP client VTY
 *  (called once at startup by the application process).
 *  \param[in] talloc_ctx talloc context to be used by the VTY for allocating memory.
 *  \param[in] node identifier of the node on which the VTY commands should be installed.
 *  \param[in] conf user provided memory to to store the MGCP client configuration data. */
void mgcp_client_vty_init(void *talloc_ctx, int node, struct mgcp_client_conf *conf)
{
	global_mgcp_client_conf = conf;

	/* deprecated 'mgcpgw' commands */
	install_lib_element(node, &cfg_mgcpgw_local_ip_cmd);
	install_lib_element(node, &cfg_mgcpgw_local_port_cmd);
	install_lib_element(node, &cfg_mgcpgw_remote_ip_cmd);
	install_lib_element(node, &cfg_mgcpgw_remote_port_cmd);
	install_lib_element(node, &cfg_mgcpgw_endpoint_range_cmd);
	install_lib_element(node, &cfg_mgcpgw_rtp_bts_base_port_cmd);

	vty_init_common(talloc_ctx, node);
}

/* Mark whether user called mgcp_client_pool_config_write() and hence support new API */
static bool mgcp_client_pool_config_write_called = false;

static int _mgcp_client_pool_config_write(struct vty *vty, const char *indent)
{
	struct mgcp_client_pool *pool = global_mgcp_client_pool;
	struct mgcp_client_pool_member *pool_member;
	unsigned int subindent_buf_len;
	char *subindent;

	if (!indent)
		indent = pool->vty_indent ? : "";
	subindent_buf_len = strlen(indent) + 1 + 1;
	subindent = talloc_zero_size(vty, subindent_buf_len);

	snprintf(subindent, subindent_buf_len, "%s ", indent);

	llist_for_each_entry(pool_member, &pool->member_list, list) {
		vty_out(vty, "%smgw %u%s", indent, pool_member->nr, VTY_NEWLINE);
		config_write(vty, subindent, &pool_member->conf);
	}

	/* MGW pool API is supported by user (global_mgcp_client_pool is set
	 * because mgcp_client_pool_vty_init was called). If single MGW was
	 * configured through old VTY and no mgw in the new MGW pool VTY is
	 * replacing it, then output the single MGW converted to the new MGW
	 * pool VTY. */
	if (llist_empty(&pool->member_list) && pool->mgcp_client_single) {
		vty_out(vty, "%smgw 0%s", indent, VTY_NEWLINE);
		config_write(vty, subindent, global_mgcp_client_conf);
	}

	talloc_free(subindent);
	return CMD_SUCCESS;
}

/* Deprecated, used for backward compatibility with older users which didn't call
 * mgcp_client_pool_config_write(): */
static int config_write_pool(struct vty *vty)
{
	if (mgcp_client_pool_config_write_called)
		return CMD_SUCCESS;

	return _mgcp_client_pool_config_write(vty, NULL);
}

/*! Write out MGCP client config to VTY.
 *  \param[in] vty VTY to which we should print.
 *  \param[in] indent string used for indentation (e.g. " ").
	       If NULL, indentation passed during mgcp_client_pool_vty_init() will be used.
 *  \returns CMD_SUCCESS on success, CMD_WARNING on error */
int mgcp_client_pool_config_write(struct vty *vty, const char *indent)
{
	/* Tell internal node write function that the user supports calling proper API: */
	mgcp_client_pool_config_write_called = true;
	return _mgcp_client_pool_config_write(vty, indent);
}

DEFUN_ATTR(cfg_mgw,
	   cfg_mgw_cmd, "mgw <0-255>", "Select a MGCP client config to setup\n" "reference number\n", CMD_ATTR_IMMEDIATE)
{
	int nr = atoi(argv[0]);
	struct mgcp_client_pool_member *pool_member;

	pool_member = mgcp_client_pool_find_member_by_nr(global_mgcp_client_pool, nr);
	if (!pool_member) {
		pool_member = mgcp_client_pool_member_alloc(global_mgcp_client_pool, nr);
		OSMO_ASSERT(pool_member);
	}

	vty->index = &pool_member->conf;
	vty->index_sub = &pool_member->conf.description;
	vty->node = global_mgcp_client_pool->vty_node->node;

	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_no_mgw,
	   cfg_no_mgw_cmd,
	   "no mgw <0-255>", NO_STR "Select a MGCP client config to remove\n" "reference number\n", CMD_ATTR_IMMEDIATE)
{
	int nr = atoi(argv[0]);
	struct mgcp_client_pool_member *pool_member;

	pool_member = mgcp_client_pool_find_member_by_nr(global_mgcp_client_pool, nr);
	if (!pool_member) {
		vty_out(vty, "%% no such MGCP client configured ('%s')%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* Make sure that there are no ongoing calls */
	if (pool_member->refcount > 0) {
		vty_out(vty, "%% MGCP client (MGW %s) is still serving ongoing calls -- can't remove it now!%s",
			mgcp_client_pool_member_name(pool_member), VTY_NEWLINE);
		return CMD_WARNING;
	}

	mgcp_client_pool_member_free(pool_member);

	return CMD_SUCCESS;
}

DEFUN_ATTR(mgw_reconnect, mgw_reconnect_cmd,
	   "mgw <0-255> reconnect",
	   MGW_STR "reference number\n" "reconfigure and reconnect MGCP client\n", CMD_ATTR_IMMEDIATE)
{
	int nr = atoi(argv[0]);
	struct mgcp_client_pool_member *pool_member = NULL;

	pool_member = mgcp_client_pool_find_member_by_nr(global_mgcp_client_pool, nr);
	if (!pool_member) {
		vty_out(vty, "%% no such MGCP client configured ('%s')%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* Make sure that there are no ongoing calls */
	if (pool_member->refcount > 0) {
		vty_out(vty, "%% MGCP client (MGW %s) is still serving ongoing calls -- can't reconnect it now!%s",
			mgcp_client_pool_member_name(pool_member), VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (mgcp_client_pool_member_reinit_client(pool_member) < 0) {
		LOGP(DLMGCP, LOGL_ERROR, "(manual) MGW %s connect failed at (%s:%u)\n",
		     mgcp_client_pool_member_name(pool_member), pool_member->conf.remote_addr,
		     pool_member->conf.remote_port);
		vty_out(vty, "%% MGCP client (MGW %s) initalization failed ('%s')%s",
			mgcp_client_pool_member_name(pool_member), argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN_ATTR(mgw_block, mgw_block_cmd,
	   "mgw <0-255> block",
	   MGW_STR "reference number\n" "block MGCP client so that it won't be used for new calls\n", CMD_ATTR_IMMEDIATE)
{
	int nr = atoi(argv[0]);
	struct mgcp_client_pool_member *pool_member = NULL;

	pool_member = mgcp_client_pool_find_member_by_nr(global_mgcp_client_pool, nr);
	if (!pool_member) {
		vty_out(vty, "%% no such MGCP client configured ('%s')%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	pool_member->blocked = true;
	return CMD_SUCCESS;
}

DEFUN_ATTR(mgw_unblock, mgw_unblock_cmd,
	   "mgw <0-255> unblock",
	   MGW_STR "reference number\n" "unblock MGCP client so that it will be available for new calls\n", CMD_ATTR_IMMEDIATE)
{
	int nr = atoi(argv[0]);
	struct mgcp_client_pool_member *pool_member = NULL;

	pool_member = mgcp_client_pool_find_member_by_nr(global_mgcp_client_pool, nr);
	if (!pool_member) {
		vty_out(vty, "%% no such MGCP client configured ('%s')%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	pool_member->blocked = false;
	return CMD_SUCCESS;
}

DEFUN(mgw_show, mgw_show_cmd, "show mgw-pool", SHOW_STR "Display information about the MGW-Pool\n")
{
	vty_out(vty, "%% MGW-Pool:%s", VTY_NEWLINE);
	struct mgcp_client_pool_member *pool_member;

	if (llist_empty(&global_mgcp_client_pool->member_list) && global_mgcp_client_pool->mgcp_client_single) {
		vty_out(vty, "%%  (pool is empty, single MGCP client will be used)%s", VTY_NEWLINE);
		return CMD_SUCCESS;
	} else if (llist_empty(&global_mgcp_client_pool->member_list)) {
		vty_out(vty, "%%  (pool is empty)%s", VTY_NEWLINE);
		return CMD_SUCCESS;
	}

	llist_for_each_entry(pool_member, &global_mgcp_client_pool->member_list, list) {
		const struct mgcp_client *cli = pool_member->client;
		vty_out(vty, "%%  MGW %s%s", mgcp_client_pool_member_name(pool_member), VTY_NEWLINE);
		vty_out(vty, "%%   MGCP link:     %s,%s%s",
			cli && cli->iofd ? "connected" : "disconnected",
			cli && cli->conn_up ?
				((cli->actual.keepalive.timeout_sec > 0) ? "UP" : "MAYBE") :
				"DOWN",
			VTY_NEWLINE);
		vty_out(vty, "%%   service:       %s%s", pool_member->blocked ? "blocked" : "unblocked", VTY_NEWLINE);
		vty_out(vty, "%%   ongoing calls: %u%s", pool_member->refcount, VTY_NEWLINE);
	}
	return CMD_SUCCESS;
}

/*! Set up MGCP client VTY (pooled)
 *  (called once at startup by the application process).
 *  \param[in] parent_node identifier of the parent node on which the mgw node appears.
 *  \param[in] mgw_node identifier that should be used with the newly installed MGW node.
 *  \param[in] indent indentation string to match the indentation in the VTY config.
	       If NULL, it must be passed explicitly each time mgcp_client_pool_config_write() is called.
 *  \param[in] pool user provided memory to store the configured MGCP client (MGW) pool. */
void mgcp_client_pool_vty_init(int parent_node, int mgw_node, const char *indent, struct mgcp_client_pool *pool)
{
	/* A pool must be allocated before this function can be called */
	OSMO_ASSERT(pool);

	/* Never allow this function to be called twice on the same pool */
	OSMO_ASSERT(!pool->vty_node);

	if (indent) {
		pool->vty_indent = talloc_strdup(pool, indent);
		OSMO_ASSERT(pool->vty_indent);
	}
	pool->vty_node = talloc_zero(pool, struct cmd_node);
	OSMO_ASSERT(pool->vty_node);
	pool->vty_node->node = mgw_node;
	pool->vty_node->vtysh = 1;
	pool->vty_node->prompt = talloc_strdup(pool->vty_node, "%s(config-mgw)# ");

	install_lib_element(parent_node, &cfg_mgw_cmd);
	install_lib_element(parent_node, &cfg_no_mgw_cmd);

	/* Note: config_write_pool is deprecated and user is expected to
	 * manually call mgcp_client_pool_config_write() when printing the VTY
	 * config */
	install_node(pool->vty_node, config_write_pool);
	vty_init_common(pool, mgw_node);
	install_lib_element(mgw_node, &cfg_mgw_local_ip_cmd);
	install_lib_element(mgw_node, &cfg_mgw_local_port_cmd);
	install_lib_element(mgw_node, &cfg_mgw_remote_ip_cmd);
	install_lib_element(mgw_node, &cfg_mgw_remote_port_cmd);
	install_lib_element(mgw_node, &cfg_mgw_rtp_bts_base_port_cmd);
	install_lib_element(mgw_node, &cfg_mgw_endpoint_domain_name_cmd);
	install_lib_element(mgw_node, &cfg_mgw_reset_ep_name_cmd);
	install_lib_element(mgw_node, &cfg_mgw_no_reset_ep_name_cmd);

	install_element(mgw_node, &cfg_description_cmd);

	install_lib_element(ENABLE_NODE, &mgw_reconnect_cmd);
	install_lib_element(ENABLE_NODE, &mgw_block_cmd);
	install_lib_element(ENABLE_NODE, &mgw_unblock_cmd);

	install_lib_element_ve(&mgw_show_cmd);

	global_mgcp_client_pool = pool;
}

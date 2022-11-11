/* A Media Gateway Control Protocol Media Gateway: RFC 3435 */
/* The main method to drive it as a standalone process      */

/*
 * (C) 2009-2011 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009-2011 by On-Waves
 * (C) 2017 by sysmocom - s.f.m.c. GmbH, Author: Philipp Maier
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

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>
#include <osmocom/core/msgb.h>
#include <osmocom/abis/e1_input.h>

#include <sys/socket.h>

#include <osmocom/mgcp/mgcp.h>
#include <osmocom/mgcp/mgcp_protocol.h>
#include <osmocom/mgcp/vty.h>
#include <osmocom/mgcp/debug.h>
#include <osmocom/mgcp/mgcp_endp.h>
#include <osmocom/mgcp/mgcp_trunk.h>

#include <osmocom/core/application.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/select.h>
#include <osmocom/core/stats.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/socket.h>
#include <osmocom/ctrl/control_if.h>
#include <osmocom/ctrl/control_vty.h>

#include <osmocom/vty/telnet_interface.h>
#include <osmocom/vty/logging.h>
#include <osmocom/vty/ports.h>
#include <osmocom/vty/command.h>
#include <osmocom/vty/stats.h>
#include <osmocom/vty/misc.h>
#include <osmocom/vty/cpu_sched_vty.h>

#include <osmocom/abis/abis.h>

#include "../../bscconfig.h"

#define _GNU_SOURCE
#include <getopt.h>

/* can be changed once libosmocore 1.4.0 is released */
#ifndef OSMO_CTRL_PORT_MGW
#define OSMO_CTRL_PORT_MGW 4267
#endif

/* FIXME: Make use of the rtp proxy code */

static struct mgcp_config *cfg;
static struct mgcp_trunk *reset_trunk;
static int reset_endpoints = 0;
static int daemonize = 0;

const char *osmomgw_copyright =
	"Copyright (C) 2009-2010 Holger Freyther and On-Waves\r\n"
	"Copyright (C) 2017-2022 by sysmocom s.f.m.c. GmbH\r\n"
	"Contributions by Pablo Neira Ayuso, Jacob Erlbeck, Neels Hofmeyr\r\n"
	"Philipp Maier\r\n\r\n"
	"License AGPLv3+: GNU AGPL version 3 or later <http://gnu.org/licenses/agpl-3.0.html>\r\n"
	"This is free software: you are free to change and redistribute it.\r\n"
	"There is NO WARRANTY, to the extent permitted by law.\r\n";

static char *config_file = "osmo-mgw.cfg";

/* used by msgb and mgcp */
void *tall_mgw_ctx = NULL;

static void print_help(void)
{
	printf("Some useful options:\n");
	printf(" -h --help is printing this text.\n");
	printf(" -c --config-file filename The config file to use.\n");
	printf(" -s --disable-color\n");
	printf(" -D --daemonize Fork the process into a background daemon\n");
	printf(" -V --version Print the version number\n");

	printf("\nVTY reference generation:\n");
	printf("    --vty-ref-mode MODE		VTY reference generation mode (e.g. 'expert').\n");
	printf("    --vty-ref-xml		Generate the VTY reference XML output and exit.\n");
}

static void handle_long_options(const char *prog_name, const int long_option)
{
	static int vty_ref_mode = VTY_REF_GEN_MODE_DEFAULT;

	switch (long_option) {
	case 1:
		vty_ref_mode = get_string_value(vty_ref_gen_mode_names, optarg);
		if (vty_ref_mode < 0) {
			fprintf(stderr, "%s: Unknown VTY reference generation "
				"mode '%s'\n", prog_name, optarg);
			exit(2);
		}
		break;
	case 2:
		fprintf(stderr, "Generating the VTY reference in mode '%s' (%s)\n",
			get_value_string(vty_ref_gen_mode_names, vty_ref_mode),
			get_value_string(vty_ref_gen_mode_desc, vty_ref_mode));
		vty_dump_xml_ref_mode(stdout, (enum vty_ref_gen_mode) vty_ref_mode);
		exit(0);
	default:
		fprintf(stderr, "%s: error parsing cmdline options\n", prog_name);
		exit(2);
	}
}

static void handle_options(int argc, char **argv)
{
	while (1) {
		int option_index = 0, c;
		static int long_option = 0;
		static struct option long_options[] = {
			{"help", 0, 0, 'h'},
			{"config-file", 1, 0, 'c'},
			{"daemonize", 0, 0, 'D'},
			{"version", 0, 0, 'V'},
			{"disable-color", 0, 0, 's'},
			{"vty-ref-mode", 1, &long_option, 1},
			{"vty-ref-xml", 0, &long_option, 2},
			{0, 0, 0, 0},
		};

		c = getopt_long(argc, argv, "hc:sVD", long_options, &option_index);

		if (c == -1)
			break;

		switch(c) {
		case 'h':
			print_help();
			exit(0);
			break;
		case 0:
			handle_long_options(argv[0], long_option);
			break;
		case 'c':
			config_file = talloc_strdup(tall_mgw_ctx, optarg);
			break;
		case 's':
			log_set_use_color(osmo_stderr_target, 0);
			break;
		case 'V':
			print_version(1);
			exit(0);
			break;
		case 'D':
			daemonize = 1;
			break;
		default:
			/* ignore */
			break;
		};
	}
	if (argc > optind) {
		fprintf(stderr, "Unsupported positional arguments on command line\n");
		exit(2);
	}
}

/* Callback function to be called when the RSIP ("Reset in Progress") mgcp
 * command is received */
static int mgcp_rsip_cb(struct mgcp_trunk *trunk)
{
	/* Set flag so that, when read_call_agent() is called next time
	 * the reset can progress */
	reset_endpoints = 1;

	reset_trunk = trunk;

	return 0;
}

static int read_call_agent(struct osmo_fd *fd, unsigned int what)
{
	struct osmo_sockaddr addr;
	socklen_t slen = sizeof(addr);
	struct msgb *msg;
	struct msgb *resp;
	int i;

	msg = (struct msgb *) fd->data;

	/* read one less so we can use it as a \0 */
	int rc = recvfrom(cfg->gw_fd.bfd.fd, msg->data, msg->data_len - 1, 0,
		(struct sockaddr *) &addr, &slen);
	if (rc < 0) {
		perror("Gateway failed to read");
		return -1;
	} else if (slen > sizeof(addr)) {
		fprintf(stderr, "Gateway received message from outerspace: %zu %zu\n",
			(size_t) slen, sizeof(addr));
		return -1;
	}

	/* handle message now */
	msg->l2h = msgb_put(msg, rc);
	resp = mgcp_handle_message(cfg, msg);
	msgb_reset(msg);

	if (resp) {
		sendto(cfg->gw_fd.bfd.fd, resp->l2h, msgb_l2len(resp), 0, &addr.u.sa, sizeof(addr));
		msgb_free(resp);
	}

	/* reset endpoints */
	if (reset_endpoints) {
		LOGP(DLMGCP, LOGL_NOTICE,
		     "Asked to reset endpoints: %u/%d\n",
		     reset_trunk->trunk_nr, reset_trunk->trunk_type);

		/* reset flag */
		reset_endpoints = 0;

		/* Walk over all endpoints and trigger a release, this will release all
		 * endpoints, possible open connections are forcefully dropped */
		for (i = 0; i < reset_trunk->number_endpoints; ++i)
			mgcp_endp_release(reset_trunk->endpoints[i]);
	}

	return 0;
}

int mgcp_vty_is_config_node(struct vty *vty, int node)
{
	switch (node) {
	case CONFIG_NODE:
		return 0;

	default:
		return 1;
	}
}

int mgcp_vty_go_parent(struct vty *vty)
{
	switch (vty->node) {
	case TRUNK_NODE:
		vty->node = MGCP_NODE;
		vty->index = NULL;
		break;
	case MGCP_NODE:
	default:
		if (mgcp_vty_is_config_node(vty, vty->node))
			vty->node = CONFIG_NODE;
		else
			vty->node = ENABLE_NODE;

		vty->index = NULL;
	}

	return vty->node;
}


static struct vty_app_info vty_info = {
	.name 		= "OsmoMGW",
	.version	= PACKAGE_VERSION,
	.go_parent_cb	= mgcp_vty_go_parent,
	.is_config_node	= mgcp_vty_is_config_node,
};

static const struct log_info_cat log_categories[] = {
	/* DLMGCP is provided by the MGCP library */
	[DRTP] = {
		  .name = "DRTP",
		  .description = "RTP stream handling",
		  .color = "\033[1;30m",
		  .enabled = 1,
		  .loglevel = LOGL_NOTICE,
	},
	[DE1] = {
		  .name = "DE1",
		  .description = "E1 line handling",
		  .color = "\033[1;31m",
		  .enabled = 1,
		  .loglevel = LOGL_NOTICE,
	},
	[DOSMUX] = {
		  .name = "DOSMUX",
		  .description = "Osmux (Osmocom RTP multiplexing)",
		  .color = "\033[1;32m",
		  .enabled = 1,
		  .loglevel = LOGL_NOTICE,
	},
};

const struct log_info log_info = {
	.cat = log_categories,
	.num_cat = ARRAY_SIZE(log_categories),
};

int main(int argc, char **argv)
{
	unsigned int flags;
	int rc;

	tall_mgw_ctx = talloc_named_const(NULL, 1, "mgcp-callagent");
	vty_info.tall_ctx = tall_mgw_ctx;

	msgb_talloc_ctx_init(tall_mgw_ctx, 0);

	osmo_init_ignore_signals();
	osmo_init_logging2(tall_mgw_ctx, &log_info);
	libosmo_abis_init(tall_mgw_ctx);

	cfg = mgcp_config_alloc();
	if (!cfg)
		return -1;

	vty_info.copyright = osmomgw_copyright;
	vty_info.usr_attr_desc[MGW_CMD_ATTR_NEWCONN] = \
		"This command applies when a new connection is created";
	vty_info.usr_attr_letters[MGW_CMD_ATTR_NEWCONN] = 'n';

	vty_init(&vty_info);
	logging_vty_add_cmds();
	osmo_talloc_vty_add_cmds();
	osmo_stats_vty_add_cmds();
	mgcp_vty_init();
	ctrl_vty_init(cfg);
	e1inp_vty_init();
	osmo_cpu_sched_vty_init(tall_mgw_ctx);

	handle_options(argc, argv);

	rate_ctr_init(tall_mgw_ctx);
	osmo_stats_init(tall_mgw_ctx);

	rc = mgcp_parse_config(config_file, cfg, MGCP_BSC);
	if (rc < 0)
		return rc;

	/* start telnet after reading config for vty_get_bind_addr() */
	rc = telnet_init_dynif(tall_mgw_ctx, NULL,
			       vty_get_bind_addr(), OSMO_VTY_PORT_MGW);
	if (rc < 0)
		return rc;

	cfg->ctrl = ctrl_interface_setup(cfg, OSMO_CTRL_PORT_MGW, NULL);
	if (!cfg->ctrl) {
		fprintf(stderr, "Failed to init the control interface on %s:%u. Exiting\n",
			ctrl_vty_get_bind_addr(), OSMO_CTRL_PORT_MGW);
	}

	/* Set the reset callback function. This functions is called when the
	 * mgcp-command "RSIP" (Reset in Progress) is received */
	cfg->reset_cb = mgcp_rsip_cb;

	/* we need to bind a socket */
	flags = OSMO_SOCK_F_BIND;
	if (strlen(cfg->call_agent_addr))
		flags |= OSMO_SOCK_F_CONNECT;

	rc = osmo_sock_init2_ofd(&cfg->gw_fd.bfd, AF_UNSPEC, SOCK_DGRAM, IPPROTO_UDP,
				cfg->source_addr, cfg->source_port,
				cfg->call_agent_addr, strlen(cfg->call_agent_addr) ? 2727 : 0, flags);
	if (rc < 0) {
		perror("Gateway failed to bind");
		return -1;
	}

	cfg->gw_fd.bfd.cb = read_call_agent;
	cfg->gw_fd.bfd.data = msgb_alloc(4096, "mgcp-msg");
	if (!cfg->gw_fd.bfd.data) {
		fprintf(stderr, "Gateway memory error.\n");
		return -1;
	}

	LOGP(DLMGCP, LOGL_NOTICE, "Configured for MGCP, listen on %s:%u\n",
	     cfg->source_addr, cfg->source_port);

	/* initialisation */
	srand(time(NULL));

	if (daemonize) {
		rc = osmo_daemonize();
		if (rc < 0) {
			perror("Error during daemonize");
			exit(1);
		}
	}

	/* main loop */
	while (1) {
		osmo_select_main(0);
	}


	return 0;
}

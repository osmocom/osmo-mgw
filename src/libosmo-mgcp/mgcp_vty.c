/* A Media Gateway Control Protocol Media Gateway: RFC 3435 */
/* The protocol implementation */

/*
 * (C) 2009-2014 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009-2011 by On-Waves
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

#include <osmocom/core/talloc.h>
#include <osmocom/core/sockaddr_str.h>
#include <osmocom/vty/misc.h>
#include <osmocom/mgcp/mgcp.h>
#include <osmocom/mgcp/mgcp_common.h>
#include <osmocom/mgcp/osmux.h>
#include <osmocom/mgcp/mgcp_protocol.h>
#include <osmocom/mgcp/vty.h>
#include <osmocom/mgcp/mgcp_conn.h>
#include <osmocom/mgcp/mgcp_endp.h>
#include <osmocom/mgcp/mgcp_trunk.h>

#include <string.h>
#include <inttypes.h>
#include <limits.h>

#define RTCP_OMIT_STR "Drop RTCP packets in both directions\n"
#define RTP_PATCH_STR "Modify RTP packet header in both directions\n"
#define RTP_KEEPALIVE_STR "Send dummy UDP packet to net RTP destination\n"
#define RTP_TS101318_RFC5993_CONV_STR "Convert GSM-HR from TS101318 to RFC5993 and vice versa\n"

#define X(x) (1 << x)

static struct mgcp_config *g_cfg = NULL;

struct cmd_node mgcp_node = {
	MGCP_NODE,
	"%s(config-mgcp)# ",
	1,
};

struct cmd_node trunk_node = {
	TRUNK_NODE,
	"%s(config-mgcp-trunk)# ",
	1,
};

static int config_write_mgcp(struct vty *vty)
{
	struct mgcp_trunk *trunk = mgcp_trunk_by_num(g_cfg, MGCP_TRUNK_VIRTUAL, MGCP_VIRT_TRUNK_ID);
	OSMO_ASSERT(trunk);

	vty_out(vty, "mgcp%s", VTY_NEWLINE);
	vty_out(vty, " domain %s%s", g_cfg->domain, VTY_NEWLINE);
	if (g_cfg->local_ip)
		vty_out(vty, "  local ip %s%s", g_cfg->local_ip, VTY_NEWLINE);
	vty_out(vty, " bind ip %s%s", g_cfg->source_addr, VTY_NEWLINE);
	vty_out(vty, " bind port %u%s", g_cfg->source_port, VTY_NEWLINE);
	vty_out(vty, " rtp port-range %u %u%s",
		g_cfg->net_ports.range_start, g_cfg->net_ports.range_end,
		VTY_NEWLINE);
	if (g_cfg->net_ports.bind_addr_v4)
		vty_out(vty, " rtp bind-ip %s%s",
			g_cfg->net_ports.bind_addr_v4, VTY_NEWLINE);
	if (g_cfg->net_ports.bind_addr_v6)
		vty_out(vty, " rtp bind-ip-v6 %s%s",
			g_cfg->net_ports.bind_addr_v6, VTY_NEWLINE);
	if (g_cfg->net_ports.bind_addr_probe)
		vty_out(vty, " rtp ip-probing%s", VTY_NEWLINE);
	else
		vty_out(vty, " no rtp ip-probing%s", VTY_NEWLINE);
	vty_out(vty, " rtp ip-dscp %d%s", g_cfg->endp_dscp, VTY_NEWLINE);
	if (trunk->keepalive_interval == MGCP_KEEPALIVE_ONCE)
		vty_out(vty, " rtp keep-alive once%s", VTY_NEWLINE);
	else if (trunk->keepalive_interval)
		vty_out(vty, " rtp keep-alive %d%s",
			trunk->keepalive_interval, VTY_NEWLINE);
	else
		vty_out(vty, " no rtp keep-alive%s", VTY_NEWLINE);

	if (trunk->omit_rtcp)
		vty_out(vty, " rtcp-omit%s", VTY_NEWLINE);
	else
		vty_out(vty, " no rtcp-omit%s", VTY_NEWLINE);
	if (trunk->force_constant_ssrc
	    || trunk->force_aligned_timing
	    || trunk->rfc5993_hr_convert) {
		vty_out(vty, " %srtp-patch ssrc%s",
			trunk->force_constant_ssrc ? "" : "no ",
			VTY_NEWLINE);
		vty_out(vty, " %srtp-patch timestamp%s",
			trunk->force_aligned_timing ? "" : "no ",
			VTY_NEWLINE);
		vty_out(vty, " %srtp-patch rfc5993hr%s",
			trunk->rfc5993_hr_convert ? "" : "no ",
			VTY_NEWLINE);
	} else
		vty_out(vty, " no rtp-patch%s", VTY_NEWLINE);
	if (trunk->audio_fmtp_extra)
		vty_out(vty, " sdp audio fmtp-extra %s%s",
			trunk->audio_fmtp_extra, VTY_NEWLINE);
	vty_out(vty, " %ssdp audio-payload send-ptime%s",
		trunk->audio_send_ptime ? "" : "no ", VTY_NEWLINE);
	vty_out(vty, " %ssdp audio-payload send-name%s",
		trunk->audio_send_name ? "" : "no ", VTY_NEWLINE);
	vty_out(vty, " number endpoints %u%s",
		trunk->v.vty_number_endpoints, VTY_NEWLINE);
	vty_out(vty, " %sallow-transcoding%s",
		trunk->no_audio_transcoding ? "no " : "", VTY_NEWLINE);
	if (g_cfg->call_agent_addr)
		vty_out(vty, " call-agent ip %s%s", g_cfg->call_agent_addr,
			VTY_NEWLINE);
	if (g_cfg->force_ptime > 0)
		vty_out(vty, " rtp force-ptime %d%s", g_cfg->force_ptime,
			VTY_NEWLINE);

	switch (g_cfg->osmux) {
	case OSMUX_USAGE_ON:
		vty_out(vty, " osmux on%s", VTY_NEWLINE);
		break;
	case OSMUX_USAGE_ONLY:
		vty_out(vty, " osmux only%s", VTY_NEWLINE);
		break;
	case OSMUX_USAGE_OFF:
	default:
		vty_out(vty, " osmux off%s", VTY_NEWLINE);
		break;
	}
	if (g_cfg->osmux) {
		vty_out(vty, " osmux bind-ip %s%s",
			g_cfg->osmux_addr, VTY_NEWLINE);
		vty_out(vty, " osmux batch-factor %d%s",
			g_cfg->osmux_batch, VTY_NEWLINE);
		vty_out(vty, " osmux batch-size %u%s",
			g_cfg->osmux_batch_size, VTY_NEWLINE);
		vty_out(vty, " osmux port %u%s",
			g_cfg->osmux_port, VTY_NEWLINE);
		vty_out(vty, " osmux dummy %s%s",
			g_cfg->osmux_dummy ? "on" : "off", VTY_NEWLINE);
	}

	if (g_cfg->conn_timeout)
		vty_out(vty, " conn-timeout %u%s", g_cfg->conn_timeout, VTY_NEWLINE);

	return CMD_SUCCESS;
}

static void dump_rtp_end(struct vty *vty, struct mgcp_conn_rtp *conn)
{
	struct mgcp_rtp_state *state = &conn->state;
	struct mgcp_rtp_end *end = &conn->end;
	struct mgcp_rtp_codec *codec = end->codec;
	struct rate_ctr *tx_packets, *tx_bytes;
	struct rate_ctr *rx_packets, *rx_bytes;
	struct rate_ctr *dropped_packets;

	tx_packets = &conn->rate_ctr_group->ctr[RTP_PACKETS_TX_CTR];
	tx_bytes = &conn->rate_ctr_group->ctr[RTP_OCTETS_TX_CTR];
	rx_packets = &conn->rate_ctr_group->ctr[RTP_PACKETS_RX_CTR];
	rx_bytes = &conn->rate_ctr_group->ctr[RTP_OCTETS_RX_CTR];
	dropped_packets = &conn->rate_ctr_group->ctr[RTP_DROPPED_PACKETS_CTR];

	vty_out(vty,
		"   Packets Sent: %" PRIu64 " (%" PRIu64 " bytes total)%s"
		"   Packets Received: %" PRIu64 " (%" PRIu64 " bytes total)%s"
		"   Timestamp Errs: %" PRIu64 "->%" PRIu64 "%s"
		"   Dropped Packets: %" PRIu64 "%s"
		"   Payload Type: %d Rate: %u Channels: %d %s"
		"   Frame Duration: %u Frame Denominator: %u%s"
		"   FPP: %d Packet Duration: %u%s"
		"   FMTP-Extra: %s Audio-Name: %s Sub-Type: %s%s"
		"   Output-Enabled: %d Force-PTIME: %d%s",
		tx_packets->current, tx_bytes->current, VTY_NEWLINE,
		rx_packets->current, rx_bytes->current, VTY_NEWLINE,
		state->in_stream.err_ts_ctr->current,
		state->out_stream.err_ts_ctr->current,
	        VTY_NEWLINE,
		dropped_packets->current, VTY_NEWLINE,
		codec->payload_type, codec->rate, codec->channels, VTY_NEWLINE,
		codec->frame_duration_num, codec->frame_duration_den,
		VTY_NEWLINE, end->frames_per_packet, end->packet_duration_ms,
		VTY_NEWLINE, end->fmtp_extra, codec->audio_name,
		codec->subtype_name, VTY_NEWLINE, end->output_enabled,
		end->force_output_ptime, VTY_NEWLINE);
}

static void dump_endpoint(struct vty *vty, struct mgcp_endpoint *endp,
			  int trunk_nr, enum mgcp_trunk_type trunk_type, int show_stats)
{
	struct mgcp_conn *conn;

	vty_out(vty, "%s trunk %d endpoint %s:%s",
		trunk_type == MGCP_TRUNK_VIRTUAL ? "Virtual" : "E1", trunk_nr, endp->name, VTY_NEWLINE);
	vty_out(vty, "   Availability: %s%s",
		mgcp_endp_avail(endp) ? "available" : "not in service", VTY_NEWLINE);

	if (llist_empty(&endp->conns)) {
		vty_out(vty, "   No active connections%s", VTY_NEWLINE);
		return;
	}

	llist_for_each_entry(conn, &endp->conns, entry) {
		vty_out(vty, "   CONN: %s%s", mgcp_conn_dump(conn), VTY_NEWLINE);

		if (show_stats) {
			if (endp->cfg->conn_timeout) {
				struct timeval remaining;
				osmo_timer_remaining(&conn->watchdog, NULL, &remaining);
				vty_out(vty, "   Currently remaining timeout (seconds): %d.%06d%s",
					(int)remaining.tv_sec, (int)remaining.tv_usec, VTY_NEWLINE);
			}

			/* FIXME: Also add verbosity for other
			 * connection types (E1) as soon as
			 * the implementation is available */
			if (conn->type == MGCP_CONN_TYPE_RTP) {
				dump_rtp_end(vty, &conn->u.rtp);
			}
		}
	}
}

static void dump_ratectr_global(struct vty *vty, struct mgcp_ratectr_global *ratectr)
{
	vty_out(vty, "%s", VTY_NEWLINE);
	vty_out(vty, "Rate counters (global):%s", VTY_NEWLINE);

	if (ratectr->mgcp_general_ctr_group) {
		vty_out(vty, "   %s:%s",
			ratectr->mgcp_general_ctr_group->desc->
			group_description, VTY_NEWLINE);
		vty_out_rate_ctr_group_fmt(vty,
					   "   %25n: %10c (%S/s %M/m %H/h %D/d) %d",
					   ratectr->mgcp_general_ctr_group);
	}
}

static void dump_ratectr_trunk(struct vty *vty, struct mgcp_trunk *trunk)
{
	struct mgcp_ratectr_trunk *ratectr = &trunk->ratectr;

	vty_out(vty, "%s", VTY_NEWLINE);
	vty_out(vty, "Rate counters (trunk):%s", VTY_NEWLINE);

	if (ratectr->mgcp_crcx_ctr_group) {
		vty_out(vty, "   %s:%s",
			ratectr->mgcp_crcx_ctr_group->desc->group_description,
			VTY_NEWLINE);
		vty_out_rate_ctr_group_fmt(vty,
					   "   %25n: %10c (%S/s %M/m %H/h %D/d) %d",
					   ratectr->mgcp_crcx_ctr_group);
	}
	if (ratectr->mgcp_dlcx_ctr_group) {
		vty_out(vty, "   %s:%s",
			ratectr->mgcp_dlcx_ctr_group->desc->group_description,
			VTY_NEWLINE);
		vty_out_rate_ctr_group_fmt(vty,
					   "   %25n: %10c (%S/s %M/m %H/h %D/d) %d",
					   ratectr->mgcp_dlcx_ctr_group);
	}
	if (ratectr->mgcp_mdcx_ctr_group) {
		vty_out(vty, "   %s:%s",
			ratectr->mgcp_mdcx_ctr_group->desc->group_description,
			VTY_NEWLINE);
		vty_out_rate_ctr_group_fmt(vty,
					   "   %25n: %10c (%S/s %M/m %H/h %D/d) %d",
					   ratectr->mgcp_mdcx_ctr_group);
	}
	if (ratectr->all_rtp_conn_stats) {
		vty_out(vty, "   %s:%s",
			ratectr->all_rtp_conn_stats->desc->group_description,
			VTY_NEWLINE);
		vty_out_rate_ctr_group_fmt(vty,
					   "   %25n: %10c (%S/s %M/m %H/h %D/d) %d",
					   ratectr->all_rtp_conn_stats);
	}

	if (ratectr->e1_stats && trunk->trunk_type == MGCP_TRUNK_E1) {
		vty_out(vty, "   %s:%s",
			ratectr->e1_stats->desc->group_description,
			VTY_NEWLINE);
		vty_out_rate_ctr_group_fmt(vty,
					   "   %25n: %10c (%S/s %M/m %H/h %D/d) %d",
					   ratectr->e1_stats);
	}
}


static void dump_trunk(struct vty *vty, struct mgcp_trunk *trunk, int show_stats)
{
	int i;

	vty_out(vty, "%s trunk %d with %d endpoints:%s",
		trunk->trunk_type == MGCP_TRUNK_VIRTUAL ? "Virtual" : "E1",
		trunk->trunk_nr, trunk->number_endpoints, VTY_NEWLINE);

	if (!trunk->endpoints) {
		vty_out(vty, "No endpoints allocated yet.%s", VTY_NEWLINE);
		return;
	}

	for (i = 0; i < trunk->number_endpoints; ++i) {
		struct mgcp_endpoint *endp = trunk->endpoints[i];
		dump_endpoint(vty, endp, trunk->trunk_nr, trunk->trunk_type,
			      show_stats);
		if (i < trunk->number_endpoints - 1)
			vty_out(vty, "%s", VTY_NEWLINE);
	}

	if (show_stats)
		dump_ratectr_trunk(vty, trunk);
}

#define SHOW_MGCP_STR "Display information about the MGCP Media Gateway\n"

DEFUN(show_mcgp, show_mgcp_cmd,
      "show mgcp [stats]",
      SHOW_STR
      SHOW_MGCP_STR
      "Include Statistics\n")
{
	struct mgcp_trunk *trunk;
	int show_stats = argc >= 1;

	llist_for_each_entry(trunk, &g_cfg->trunks, entry)
		dump_trunk(vty, trunk, show_stats);

	if (g_cfg->osmux)
		vty_out(vty, "Osmux used CID: %d%s", osmux_cid_pool_count_used(),
			VTY_NEWLINE);

	if (show_stats)
		dump_ratectr_global(vty, &g_cfg->ratectr);

	return CMD_SUCCESS;
}

static void
dump_mgcp_endpoint(struct vty *vty, struct mgcp_trunk *trunk, const char *epname)
{
	struct mgcp_endpoint *endp;

	if (trunk) {
		/* If a trunk is given, search on that specific trunk only */
		endp = mgcp_endp_by_name_trunk(NULL, epname, trunk);
		if (!endp) {
			vty_out(vty, "endpoint %s not configured on trunk %d%s", epname, trunk->trunk_nr, VTY_NEWLINE);
			return;
		}
	} else {
		/* If no trunk is given, search on all possible trunks */
		endp = mgcp_endp_by_name(NULL, epname, g_cfg);
		if (!endp) {
			vty_out(vty, "endpoint %s not configured%s", epname, VTY_NEWLINE);
			return;
		}
	}

	trunk = endp->trunk;
	dump_endpoint(vty, endp, trunk->trunk_nr, trunk->trunk_type, true);
}

DEFUN(show_mcgp_endpoint, show_mgcp_endpoint_cmd,
      "show mgcp endpoint NAME",
      SHOW_STR
      SHOW_MGCP_STR
      "Display information about an endpoint\n" "The name of the endpoint\n")
{
	dump_mgcp_endpoint(vty, NULL, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(show_mcgp_trunk_endpoint, show_mgcp_trunk_endpoint_cmd,
      "show mgcp trunk <0-64> endpoint NAME",
      SHOW_STR
      SHOW_MGCP_STR
      "Display information about a trunk\n" "Trunk number\n"
      "Display information about an endpoint\n" "The name of the endpoint\n")
{
	struct mgcp_trunk *trunk;
	int trunkidx = atoi(argv[0]);

	trunk = mgcp_trunk_by_num(g_cfg, MGCP_TRUNK_E1, trunkidx);
	if (!trunk) {
		vty_out(vty, "trunk %d not found%s", trunkidx, VTY_NEWLINE);
		return CMD_WARNING;
	}

	dump_mgcp_endpoint(vty, trunk, argv[1]);
	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp, cfg_mgcp_cmd, "mgcp", "Configure the MGCP")
{
	vty->node = MGCP_NODE;
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_mgcp_local_ip,
	      cfg_mgcp_local_ip_cmd,
	      X(MGW_CMD_ATTR_NEWCONN),
	      "local ip " VTY_IPV46_CMD,
	      "Local options for the SDP record\n"
	      IP_STR
	      "IPv4 Address to use in SDP record\n"
	      "IPv6 Address to use in SDP record\n")
{
	osmo_talloc_replace_string(g_cfg, &g_cfg->local_ip, argv[0]);
	return CMD_SUCCESS;
}

#define BIND_STR "Listen/Bind related socket option\n"
DEFUN(cfg_mgcp_bind_ip,
      cfg_mgcp_bind_ip_cmd,
      "bind ip " VTY_IPV46_CMD,
      BIND_STR IP_STR
      "IPv4 Address to bind to\n"
      "IPv6 Address to bind to\n")
{
	osmo_talloc_replace_string(g_cfg, &g_cfg->source_addr, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp_bind_port,
      cfg_mgcp_bind_port_cmd,
      "bind port <0-65534>",
      BIND_STR "Port information\n" "UDP port to listen for MGCP messages\n")
{
	unsigned int port = atoi(argv[0]);
	g_cfg->source_port = port;
	return CMD_SUCCESS;
}

DEFUN_DEPRECATED(cfg_mgcp_bind_early,
		 cfg_mgcp_bind_early_cmd,
		 "bind early (0|1)",
		 BIND_STR
		 "Bind local ports on start up\n" "Bind on demand\n" "Bind on startup\n")
{
	return CMD_SUCCESS;
}

#define RTP_STR "RTP configuration\n"
#define UDP_PORT_STR "UDP Port number\n"
#define NET_START_STR "First UDP port allocated\n"
#define RANGE_START_STR "Start of the range of ports\n"
#define RANGE_END_STR "End of the range of ports\n"

DEFUN(cfg_mgcp_rtp_port_range,
      cfg_mgcp_rtp_port_range_cmd,
      "rtp port-range <1024-65534> <1025-65535>",
      RTP_STR "Range of ports to use for the NET side\n"
      RANGE_START_STR RANGE_END_STR)
{
	int start;
	int end;

	start = atoi(argv[0]);
	end = atoi(argv[1]);

	if (end < start) {
		vty_out(vty, "range end port (%i) must be greater than the range start port (%i)!%s",
			end, start, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (start & 1) {
		vty_out(vty, "range must begin at an even port number, autocorrecting port (%i) to: %i%s",
			start, start & 0xFFFE, VTY_NEWLINE);
		start &= 0xFFFE;
	}

	if ((end & 1) == 0) {
		vty_out(vty, "range must end at an odd port number, autocorrecting port (%i) to: %i%s",
			end, end | 1, VTY_NEWLINE);
		end |= 1;
	}

	g_cfg->net_ports.range_start = start;
	g_cfg->net_ports.range_end = end;
	g_cfg->net_ports.last_port = g_cfg->net_ports.range_start;

	return CMD_SUCCESS;
}
ALIAS_DEPRECATED(cfg_mgcp_rtp_port_range,
		 cfg_mgcp_rtp_net_range_cmd,
		 "rtp net-range <0-65534> <0-65534>",
		 RTP_STR "Range of ports to use for the NET side\n"
		 RANGE_START_STR RANGE_END_STR)

DEFUN_USRATTR(cfg_mgcp_rtp_bind_ip,
	      cfg_mgcp_rtp_bind_ip_cmd,
	      X(MGW_CMD_ATTR_NEWCONN),
	      "rtp bind-ip A.B.C.D",
	      RTP_STR "Bind endpoints facing the Network\n"
	      "IPv4 Address to bind to\n")
{
	osmo_talloc_replace_string(g_cfg, &g_cfg->net_ports.bind_addr_v4, argv[0]);
	return CMD_SUCCESS;
}
ALIAS_DEPRECATED(cfg_mgcp_rtp_bind_ip,
		 cfg_mgcp_rtp_net_bind_ip_cmd,
		 "rtp net-bind-ip A.B.C.D",
		 RTP_STR "Bind endpoints facing the Network\n" "Address to bind to\n")

DEFUN_USRATTR(cfg_mgcp_rtp_no_bind_ip,
	      cfg_mgcp_rtp_no_bind_ip_cmd,
	      X(MGW_CMD_ATTR_NEWCONN),
	      "no rtp bind-ip",
	      NO_STR RTP_STR "Bind endpoints facing the Network\n"
	      "Address to bind to\n")
{
	talloc_free(g_cfg->net_ports.bind_addr_v4);
	g_cfg->net_ports.bind_addr_v4 = NULL;
	return CMD_SUCCESS;
}
ALIAS_DEPRECATED(cfg_mgcp_rtp_no_bind_ip,
		 cfg_mgcp_rtp_no_net_bind_ip_cmd,
		 "no rtp net-bind-ip",
		 NO_STR RTP_STR "Bind endpoints facing the Network\n"
		 "Address to bind to\n")

DEFUN_USRATTR(cfg_mgcp_rtp_bind_ip_v6,
	      cfg_mgcp_rtp_bind_ip_v6_cmd,
	      X(MGW_CMD_ATTR_NEWCONN),
	      "rtp bind-ip-v6 " VTY_IPV6_CMD,
	      RTP_STR "Bind endpoints facing the Network\n"
	      "IPv6 Address to bind to\n")
{
	osmo_talloc_replace_string(g_cfg, &g_cfg->net_ports.bind_addr_v6, argv[0]);
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_mgcp_rtp_no_bind_ip_v6,
	      cfg_mgcp_rtp_no_bind_ip_v6_cmd,
	      X(MGW_CMD_ATTR_NEWCONN),
	      "no rtp bind-ip-v6",
	      NO_STR RTP_STR "Bind endpoints facing the Network\n"
	      "Address to bind to\n")
{
	talloc_free(g_cfg->net_ports.bind_addr_v6);
	g_cfg->net_ports.bind_addr_v6 = NULL;
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_mgcp_rtp_net_bind_ip_probing,
	      cfg_mgcp_rtp_net_bind_ip_probing_cmd,
	      X(MGW_CMD_ATTR_NEWCONN),
	      "rtp ip-probing",
	      RTP_STR "automatic rtp bind ip selection\n")
{
	g_cfg->net_ports.bind_addr_probe = true;
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_mgcp_rtp_no_net_bind_ip_probing,
	      cfg_mgcp_rtp_no_net_bind_ip_probing_cmd,
	      X(MGW_CMD_ATTR_NEWCONN),
	      "no rtp ip-probing",
	      NO_STR RTP_STR "no automatic rtp bind ip selection\n")
{
	g_cfg->net_ports.bind_addr_probe = false;
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_mgcp_rtp_ip_dscp,
	      cfg_mgcp_rtp_ip_dscp_cmd,
	      X(MGW_CMD_ATTR_NEWCONN),
	      "rtp ip-dscp <0-255>",
	      RTP_STR
	      "Apply IP_TOS to the audio stream (including Osmux)\n" "The DSCP value\n")
{
	int dscp = atoi(argv[0]);
	g_cfg->endp_dscp = dscp;
	return CMD_SUCCESS;
}

ALIAS_DEPRECATED(cfg_mgcp_rtp_ip_dscp, cfg_mgcp_rtp_ip_tos_cmd,
		 "rtp ip-tos <0-255>",
		 RTP_STR
		 "Apply IP_TOS to the audio stream\n" "The DSCP value\n")
#define FORCE_PTIME_STR "Force a fixed ptime for packets sent"
DEFUN_USRATTR(cfg_mgcp_rtp_force_ptime,
	      cfg_mgcp_rtp_force_ptime_cmd,
	      X(MGW_CMD_ATTR_NEWCONN),
	      "rtp force-ptime (10|20|40)",
	      RTP_STR FORCE_PTIME_STR
	      "The required ptime (packet duration) in ms\n" "10 ms\n20 ms\n40 ms\n")
{
	g_cfg->force_ptime = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_mgcp_no_rtp_force_ptime,
	      cfg_mgcp_no_rtp_force_ptime_cmd,
	      X(MGW_CMD_ATTR_NEWCONN),
	      "no rtp force-ptime", NO_STR RTP_STR FORCE_PTIME_STR)
{
	g_cfg->force_ptime = 0;
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_mgcp_sdp_fmtp_extra,
	      cfg_mgcp_sdp_fmtp_extra_cmd,
	      X(MGW_CMD_ATTR_NEWCONN),
	      "sdp audio fmtp-extra .NAME",
	      "Add extra fmtp for the SDP file\n" "Audio\n" "Fmtp-extra\n"
	      "Extra Information\n")
{
	struct mgcp_trunk *trunk = mgcp_trunk_by_num(g_cfg, MGCP_TRUNK_VIRTUAL, MGCP_VIRT_TRUNK_ID);
	OSMO_ASSERT(trunk);
	char *txt = argv_concat(argv, argc, 0);
	if (!txt)
		return CMD_WARNING;

	osmo_talloc_replace_string(g_cfg, &trunk->audio_fmtp_extra, txt);
	talloc_free(txt);
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_mgcp_allow_transcoding,
	      cfg_mgcp_allow_transcoding_cmd,
	      X(MGW_CMD_ATTR_NEWCONN),
	      "allow-transcoding", "Allow transcoding\n")
{
	struct mgcp_trunk *trunk = mgcp_trunk_by_num(g_cfg, MGCP_TRUNK_VIRTUAL, MGCP_VIRT_TRUNK_ID);
	OSMO_ASSERT(trunk);
	trunk->no_audio_transcoding = 0;
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_mgcp_no_allow_transcoding,
	      cfg_mgcp_no_allow_transcoding_cmd,
	      X(MGW_CMD_ATTR_NEWCONN),
	      "no allow-transcoding", NO_STR "Allow transcoding\n")
{
	struct mgcp_trunk *trunk = mgcp_trunk_by_num(g_cfg, MGCP_TRUNK_VIRTUAL, MGCP_VIRT_TRUNK_ID);
	OSMO_ASSERT(trunk);
	trunk->no_audio_transcoding = 1;
	return CMD_SUCCESS;
}

#define SDP_STR "SDP File related options\n"
#define AUDIO_STR "Audio payload options\n"
DEFUN_DEPRECATED(cfg_mgcp_sdp_payload_number,
      cfg_mgcp_sdp_payload_number_cmd,
      "sdp audio-payload number <0-255>",
      SDP_STR AUDIO_STR "Number\n" "Payload number\n")
{
	return CMD_SUCCESS;
}

ALIAS_DEPRECATED(cfg_mgcp_sdp_payload_number,
		 cfg_mgcp_sdp_payload_number_cmd_old,
		 "sdp audio payload number <0-255>",
		 SDP_STR AUDIO_STR AUDIO_STR "Number\n" "Payload number\n")

DEFUN_DEPRECATED(cfg_mgcp_sdp_payload_name,
      cfg_mgcp_sdp_payload_name_cmd,
      "sdp audio-payload name NAME",
      SDP_STR AUDIO_STR "Name\n" "Payload name\n")
{
	return CMD_SUCCESS;
}

ALIAS_DEPRECATED(cfg_mgcp_sdp_payload_name, cfg_mgcp_sdp_payload_name_cmd_old,
		 "sdp audio payload name NAME",
		 SDP_STR AUDIO_STR AUDIO_STR "Name\n" "Payload name\n")

DEFUN_USRATTR(cfg_mgcp_sdp_payload_send_ptime,
	      cfg_mgcp_sdp_payload_send_ptime_cmd,
	      X(MGW_CMD_ATTR_NEWCONN),
	      "sdp audio-payload send-ptime",
	      SDP_STR AUDIO_STR "Send SDP ptime (packet duration) attribute\n")
{
	struct mgcp_trunk *trunk = mgcp_trunk_by_num(g_cfg, MGCP_TRUNK_VIRTUAL, MGCP_VIRT_TRUNK_ID);
	OSMO_ASSERT(trunk);
	trunk->audio_send_ptime = 1;
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_mgcp_no_sdp_payload_send_ptime,
	      cfg_mgcp_no_sdp_payload_send_ptime_cmd,
	      X(MGW_CMD_ATTR_NEWCONN),
	      "no sdp audio-payload send-ptime",
	      NO_STR SDP_STR AUDIO_STR "Send SDP ptime (packet duration) attribute\n")
{
	struct mgcp_trunk *trunk = mgcp_trunk_by_num(g_cfg, MGCP_TRUNK_VIRTUAL, MGCP_VIRT_TRUNK_ID);
	OSMO_ASSERT(trunk);
	trunk->audio_send_ptime = 0;
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_mgcp_sdp_payload_send_name,
	      cfg_mgcp_sdp_payload_send_name_cmd,
	      X(MGW_CMD_ATTR_NEWCONN),
	      "sdp audio-payload send-name",
	      SDP_STR AUDIO_STR "Send SDP rtpmap with the audio name\n")
{
	struct mgcp_trunk *trunk = mgcp_trunk_by_num(g_cfg, MGCP_TRUNK_VIRTUAL, MGCP_VIRT_TRUNK_ID);
	OSMO_ASSERT(trunk);
	trunk->audio_send_name = 1;
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_mgcp_no_sdp_payload_send_name,
	      cfg_mgcp_no_sdp_payload_send_name_cmd,
	      X(MGW_CMD_ATTR_NEWCONN),
	      "no sdp audio-payload send-name",
	      NO_STR SDP_STR AUDIO_STR "Send SDP rtpmap with the audio name\n")
{
	struct mgcp_trunk *trunk = mgcp_trunk_by_num(g_cfg, MGCP_TRUNK_VIRTUAL, MGCP_VIRT_TRUNK_ID);
	OSMO_ASSERT(trunk);
	trunk->audio_send_name = 0;
	return CMD_SUCCESS;
}

DEFUN_DEPRECATED(cfg_mgcp_loop,
		 cfg_mgcp_loop_cmd,
		 "loop (0|1)",
		 "Loop audio for all endpoints on main trunk\n" "Don't Loop\n" "Loop\n")
{
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_mgcp_force_realloc,
	      cfg_mgcp_force_realloc_cmd,
	      X(MGW_CMD_ATTR_NEWCONN),
	      "force-realloc (0|1)",
	      "Force endpoint reallocation when the endpoint is still seized\n"
	      "Don't force reallocation\n" "force reallocation\n")
{
	struct mgcp_trunk *trunk = mgcp_trunk_by_num(g_cfg, MGCP_TRUNK_VIRTUAL, MGCP_VIRT_TRUNK_ID);
	OSMO_ASSERT(trunk);
	trunk->force_realloc = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_mgcp_rtp_accept_all,
	   cfg_mgcp_rtp_accept_all_cmd,
	   "rtp-accept-all (0|1)",
	   "Accept all RTP packets, even when the originating IP/Port does not match\n"
	   "enable filter\n" "disable filter\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct mgcp_trunk *trunk = mgcp_trunk_by_num(g_cfg, MGCP_TRUNK_VIRTUAL, MGCP_VIRT_TRUNK_ID);
	OSMO_ASSERT(trunk);
	trunk->rtp_accept_all = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp_number_endp,
      cfg_mgcp_number_endp_cmd,
      "number endpoints <1-65534>",
      "Number options\n" "Endpoints available\n" "Number endpoints\n")
{
	struct mgcp_trunk *trunk = mgcp_trunk_by_num(g_cfg, MGCP_TRUNK_VIRTUAL, MGCP_VIRT_TRUNK_ID);
	OSMO_ASSERT(trunk);
	trunk->v.vty_number_endpoints = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_mgcp_omit_rtcp,
	   cfg_mgcp_omit_rtcp_cmd,
	   "rtcp-omit", RTCP_OMIT_STR,
	   CMD_ATTR_IMMEDIATE)
{
	struct mgcp_trunk *trunk = mgcp_trunk_by_num(g_cfg, MGCP_TRUNK_VIRTUAL, MGCP_VIRT_TRUNK_ID);
	trunk->omit_rtcp = 1;
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_mgcp_no_omit_rtcp,
	   cfg_mgcp_no_omit_rtcp_cmd,
	   "no rtcp-omit",
	   NO_STR RTCP_OMIT_STR,
	   CMD_ATTR_IMMEDIATE)
{
	struct mgcp_trunk *trunk = mgcp_trunk_by_num(g_cfg, MGCP_TRUNK_VIRTUAL, MGCP_VIRT_TRUNK_ID);
	OSMO_ASSERT(trunk);
	trunk->omit_rtcp = 0;
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_mgcp_patch_rtp_ssrc,
	      cfg_mgcp_patch_rtp_ssrc_cmd,
	      X(MGW_CMD_ATTR_NEWCONN),
	      "rtp-patch ssrc", RTP_PATCH_STR "Force a fixed SSRC\n")
{
	struct mgcp_trunk *trunk = mgcp_trunk_by_num(g_cfg, MGCP_TRUNK_VIRTUAL, MGCP_VIRT_TRUNK_ID);
	OSMO_ASSERT(trunk);
	trunk->force_constant_ssrc = 1;
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_mgcp_no_patch_rtp_ssrc,
	      cfg_mgcp_no_patch_rtp_ssrc_cmd,
	      X(MGW_CMD_ATTR_NEWCONN),
	      "no rtp-patch ssrc", NO_STR RTP_PATCH_STR "Force a fixed SSRC\n")
{
	struct mgcp_trunk *trunk = mgcp_trunk_by_num(g_cfg, MGCP_TRUNK_VIRTUAL, MGCP_VIRT_TRUNK_ID);
	OSMO_ASSERT(trunk);
	trunk->force_constant_ssrc = 0;
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_mgcp_patch_rtp_ts,
	      cfg_mgcp_patch_rtp_ts_cmd,
	      X(MGW_CMD_ATTR_NEWCONN),
	      "rtp-patch timestamp", RTP_PATCH_STR "Adjust RTP timestamp\n")
{
	struct mgcp_trunk *trunk = mgcp_trunk_by_num(g_cfg, MGCP_TRUNK_VIRTUAL, MGCP_VIRT_TRUNK_ID);
	OSMO_ASSERT(trunk);
	trunk->force_aligned_timing = 1;
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_mgcp_no_patch_rtp_ts,
	      cfg_mgcp_no_patch_rtp_ts_cmd,
	      X(MGW_CMD_ATTR_NEWCONN),
	      "no rtp-patch timestamp", NO_STR RTP_PATCH_STR "Adjust RTP timestamp\n")
{
	struct mgcp_trunk *trunk = mgcp_trunk_by_num(g_cfg, MGCP_TRUNK_VIRTUAL, MGCP_VIRT_TRUNK_ID);
	OSMO_ASSERT(trunk);
	trunk->force_aligned_timing = 0;
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_mgcp_patch_rtp_rfc5993hr,
	      cfg_mgcp_patch_rtp_rfc5993hr_cmd,
	      X(MGW_CMD_ATTR_NEWCONN),
	      "rtp-patch rfc5993hr", RTP_PATCH_STR RTP_TS101318_RFC5993_CONV_STR)
{
	struct mgcp_trunk *trunk = mgcp_trunk_by_num(g_cfg, MGCP_TRUNK_VIRTUAL, MGCP_VIRT_TRUNK_ID);
	OSMO_ASSERT(trunk);
	trunk->rfc5993_hr_convert = true;
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_mgcp_no_patch_rtp_rfc5993hr,
	      cfg_mgcp_no_patch_rtp_rfc5993hr_cmd,
	      X(MGW_CMD_ATTR_NEWCONN),
	      "no rtp-patch rfc5993hr", NO_STR RTP_PATCH_STR RTP_TS101318_RFC5993_CONV_STR)
{
	struct mgcp_trunk *trunk = mgcp_trunk_by_num(g_cfg, MGCP_TRUNK_VIRTUAL, MGCP_VIRT_TRUNK_ID);
	OSMO_ASSERT(trunk);
	trunk->rfc5993_hr_convert = false;
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_mgcp_no_patch_rtp,
	      cfg_mgcp_no_patch_rtp_cmd,
	      X(MGW_CMD_ATTR_NEWCONN),
	      "no rtp-patch", NO_STR RTP_PATCH_STR)
{
	struct mgcp_trunk *trunk = mgcp_trunk_by_num(g_cfg, MGCP_TRUNK_VIRTUAL, MGCP_VIRT_TRUNK_ID);
	OSMO_ASSERT(trunk);
	trunk->force_constant_ssrc = 0;
	trunk->force_aligned_timing = 0;
	trunk->rfc5993_hr_convert = false;
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_mgcp_rtp_keepalive,
	   cfg_mgcp_rtp_keepalive_cmd,
	   "rtp keep-alive <1-120>",
	   RTP_STR RTP_KEEPALIVE_STR "Keep alive interval in secs\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct mgcp_trunk *trunk = mgcp_trunk_by_num(g_cfg, MGCP_TRUNK_VIRTUAL, MGCP_VIRT_TRUNK_ID);
	OSMO_ASSERT(trunk);
	mgcp_trunk_set_keepalive(trunk, atoi(argv[0]));
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_mgcp_rtp_keepalive_once,
	   cfg_mgcp_rtp_keepalive_once_cmd,
	   "rtp keep-alive once",
	   RTP_STR RTP_KEEPALIVE_STR "Send dummy packet only once after CRCX/MDCX\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct mgcp_trunk *trunk = mgcp_trunk_by_num(g_cfg, MGCP_TRUNK_VIRTUAL, MGCP_VIRT_TRUNK_ID);
	OSMO_ASSERT(trunk);
	mgcp_trunk_set_keepalive(trunk, MGCP_KEEPALIVE_ONCE);
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_mgcp_no_rtp_keepalive,
	   cfg_mgcp_no_rtp_keepalive_cmd,
	   "no rtp keep-alive", NO_STR RTP_STR RTP_KEEPALIVE_STR,
	   CMD_ATTR_IMMEDIATE)
{
	struct mgcp_trunk *trunk = mgcp_trunk_by_num(g_cfg, MGCP_TRUNK_VIRTUAL, MGCP_VIRT_TRUNK_ID);
	OSMO_ASSERT(trunk);
	mgcp_trunk_set_keepalive(trunk, MGCP_KEEPALIVE_NEVER);
	return CMD_SUCCESS;
}

#define CALL_AGENT_STR "Call agent information\n"
DEFUN(cfg_mgcp_agent_addr,
      cfg_mgcp_agent_addr_cmd,
      "call-agent ip " VTY_IPV46_CMD,
      CALL_AGENT_STR IP_STR
      "IPv4 Address of the call agent\n"
      "IPv6 Address of the call agent\n")
{
	osmo_talloc_replace_string(g_cfg, &g_cfg->call_agent_addr, argv[0]);
	return CMD_SUCCESS;
}

ALIAS_DEPRECATED(cfg_mgcp_agent_addr, cfg_mgcp_agent_addr_cmd_old,
		 "call agent ip A.B.C.D",
		 CALL_AGENT_STR CALL_AGENT_STR IP_STR
		 "IPv4 Address of the callagent\n")

DEFUN(cfg_mgcp_trunk, cfg_mgcp_trunk_cmd,
      "trunk <0-64>", "Configure a SS7 trunk\n" "Trunk Nr\n")
{
	struct mgcp_trunk *trunk;
	int index = atoi(argv[0]);

	trunk = mgcp_trunk_by_num(g_cfg, MGCP_TRUNK_E1, index);
	if (!trunk) {
		trunk = mgcp_trunk_alloc(g_cfg, MGCP_TRUNK_E1, index);
		if (!trunk) {
			vty_out(vty, "%%Unable to allocate trunk %u.%s",
				index, VTY_NEWLINE);
			return CMD_WARNING;
		}
	}

	vty->node = TRUNK_NODE;
	vty->index = trunk;
	return CMD_SUCCESS;
}

static int config_write_trunk(struct vty *vty)
{
	struct mgcp_trunk *trunk;

	llist_for_each_entry(trunk, &g_cfg->trunks, entry) {

		/* Due to historical reasons, the virtual trunk is configured
		   using separate VTY parameters, so we omit writing the trunk
		   config of trunk 0 here. The configuration for the virtual
		   trunk is written by config_write_mgcp(). */

		if (trunk->trunk_type == MGCP_TRUNK_VIRTUAL
		    && trunk->trunk_nr == MGCP_VIRT_TRUNK_ID)
			continue;

		vty_out(vty, " trunk %d%s", trunk->trunk_nr, VTY_NEWLINE);
		vty_out(vty, "  line %u%s", trunk->e1.vty_line_nr, VTY_NEWLINE);
		vty_out(vty, "  %ssdp audio-payload send-ptime%s",
			trunk->audio_send_ptime ? "" : "no ", VTY_NEWLINE);
		vty_out(vty, "  %ssdp audio-payload send-name%s",
			trunk->audio_send_name ? "" : "no ", VTY_NEWLINE);

		if (trunk->keepalive_interval == MGCP_KEEPALIVE_ONCE)
			vty_out(vty, "  rtp keep-alive once%s", VTY_NEWLINE);
		else if (trunk->keepalive_interval)
			vty_out(vty, "  rtp keep-alive %d%s",
				trunk->keepalive_interval, VTY_NEWLINE);
		else
			vty_out(vty, "  no rtp keep-alive%s", VTY_NEWLINE);
		vty_out(vty, "  force-realloc %d%s",
			trunk->force_realloc, VTY_NEWLINE);
		vty_out(vty, "  rtp-accept-all %d%s",
			trunk->rtp_accept_all, VTY_NEWLINE);
		if (trunk->omit_rtcp)
			vty_out(vty, "  rtcp-omit%s", VTY_NEWLINE);
		else
			vty_out(vty, "  no rtcp-omit%s", VTY_NEWLINE);
		if (trunk->force_constant_ssrc || trunk->force_aligned_timing
		    || trunk->rfc5993_hr_convert) {
			vty_out(vty, "  %srtp-patch ssrc%s",
				trunk->force_constant_ssrc ? "" : "no ",
				VTY_NEWLINE);
			vty_out(vty, "  %srtp-patch timestamp%s",
				trunk->force_aligned_timing ? "" : "no ",
				VTY_NEWLINE);
			vty_out(vty, "  %srtp-patch rfc5993hr%s",
				trunk->rfc5993_hr_convert ? "" : "no ",
				VTY_NEWLINE);
		} else
			vty_out(vty, "  no rtp-patch%s", VTY_NEWLINE);
		if (trunk->audio_fmtp_extra)
			vty_out(vty, "   sdp audio fmtp-extra %s%s",
				trunk->audio_fmtp_extra, VTY_NEWLINE);
		vty_out(vty, "  %sallow-transcoding%s",
			trunk->no_audio_transcoding ? "no " : "", VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_trunk_sdp_fmtp_extra,
	      cfg_trunk_sdp_fmtp_extra_cmd,
	      X(MGW_CMD_ATTR_NEWCONN),
	      "sdp audio fmtp-extra .NAME",
	      "Add extra fmtp for the SDP file\n" "Audio\n" "Fmtp-extra\n"
	      "Extra Information\n")
{
	struct mgcp_trunk *trunk = vty->index;
	char *txt = argv_concat(argv, argc, 0);
	if (!txt)
		return CMD_WARNING;

	osmo_talloc_replace_string(g_cfg, &trunk->audio_fmtp_extra, txt);
	talloc_free(txt);
	return CMD_SUCCESS;
}

DEFUN_DEPRECATED(cfg_trunk_payload_number,
      cfg_trunk_payload_number_cmd,
      "sdp audio-payload number <0-255>",
      SDP_STR AUDIO_STR "Number\n" "Payload Number\n")
{
	return CMD_SUCCESS;
}

ALIAS_DEPRECATED(cfg_trunk_payload_number, cfg_trunk_payload_number_cmd_old,
		 "sdp audio payload number <0-255>",
		 SDP_STR AUDIO_STR AUDIO_STR "Number\n" "Payload Number\n")

DEFUN_DEPRECATED(cfg_trunk_payload_name,
      cfg_trunk_payload_name_cmd,
      "sdp audio-payload name NAME",
      SDP_STR AUDIO_STR "Payload\n" "Payload Name\n")
{
	return CMD_SUCCESS;
}

ALIAS_DEPRECATED(cfg_trunk_payload_name, cfg_trunk_payload_name_cmd_old,
		 "sdp audio payload name NAME",
		 SDP_STR AUDIO_STR AUDIO_STR "Payload\n" "Payload Name\n")

DEFUN_DEPRECATED(cfg_trunk_loop,
		 cfg_trunk_loop_cmd,
		 "loop (0|1)",
		 "Loop audio for all endpoints on this trunk\n" "Don't Loop\n" "Loop\n")
{
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_trunk_force_realloc,
	      cfg_trunk_force_realloc_cmd,
	      X(MGW_CMD_ATTR_NEWCONN),
	      "force-realloc (0|1)",
	      "Force endpoint reallocation when the endpoint is still seized\n"
	      "Don't force reallocation\n" "force reallocation\n")
{
	struct mgcp_trunk *trunk = vty->index;
	OSMO_ASSERT(trunk);
	trunk->force_realloc = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_trunk_rtp_accept_all,
	   cfg_trunk_rtp_accept_all_cmd,
	   "rtp-accept-all (0|1)",
	   "Accept all RTP packets, even when the originating IP/Port does not match\n"
	   "enable filter\n" "disable filter\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct mgcp_trunk *trunk = vty->index;
	OSMO_ASSERT(trunk);
	trunk->rtp_accept_all = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_trunk_sdp_payload_send_ptime,
	      cfg_trunk_sdp_payload_send_ptime_cmd,
	      X(MGW_CMD_ATTR_NEWCONN),
	      "sdp audio-payload send-ptime",
	      SDP_STR AUDIO_STR "Send SDP ptime (packet duration) attribute\n")
{
	struct mgcp_trunk *trunk = vty->index;
	trunk->audio_send_ptime = 1;
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_trunk_no_sdp_payload_send_ptime,
	      cfg_trunk_no_sdp_payload_send_ptime_cmd,
	      X(MGW_CMD_ATTR_NEWCONN),
	      "no sdp audio-payload send-ptime",
	      NO_STR SDP_STR AUDIO_STR "Send SDP ptime (packet duration) attribute\n")
{
	struct mgcp_trunk *trunk = vty->index;
	trunk->audio_send_ptime = 0;
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_trunk_sdp_payload_send_name,
	      cfg_trunk_sdp_payload_send_name_cmd,
	      X(MGW_CMD_ATTR_NEWCONN),
	      "sdp audio-payload send-name",
	      SDP_STR AUDIO_STR "Send SDP rtpmap with the audio name\n")
{
	struct mgcp_trunk *trunk = vty->index;
	trunk->audio_send_name = 1;
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_trunk_no_sdp_payload_send_name,
	      cfg_trunk_no_sdp_payload_send_name_cmd,
	      X(MGW_CMD_ATTR_NEWCONN),
	      "no sdp audio-payload send-name",
	      NO_STR SDP_STR AUDIO_STR "Send SDP rtpmap with the audio name\n")
{
	struct mgcp_trunk *trunk = vty->index;
	trunk->audio_send_name = 0;
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_trunk_omit_rtcp,
	   cfg_trunk_omit_rtcp_cmd,
	   "rtcp-omit", RTCP_OMIT_STR,
	   CMD_ATTR_IMMEDIATE)
{
	struct mgcp_trunk *trunk = vty->index;
	trunk->omit_rtcp = 1;
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_trunk_no_omit_rtcp,
	   cfg_trunk_no_omit_rtcp_cmd,
	   "no rtcp-omit", NO_STR RTCP_OMIT_STR,
	   CMD_ATTR_IMMEDIATE)
{
	struct mgcp_trunk *trunk = vty->index;
	trunk->omit_rtcp = 0;
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_trunk_patch_rtp_ssrc,
	      cfg_trunk_patch_rtp_ssrc_cmd,
	      X(MGW_CMD_ATTR_NEWCONN),
	      "rtp-patch ssrc", RTP_PATCH_STR "Force a fixed SSRC\n")
{
	struct mgcp_trunk *trunk = vty->index;
	trunk->force_constant_ssrc = 1;
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_trunk_no_patch_rtp_ssrc,
	      cfg_trunk_no_patch_rtp_ssrc_cmd,
	      X(MGW_CMD_ATTR_NEWCONN),
	      "no rtp-patch ssrc", NO_STR RTP_PATCH_STR "Force a fixed SSRC\n")
{
	struct mgcp_trunk *trunk = vty->index;
	trunk->force_constant_ssrc = 0;
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_trunk_patch_rtp_ts,
	      cfg_trunk_patch_rtp_ts_cmd,
	      X(MGW_CMD_ATTR_NEWCONN),
	      "rtp-patch timestamp", RTP_PATCH_STR "Adjust RTP timestamp\n")
{
	struct mgcp_trunk *trunk = vty->index;
	trunk->force_aligned_timing = 1;
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_trunk_no_patch_rtp_ts,
	      cfg_trunk_no_patch_rtp_ts_cmd,
	      X(MGW_CMD_ATTR_NEWCONN),
	      "no rtp-patch timestamp", NO_STR RTP_PATCH_STR "Adjust RTP timestamp\n")
{
	struct mgcp_trunk *trunk = vty->index;
	trunk->force_aligned_timing = 0;
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_trunk_patch_rtp_rfc5993hr,
	      cfg_trunk_patch_rtp_rfc5993hr_cmd,
	      X(MGW_CMD_ATTR_NEWCONN),
	      "rtp-patch rfc5993hr", RTP_PATCH_STR RTP_TS101318_RFC5993_CONV_STR)
{
	struct mgcp_trunk *trunk = vty->index;
	trunk->rfc5993_hr_convert = true;
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_trunk_no_patch_rtp_rfc5993hr,
	      cfg_trunk_no_patch_rtp_rfc5993hr_cmd,
	      X(MGW_CMD_ATTR_NEWCONN),
	      "no rtp-patch rfc5993hr", NO_STR RTP_PATCH_STR RTP_TS101318_RFC5993_CONV_STR)
{
	struct mgcp_trunk *trunk = vty->index;
	trunk->rfc5993_hr_convert = false;
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_trunk_no_patch_rtp,
	      cfg_trunk_no_patch_rtp_cmd,
	      X(MGW_CMD_ATTR_NEWCONN),
	      "no rtp-patch", NO_STR RTP_PATCH_STR)
{
	struct mgcp_trunk *trunk = vty->index;
	trunk->force_constant_ssrc = 0;
	trunk->force_aligned_timing = 0;
	trunk->rfc5993_hr_convert = false;
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_trunk_rtp_keepalive,
	   cfg_trunk_rtp_keepalive_cmd,
	   "rtp keep-alive <1-120>",
	   RTP_STR RTP_KEEPALIVE_STR "Keep-alive interval in secs\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct mgcp_trunk *trunk = vty->index;
	mgcp_trunk_set_keepalive(trunk, atoi(argv[0]));
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_trunk_rtp_keepalive_once,
	   cfg_trunk_rtp_keepalive_once_cmd,
	   "rtp keep-alive once",
	   RTP_STR RTP_KEEPALIVE_STR "Send dummy packet only once after CRCX/MDCX\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct mgcp_trunk *trunk = vty->index;
	mgcp_trunk_set_keepalive(trunk, MGCP_KEEPALIVE_ONCE);
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_trunk_no_rtp_keepalive,
	   cfg_trunk_no_rtp_keepalive_cmd,
	   "no rtp keep-alive", NO_STR RTP_STR RTP_KEEPALIVE_STR,
	   CMD_ATTR_IMMEDIATE)
{
	struct mgcp_trunk *trunk = vty->index;
	mgcp_trunk_set_keepalive(trunk, 0);
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_trunk_allow_transcoding,
	      cfg_trunk_allow_transcoding_cmd,
	      X(MGW_CMD_ATTR_NEWCONN),
	      "allow-transcoding", "Allow transcoding\n")
{
	struct mgcp_trunk *trunk = vty->index;
	trunk->no_audio_transcoding = 0;
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_trunk_no_allow_transcoding,
	      cfg_trunk_no_allow_transcoding_cmd,
	      X(MGW_CMD_ATTR_NEWCONN),
	      "no allow-transcoding", NO_STR "Allow transcoding\n")
{
	struct mgcp_trunk *trunk = vty->index;
	trunk->no_audio_transcoding = 1;
	return CMD_SUCCESS;
}

#define LINE_STR "Configure trunk for given Line\nE1/T1 Line Number\n"

DEFUN(cfg_trunk_line,
      cfg_trunk_line_cmd,
      "line <0-255>",
      LINE_STR)
{
	struct mgcp_trunk *trunk = vty->index;
	int line_nr = atoi(argv[0]);
	trunk->e1.vty_line_nr = line_nr;
	return CMD_SUCCESS;
}

DEFUN(loop_conn,
      loop_conn_cmd,
      "loop-endpoint <0-64> NAME (0|1)",
      "Loop a given endpoint\n" "Trunk number\n"
      "The name in hex of the endpoint\n" "Disable the loop\n"
      "Enable the loop\n")
{
	struct mgcp_trunk *trunk;
	struct mgcp_endpoint *endp;
	struct mgcp_conn *conn;

	trunk = mgcp_trunk_by_num(g_cfg, MGCP_TRUNK_E1, atoi(argv[0]));
	if (!trunk) {
		vty_out(vty, "%%Trunk %d not found in the config.%s",
			atoi(argv[0]), VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!trunk->endpoints) {
		vty_out(vty, "%%Trunk %d has no endpoints allocated.%s",
			trunk->trunk_nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	int endp_no = strtoul(argv[1], NULL, 16);
	if (endp_no < 1 || endp_no >= trunk->number_endpoints) {
		vty_out(vty, "Loopback number %s/%d is invalid.%s",
			argv[1], endp_no, VTY_NEWLINE);
		return CMD_WARNING;
	}

	endp = trunk->endpoints[endp_no];
	int loop = atoi(argv[2]);
	llist_for_each_entry(conn, &endp->conns, entry) {
		if (conn->type == MGCP_CONN_TYPE_RTP)
			/* Handle it like a MDCX, switch on SSRC patching if enabled */
			mgcp_rtp_end_config(endp, 1, &conn->u.rtp.end);
		else {
			/* FIXME: Introduce support for other connection (E1)
			 * types when implementation is available */
			vty_out(vty, "%%Can't enable SSRC patching,"
				"connection %s is not an RTP connection.%s",
				mgcp_conn_dump(conn), VTY_NEWLINE);
		}

		if (loop)
			conn->mode = MGCP_CONN_LOOPBACK;
		else
			conn->mode = conn->mode_orig;
	}

	return CMD_SUCCESS;
}

DEFUN(tap_rtp,
      tap_rtp_cmd,
      "tap-rtp <0-64> ENDPOINT CONN (in|out) " VTY_IPV46_CMD " <0-65534>",
      "Forward data on endpoint to a different system\n" "Trunk number\n"
      "The endpoint in hex\n"
      "The connection id in hex\n"
      "Forward incoming data\n"
      "Forward leaving data\n"
      "Destination IPv4 of the data\n"
      "Destination IPv6 of the data\n"
      "Destination port\n")
{
	struct mgcp_rtp_tap *tap;
	struct mgcp_trunk *trunk;
	struct mgcp_endpoint *endp;
	struct mgcp_conn_rtp *conn;
        const char *conn_id = NULL;

	trunk = mgcp_trunk_by_num(g_cfg, MGCP_TRUNK_E1, atoi(argv[0]));
	if (!trunk) {
		vty_out(vty, "%%Trunk %d not found in the config.%s",
			atoi(argv[0]), VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!trunk->endpoints) {
		vty_out(vty, "%%Trunk %d has no endpoints allocated.%s",
			trunk->trunk_nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	int endp_no = strtoul(argv[1], NULL, 16);
	if (endp_no < 1 || endp_no >= trunk->number_endpoints) {
		vty_out(vty, "Endpoint number %s/%d is invalid.%s",
			argv[1], endp_no, VTY_NEWLINE);
		return CMD_WARNING;
	}

	endp = trunk->endpoints[endp_no];

	conn_id = argv[2];
	conn = mgcp_conn_get_rtp(endp, conn_id);
	if (!conn) {
		vty_out(vty, "Conn ID %s is invalid.%s",
			conn_id, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (strcmp(argv[3], "in") == 0)
		tap = &conn->tap_in;
	else if (strcmp(argv[3], "out") == 0)
		tap = &conn->tap_out;
	else {
		vty_out(vty, "Unknown mode... tricked vty?%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	memset(&tap->forward, 0, sizeof(tap->forward));

	tap->forward.u.sa.sa_family = osmo_ip_str_type(argv[4]);
	switch (tap->forward.u.sa.sa_family) {
	case AF_INET:
		if (inet_pton(AF_INET, argv[4], &tap->forward.u.sin.sin_addr) != 1)
			return CMD_WARNING;
		tap->forward.u.sin.sin_port = htons(atoi(argv[5]));
		break;
	case AF_INET6:
		if (inet_pton(AF_INET6, argv[4], &tap->forward.u.sin6.sin6_addr) != 1)
			return CMD_WARNING;
		tap->forward.u.sin6.sin6_port = htons(atoi(argv[5]));
		break;
	default:
		return CMD_WARNING;
	}
	tap->enabled = 1;
	return CMD_SUCCESS;
}

DEFUN(free_endp, free_endp_cmd,
      "free-endpoint <0-64> NUMBER",
      "Free the given endpoint\n" "Trunk number\n" "Endpoint number in hex.\n")
{
	struct mgcp_trunk *trunk;
	struct mgcp_endpoint *endp;

	trunk = mgcp_trunk_by_num(g_cfg, MGCP_TRUNK_E1, atoi(argv[0]));
	if (!trunk) {
		vty_out(vty, "%%Trunk %d not found in the config.%s",
			atoi(argv[0]), VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!trunk->endpoints) {
		vty_out(vty, "%%Trunk %d has no endpoints allocated.%s",
			trunk->trunk_nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	int endp_no = strtoul(argv[1], NULL, 16);
	if (endp_no < 1 || endp_no >= trunk->number_endpoints) {
		vty_out(vty, "Endpoint number %s/%d is invalid.%s",
			argv[1], endp_no, VTY_NEWLINE);
		return CMD_WARNING;
	}

	endp = trunk->endpoints[endp_no];
	mgcp_endp_release(endp);
	return CMD_SUCCESS;
}

DEFUN(reset_endp, reset_endp_cmd,
      "reset-endpoint <0-64> NUMBER",
      "Reset the given endpoint\n" "Trunk number\n" "Endpoint number in hex.\n")
{
	struct mgcp_trunk *trunk;
	struct mgcp_endpoint *endp;
	int endp_no, rc;

	trunk = mgcp_trunk_by_num(g_cfg, MGCP_TRUNK_E1, atoi(argv[0]));
	if (!trunk) {
		vty_out(vty, "%%Trunk %d not found in the config.%s",
			atoi(argv[0]), VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!trunk->endpoints) {
		vty_out(vty, "%%Trunk %d has no endpoints allocated.%s",
			trunk->trunk_nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	endp_no = strtoul(argv[1], NULL, 16);
	if (endp_no < 1 || endp_no >= trunk->number_endpoints) {
		vty_out(vty, "Endpoint number %s/%d is invalid.%s",
			argv[1], endp_no, VTY_NEWLINE);
		return CMD_WARNING;
	}

	endp = trunk->endpoints[endp_no];
	rc = mgcp_send_reset_ep(endp);
	if (rc < 0) {
		vty_out(vty, "Error %d sending reset.%s", rc, VTY_NEWLINE);
		return CMD_WARNING;
	}
	return CMD_SUCCESS;
}

DEFUN(reset_all_endp, reset_all_endp_cmd,
      "reset-all-endpoints", "Reset all endpoints\n")
{
	int rc;

	rc = mgcp_send_reset_all(g_cfg);
	if (rc < 0) {
		vty_out(vty, "Error %d during endpoint reset.%s",
			rc, VTY_NEWLINE);
		return CMD_WARNING;
	}
	return CMD_SUCCESS;
}

#define OSMUX_STR "RTP multiplexing\n"
DEFUN(cfg_mgcp_osmux,
      cfg_mgcp_osmux_cmd,
      "osmux (on|off|only)",
      OSMUX_STR "Enable OSMUX\n" "Disable OSMUX\n" "Only use OSMUX\n")
{
	struct mgcp_trunk *trunk = mgcp_trunk_by_num(g_cfg, MGCP_TRUNK_VIRTUAL, MGCP_VIRT_TRUNK_ID);
	OSMO_ASSERT(trunk);

	if (strcmp(argv[0], "off") == 0) {
		g_cfg->osmux = OSMUX_USAGE_OFF;
		return CMD_SUCCESS;
	} else if (strcmp(argv[0], "on") == 0)
		g_cfg->osmux = OSMUX_USAGE_ON;
	else if (strcmp(argv[0], "only") == 0)
		g_cfg->osmux = OSMUX_USAGE_ONLY;

	return CMD_SUCCESS;

}

DEFUN(cfg_mgcp_osmux_ip,
      cfg_mgcp_osmux_ip_cmd,
      "osmux bind-ip " VTY_IPV46_CMD,
      OSMUX_STR IP_STR
      "IPv4 Address to bind to\n"
      "IPv6 Address to bind to\n")
{
	osmo_talloc_replace_string(g_cfg, &g_cfg->osmux_addr, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp_osmux_batch_factor,
      cfg_mgcp_osmux_batch_factor_cmd,
      "osmux batch-factor <1-8>",
      OSMUX_STR "Batching factor\n" "Number of messages in the batch\n")
{
	g_cfg->osmux_batch = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp_osmux_batch_size,
      cfg_mgcp_osmux_batch_size_cmd,
      "osmux batch-size <1-65535>",
      OSMUX_STR "batch size\n" "Batch size in bytes\n")
{
	g_cfg->osmux_batch_size = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp_osmux_port,
      cfg_mgcp_osmux_port_cmd,
      "osmux port <1-65535>", OSMUX_STR "port\n" "UDP port\n")
{
	g_cfg->osmux_port = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp_osmux_dummy,
      cfg_mgcp_osmux_dummy_cmd,
      "osmux dummy (on|off)",
      OSMUX_STR "Dummy padding\n" "Enable dummy padding\n"
      "Disable dummy padding\n")
{
	if (strcmp(argv[0], "on") == 0)
		g_cfg->osmux_dummy = 1;
	else if (strcmp(argv[0], "off") == 0)
		g_cfg->osmux_dummy = 0;

	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp_domain,
      cfg_mgcp_domain_cmd,
      "domain NAME",
      "Set the domain part expected in MGCP messages' endpoint names\n"
      "Qualified domain name expected in MGCP endpoint names, or '*' to accept any domain\n")
{
	osmo_strlcpy(g_cfg->domain, argv[0], sizeof(g_cfg->domain));
	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp_conn_timeout,
      cfg_mgcp_conn_timeout_cmd,
      "conn-timeout <0-65534>",
      "Set a time after which inactive connections (CIs) are closed. Set to 0 to disable timeout. This can be used to"
      " work around interoperability problems causing connections to stay open forever, and slowly exhausting all"
      " available ports. Enable keep-alive packets in MGW clients when using this option together with LCLS (OsmoBSC,"
      " OsmoMSC: 'rtp keep-alive')!\n"
      "Timeout value (sec.)\n")
{
	g_cfg->conn_timeout = strtoul(argv[0], NULL, 10);
	return CMD_SUCCESS;
}

int mgcp_vty_init(void)
{
	install_element_ve(&show_mgcp_cmd);
	install_element_ve(&show_mgcp_endpoint_cmd);
	install_element_ve(&show_mgcp_trunk_endpoint_cmd);
	install_element(ENABLE_NODE, &loop_conn_cmd);
	install_element(ENABLE_NODE, &tap_rtp_cmd);
	install_element(ENABLE_NODE, &free_endp_cmd);
	install_element(ENABLE_NODE, &reset_endp_cmd);
	install_element(ENABLE_NODE, &reset_all_endp_cmd);

	install_element(CONFIG_NODE, &cfg_mgcp_cmd);
	install_node(&mgcp_node, config_write_mgcp);

	install_element(MGCP_NODE, &cfg_mgcp_local_ip_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_bind_ip_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_bind_port_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_bind_early_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_rtp_net_range_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_rtp_port_range_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_rtp_net_bind_ip_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_rtp_bind_ip_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_rtp_bind_ip_v6_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_rtp_no_net_bind_ip_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_rtp_no_bind_ip_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_rtp_no_bind_ip_v6_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_rtp_net_bind_ip_probing_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_rtp_no_net_bind_ip_probing_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_rtp_ip_dscp_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_rtp_ip_tos_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_rtp_force_ptime_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_no_rtp_force_ptime_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_rtp_keepalive_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_rtp_keepalive_once_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_no_rtp_keepalive_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_agent_addr_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_agent_addr_cmd_old);
	install_element(MGCP_NODE, &cfg_mgcp_sdp_payload_number_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_sdp_payload_name_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_sdp_payload_number_cmd_old);
	install_element(MGCP_NODE, &cfg_mgcp_sdp_payload_name_cmd_old);
	install_element(MGCP_NODE, &cfg_mgcp_loop_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_force_realloc_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_rtp_accept_all_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_number_endp_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_omit_rtcp_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_no_omit_rtcp_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_patch_rtp_ssrc_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_no_patch_rtp_ssrc_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_patch_rtp_ts_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_no_patch_rtp_ts_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_no_patch_rtp_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_patch_rtp_rfc5993hr_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_no_patch_rtp_rfc5993hr_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_sdp_fmtp_extra_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_sdp_payload_send_ptime_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_no_sdp_payload_send_ptime_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_sdp_payload_send_name_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_no_sdp_payload_send_name_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_osmux_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_osmux_ip_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_osmux_batch_factor_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_osmux_batch_size_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_osmux_port_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_osmux_dummy_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_allow_transcoding_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_no_allow_transcoding_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_domain_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_conn_timeout_cmd);

	install_element(MGCP_NODE, &cfg_mgcp_trunk_cmd);
	install_node(&trunk_node, config_write_trunk);
	install_element(TRUNK_NODE, &cfg_trunk_rtp_keepalive_cmd);
	install_element(TRUNK_NODE, &cfg_trunk_rtp_keepalive_once_cmd);
	install_element(TRUNK_NODE, &cfg_trunk_no_rtp_keepalive_cmd);
	install_element(TRUNK_NODE, &cfg_trunk_payload_number_cmd);
	install_element(TRUNK_NODE, &cfg_trunk_payload_name_cmd);
	install_element(TRUNK_NODE, &cfg_trunk_payload_number_cmd_old);
	install_element(TRUNK_NODE, &cfg_trunk_payload_name_cmd_old);
	install_element(TRUNK_NODE, &cfg_trunk_loop_cmd);
	install_element(TRUNK_NODE, &cfg_trunk_force_realloc_cmd);
	install_element(TRUNK_NODE, &cfg_trunk_rtp_accept_all_cmd);
	install_element(TRUNK_NODE, &cfg_trunk_omit_rtcp_cmd);
	install_element(TRUNK_NODE, &cfg_trunk_no_omit_rtcp_cmd);
	install_element(TRUNK_NODE, &cfg_trunk_patch_rtp_ssrc_cmd);
	install_element(TRUNK_NODE, &cfg_trunk_no_patch_rtp_ssrc_cmd);
	install_element(TRUNK_NODE, &cfg_trunk_patch_rtp_ts_cmd);
	install_element(TRUNK_NODE, &cfg_trunk_patch_rtp_rfc5993hr_cmd);
	install_element(TRUNK_NODE, &cfg_trunk_no_patch_rtp_rfc5993hr_cmd);
	install_element(TRUNK_NODE, &cfg_trunk_no_patch_rtp_ts_cmd);
	install_element(TRUNK_NODE, &cfg_trunk_no_patch_rtp_cmd);
	install_element(TRUNK_NODE, &cfg_trunk_sdp_fmtp_extra_cmd);
	install_element(TRUNK_NODE, &cfg_trunk_sdp_payload_send_ptime_cmd);
	install_element(TRUNK_NODE, &cfg_trunk_no_sdp_payload_send_ptime_cmd);
	install_element(TRUNK_NODE, &cfg_trunk_sdp_payload_send_name_cmd);
	install_element(TRUNK_NODE, &cfg_trunk_no_sdp_payload_send_name_cmd);
	install_element(TRUNK_NODE, &cfg_trunk_allow_transcoding_cmd);
	install_element(TRUNK_NODE, &cfg_trunk_no_allow_transcoding_cmd);
	install_element(TRUNK_NODE, &cfg_trunk_line_cmd);

	return 0;
}

int mgcp_parse_config(const char *config_file, struct mgcp_config *cfg,
		      enum mgcp_role role)
{
	int rc;
	struct mgcp_trunk *trunk;

	cfg->osmux_port = OSMUX_PORT;
	cfg->osmux_batch = 4;
	cfg->osmux_batch_size = OSMUX_BATCH_DEFAULT_MAX;

	g_cfg = cfg;
	rc = vty_read_config_file(config_file, NULL);
	if (rc < 0) {
		fprintf(stderr, "Failed to parse the config file: '%s'\n",
			config_file);
		return rc;
	}

	if (!g_cfg->source_addr) {
		fprintf(stderr, "You need to specify a bind address.\n");
		return -1;
	}

	llist_for_each_entry(trunk, &g_cfg->trunks, entry) {
		if (mgcp_trunk_equip(trunk) != 0) {
			LOGP(DLMGCP, LOGL_ERROR,
			     "Failed to initialize trunk %d (%d endpoints)\n",
			     trunk->trunk_nr, trunk->number_endpoints);
			return -1;
		}
	}
	cfg->role = role;

	return 0;
}

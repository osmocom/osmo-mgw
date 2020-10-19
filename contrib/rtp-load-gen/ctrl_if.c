/* CTRL interface of rtpsource program
 *
 * (C) 2020 by Harald Welte <laforge@gnumonks.org>
 *
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
 */

#include <osmocom/ctrl/control_cmd.h>

#include "internal.h"
#include "rtp_provider.h"

static struct rtpsim_connection *find_connection_by_cname(const char *cname)
{
	struct rtpsim_connection *rtpc;
	struct rtpsim_instance *ri;

	pthread_rwlock_rdlock(&g_rtpsim->rwlock);
	llist_for_each_entry(ri, &g_rtpsim->instances, list) {
		rtpc = rtpsim_conn_find(ri, cname);
		if (rtpc) {
			pthread_rwlock_unlock(&g_rtpsim->rwlock);
			return rtpc;
		}
	}
	pthread_rwlock_unlock(&g_rtpsim->rwlock);
	return NULL;
}

static struct rtpsim_connection *create_connection(const char *cname, enum codec_type codec)
{
	struct rtpsim_connection *rtpc;
	struct rtpsim_instance *ri;

	pthread_rwlock_rdlock(&g_rtpsim->rwlock);
	llist_for_each_entry(ri, &g_rtpsim->instances, list) {
		rtpc = rtpsim_conn_reserve(ri, cname, codec);
		if (rtpc) {
			pthread_rwlock_unlock(&g_rtpsim->rwlock);
			return rtpc;
		}
	}
	pthread_rwlock_unlock(&g_rtpsim->rwlock);
	return NULL;
}

static int connect_connection(struct rtpsim_connection *rtpc, const char *remote_host,
			      uint16_t remote_port, uint8_t pt)
{
	int rc;

	osmo_sockaddr_str_from_str(&rtpc->cfg.remote, remote_host, remote_port);
	rtpc->cfg.pt = pt;

	rc = rtpsim_conn_connect(rtpc);
	if (rc < 0)
		return rc;

	rc = rtpsim_conn_start(rtpc);

	return rc;
}

static int delete_connection(struct rtpsim_connection *rtpc)
{
	rtpsim_conn_stop(rtpc);
	rtpsim_conn_unreserve(rtpc);
	return 0;
}

CTRL_CMD_DEFINE_WO_NOVRF(rtp_create, "rtp_create");
static int set_rtp_create(struct ctrl_cmd *cmd, void *data)
{
	struct rtpsim_connection *conn;
	const char *cname, *codec_str;
	char *tmp, *saveptr;
	enum codec_type codec;

	tmp = talloc_strdup(cmd, cmd->value);
	OSMO_ASSERT(tmp);

	cname = strtok_r(tmp, ",", &saveptr);
	codec_str = strtok_r(NULL, ",", &saveptr);

	if (!cname || !codec_str) {
		cmd->reply = "Format is cname,codec";
		goto error;
	}

	if (find_connection_by_cname(cname)) {
		cmd->reply = "Connection already exists for cname";
		goto error;
	}

	codec = get_string_value(codec_type_names, codec_str);
	if (codec < 0) {
		cmd->reply = "Invalid codec name (try GSM_FR, GSM_EFR etc.)";
		goto error;
	}

	conn = create_connection(cname, codec);
	if (!conn) {
		cmd->reply = "Error creating RTP connection";
		goto error;
	}

	/* Respond */
	cmd->reply = talloc_asprintf(cmd, "%s,%s,%d", conn->cname, conn->cfg.local.ip, conn->cfg.local.port);
	talloc_free(tmp);
	return CTRL_CMD_REPLY;

error:
	talloc_free(tmp);
	return CTRL_CMD_ERROR;
}

CTRL_CMD_DEFINE_WO_NOVRF(rtp_connect, "rtp_connect");
static int set_rtp_connect(struct ctrl_cmd *cmd, void *data)
{
	struct rtpsim_connection *conn;
	const char *cname, *remote_host, *remote_port, *pt;
	char *tmp, *saveptr;
	int rc;

	tmp = talloc_strdup(cmd, cmd->value);
	OSMO_ASSERT(tmp);

	/* FIXME: parse command */
	cname = strtok_r(tmp, ",", &saveptr);
	remote_host = strtok_r(NULL, ",", &saveptr);
	remote_port = strtok_r(NULL, ",", &saveptr);
	pt = strtok_r(NULL, ",", &saveptr);

	if (!cname || !remote_host || !remote_port || !pt) {
		cmd->reply = "Format is cname,remote_host,remote_port,pt";
		talloc_free(tmp);
		return CTRL_CMD_ERROR;
	}

	conn = find_connection_by_cname(cname);
	if (!conn) {
		cmd->reply = "Error finding RTP connection for connect";
		talloc_free(tmp);
		return CTRL_CMD_ERROR;
	}

	rc = connect_connection(conn, remote_host, atoi(remote_port), atoi(pt));
	if (rc < 0) {
		cmd->reply = "Error binding RTP connection";
		talloc_free(tmp);
		return CTRL_CMD_ERROR;
	}

	/* Respond */
	talloc_free(tmp);
	cmd->reply = talloc_asprintf(cmd, "%s,%s,%d,%d", conn->cname, conn->cfg.remote.ip,
					conn->cfg.remote.port, conn->cfg.pt);
	return CTRL_CMD_REPLY;
}

CTRL_CMD_DEFINE_WO_NOVRF(rtp_delete, "rtp_delete");
static int set_rtp_delete(struct ctrl_cmd *cmd, void *data)
{
	struct rtpsim_connection *conn;
	const char *cname = cmd->value;

	conn = find_connection_by_cname(cname);
	if (!conn) {
		cmd->reply = "Error finding RTP connection for delete";
		return CTRL_CMD_ERROR;
	}
	cmd->reply = talloc_asprintf(cmd, "%s", conn->cname);

	delete_connection(conn);

	/* Respond */
	return CTRL_CMD_REPLY;
}





int rtpsource_ctrl_cmds_install(void)
{
	int rc;

	rc = ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_rtp_create);
	if (rc)
		goto end;

	rc = ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_rtp_connect);
	if (rc)
		goto end;

	rc = ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_rtp_delete);
	if (rc)
		goto end;
end:
	return rc;
}

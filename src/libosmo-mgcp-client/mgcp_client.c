/* mgcp_utils - common functions to setup an MGCP connection
 */
/* (C) 2016 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
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

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/select.h>
#include <osmocom/core/write_queue.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/byteswap.h>
#include <osmocom/core/socket.h>

#include <osmocom/mgcp_client/mgcp_client.h>
#include <osmocom/mgcp_client/mgcp_client_internal.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <unistd.h>
#include <string.h>

void mgcp_client_conf_init(struct mgcp_client_conf *conf)
{
	/* NULL and -1 default to MGCP_CLIENT_*_DEFAULT values */
	*conf = (struct mgcp_client_conf){
		.local_addr = NULL,
		.local_port = -1,
		.remote_addr = NULL,
		.remote_port = -1,
		.first_endpoint = 0,
		.last_endpoint = 0,
		.bts_base = 0,
	};
}

/* Test if a given endpoint id is currently in use */
static bool endpoint_in_use(uint16_t id, struct mgcp_client *client)
{
	struct mgcp_inuse_endpoint *endpoint;
	llist_for_each_entry(endpoint, &client->inuse_endpoints, entry) {
		if (endpoint->id == id)
			return true;
	}

	return false;
}

/* Find and seize an unsused endpoint id */
int mgcp_client_next_endpoint(struct mgcp_client *client)
{
	int i;
	uint16_t first_endpoint = client->actual.first_endpoint;
	uint16_t last_endpoint = client->actual.last_endpoint;
	struct mgcp_inuse_endpoint *endpoint;

	/* Use the maximum permitted range if the VTY
	 * configuration does not specify a range */
	if (client->actual.last_endpoint == 0) {
		first_endpoint = 1;
		last_endpoint = 65534;
	}

	/* Test the permitted endpoint range for an endpoint
	 * number that is not in use. When a suitable endpoint
	 * number can be found, seize it by adding it to the
	 * inuse list. */
	for (i=first_endpoint;i<last_endpoint;i++)
	{
		if (endpoint_in_use(i,client) == false) {
			endpoint = talloc_zero(client, struct mgcp_inuse_endpoint);
			endpoint->id = i;
			llist_add_tail(&endpoint->entry, &client->inuse_endpoints);
			return endpoint->id;
		}
	}

	/* All endpoints are busy! */
	return -EINVAL;
}

/* Release a seized endpoint id to make it available again for other calls */
void mgcp_client_release_endpoint(uint16_t id, struct mgcp_client *client)
{
	struct mgcp_inuse_endpoint *endpoint;
	struct mgcp_inuse_endpoint *endpoint_tmp;
	llist_for_each_entry_safe(endpoint, endpoint_tmp, &client->inuse_endpoints, entry) {
		if (endpoint->id == id) {
			llist_del(&endpoint->entry);
			talloc_free(endpoint);
		}
	}
}

static void mgcp_client_handle_response(struct mgcp_client *mgcp,
					struct mgcp_response_pending *pending,
					struct mgcp_response *response)
{
	if (!pending) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "Cannot handle NULL response\n");
		return;
	}
	if (pending->response_cb)
		pending->response_cb(response, pending->priv);
	else
		LOGP(DLMGCP, LOGL_INFO, "MGCP response ignored (NULL cb)\n");
	talloc_free(pending);
}

static int mgcp_response_parse_head(struct mgcp_response *r, struct msgb *msg)
{
	int comment_pos;
	char *end;

	if (mgcp_msg_terminate_nul(msg))
		goto response_parse_failure;

	r->body = (char *)msg->data;

	if (sscanf(r->body, "%3d %u %n",
		   &r->head.response_code, &r->head.trans_id,
		   &comment_pos) != 2)
		goto response_parse_failure;

	r->head.comment = r->body + comment_pos;
	end = strchr(r->head.comment, '\r');
	if (!end)
		goto response_parse_failure;
	/* Mark the end of the comment */
	*end = '\0';
	r->body = end + 1;
	if (r->body[0] == '\n')
		r->body ++;
	return 0;

response_parse_failure:
	LOGP(DLMGCP, LOGL_ERROR,
	     "Failed to parse MGCP response header\n");
	return -EINVAL;
}

/* TODO undup against mgcp_protocol.c:mgcp_check_param() */
static bool mgcp_line_is_valid(const char *line)
{
	const size_t line_len = strlen(line);
	if (line[0] == '\0')
		return true;

	if (line_len < 2
	    || line[1] != '=') {
		LOGP(DLMGCP, LOGL_ERROR,
		     "Wrong MGCP option format: '%s'\n",
		     line);
		return false;
	}

	return true;
}

/* Parse a line like "m=audio 16002 RTP/AVP 98" */
static int mgcp_parse_audio_port(struct mgcp_response *r, const char *line)
{
	if (sscanf(line, "m=audio %hu",
		   &r->audio_port) != 1)
		goto response_parse_failure;

	if (r->audio_port == 0)
		goto response_parse_failure;

	return 0;

response_parse_failure:
	LOGP(DLMGCP, LOGL_ERROR,
	     "Failed to parse MGCP response header (audio port)\n");
	return -EINVAL;
}

/* Parse a line like "c=IN IP4 10.11.12.13" */
static int mgcp_parse_audio_ip(struct mgcp_response *r, const char *line)
{
	struct in_addr ip_test;

	if (strlen(line) < 16)
		goto response_parse_failure;

	/* The current implementation strictly supports IPV4 only ! */
	if (memcmp("c=IN IP4 ", line, 9) != 0)
		goto response_parse_failure;

	/* Extract IP-Address */
	osmo_strlcpy(r->audio_ip, line + 9, sizeof(r->audio_ip));

	/* Check IP-Address */
	if (inet_aton(r->audio_ip, &ip_test) == 0)
		goto response_parse_failure;

	return 0;

response_parse_failure:
	LOGP(DLMGCP, LOGL_ERROR,
	     "Failed to parse MGCP response header (audio ip)\n");
	return -EINVAL;
}

/* A new section is marked by a double line break, check a few more
 * patterns as there may be variants */
static char *mgcp_find_section_end(char *string)
{
	char *rc;

	rc = strstr(string, "\n\n");
	if (rc)
		return rc;

	rc = strstr(string, "\n\r\n\r");
	if (rc)
		return rc;

	rc = strstr(string, "\r\n\r\n");
	if (rc)
		return rc;

	return NULL;
}

int mgcp_response_parse_params(struct mgcp_response *r)
{
	char *line;
	int rc;
	OSMO_ASSERT(r->body);
	char *data = mgcp_find_section_end(r->body);

	if (!data) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "MGCP response: cannot find start of parameters\n");
		return -EINVAL;
	}

	/* Advance to after the \n\n, replace the second \n with \0. That's
	 * where the parameters start. */
	data ++;
	*data = '\0';
	data ++;

	for_each_non_empty_line(line, data) {
		if (!mgcp_line_is_valid(line))
			return -EINVAL;

		switch (line[0]) {
		case 'm':
			rc = mgcp_parse_audio_port(r, line);
			if (rc)
				return rc;
			break;
		case 'c':
			rc = mgcp_parse_audio_ip(r, line);
			if (rc)
				return rc;
			break;
		default:
			/* skip unhandled parameters */
			break;
		}
	}
	return 0;
}

/* Parse a line like "I: 0cedfd5a19542d197af9afe5231f1d61" */
static int mgcp_parse_conn_id(struct mgcp_response *r, const char *line)
{
	if (strlen(line) < 4)
		goto response_parse_failure;

	if (memcmp("I: ", line, 3) != 0)
		goto response_parse_failure;

	osmo_strlcpy(r->head.conn_id, line + 3, sizeof(r->head.conn_id));
	return 0;

response_parse_failure:
	LOGP(DLMGCP, LOGL_ERROR,
	     "Failed to parse MGCP response (connectionIdentifier)\n");
	return -EINVAL;
}

/* Parse MGCP parameters of the response */
static int parse_head_params(struct mgcp_response *r)
{
	char *line;
	int rc = 0;
	OSMO_ASSERT(r->body);
	char *data = r->body;
	char *data_end = mgcp_find_section_end(r->body);

	/* Protect SDP body, for_each_non_empty_line() will
	 * only parse until it hits \0 mark. */
	if (data_end)
		*data_end = '\0';

	for_each_non_empty_line(line, data) {
		switch (line[0]) {
		case 'I':
			rc = mgcp_parse_conn_id(r, line);
			if (rc)
				goto exit;
			break;
		default:
			/* skip unhandled parameters */
			break;
		}
	}
exit:
	/* Restore original state */
	if (data_end)
		*data_end = '\n';

	return rc;
}

static struct mgcp_response_pending *mgcp_client_response_pending_get(
					 struct mgcp_client *mgcp,
					 mgcp_trans_id_t trans_id)
{
	struct mgcp_response_pending *pending;
	llist_for_each_entry(pending, &mgcp->responses_pending, entry) {
		if (pending->trans_id == trans_id) {
			llist_del(&pending->entry);
			return pending;
		}
	}
	return NULL;
}

/* Feed an MGCP message into the receive processing.
 * Parse the head and call any callback registered for the transaction id found
 * in the MGCP message. This is normally called directly from the internal
 * mgcp_do_read that reads from the socket connected to the MGCP gateway. This
 * function is published mainly to be able to feed data from the test suite.
 */
int mgcp_client_rx(struct mgcp_client *mgcp, struct msgb *msg)
{
	struct mgcp_response r = { 0 };
	struct mgcp_response_pending *pending;
	int rc;

	rc = mgcp_response_parse_head(&r, msg);
	if (rc) {
		LOGP(DLMGCP, LOGL_ERROR, "Cannot parse MGCP response (head)\n");
		return -1;
	}

	rc = parse_head_params(&r);
	if (rc) {
		LOGP(DLMGCP, LOGL_ERROR, "Cannot parse MGCP response (head parameters)\n");
		return -1;
	}

	pending = mgcp_client_response_pending_get(mgcp, r.head.trans_id);
	if (!pending) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "Cannot find matching MGCP transaction for trans_id %d\n",
		     r.head.trans_id);
		return -ENOENT;
	}

	mgcp_client_handle_response(mgcp, pending, &r);
	return 0;
}

static int mgcp_do_read(struct osmo_fd *fd)
{
	struct mgcp_client *mgcp = fd->data;
	struct msgb *msg;
	int ret;

	msg = msgb_alloc_headroom(4096, 128, "mgcp_from_gw");
	if (!msg) {
		LOGP(DLMGCP, LOGL_ERROR, "Failed to allocate MGCP message.\n");
		return -1;
	}

	ret = read(fd->fd, msg->data, 4096 - 128);
	if (ret <= 0) {
		LOGP(DLMGCP, LOGL_ERROR, "Failed to read: %d/%s\n", errno, strerror(errno));
		msgb_free(msg);
		return -1;
	} else if (ret > 4096 - 128) {
		LOGP(DLMGCP, LOGL_ERROR, "Too much data: %d\n", ret);
		msgb_free(msg);
		return -1;
	}

	msg->l2h = msgb_put(msg, ret);
	ret = mgcp_client_rx(mgcp, msg);
	talloc_free(msg);
	return ret;
}

static int mgcp_do_write(struct osmo_fd *fd, struct msgb *msg)
{
	int ret;
	static char strbuf[4096];
	unsigned int l = msg->len < sizeof(strbuf) ? msg->len : sizeof(strbuf);
	unsigned int i;

	osmo_strlcpy(strbuf, (const char*)msg->data, l);
	for (i = 0; i < sizeof(strbuf); i++) {
		if (strbuf[i] == '\n' || strbuf[i] == '\r') {
			strbuf[i] = '\0';
			break;
		}
	}
	DEBUGP(DLMGCP, "Tx MGCP msg to MGCP GW: '%s'\n", strbuf);

	LOGP(DLMGCP, LOGL_DEBUG, "Sending msg to MGCP GW size: %u\n", msg->len);

	ret = write(fd->fd, msg->data, msg->len);
	if (ret != msg->len)
		LOGP(DLMGCP, LOGL_ERROR, "Failed to forward message to MGCP"
		     " GW: %s\n", strerror(errno));

	return ret;
}

struct mgcp_client *mgcp_client_init(void *ctx,
				     struct mgcp_client_conf *conf)
{
	struct mgcp_client *mgcp;

	mgcp = talloc_zero(ctx, struct mgcp_client);

	INIT_LLIST_HEAD(&mgcp->responses_pending);
	INIT_LLIST_HEAD(&mgcp->inuse_endpoints);

	mgcp->next_trans_id = 1;

	mgcp->actual.local_addr = conf->local_addr ? conf->local_addr :
		MGCP_CLIENT_LOCAL_ADDR_DEFAULT;
	mgcp->actual.local_port = conf->local_port >= 0 ? (uint16_t)conf->local_port :
		MGCP_CLIENT_LOCAL_PORT_DEFAULT;

	mgcp->actual.remote_addr = conf->remote_addr ? conf->remote_addr :
		MGCP_CLIENT_REMOTE_ADDR_DEFAULT;
	mgcp->actual.remote_port = conf->remote_port >= 0 ? (uint16_t)conf->remote_port :
		MGCP_CLIENT_REMOTE_PORT_DEFAULT;

	mgcp->actual.first_endpoint = conf->first_endpoint > 0 ? (uint16_t)conf->first_endpoint : 0;
	mgcp->actual.last_endpoint = conf->last_endpoint > 0 ? (uint16_t)conf->last_endpoint : 0;
	mgcp->actual.bts_base = conf->bts_base > 0 ? (uint16_t)conf->bts_base : 4000;

	return mgcp;
}

int mgcp_client_connect(struct mgcp_client *mgcp)
{
	struct sockaddr_in addr;
	struct osmo_wqueue *wq;
	int rc;

	if (!mgcp) {
		LOGP(DLMGCP, LOGL_FATAL, "MGCPGW client not initialized properly\n");
		return -EINVAL;
	}

	wq = &mgcp->wq;

	rc = osmo_sock_init2_ofd(&wq->bfd, AF_INET, SOCK_DGRAM, IPPROTO_UDP,
				 mgcp->actual.local_addr, mgcp->actual.local_port,
				 mgcp->actual.remote_addr, mgcp->actual.remote_port,
				 OSMO_SOCK_F_BIND | OSMO_SOCK_F_CONNECT);
	if (rc < 0) {
		LOGP(DLMGCP, LOGL_FATAL,
		     "Failed to initialize socket %s:%u -> %s:%u for MGCP GW: %s\n",
		     mgcp->actual.local_addr, mgcp->actual.local_port,
		     mgcp->actual.remote_addr, mgcp->actual.remote_port, strerror(errno));
		goto error_close_fd;
	}

	inet_aton(mgcp->actual.remote_addr, &addr.sin_addr);
	mgcp->remote_addr = htonl(addr.sin_addr.s_addr);

	osmo_wqueue_init(wq, 10);
	wq->bfd.when = BSC_FD_READ;
	wq->bfd.data = mgcp;
	wq->read_cb = mgcp_do_read;
	wq->write_cb = mgcp_do_write;

	LOGP(DLMGCP, LOGL_INFO, "MGCP GW connection: %s:%u -> %s:%u\n",
	     mgcp->actual.local_addr, mgcp->actual.local_port,
	     mgcp->actual.remote_addr, mgcp->actual.remote_port);

	return 0;
error_close_fd:
	close(wq->bfd.fd);
	wq->bfd.fd = -1;
	return rc;
}

const char *mgcp_client_remote_addr_str(struct mgcp_client *mgcp)
{
	return mgcp->actual.remote_addr;
}

uint16_t mgcp_client_remote_port(struct mgcp_client *mgcp)
{
	return mgcp->actual.remote_port;
}

/* Return the MGCP GW binary IPv4 address in network byte order. */
uint32_t mgcp_client_remote_addr_n(struct mgcp_client *mgcp)
{
	return mgcp->remote_addr;
}

struct mgcp_response_pending * mgcp_client_pending_add(
					struct mgcp_client *mgcp,
					mgcp_trans_id_t trans_id,
					mgcp_response_cb_t response_cb,
					void *priv)
{
	struct mgcp_response_pending *pending;

	pending = talloc_zero(mgcp, struct mgcp_response_pending);
	pending->trans_id = trans_id;
	pending->response_cb = response_cb;
	pending->priv = priv;
	llist_add_tail(&pending->entry, &mgcp->responses_pending);

	return pending;
}

/* Send the MGCP message in msg to the MGCP GW and handle a response with
 * response_cb. NOTE: the response_cb still needs to call
 * mgcp_response_parse_params(response) to get the parsed parameters -- to
 * potentially save some CPU cycles, only the head line has been parsed when
 * the response_cb is invoked.
 * Before the priv pointer becomes invalid, e.g. due to transaction timeout,
 * mgcp_client_cancel() needs to be called for this transaction.
 */
int mgcp_client_tx(struct mgcp_client *mgcp, struct msgb *msg,
		   mgcp_response_cb_t response_cb, void *priv)
{
	struct mgcp_response_pending *pending;
	mgcp_trans_id_t trans_id;
	int rc;

	trans_id = msg->cb[MSGB_CB_MGCP_TRANS_ID];
	if (!trans_id) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "Unset transaction id in mgcp send request\n");
		talloc_free(msg);
		return -EINVAL;
	}

	pending = mgcp_client_pending_add(mgcp, trans_id, response_cb, priv);

	if (msgb_l2len(msg) > 4096) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "Cannot send, MGCP message too large: %u\n",
		     msgb_l2len(msg));
		msgb_free(msg);
		rc = -EINVAL;
		goto mgcp_tx_error;
	}

	rc = osmo_wqueue_enqueue(&mgcp->wq, msg);
	if (rc) {
		LOGP(DLMGCP, LOGL_FATAL, "Could not queue message to MGCP GW\n");
		msgb_free(msg);
		goto mgcp_tx_error;
	} else
		LOGP(DLMGCP, LOGL_INFO, "Queued %u bytes for MGCP GW\n",
		     msgb_l2len(msg));
	return 0;

mgcp_tx_error:
	/* Pass NULL to response cb to indicate an error */
	mgcp_client_handle_response(mgcp, pending, NULL);
	return -1;
}

/* Cancel a pending transaction.
 * Should a priv pointer passed to mgcp_client_tx() become invalid, this function must be called. In
 * practical terms, if the caller of mgcp_client_tx() wishes to tear down a transaction without having
 * received a response this function must be called. The trans_id can be obtained by calling
 * mgcp_msg_trans_id() on the msgb produced by mgcp_msg_gen().
 */
int mgcp_client_cancel(struct mgcp_client *mgcp, mgcp_trans_id_t trans_id)
{
	struct mgcp_response_pending *pending = mgcp_client_response_pending_get(mgcp, trans_id);
	if (!pending) {
		/* INFO is sufficient, it is not harmful to cancel a transaction twice. */
		LOGP(DLMGCP, LOGL_INFO, "Cannot cancel, no such transaction: %u\n", trans_id);
		return -ENOENT;
	}
	LOGP(DLMGCP, LOGL_INFO, "Canceled transaction %u\n", trans_id);
	talloc_free(pending);
	return 0;
	/* We don't really need to clean up the wqueue: In all sane cases, the msgb has already been sent
	 * out and is no longer in the wqueue. If it still is in the wqueue, then sending MGCP messages
	 * per se is broken and the program should notice so by a full wqueue. Even if this was called
	 * before we had a chance to send out the message and it is still going to be sent, we will just
	 * ignore the reply to it later. Removing a msgb from the wqueue here would just introduce more
	 * bug surface in terms of failing to update wqueue API's counters or some such.
	 */
}

static struct msgb *mgcp_msg_from_buf(mgcp_trans_id_t trans_id,
				      const char *buf, int len)
{
	struct msgb *msg;

	if (len > (4096 - 128)) {
		LOGP(DLMGCP, LOGL_ERROR, "Cannot send to MGCP GW:"
		     " message too large: %d\n", len);
		return NULL;
	}

	msg = msgb_alloc_headroom(4096, 128, "MGCP tx");
	OSMO_ASSERT(msg);

	char *dst = (char*)msgb_put(msg, len);
	memcpy(dst, buf, len);
	msg->l2h = msg->data;
	msg->cb[MSGB_CB_MGCP_TRANS_ID] = trans_id;

	return msg;
}

static struct msgb *mgcp_msg_from_str(mgcp_trans_id_t trans_id,
				      const char *fmt, ...)
{
	static char compose[4096 - 128];
	va_list ap;
	int len;
	OSMO_ASSERT(fmt);

	va_start(ap, fmt);
	len = vsnprintf(compose, sizeof(compose), fmt, ap);
	va_end(ap);
	if (len >= sizeof(compose)) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "Message too large: trans_id=%u len=%d\n",
		     trans_id, len);
		return NULL;
	}
	if (len < 1) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "Failed to compose message: trans_id=%u len=%d\n",
		     trans_id, len);
		return NULL;
	}
	return mgcp_msg_from_buf(trans_id, compose, len);
}

static mgcp_trans_id_t mgcp_client_next_trans_id(struct mgcp_client *mgcp)
{
	/* avoid zero trans_id to distinguish from unset trans_id */
	if (!mgcp->next_trans_id)
		mgcp->next_trans_id ++;
	return mgcp->next_trans_id ++;
}

struct msgb *mgcp_msg_crcx(struct mgcp_client *mgcp,
			   uint16_t rtp_endpoint, unsigned int call_id,
			   enum mgcp_connection_mode mode)
{
	mgcp_trans_id_t trans_id = mgcp_client_next_trans_id(mgcp);
	return mgcp_msg_from_str(trans_id,
		 "CRCX %u %x@mgw MGCP 1.0\r\n"
		 "C: %x\r\n"
		 "L: p:20, a:AMR, nt:IN\r\n"
		 "M: %s\r\n"
		 ,
		 trans_id,
		 rtp_endpoint,
		 call_id,
		 mgcp_client_cmode_name(mode));
}

struct msgb *mgcp_msg_mdcx(struct mgcp_client *mgcp,
			   uint16_t rtp_endpoint, const char *rtp_conn_addr,
			   uint16_t rtp_port, enum mgcp_connection_mode mode)

{
	mgcp_trans_id_t trans_id = mgcp_client_next_trans_id(mgcp);
	return mgcp_msg_from_str(trans_id,
		 "MDCX %u %x@mgw MGCP 1.0\r\n"
		 "M: %s\r\n"
		 "\r\n"
		 "c=IN IP4 %s\r\n"
		 "m=audio %u RTP/AVP 255\r\n"
		 ,
		 trans_id,
		 rtp_endpoint,
		 mgcp_client_cmode_name(mode),
		 rtp_conn_addr,
		 rtp_port);
}

struct msgb *mgcp_msg_dlcx(struct mgcp_client *mgcp, uint16_t rtp_endpoint,
			   unsigned int call_id)
{
	mgcp_trans_id_t trans_id = mgcp_client_next_trans_id(mgcp);
	return mgcp_msg_from_str(trans_id,
				 "DLCX %u %x@mgw MGCP 1.0\r\n"
				 "C: %x\r\n", trans_id, rtp_endpoint, call_id);
}

#define MGCP_CRCX_MANDATORY (MGCP_MSG_PRESENCE_ENDPOINT | \
			     MGCP_MSG_PRESENCE_CALL_ID | \
			     MGCP_MSG_PRESENCE_CONN_MODE)
#define MGCP_MDCX_MANDATORY (MGCP_MSG_PRESENCE_ENDPOINT | \
			     MGCP_MSG_PRESENCE_CALL_ID |  \
			     MGCP_MSG_PRESENCE_CONN_ID)
#define MGCP_DLCX_MANDATORY (MGCP_MSG_PRESENCE_ENDPOINT)
#define MGCP_AUEP_MANDATORY (MGCP_MSG_PRESENCE_ENDPOINT)
#define MGCP_RSIP_MANDATORY 0	/* none */

struct msgb *mgcp_msg_gen(struct mgcp_client *mgcp, struct mgcp_msg *mgcp_msg)
{
	mgcp_trans_id_t trans_id = mgcp_client_next_trans_id(mgcp);
	uint32_t mandatory_mask;
	struct msgb *msg = msgb_alloc_headroom(4096, 128, "MGCP tx");
	int rc = 0;
	char local_ip[INET_ADDRSTRLEN];

	msg->l2h = msg->data;
	msg->cb[MSGB_CB_MGCP_TRANS_ID] = trans_id;

	/* Add command verb */
	switch (mgcp_msg->verb) {
	case MGCP_VERB_CRCX:
		mandatory_mask = MGCP_CRCX_MANDATORY;
		rc += msgb_printf(msg, "CRCX %u", trans_id);
		break;
	case MGCP_VERB_MDCX:
		mandatory_mask = MGCP_MDCX_MANDATORY;
		rc += msgb_printf(msg, "MDCX %u", trans_id);
		break;
	case MGCP_VERB_DLCX:
		mandatory_mask = MGCP_DLCX_MANDATORY;
		rc += msgb_printf(msg, "DLCX %u", trans_id);
		break;
	case MGCP_VERB_AUEP:
		mandatory_mask = MGCP_AUEP_MANDATORY;
		rc += msgb_printf(msg, "AUEP %u", trans_id);
		break;
	case MGCP_VERB_RSIP:
		mandatory_mask = MGCP_RSIP_MANDATORY;
		rc += msgb_printf(msg, "RSIP %u", trans_id);
		break;
	default:
		LOGP(DLMGCP, LOGL_ERROR,
		     "Invalid command verb, can not generate MGCP message\n");
		msgb_free(msg);
		return NULL;
	}

	/* Check if mandatory fields are missing */
	if (!((mgcp_msg->presence & mandatory_mask) == mandatory_mask)) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "One or more missing mandatory fields, can not generate MGCP message\n");
		msgb_free(msg);
		return NULL;
	}

	/* Add endpoint name */
	if (mgcp_msg->presence & MGCP_MSG_PRESENCE_ENDPOINT) {
		if (strlen(mgcp_msg->endpoint) <= 0) {
			LOGP(DLMGCP, LOGL_ERROR,
			     "Empty endpoint name, can not generate MGCP message\n");
			msgb_free(msg);
			return NULL;
		}
		rc += msgb_printf(msg, " %s", mgcp_msg->endpoint);
	}

	/* Add protocol version */
	rc += msgb_printf(msg, " MGCP 1.0\r\n");

	/* Add call id */
	if (mgcp_msg->presence & MGCP_MSG_PRESENCE_CALL_ID)
		rc += msgb_printf(msg, "C: %x\r\n", mgcp_msg->call_id);

	/* Add connection id */
	if (mgcp_msg->presence & MGCP_MSG_PRESENCE_CONN_ID) {
		if (strlen(mgcp_msg->conn_id) <= 0) {
			LOGP(DLMGCP, LOGL_ERROR,
			     "Empty connection id, can not generate MGCP message\n");
			msgb_free(msg);
			return NULL;
		}
		rc += msgb_printf(msg, "I: %s\r\n", mgcp_msg->conn_id);
	}

	/* Add local connection options */
	if (mgcp_msg->verb == MGCP_VERB_CRCX)
		rc += msgb_printf(msg, "L: p:20, a:AMR, nt:IN\r\n");

	/* Add mode */
	if (mgcp_msg->presence & MGCP_MSG_PRESENCE_CONN_MODE)
		rc +=
		    msgb_printf(msg, "M: %s\r\n",
				mgcp_client_cmode_name(mgcp_msg->conn_mode));

	/* Add SDP body */
	if (mgcp_msg->presence & MGCP_MSG_PRESENCE_AUDIO_IP
	    && mgcp_msg->presence & MGCP_MSG_PRESENCE_AUDIO_PORT) {

		/* Add separator to mark the beginning of the SDP block */
		rc += msgb_printf(msg, "\r\n");

		/* Add SDP protocol version */
		rc += msgb_printf(msg, "v=0\r\n");

		/* Add session name (none) */
		rc += msgb_printf(msg, "s=-\r\n");

		/* Determine local IP-Address */
		if (osmo_sock_local_ip(local_ip, mgcp->actual.remote_addr) < 0) {
			LOGP(DLMGCP, LOGL_ERROR,
			     "Could not determine local IP-Address!\n");
			msgb_free(msg);
			return NULL;
		}

		/* Add owner/creator (SDP) */
		rc += msgb_printf(msg, "o=- %x 23 IN IP4 %s\r\n",
				  mgcp_msg->call_id, local_ip);

		/* Add RTP address and port */
		if (mgcp_msg->audio_port == 0) {
			LOGP(DLMGCP, LOGL_ERROR,
			     "Invalid port number, can not generate MGCP message\n");
			msgb_free(msg);
			return NULL;
		}
		if (strlen(mgcp_msg->audio_ip) <= 0) {
			LOGP(DLMGCP, LOGL_ERROR,
			     "Empty ip address, can not generate MGCP message\n");
			msgb_free(msg);
			return NULL;
		}
		rc += msgb_printf(msg, "c=IN IP4 %s\r\n", mgcp_msg->audio_ip);
		rc +=
		    msgb_printf(msg, "m=audio %u RTP/AVP 255\r\n",
				mgcp_msg->audio_port);

		/* Add time description, active time (SDP) */
		rc += msgb_printf(msg, "t=0 0\r\n");
	}

	if (rc != 0) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "message buffer to small, can not generate MGCP message\n");
		msgb_free(msg);
		msg = NULL;
	}

	return msg;
}

/* Retrieve the MGCP transaction ID from a msgb generated by mgcp_msg_gen() */
mgcp_trans_id_t mgcp_msg_trans_id(struct msgb *msg)
{
	return (mgcp_trans_id_t)msg->cb[MSGB_CB_MGCP_TRANS_ID];
}

struct mgcp_client_conf *mgcp_client_conf_actual(struct mgcp_client *mgcp)
{
	return &mgcp->actual;
}

const struct value_string mgcp_client_connection_mode_strs[] = {
	{ MGCP_CONN_NONE, "none" },
	{ MGCP_CONN_RECV_SEND, "sendrecv" },
	{ MGCP_CONN_SEND_ONLY, "sendonly" },
	{ MGCP_CONN_RECV_ONLY, "recvonly" },
	{ MGCP_CONN_LOOPBACK, "loopback" },
	{ 0, NULL }
};

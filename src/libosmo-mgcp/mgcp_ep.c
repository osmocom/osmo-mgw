/* Endpoint types */

/*
 * (C) 2017 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Philipp Maier
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

#include <osmocom/mgcp/mgcp_internal.h>
#include <osmocom/mgcp/mgcp_ep.h>

/* Endpoint typeset definition */
const struct mgcp_endpoint_typeset ep_typeset = {
	/* Specify endpoint properties for RTP endpoint */
	.rtp.max_conns = 2,
	.rtp.dispatch_rtp_cb = mgcp_dispatch_rtp_bridge_cb
};

/*! release endpoint, all open connections are closed.
 *  \param[in] endp endpoint to release */
void mgcp_release_endp(struct mgcp_endpoint *endp)
{
	LOGP(DLMGCP, LOGL_DEBUG, "Releasing endpoint:0x%x\n",
	     ENDPOINT_NUMBER(endp));

	/* Normally this function should only be called when
	 * all connections have been removed already. In case
	 * that there are still connections open (e.g. when
	 * RSIP is executed), free them all at once. */
	mgcp_conn_free_all(endp);

	/* Reset endpoint parameters and states */
	talloc_free(endp->callid);
	endp->callid = NULL;
	talloc_free(endp->local_options.string);
	endp->local_options.string = NULL;
	talloc_free(endp->local_options.codec);
	endp->local_options.codec = NULL;
	endp->wildcarded_crcx = false;
}

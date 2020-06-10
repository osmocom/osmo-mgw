/* Endpoint types */

/*
 * (C) 2017-2020 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
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
#include <osmocom/mgcp/mgcp_endp.h>
#include <osmocom/mgcp/mgcp_trunk.h>

/* Endpoint typeset definition */
const struct mgcp_endpoint_typeset ep_typeset = {
	/* Specify endpoint properties for RTP endpoint */
	.rtp = {
		.max_conns = 2,
		.dispatch_rtp_cb = mgcp_dispatch_rtp_bridge_cb,
		.cleanup_cb = mgcp_cleanup_rtp_bridge_cb,
	},
	/* Specify endpoint properties for E1 endpoint */
	.e1 = {
		.max_conns = 1,
		.dispatch_rtp_cb = mgcp_dispatch_e1_bridge_cb,
		.cleanup_cb = mgcp_cleanup_e1_bridge_cb,
	},
};

/* Generate virtual endpoint name from given parameters */
static char *gen_virtual_epname(void *ctx, const char *domain,
			       unsigned int index)
{
	return talloc_asprintf(ctx, "%s%x@%s",
		 MGCP_ENDPOINT_PREFIX_VIRTUAL_TRUNK, index, domain);
}

/* Generate E1 endpoint name from given numeric parameters */
static char *gen_e1_epname(void *ctx, uint8_t trunk_nr, uint8_t ts_nr,
			  uint8_t ss_nr)
{
	/* A 64k timeslot on an E1 line can be subdevied into the following
	 * subslot combinations:
	 *
	 * subslot:                                          offset:
	 * [          ][          ][   16k    ][8k_subslot]  0
	 * [          ][   32k    ][_subslot__][8k_subslot]  1
	 * [          ][ subslot  ][   16k    ][8k_subslot]  2
	 * [   64k    ][__________][_subslot__][8k_subslot]  3
	 * [ timeslot ][          ][   16k    ][8k_subslot]  4
	 * [          ][   32K    ][_subslot__][8k_subslot]  5
	 * [          ][ subslot  ][   16k    ][8k_subslot]  6
	 * [          ][          ][ subslot  ][8k_subslot]  7
	 *
	 * Since overlapping assignment of subsolts is not possible there is
	 * a limited set of subsolt assignments possible. The rates array
	 * lists the possible assignments as depicted above. Also each subslot
	 * assignment comes along with a bit offset in the E1 bitstream. The
	 * offsets arrays lists the bit offsets. */
	static const uint8_t rates[] =
		{ 64, 32, 32, 16, 16, 16, 16, 8, 8, 8, 8, 8, 8, 8, 8 };
	static const uint8_t offsets[] =
		{ 0, 0, 4, 0, 2, 4, 6, 0, 1, 2, 3, 4, 5, 6, 7 };
	unsigned int rate;
	unsigned int offset;

	OSMO_ASSERT(ss_nr < sizeof(rates));

	rate = rates[ss_nr];
	offset = offsets[ss_nr];

	return talloc_asprintf(ctx, "%s%u/s-%u/su%u-%u",
			MGCP_ENDPOINT_PREFIX_E1_TRUNK, trunk_nr, ts_nr, rate, offset);
}

/*! allocate an endpoint and set default values.
 *  \param[in] trunk configuration.
 *  \param[in] name endpoint index.
 *  \returns endpoint on success, NULL on failure. */
struct mgcp_endpoint *mgcp_endp_alloc(struct mgcp_trunk *trunk,
				      unsigned int index)
{
	struct mgcp_endpoint *endp;

	endp = talloc_zero(trunk->endpoints, struct mgcp_endpoint);
	if (!endp)
		return NULL;

	INIT_LLIST_HEAD(&endp->conns);
	endp->cfg = trunk->cfg;
	endp->trunk = trunk;

	switch (trunk->trunk_type) {
	case MGCP_TRUNK_VIRTUAL:
		endp->type = &ep_typeset.rtp;
		endp->name = gen_virtual_epname(endp, trunk->cfg->domain, index);
		break;
	case MGCP_TRUNK_E1:
		endp->type = &ep_typeset.rtp;
		endp->name = gen_e1_epname(endp, trunk->trunk_nr, index / 15, index % 15);
		break;
	default:
		osmo_panic("Cannot allocate unimplemented trunk type %d! %s:%d\n",
			   trunk->trunk_type, __FILE__, __LINE__);
	}

	return endp;
}

/*! release endpoint, all open connections are closed.
 *  \param[in] endp endpoint to release */
void mgcp_endp_release(struct mgcp_endpoint *endp)
{
	LOGPENDP(endp, DLMGCP, LOGL_DEBUG, "Releasing endpoint\n");

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
	endp->wildcarded_req = false;
}

/* Check if the endpoint name contains the prefix (e.g. "rtpbridge/" or
 * "ds/e1-") and write the epname without the prefix back to the memory
 * pointed at by epname. (per trunk the prefix is the same for all endpoints,
 * so no ambiguity is introduced) */
static void chop_epname_prefix(char *epname, const struct mgcp_trunk *trunk)
{
	size_t prefix_len;
	switch (trunk->trunk_type) {
	case MGCP_TRUNK_VIRTUAL:
		prefix_len = sizeof(MGCP_ENDPOINT_PREFIX_VIRTUAL_TRUNK) - 1;
		if (strncmp
		    (epname, MGCP_ENDPOINT_PREFIX_VIRTUAL_TRUNK,
		     prefix_len) == 0)
			memmove(epname, epname + prefix_len,
				strlen(epname) - prefix_len + 1);
		return;
	case MGCP_TRUNK_E1:
		prefix_len = sizeof(MGCP_ENDPOINT_PREFIX_E1_TRUNK) - 1;
		if (strncmp
		    (epname, MGCP_ENDPOINT_PREFIX_VIRTUAL_TRUNK,
		     prefix_len) == 0)
			memmove(epname, epname + prefix_len,
				strlen(epname) - prefix_len + 1);
		return;
	default:
		OSMO_ASSERT(false);
	}
}

/* Check if the endpoint name contains a suffix (e.g. "@mgw") and truncate
 * epname by writing a '\0' char where the suffix starts. */
static void chop_epname_suffix(char *epname, const struct mgcp_trunk *trunk)
{
	char *suffix_begin;

	/* Endpoints on the virtual trunk may have a domain name that is
	 * followed after an @ character, this can be chopped off. All
	 * other supported trunk types do not have any suffixes that may
	 * be chopped off */
	if (trunk->trunk_type == MGCP_TRUNK_VIRTUAL) {
		suffix_begin = strchr(epname, '@');
		if (!suffix_begin)
			return;
		*suffix_begin = '\0';
	}
}

/* Convert all characters in epname to lowercase and strip trunk prefix and
 * endpoint name suffix (domain name) from epname. The result is written to
 * to the memory pointed at by epname_stripped. The expected size of the
 * result is either equal or lower then the length of the input string
 * (epname) */
static void strip_epname(char *epname_stripped, const char *epname,
			 const struct mgcp_trunk *trunk)
{
	osmo_str_tolower_buf(epname_stripped, MGCP_ENDPOINT_MAXLEN, epname);
	chop_epname_prefix(epname_stripped, trunk);
	chop_epname_suffix(epname_stripped, trunk);
}

/* Go through the trunk and find a random free (no active calls) endpoint,
 * this function is called when a wildcarded request is carried out, which
 * means that it is up to the MGW to choose a random free endpoint. */
static struct mgcp_endpoint *find_free_endpoint(const struct mgcp_trunk *trunk)
{
	struct mgcp_endpoint *endp;
	unsigned int i;

	for (i = 0; i < trunk->number_endpoints; i++) {
		endp = trunk->endpoints[i];
		if (endp->callid == NULL)
			return endp;
	}

	return NULL;
}

/* Find an endpoint specified by its name. If the endpoint can not be found,
 * return NULL */
static struct mgcp_endpoint *find_specific_endpoint(const char *epname,
						    const struct mgcp_trunk *trunk)
{
	char epname_stripped[MGCP_ENDPOINT_MAXLEN];
	char epname_stripped_endp[MGCP_ENDPOINT_MAXLEN];
	struct mgcp_endpoint *endp;
	unsigned int i;

	/* Strip irrelevant information from the endpoint name */
	strip_epname(epname_stripped, epname, trunk);

	for (i = 0; i < trunk->number_endpoints; i++) {
		endp = trunk->endpoints[i];
		strip_epname(epname_stripped_endp, endp->name, trunk);
		if (strcmp(epname_stripped_endp, epname_stripped) == 0)
			return endp;
	}

	return NULL;
}

/*! Find an endpoint by its name on a specified trunk.
 *  \param[out] cause pointer to store cause code, can be NULL.
 *  \param[in] epname endpoint name to lookup.
 *  \param[in] trunk where the endpoint is located.
 *  \returns endpoint or NULL if endpoint was not found. */
struct mgcp_endpoint *mgcp_endp_by_name_trunk(int *cause, const char *epname,
					      const struct mgcp_trunk *trunk)
{
	struct mgcp_endpoint *endp;

	if (cause)
		*cause = 0;

	/* At the moment we only support a primitive ('*'-only) method of
	 * wildcarded endpoint searches that picks the next free endpoint on
	 * a trunk. */
	if (strstr(epname, "*")) {
		endp = find_free_endpoint(trunk);
		if (endp) {
			LOGPENDP(endp, DLMGCP, LOGL_DEBUG,
				 "(trunk:%d) found free endpoint: %s\n",
				 trunk->trunk_nr, endp->name);
			endp->wildcarded_req = true;
			return endp;
		}

		LOGP(DLMGCP, LOGL_ERROR,
		     "(trunk:%d) Not able to find a free endpoint\n",
		     trunk->trunk_nr);
		if (cause)
			*cause = -403;
		return NULL;
	}

	/* Find an endpoint by its name (if wildcarded request is not
	 * applicable) */
	endp = find_specific_endpoint(epname, trunk);
	if (endp) {
		LOGPENDP(endp, DLMGCP, LOGL_DEBUG,
			 "(trunk:%d) found endpoint: %s\n",
			 trunk->trunk_nr, endp->name);
		endp->wildcarded_req = false;
		return endp;
	}

	LOGP(DLMGCP, LOGL_ERROR,
	     "(trunk:%d) Not able to find specified endpoint: %s\n",
	     trunk->trunk_nr, epname);
	if (cause)
		*cause = -500;

	return NULL;
}

/* Check if the domain name, which is supplied with the endpoint name
 * matches the configuration. */
static int check_domain_name(const char *epname, struct mgcp_config *cfg)
{
	char *domain_to_check;

	domain_to_check = strstr(epname, "@");
	if (!domain_to_check) {
		LOGP(DLMGCP, LOGL_ERROR, "missing domain name in endpoint name \"%s\", expecting \"%s\"\n",
		     epname, cfg->domain);
		return -EINVAL;
	}

	/* Accept any domain if configured as "*" */
	if (!strcmp(cfg->domain, "*"))
		return 0;

	if (strcmp(domain_to_check+1, cfg->domain) != 0) {
		LOGP(DLMGCP, LOGL_ERROR, "wrong domain name in endpoint name \"%s\", expecting \"%s\"\n",
		     epname, cfg->domain);
		return -EINVAL;
	}

	return 0;
}

/*! Find an endpoint by its name, search at all trunks.
 *  \param[out] cause, pointer to store cause code, can be NULL.
 *  \param[in] epname, must contain trunk prefix.
 *  \param[in] cfg, mgcp configuration (trunks).
 *  \returns endpoint or NULL if endpoint was not found. */
struct mgcp_endpoint *mgcp_endp_by_name(int *cause, const char *epname,
					struct mgcp_config *cfg)
{
	struct mgcp_trunk *trunk;
	struct mgcp_endpoint *endp;
	char epname_lc[MGCP_ENDPOINT_MAXLEN];

	osmo_str_tolower_buf(epname_lc, sizeof(epname_lc), epname);
	epname = epname_lc;

	if (cause)
		*cause = -500;

	/* Identify the trunk where the endpoint is located */
	trunk = mgcp_trunk_by_name(cfg, epname);
	if (!trunk)
		return NULL;

	/* Virtual endpoints require a domain name (see RFC3435, section E.3) */
	  if (trunk->trunk_type == MGCP_TRUNK_VIRTUAL) {
		  if (check_domain_name(epname, cfg))
			return NULL;
	}

	/* Identify the endpoint on the trunk */
        endp = mgcp_endp_by_name_trunk(cause, epname, trunk);
	if (!endp) {
		return NULL;
	}

	if (cause)
		*cause = 0;
	return endp;
}

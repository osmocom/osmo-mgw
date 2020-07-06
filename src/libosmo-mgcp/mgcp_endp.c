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

#include <osmocom/mgcp/mgcp_e1.h>

#define E1_TIMESLOTS 32
#define E1_RATE_MAX 64
#define E1_OFFS_MAX 8

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
static char *gen_e1_epname(void *ctx, const char *domain, uint8_t trunk_nr,
			   uint8_t ts_nr, uint8_t ss_nr)
{
	unsigned int rate;
	unsigned int offset;

	OSMO_ASSERT(ss_nr < sizeof(e1_rates));

	rate = e1_rates[ss_nr];
	offset = e1_offsets[ss_nr];

	return talloc_asprintf(ctx, "%s%u/s-%u/su%u-%u@%s",
			       MGCP_ENDPOINT_PREFIX_E1_TRUNK, trunk_nr, ts_nr,
			       rate, offset, domain);
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
		endp->type = &ep_typeset.e1;
		endp->name = gen_e1_epname(endp, trunk->cfg->domain,
					   trunk->trunk_nr,
					   index / MGCP_ENDP_E1_SUBSLOTS, index % MGCP_ENDP_E1_SUBSLOTS);
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

	if (endp->trunk->trunk_type == MGCP_TRUNK_E1)
		mgcp_e1_endp_release(endp);
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
		/* A free endpoint must not serve a call already and it must
		 * be available. */
		if (endp->callid == NULL && mgcp_endp_avail(endp))
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

	/* All endpoint names require a domain as suffix */
	if (check_domain_name(epname, cfg))
		return NULL;

	/* Identify the endpoint on the trunk */
        endp = mgcp_endp_by_name_trunk(cause, epname, trunk);
	if (!endp) {
		return NULL;
	}

	if (cause)
		*cause = 0;
	return endp;
}

/* Get the E1 timeslot number from a given E1 endpoint name
 * (e.g. ds/e1-0/s-30/su16-4), returns 0xff on error. */
static uint8_t e1_ts_nr_from_epname(const char *epname)
{
	char buf[MGCP_ENDPOINT_MAXLEN + 1];
	char *save_ptr = NULL;
	char *buf_ptr = buf;
	char *token;
	unsigned long int res = 0;

	strncpy(buf, epname, MGCP_ENDPOINT_MAXLEN);

	while (1) {
		token = strtok_r(buf_ptr, "/", &save_ptr);
		buf_ptr = NULL;
		if (!token)
			break;
		if (strncmp(token, "s-", 2) == 0) {
			errno = 0;
			res = strtoul(token + 2, NULL, 10);
			if (errno == ERANGE || res > E1_TIMESLOTS)
				return 0xff;
			return (uint8_t) res;
		}
	}

	return 0xff;
}

/* Get the E1 timeslot number from a given E1 endpoint name
 * (e.g. ds/e1-0/s-30/su16-4), returns 0xff on error. */
static uint8_t e1_rate_from_epname(const char *epname)
{
	char buf[MGCP_ENDPOINT_MAXLEN + 1];
	char *save_ptr = NULL;
	char *buf_ptr = buf;
	char *token;
	unsigned long int res = 0;
	unsigned int i;

	strncpy(buf, epname, MGCP_ENDPOINT_MAXLEN);

	while (1) {
		token = strtok_r(buf_ptr, "/", &save_ptr);
		buf_ptr = NULL;
		if (!token)
			break;
		if (strncmp(token, "su", 2) == 0) {
			errno = 0;
			res = strtoul(token + 2, NULL, 10);
			if (errno == ERANGE || res > E1_RATE_MAX)
				return 0xff;
			/* Make sure the rate is a valid rate */
			for (i = 0; i < sizeof(e1_rates); i++) {
				if (res == e1_rates[i])
					return (uint8_t) res;
			}
			return 0xff;
		}
	}

	return 0xff;
}

/* Get the E1 bitstream offset from a given E1 endpoint name
 * (e.g. ds/e1-0/s-30/su16-4), returns 0xff on error. */
static uint8_t e1_offs_from_epname(const char *epname)
{
	char buf[MGCP_ENDPOINT_MAXLEN + 1];
	char *save_ptr = NULL;
	char *buf_ptr = buf;
	char *token;
	unsigned long int res = 0;

	strncpy(buf, epname, MGCP_ENDPOINT_MAXLEN);

	while (1) {
		token = strtok_r(buf_ptr, "/", &save_ptr);
		buf_ptr = NULL;
		if (!token)
			break;
		if (strncmp(token, "su", 2) == 0) {
			token = strstr(token, "-");
			if (!token)
				return 0xff;
			token += 1;
			errno = 0;
			res = strtoul(token, NULL, 10);
			if (errno == ERANGE || res > E1_OFFS_MAX)
				return 0xff;
			return (uint8_t) res;
		}
	}

	return 0xff;
}

/* Get the E1 subslot number (internal) from a given E1 endpoint name
 * (e.g. ds/e1-0/s-30/su16-4), returns 0xff on error. */
static uint8_t e1_ss_nr_from_epname(const char *epname)
{
	uint8_t rate;
	uint8_t offs;
	unsigned int i;

	rate = e1_rate_from_epname(epname);
	offs = e1_offs_from_epname(epname);

	osmo_static_assert(sizeof(e1_rates) == sizeof(e1_offsets), e1_rates_e1_offsets_size);

	for (i = 0; i < sizeof(e1_rates); i++) {
		if ((e1_rates[i] == rate) && (e1_offsets[i] == offs))
			return i;
	}

	return 0xff;
}

/* Check if the selected E1 endpoint is avalable, which means that none of
 * the overlapping endpoints are currently serving a call. (if the system
 * is properly configured such a situation should never ocurr!) */
static bool endp_avail_e1(struct mgcp_endpoint *endp)
{
	/* The following map shows the overlapping of the subslots and their
	 * respective rates. The numbers on the right running from top to bottom
	 * are the bit offsets in the whole 64k timeslot. The numbers inside the
	 * boxes symbolize the internal subslot number (array index) and the
	 * rate in the form: i:r where i is the subslot number and r the
	 * respective rate.
	 *
	 * +--------+--------+--------+--------+ 0
	 * |        |        |        |  7:8k  |
	 * |        |        + 3:16k  +--------+ 1
	 * |        |        |        |  8:8k  |
	 * |        | 1:32k  +--------+--------+ 2
	 * |        |        |        |  9:8k  |
	 * |        |        + 4:16k  +--------+ 3
	 * |        |        |        | 10:8k  |
	 * | 0:64k  +--------+--------+--------+ 4
	 * |        |        |        | 11:8k  |
	 * |        |        + 5:16k  +--------+ 5
	 * |        |        |        | 12:8k  |
	 * |        | 2:32k  +--------+--------+ 6
	 * |        |        |        | 13:8k  |
	 * |        |        + 6:16k  +--------+ 7
	 * |        |        |        | 14:8k  |
	 * +--------+--------+--------+--------+ 8
	 *
	 * The following array contains tables with the subslot numbers that must be
	 * unused for each subslot. During this test we do not have to check the
	 * endpoint we need to verify, only the overlaps need to be checked. This is
	 * also the reason why the related subslot number is missing from each each
	 * line. */
	const int8_t interlock_tab[MGCP_ENDP_E1_SUBSLOTS][15] = {
		{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, -1 },
		{ 0, 3, 4, 7, 8, 9, 10, -1, -1, -1, -1, -1, -1, -1, -1 },
		{ 0, 5, 6, 11, 12, 13, 14, -1, -1, -1, -1, -1, -1, -1, -1 },
		{ 0, 1, 7, 8, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
		{ 0, 1, 9, 10, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
		{ 0, 2, 11, 12, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
		{ 0, 2, 13, 14, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
		{ 0, 1, 3, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
		{ 0, 1, 3, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
		{ 0, 1, 4, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
		{ 0, 1, 4, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
		{ 0, 2, 5, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
		{ 0, 2, 5, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
		{ 0, 2, 6, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
		{ 0, 2, 6, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 } };

	const int8_t *interlock;
	unsigned int i;
	uint8_t ts_nr = 0;
	uint8_t ss_nr = 0;
	char *epname_check;
	struct mgcp_endpoint *endp_check;
	bool available = true;

	/* This function must only be used with E1 type endpoints! */
	OSMO_ASSERT(endp->trunk->trunk_type == MGCP_TRUNK_E1);

	ts_nr = e1_ts_nr_from_epname(endp->name);
	ss_nr = e1_ss_nr_from_epname(endp->name);
	if (ts_nr == 0xff || ss_nr == 0xff) {
		LOGPENDP(endp, DLMGCP, LOGL_ERROR,
			 "cannot check endpoint availability, endpoint name not parseable!\n");
		return false;
	}

	interlock = interlock_tab[ss_nr];

	for (i = 0; i < sizeof(interlock_tab[0]); i++) {
		/* Detect row end */
		if (interlock[i] == -1)
			break;

		/* Pick overlapping endpoint to check */
		epname_check = gen_e1_epname(endp, endp->trunk->cfg->domain,
					     endp->trunk->trunk_nr, ts_nr,
					     interlock[i]);
		endp_check = find_specific_endpoint(epname_check, endp->trunk);
		if (!endp_check) {
			LOGPENDP(endp, DLMGCP, LOGL_ERROR,
				 "cannot check endpoint availability, overlapping endpoint:%s not found!\n",
				 epname_check);
			talloc_free(epname_check);
			continue;
		}
		talloc_free(epname_check);

		/* Check if overlapping endpoint currently serves another call
		 * (This is an exceptional situation, that should not occur
		 * in a properly configured environment!) */
		if (endp_check->callid) {
			LOGPENDP(endp, DLMGCP, LOGL_ERROR,
				 "endpoint unavailable - overlapping endpoint:%s already serves a call!\n",
				 endp_check->name);
			available = false;
		}
	}

	return available;
}

/*! check if an endpoint is available for any kind of operation.
 *  \param[in] endp endpoint to check.
 *  \returns true if endpoint is avalable, false it is blocked for any reason. */
bool mgcp_endp_avail(struct mgcp_endpoint *endp)
{
	switch (endp->trunk->trunk_type) {
	case MGCP_TRUNK_VIRTUAL:
		/* There are no obstacles that may render a virtual trunk
		 * endpoint unusable, so virtual trunk endpoints are always
		 * available */
		return true;
	case MGCP_TRUNK_E1:
		return endp_avail_e1(endp);
	default:
		OSMO_ASSERT(false);
	}

	return false;
}

/*! claim endpoint, sets callid and activates endpoint, should be called at the
 *  beginning of the CRCX procedure when it is clear that a new call should be
 *  created.
 *  \param[in] endp endpoint to claim.
 *  \param[in] callid that is assingned to this endpoint. */
int mgcp_endp_claim(struct mgcp_endpoint *endp, const char *callid)
{
	int rc = 0;
	uint8_t ts;
	uint8_t ss;
	uint8_t offs;

	/* TODO: Make this function more intelligent, it should run the
	 * call id checks we currently have in protocol.c directly here. */

	/* Set the callid, creation of another connection will only be possible
	 * when the callid matches up. (Connections are distinguished by their
	 * connection ids) */
	endp->callid = talloc_strdup(endp, callid);
	OSMO_ASSERT(endp->callid);

	/* Allocate resources */
	switch (endp->trunk->trunk_type) {
	case MGCP_TRUNK_VIRTUAL:
		/* No additional initaliziation required here, virtual
		 * endpoints will open/close network sockets themselves
		 * on demand. */
		break;
	case MGCP_TRUNK_E1:
		ts = e1_ts_nr_from_epname(endp->name);
		ss = e1_ss_nr_from_epname(endp->name);
		offs = e1_offs_from_epname(endp->name);
		OSMO_ASSERT(ts != 0xFF);
		OSMO_ASSERT(ts != 0);
		OSMO_ASSERT(ss != 0xFF);
		OSMO_ASSERT(offs != 0xFF);
		rc = mgcp_e1_endp_equip(endp, ts, ss, offs);
		break;
	default:
		OSMO_ASSERT(false);
	}

	/* Make sure the endpoint is released when claiming the endpoint
	 * failes. */
	if (rc < 0)
		mgcp_endp_release(endp);

	return rc;
}

/*! update endpoint, updates internal endpoint specific data, should be
 *  after when MDCX or CRCX has been executed successuflly.
 *  \param[in] endp endpoint to update. */
void mgcp_endp_update(struct mgcp_endpoint *endp)
{
	/* Allocate resources */
	switch (endp->trunk->trunk_type) {
	case MGCP_TRUNK_VIRTUAL:
		/* No updating initaliziation required for virtual endpoints. */
		break;
	case MGCP_TRUNK_E1:
		mgcp_e1_endp_update(endp);
		break;
	default:
		OSMO_ASSERT(false);
	}
}

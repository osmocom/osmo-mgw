/* Trunk handling */

/*
 * (C) 2009-2012 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009-2012 by On-Waves
 * (C) 2017-2020 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
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

#include <osmocom/mgcp/mgcp_internal.h>
#include <osmocom/mgcp/mgcp_endp.h>
#include <osmocom/mgcp/mgcp_trunk.h>

/*! allocate trunk and add it (if required) to the trunk list.
 *  (called once at startup by VTY).
 *  \param[in] cfg mgcp configuration.
 *  \param[in] ttype trunk type.
 *  \param[in] nr trunk number.
 *  \returns pointer to allocated trunk, NULL on failure. */
struct mgcp_trunk *mgcp_trunk_alloc(struct mgcp_config *cfg, enum mgcp_trunk_type ttype, int nr)
{
	struct mgcp_trunk *trunk;

	trunk = talloc_zero(cfg, struct mgcp_trunk);
	if (!trunk) {
		LOGP(DLMGCP, LOGL_ERROR, "Failed to allocate.\n");
		return NULL;
	}

	trunk->cfg = cfg;
	trunk->trunk_type = ttype;
	trunk->trunk_nr = nr;

	trunk->audio_send_ptime = 1;
	trunk->audio_send_name = 1;
	trunk->vty_number_endpoints = 32;
	trunk->omit_rtcp = 0;

	mgcp_trunk_set_keepalive(trunk, MGCP_KEEPALIVE_ONCE);

	llist_add_tail(&trunk->entry, &cfg->trunks);

        mgcp_ratectr_trunk_alloc(cfg, &trunk->ratectr);

	return trunk;
}

/*! allocate endpoints and set default values
 *  (called once at startup by VTY).
 *  \param[in] trunk trunk configuration.
 *  \returns 0 on success, -1 on failure. */
int mgcp_trunk_alloc_endpts(struct mgcp_trunk *trunk)
{
	int i;
	struct mgcp_endpoint *endp;
	unsigned int number_endpoints;
	unsigned int first_endpoint_nr;

	/* This function is called once on startup by the VTY to allocate the
	 * endpoints. The number of endpoints must not change througout the
	 * runtime of the MGW */
	OSMO_ASSERT(trunk->number_endpoints == 0);
	OSMO_ASSERT(trunk->endpoints == NULL);

	switch (trunk->trunk_type) {
	case MGCP_TRUNK_VIRTUAL:
		/* Due to historical reasons the endpoints on the virtual
		 * trunk start counting at 1. */
		first_endpoint_nr = 1;
		number_endpoints = trunk->vty_number_endpoints;
		break;
	case MGCP_TRUNK_E1:
		/* The first timeslot on an E1 line is reserved for framing
		 * and alignment and can not be used for audio transport */
	        first_endpoint_nr = 1 * MGCP_ENDP_E1_SUBSLOTS;
		number_endpoints = 31 * MGCP_ENDP_E1_SUBSLOTS;
		break;
	default:
		OSMO_ASSERT(false);
	}

	/* Make sure the amount of requested endpoints does not execeed
	 * sane limits. The VTY already limits the possible amount,
	 * however miss-initialization of the struct or memory corruption
	 * could still lead to an excessive allocation of endpoints, so
	 * better stop early if that is the case. */
	OSMO_ASSERT(number_endpoints < 65534);

	/* allocate pointer array for the endpoints */
	trunk->endpoints = talloc_zero_array(trunk->cfg, struct mgcp_endpoint*,
					     number_endpoints);
	if (!trunk->endpoints)
		return -1;

	/* create endpoints */
	for (i = 0; i < number_endpoints; i++) {
		endp = mgcp_endp_alloc(trunk, i + first_endpoint_nr);
		if (!endp) {
			talloc_free(trunk->endpoints);
			return -1;
		}
		trunk->endpoints[i] = endp;
	}

	/* make the endpoints we just created available to the MGW code */
	trunk->number_endpoints = number_endpoints;

	return 0;
}

/*! get trunk configuration by trunk number (index).
 *  \param[in] cfg mgcp configuration.
 *  \param[in] ttype trunk type.
 *  \param[in] nr trunk number.
 *  \returns pointer to trunk configuration, NULL on error. */
struct mgcp_trunk *mgcp_trunk_by_num(const struct mgcp_config *cfg, enum mgcp_trunk_type ttype, int nr)
{
	struct mgcp_trunk *trunk;

	llist_for_each_entry(trunk, &cfg->trunks, entry) {
		if (trunk->trunk_nr == nr && trunk->trunk_type == ttype)
			return trunk;
	}

	return NULL;
}

/* Made public for unit-testing, do not use from outside this file */
int e1_trunk_nr_from_epname(const char *epname)
{
	unsigned long int trunk_nr;
	size_t prefix_len;
	char *str_trunk_nr_end;

	prefix_len = sizeof(MGCP_ENDPOINT_PREFIX_E1_TRUNK) - 1;
	if (strncmp(epname, MGCP_ENDPOINT_PREFIX_E1_TRUNK, prefix_len) != 0)
		return -EINVAL;

	errno = 0;
	trunk_nr = strtoul(epname + prefix_len, &str_trunk_nr_end, 10);
	if (errno == ERANGE || trunk_nr > 64 || trunk_nr == 0
	    || epname + prefix_len == str_trunk_nr_end
	    || str_trunk_nr_end[0] != '/')
		return -EINVAL;
	else
		return trunk_nr;
}

/*! Find a trunk by the trunk prefix in the endpoint name.
 *  \param[in] epname endpoint name with trunk prefix to look up.
 *  \param[in] cfg that contains the trunks where the endpoint is located.
 *  \returns trunk or NULL if trunk was not found. */
struct mgcp_trunk *mgcp_trunk_by_name(const struct mgcp_config *cfg, const char *epname)
{
	size_t prefix_len;
	char epname_lc[MGCP_ENDPOINT_MAXLEN];
	int trunk_nr;

	osmo_str_tolower_buf(epname_lc, sizeof(epname_lc), epname);
	epname = epname_lc;

	prefix_len = sizeof(MGCP_ENDPOINT_PREFIX_VIRTUAL_TRUNK) - 1;
	if (strncmp(epname, MGCP_ENDPOINT_PREFIX_VIRTUAL_TRUNK, prefix_len) == 0) {
		return mgcp_trunk_by_num(cfg, MGCP_TRUNK_VIRTUAL, MGCP_VIRT_TRUNK_ID);
	}

	trunk_nr = e1_trunk_nr_from_epname(epname);
	if (trunk_nr > 0)
		return mgcp_trunk_by_num(cfg, MGCP_TRUNK_E1, trunk_nr);

	/* Earlier versions of osmo-mgw were accepting endpoint names
	 * without trunk prefix. This is normally not allowed, each MGCP
	 * request should supply an endpoint name with trunk prefix.
	 * However in order to stay compatible with old versions of
	 * osmo-bsc and osmo-msc we still accept endpoint names without
	 * trunk prefix and just assume that the virtual trunk should
	 * be selected. There is even a TTCN3 test for this, see also:
	 * MGCP_Test.TC_crcx_noprefix */
	if ((epname[0] >= '0' && epname[0] <= '9') || (epname[0] >= 'a' && epname[0] <= 'f')) {
		LOGP(DLMGCP, LOGL_ERROR, "missing trunk prefix in endpoint name \"%s\", assuming trunk \"%s\"!\n", epname,
		     MGCP_ENDPOINT_PREFIX_VIRTUAL_TRUNK);
		return  mgcp_trunk_by_num(cfg, MGCP_TRUNK_VIRTUAL, MGCP_VIRT_TRUNK_ID);
	}

	LOGP(DLMGCP, LOGL_ERROR, "unable to find trunk for endpoint name \"%s\"!\n", epname);
	return NULL;
}

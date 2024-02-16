/*
 * (C) 2023-2024 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Neels Hofmeyr
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
#include <string.h>
#include <ctype.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/logging.h>

#include <osmocom/sdp/sdp_strings.h>
#include <osmocom/sdp/fmtp.h>

/* End of current fmtp parameter. Return a pointer to the next ';' character, if present, or the terminating '\0'. */
static const char *osmo_sdp_fmtp_end(const char *fmtp)
{
	if (!fmtp)
		return NULL;
	for (; *fmtp && *fmtp != ';'; fmtp++);
	return fmtp;
}

/* Start of next fmtp parameter. Return a pointer to the first character of the next fmtp parameter's name, or the
 * terminating '\0'. */
static const char *osmo_sdp_fmtp_next(const char *fmtp)
{
	if (!fmtp)
		return NULL;
	fmtp = osmo_sdp_fmtp_end(fmtp);
	for (; *fmtp && (*fmtp == ';' || isspace(*fmtp)); fmtp++);
	return fmtp;
}

/*! Parse a given SDP fmtp value string, returning the value of a specific option, if present.
 *
 * Example:
 *
 *   const char *fmtp_vals = "octet-align=1;mode-set=0,2,4,7";
 *
 *   char mode_set_str[23];
 *   if (osmo_sdp_fmtp_get_val(mode_set_str, sizeof(mode_set_str), fmtp_vals, "mode-set")) {
 *           // option 'mode-set' is present, now mode_set_str == "0,2,4,7"
 *           use_modeset(mode_set_str);
 *   } else {
 *           // if 'mode-set' were not present...
 *           use_modeset(MY_DEFAULT_MODESET);
 *   }
 *
 * \param[out] val  Buffer to write the option's value to.
 * \param[in] val_size  Space available in val.
 * \param[in] fmtp  fmtp value string to parse -- must not contain the "a=fmtp:N " prefix, only the value part.
 * \param[in] option_name  Which fmtp option to get the value for.
 * \return true when the option was found, false when it was not present.
 */
bool osmo_sdp_fmtp_get_val(char *val, size_t val_size, const char *fmtp, const char *option_name)
{
	const char *pos = fmtp;
	const char *end;
	int option_name_len = strlen(option_name);
	for (; pos && *pos; pos = osmo_sdp_fmtp_next(pos)) {
		if (!osmo_str_startswith(pos, option_name))
			continue;
		pos += option_name_len;
		if (*pos != '=')
			continue;
		pos++;
		break;
	}

	if (!pos || !*pos)
		return false;

	end = osmo_sdp_fmtp_end(pos);
	OSMO_ASSERT(end);
	if (val && val_size)
		osmo_strlcpy(val, pos, OSMO_MIN(val_size, end - pos + 1));
	return true;
}

/*! Parse a given SDP fmtp value string, returning the value of a specific integer option, if present.
 *
 * Example:
 *
 *   const char *fmtp_vals = "octet-align=1;mode-set=0,2,4,7";
 *   bool oa = osmo_sdp_fmtp_get_int(fmtp_vals, OSMO_SDP_AMR_OCTET_ALIGN_NAME, 1);
 *
 * \param[in] fmtp  fmtp value string to parse -- must not contain the "a=fmtp:N " prefix, only the value part.
 * \param[in] option_name  Which fmtp option to get the value for.
 * \param[in] default_value  If option_name is not present or cannot be parsed as integer, return this instead.
 * \return the integer value when the option was found and actually an integer, default_value otherwise.
 */
int64_t osmo_sdp_fmtp_get_int(const char *fmtp, const char *option_name, int64_t default_value)
{
	char val[128];
	if (!osmo_sdp_fmtp_get_val(val, sizeof(val), fmtp, option_name))
		return default_value;
	if (!val[0])
		return default_value;
	int64_t i;
	if (osmo_str_to_int64(&i, val, 10, INT64_MIN, INT64_MAX)) {
		/* error parsing number */
		return default_value;
	}
	return i;
}

/*! Return true if octet-align is present and set to 1 in the given AMR related fmtp value.
 * Default to octet-align=0, i.e. bandwidth-efficient mode.
 *
 * See RFC4867 "RTP Payload Format for AMR and AMR-WB" sections "8.1. AMR Media Type Registration" and "8.2. AMR-WB
 * Media Type Registration":
 *
 *    octet-align: Permissible values are 0 and 1.  If 1, octet-align
 *                 operation SHALL be used.  If 0 or if not present,
 *                 bandwidth-efficient operation is employed.
 *
 * https://tools.ietf.org/html/rfc4867
 */
bool osmo_sdp_fmtp_amr_is_octet_aligned(const char *fmtp)
{
	return osmo_sdp_fmtp_get_int(fmtp, OSMO_SDP_STR_AMR_OCTET_ALIGN, 0) == 1;
}

static void strip_whitespace(char *str)
{
	char *i = str;
	char *o = str;
	for (; *i; i++, o++) {
		while (isspace(*i))
			i++;
		*o = *i;
		if (!*i)
			break;
	}
}

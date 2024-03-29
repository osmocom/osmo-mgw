#pragma once

/* Internal structure while parsing a request */
struct mgcp_parse_data {
	struct mgcp_config *cfg;
	char *epname;
	char *trans;
	char *save;
};

/* Local connection options */
struct mgcp_lco {
	char *string;
	char *codec;
	int pkt_period_min; /* time in ms */
	int pkt_period_max; /* time in ms */
};

char *mgcp_debug_get_last_endpoint_name(void);

char *get_lco_identifier(const char *options);
int check_local_cx_options(void *ctx, const char *options);

struct mgcp_rtp_end;
struct mgcp_endpoint;
void mgcp_rtp_end_config(struct mgcp_endpoint *endp, int expect_ssrc_change,
			 struct mgcp_rtp_end *rtp);

uint32_t mgcp_rtp_packet_duration(const struct mgcp_endpoint *endp,
				  const struct mgcp_rtp_end *rtp);

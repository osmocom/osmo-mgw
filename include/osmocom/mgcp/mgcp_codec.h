#pragma once

void mgcp_codec_summary(struct mgcp_conn_rtp *conn);
void mgcp_codec_reset_all(struct mgcp_conn_rtp *conn);
int mgcp_codec_add(struct mgcp_conn_rtp *conn, int payload_type, const char *audio_name);
int mgcp_codec_decide(struct mgcp_conn_rtp *conn);
int mgcp_codec_pt_translate(struct mgcp_conn_rtp *conn_src, struct mgcp_conn_rtp *conn_dst, int payload_type);

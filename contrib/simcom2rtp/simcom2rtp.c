#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>


#include <osmocom/core/select.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/fsm.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/application.h>
#include <osmocom/core/serial.h>

#include <osmocom/trau/osmo_ortp.h>

#include "g711.h"

#define RTP_PT_PCMU	0
#define RTP_PT_PCMA	8

struct modem_state {
	struct osmo_fd data_fd;
	struct osmo_rtp_socket *rtp;
	/* queue of linear PCM audio in RTP -> modem direction */
	struct llist_head rtp2modem;
	/* message buffer used if samples insufficient for next RTP frame were received */
	struct msgb *modem2rtp;
};

static void *g_tall_ctx;


/* call-back on received RTP data */
static void ortp_rx_cb(struct osmo_rtp_socket *rs, const uint8_t *payload,
			unsigned int payload_len, uint16_t seq_nr, uint32_t timestamp, bool marker)
{
	/* we received a RTP frame */
	struct modem_state *ms = rs->priv;
	struct msgb *msg = msgb_alloc(payload_len*2, "RTP Rx");
	unsigned int i;
	int16_t *out;

	OSMO_ASSERT(msg);

	out = (int16_t *) msgb_put(msg, payload_len*2);

	if (payload_len != 160) {
		fprintf(stderr, "RTP payload length %d != 160, dropping\n", payload_len);
		msgb_free(msg);
		return;
	}

	/* convert from Alaw to linear PCM (160 -> 320 bytes) */
	for (i = 0; i < payload_len; i++)
		out[i] = alaw2linear(payload[i]);

	/* append to the write queue */
	msgb_enqueue(&ms->rtp2modem, msg);
	ms->data_fd.when |= OSMO_FD_WRITE;
}

static void modem2rtp(struct modem_state *ms, const uint8_t *data, unsigned int len)
{
	const int16_t *data16 = (const int16_t *)data;
	unsigned int samples = len / 2;
	unsigned int offset = 0;
	unsigned int i;

	/* samples are always 16bit, we cannot read half a sample */
	OSMO_ASSERT((len & 1) == 0);

	/* first complete any pending incomplete RTP frame */
	if (ms->modem2rtp) {
		struct msgb *msg = ms->modem2rtp;
		unsigned int missing_samples = 160 - msgb_length(msg);
		for (i = 0; i < missing_samples; i++) {
			if (i >= samples)
				break;
			msgb_put_u8(msg, linear2alaw(data16[i]));
		}
		offset = i;
		if (msgb_length(msg) == 160) {
			osmo_rtp_send_frame_ext(ms->rtp, msgb_data(msg), msgb_length(msg), 160, false);
			msgb_free(msg);
		}
	}

	/* then send as many RTP frames as we have samples */
	for (offset = offset; offset + 160 <= samples; offset += 160) {
		uint8_t buf[160];
		for (i = 0; i < sizeof(buf); i++)
			buf[i] = linear2alaw(data16[offset + i]);
		osmo_rtp_send_frame_ext(ms->rtp, buf, sizeof(buf), 160, false);
	}

	/* store remainder in msgb */
	if (offset < samples) {
		struct msgb *msg = msgb_alloc_c(ms, 160, "modem2rtp");
		OSMO_ASSERT(msg);
		OSMO_ASSERT(len - offset < 160);
		for (i = 0; i < len - offset; i++)
			msgb_put_u8(msg, linear2alaw(data16[offset + i]));
		ms->modem2rtp = msg;
	}
}


/* call back on file descriptor events of the modem DATA ttyUSB device */
static int modem_data_fd_cb(struct osmo_fd *ofd, unsigned int what)
{
	struct modem_state *ms = ofd->data;
	int rc;

	if (what & OSMO_FD_READ) {
		/* SIM5360 USB AUDIO Application Note v1.01 states 1600 bytes every 100ms */
		uint8_t rx_buf[1600];
		rc = read(ofd->fd, rx_buf, sizeof(rx_buf));
		OSMO_ASSERT(rc > 0);
		modem2rtp(ms, rx_buf, rc);
	}

	if (what & OSMO_FD_WRITE) {
		struct msgb *msg = msgb_dequeue(&ms->rtp2modem);
		if (!msg)
			ofd->when &= ~OSMO_FD_WRITE;
		else {
			/* SIM5300 USB AUDIO Application Note v1.01 states 640 bytes every 40ms;
			 * we simply write every RTP frame individually (320 bytes every 20ms) */
			rc = write(ofd->fd, msgb_data(msg), msgb_length(msg));
			if (rc != msgb_length(msg))
				fprintf(stderr, "Short write: %d < %u\n", rc, msgb_length(msg));
			msgb_free(msg);
		}
	}

	return 0;
}


static int modem_data_open(struct modem_state *ms, const char *basepath)
{
	char fname[PATH_MAX+1];
	int fd;

	/* the assumption is that the caller provides something like
	 * "/dev/serial/by-path/pci-0000:00:14.0-usb-0:2:1" */
	snprintf(fname, sizeof(fname), "%s.0-port0", basepath);

	fd = osmo_serial_init(fname, 921600);
	if (fd < 0) {
		fprintf(stderr, "failed to open device '%s': %s\n", fname, strerror(errno));
		return -1;
	}
	osmo_fd_setup(&ms->data_fd, fd, OSMO_FD_READ, modem_data_fd_cb, ms, 0);
	osmo_fd_register(&ms->data_fd);

	return 0;
}

static struct modem_state *modem_create(void *ctx)
{
	struct modem_state *ms = talloc_zero(ctx, struct modem_state);
	int rc;

	INIT_LLIST_HEAD(&ms->rtp2modem);

	ms->rtp = osmo_rtp_socket_create(ms, 0);
	OSMO_ASSERT(ms->rtp);
	osmo_rtp_socket_set_pt(ms->rtp, RTP_PT_PCMA);
	ms->rtp->priv = ms;
	ms->rtp->rx_cb = ortp_rx_cb;

	rc = osmo_rtp_socket_bind(ms->rtp, "0.0.0.0", 1111);
	OSMO_ASSERT(rc == 0);

	rc = osmo_rtp_socket_connect(ms->rtp, "127.0.0.1", 2222);
	//rc = osmo_rtp_socket_autoconnect(ms->rtp);
	OSMO_ASSERT(rc == 0);

	osmo_rtp_set_source_desc(ms->rtp, "cname", "simcom2rtp", NULL, NULL, NULL,
				 "osmo-simcom2rtp", NULL);

	return ms;
}




int main(int argc, char **argv)
{

	talloc_enable_null_tracking();
	g_tall_ctx = talloc_named_const(NULL, 1, "simcom2rtp");

	msgb_talloc_ctx_init(g_tall_ctx, 0);
	osmo_init_logging2(g_tall_ctx, NULL);
	osmo_fsm_log_timeouts(true);
	osmo_fsm_log_addr(true);
	//osmo_stats_init(g_tall_ctx);
	osmo_rtp_init(g_tall_ctx);

	struct modem_state *ms = modem_create(g_tall_ctx);
	int rc;

	OSMO_ASSERT(ms);
	rc = modem_data_open(ms, "/dev/serial/by-path/pci-0000:00:14.0-usb-0:2:1");
	OSMO_ASSERT(rc == 0);

	while (1) {
		osmo_select_main(0);
	}

}

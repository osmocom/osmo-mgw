#include <liburing.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/timerfd.h>

#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/sockaddr_str.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/application.h>
#include <osmocom/netif/rtp.h>

#include "internal.h"
#include "rtp_provider.h"
#include "internal.h"

/* use a separate rx-completion thread: submit from main, reap from completion */
//#define USE_CQ_THREAD

/* use registered files: Doesn't seem to work with sockets? */
//#define USE_REGISTERED_FILES

/* use registered buffers (mapped once into kernel, rather than at every write */
#define USE_REGISTERED_BUFFERS

/* number of sockets/flows to create */
#define NUM_FLOWS	4096

/* number of workers to spawn.  Each worker will get an equal share of NR_FLOWS to work on */
#define NR_WORKERS	4

/* size of rx/tx buffer for one RTP frame */
#define BUF_SIZE	256

#define NUM_FLOWS_PER_WORKER	(NUM_FLOWS/NR_WORKERS)

#define TX_BUF_IDX	0
#define RX_BUF_IDX	1

enum rtpsim_conn_ctr {
	RTP_CONN_CTR_TX_PKTS,
	RTP_CONN_CTR_TX_BYTES,
	RTP_CONN_CTR_RX_PKTS,
	RTP_CONN_CTR_RX_BYTES,
	RTP_CONN_CTR_RX_INVALID,
};

static const struct rate_ctr_desc rtpsim_conn_ctrs[] = {
	[RTP_CONN_CTR_TX_PKTS] = { "tx_pkts:total", "Transmitted packets" },
	[RTP_CONN_CTR_TX_BYTES] = { "tx_bytes:total", "Transmitted bytes" },
	[RTP_CONN_CTR_RX_PKTS] = { "rx_pkts:total", "Received packets (total)" },
	[RTP_CONN_CTR_RX_BYTES] = { "rx_bytes:total", "Transmitted bytes" },
	[RTP_CONN_CTR_RX_INVALID] = { "rx_pkts:invalid", "Received packets (invalidl)" },
};
static const struct rate_ctr_group_desc rtpsim_conn_ctrg_desc = {
	.group_name_prefix = "rtpsim_conn",
	.group_description = "RTP Simulator Connection",
	.class_id = 0,
	.num_ctr = ARRAY_SIZE(rtpsim_conn_ctrs),
	.ctr_desc = rtpsim_conn_ctrs,
};

enum rtpsim_ctr {
	RTP_INST_TIMERS_TOTAL,
	RTP_INST_TIMERS_LATE,
};
static const struct rate_ctr_desc rtpsim_ctrs[] = {
	[RTP_INST_TIMERS_TOTAL] = { "timers:total", "Timers expiring (total)" },
	[RTP_INST_TIMERS_LATE] = { "timers:late", "Timers expiring (late)" },
};
static const struct rate_ctr_group_desc rtpsim_ctrg_desc = {
	.group_name_prefix = "rtpsim",
	.group_description = "RTP Simulator Instance",
	.class_id = 0,
	.num_ctr = ARRAY_SIZE(rtpsim_ctrs),
	.ctr_desc = rtpsim_ctrs,
};

struct rtpsim_instance *rtpsim_instance_init(const struct rtpsim_instance_cfg *rmp)
{
	struct rtpsim_instance *ri = talloc_zero(rmp->ctx, struct rtpsim_instance);
	int rc;

	if (!ri)
		return NULL;
	ri->connections_size = NUM_FLOWS_PER_WORKER;
	ri->connections = talloc_zero_size(ri, sizeof(struct rtpsim_connection *)*ri->connections_size);
	if (!ri->connections) {
		talloc_free(ri);
		return NULL;
	}

	ri->cfg = *rmp;
	rc = io_uring_queue_init(NUM_FLOWS_PER_WORKER*2, &ri->ring, 0);
	if (rc < 0) {
		talloc_free(ri);
		return NULL;
	}
	ri->ctrg = rate_ctr_group_alloc(ri, &rtpsim_ctrg_desc, rmp->num);
	OSMO_ASSERT(ri->ctrg);
	return ri;
}

static int rtpsim_instance_conn_add(struct rtpsim_instance *ri, struct rtpsim_connection *rtpc)
{
	unsigned int i;

	for (i = 0; i < ri->connections_size; i++) {
		if (ri->connections[i] == NULL) {
			ri->connections[i] = rtpc;
			rtpc->idx = i;
			return i;
		}
	}
	return -ENOSPC;
}

static struct rtpsim_connection *
rtpsim_conn_open_bind(struct rtpsim_instance *ri, const struct rtpsim_connection_cfg *rcfg)
{
	struct rtpsim_connection *rtpc = talloc_zero(ri, struct rtpsim_connection);
	struct osmo_sockaddr sa_local;
	int rc;

	if (!rtpc)
		return NULL;

	rtpc->inst = ri;
	rtpc->cfg = *rcfg;

	osmo_sockaddr_str_to_sockaddr(&rtpc->cfg.local, &sa_local.u.sas);

	rc = osmo_sock_init_osa(SOCK_DGRAM, IPPROTO_UDP, &sa_local, NULL, OSMO_SOCK_F_BIND);
	if (rc < 0) {
		talloc_free(rtpc);
		return NULL;
	}

	rtpc->fd = rc;
	rtpc->ctrg = rate_ctr_group_alloc(rtpc, &rtpsim_conn_ctrg_desc, rtpc->cfg.local.port);
	OSMO_ASSERT(rtpc->ctrg);
#ifndef USE_REGISTERED_BUFFERS
	rtpc->tx.buf = talloc_zero_size(rtpc, BUF_SIZE);
	rtpc->rx.buf = talloc_zero_size(rtpc, BUF_SIZE);
#endif
	OSMO_ASSERT(rtpsim_instance_conn_add(ri, rtpc) >= 0);

	return rtpc;
}

/* find a connection for given cname (may be NULL to find unused connection) */
struct rtpsim_connection *rtpsim_conn_find(struct rtpsim_instance *ri, const char *cname)
{
	int i;

	for (i = 0; i < ri->connections_size; i++) {
		struct rtpsim_connection *rtpc = ri->connections[i];
		if (!rtpc)
			continue;
		if (!rtpc->cname) {
			if (!cname)
				return rtpc;
		} else {
			continue;
		}
		if (!strcmp(rtpc->cname, cname))
			return rtpc;
	}
	return NULL;
}

/* reserve a connection; associates cname with it */
struct rtpsim_connection *rtpsim_conn_reserve(struct rtpsim_instance *ri, const char *cname)
{
	struct rtpsim_connection *rtpc;

	rtpc = rtpsim_conn_find(ri, NULL);
	if (!rtpc)
		return NULL;

	/* this is called from main thread, we cannot use per-thread talloc contexts
	 * such as ri or rtpc */
	rtpc->cname = talloc_strdup(NULL, cname);

	return rtpc;
}

int rtpsim_conn_start(struct rtpsim_connection *rtpc, enum codec_type codec)
{
	const struct rtp_provider *rtp_prov;
	rtp_prov = rtp_provider_find("static"); // TODO: configurable */
	OSMO_ASSERT(rtp_prov);

	/* this is called from main thread, we cannot use per-thread talloc contexts
	 * such as ri or rtpc */
	rtpc->tx.rtp_prov_inst = rtp_provider_instance_alloc(NULL, rtp_prov, codec);
	OSMO_ASSERT(rtpc->tx.rtp_prov_inst);

	rtpc->tx.enabled = true;
	rtpc->rx.enabled = true;

	return 0;
}

/* unreserve a connection; stops all rx/tx and removes cname */
void rtpsim_conn_unreserve(struct rtpsim_connection *rtpc)
{
	/* disable Rx and Tx */
	rtpc->tx.enabled = false;
	rtpc->rx.enabled = false;
	/* re-start from zero transmit sequence number */
	rtpc->tx.seq = 0;

	rtp_provider_instance_free(rtpc->tx.rtp_prov_inst);
	rtpc->tx.rtp_prov_inst = NULL;

	talloc_free(rtpc->cname);
	rtpc->cname = NULL;
}

/* connect a RTP connection to its remote peer (as in rtpc->cfg.remote) */
int rtpsim_conn_connect(struct rtpsim_connection *rtpc)
{
	struct osmo_sockaddr sa_remote;
	int rc;

	osmo_sockaddr_str_to_sockaddr(&rtpc->cfg.remote, &sa_remote.u.sas);
	rc = connect(rtpc->fd, &sa_remote.u.sa, sizeof(struct osmo_sockaddr));
	return rc;
}

/* transmit one RTP frame for given connection */
static int rtpsim_conn_tx_frame(struct rtpsim_connection *rtpc)
{
	struct rtp_hdr *rtph = (struct rtp_hdr *) rtpc->tx.buf;
	struct io_uring_sqe *sqe;
	uint8_t *payload;
	int rc;

	rtph->version = RTP_VERSION;
	rtph->padding = 0;
	rtph->extension = 0;
	rtph->csrc_count = 0;
	rtph->marker = 0;
	rtph->payload_type = rtpc->cfg.pt;
	rtph->sequence = htons(rtpc->tx.seq++);
	rtph->timestamp = htonl(rtpc->tx.timestamp);
	rtpc->tx.timestamp += rtpc->cfg.duration;
	rtph->ssrc = htonl(rtpc->cfg.ssrc);
	payload = rtpc->tx.buf + sizeof(*rtph);
	/* add payload data */

	rc = rtp_provider_instance_gen_frame(rtpc->tx.rtp_prov_inst, payload, BUF_SIZE-sizeof(*rtph));
	OSMO_ASSERT(rc >= 0);
	rtpc->tx.buf_len = sizeof(*rtph) + rc;

	sqe = io_uring_get_sqe(&rtpc->inst->ring);
	OSMO_ASSERT(sqe);
	sqe->user_data = rtpc->idx;
#ifdef USE_REGISTERED_FILES
	io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE);
#ifdef USE_REGISTERED_BUFFERS
	io_uring_prep_write_fixed(sqe, rtpc->idx, rtpc->tx.buf, rtpc->tx.buf_len, 0, TX_BUF_IDX);
#else
	io_uring_prep_write(sqe, rtpc->idx, rtpc->tx.buf, rtpc->tx.buf_len, 0);
#endif
#else /* REGISTERED FILES */
#ifdef USE_REGISTERED_BUFFERS
	io_uring_prep_write_fixed(sqe, rtpc->fd, rtpc->tx.buf, rtpc->tx.buf_len, 0, TX_BUF_IDX);
#else
	io_uring_prep_write(sqe, rtpc->fd, rtpc->tx.buf, rtpc->tx.buf_len, 0);
#endif
#endif /* REGISTERED_FILES */

	return 0;
}

/* submit RX buffer for a RTP frame on given connection */
static int rtpsim_conn_rx_prep(struct rtpsim_connection *rtpc)
{
	struct io_uring_sqe *sqe;

	sqe = io_uring_get_sqe(&rtpc->inst->ring);
	OSMO_ASSERT(sqe);
	sqe->user_data = 0x8000000 | rtpc->idx;
#ifdef USE_REGISTERED_FILES
	io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE);
	/* FIXME */
#else /* REGISTERED FILES */
#ifdef USE_REGISTERED_BUFFERS
	io_uring_prep_read_fixed(sqe, rtpc->fd, rtpc->rx.buf, BUF_SIZE, 0, RX_BUF_IDX);
#else
	io_uring_prep_read(sqe, rtpc->fd, rtpc->rx.buf, BUF_SIZE, 0);
#endif
#endif /* REGISTERED_FILES */
	return 0;
}

/* process one completion entry */
static void handle_completion(struct rtpsim_instance *ri, struct io_uring_cqe *cqe)
{
	struct rtpsim_connection *rtpc = ri->connections[cqe->user_data & 0x7fffffff];
	OSMO_ASSERT(rtpc);

	if (cqe->user_data & 0x80000000) {
		/* read */
		rate_ctr_inc(&rtpc->ctrg->ctr[RTP_CONN_CTR_RX_PKTS]);
		rate_ctr_add(&rtpc->ctrg->ctr[RTP_CONN_CTR_RX_BYTES], cqe->res);
		OSMO_ASSERT(cqe->res >= 0);
	} else {
		/* write */
		rate_ctr_inc(&rtpc->ctrg->ctr[RTP_CONN_CTR_TX_PKTS]);
		rate_ctr_add(&rtpc->ctrg->ctr[RTP_CONN_CTR_TX_BYTES], cqe->res);
		OSMO_ASSERT(cqe->res == sizeof(struct rtp_hdr) + 33);
	}
	io_uring_cqe_seen(&ri->ring, cqe);
}

#ifdef USE_CQ_THREAD
/* 'main' function for separate completion queue reaping thread */
static void *reap_completion(void *_ri)
{
	struct rtpsim_instance *ri = _ri;
	while (1) {
		struct io_uring_cqe *cqe;
		int rc;

		rc = io_uring_wait_cqe(&ri->ring, &cqe);
		OSMO_ASSERT(rc >= 0);
		handle_completion(ri, cqe);
	}
}
#endif

static void rtpsim_main(const struct rtpsim_instance_cfg *rmp)
{
	struct rtpsim_instance *ri;
	struct rtpsim_connection *rtpc;
	int i, rc;

	ri = rtpsim_instance_init(rmp);
	OSMO_ASSERT(ri);

	/* create desired number of sockets */
	printf("binding sockets\n");
	for (i = 0; i < rmp->num_flows; i++) {
		struct rtpsim_connection *rtpc;
		struct rtpsim_connection_cfg rcfg = {};
		rcfg.local = (struct osmo_sockaddr_str) {
			.af = AF_INET,
			.ip = "127.0.0.1",
			.port = rmp->base_port + 2*i,
		};
		rcfg.remote = (struct osmo_sockaddr_str) {
			.af = AF_INET,
			.ip = "127.0.0.1",
			.port = rmp->base_port + 2*i,
		};
		rcfg.pt = 3;
		rcfg.ssrc = 0x80000000 + rmp->base_port + i;
		rcfg.duration = 160;	/* 8000 Hz sampling rate / 50 Hz RTP rate */

		rtpc = rtpsim_conn_open_bind(ri, &rcfg);
		OSMO_ASSERT(rtpc);
	}

	/* HACK */
	printf("connecting sockets\n");
	for (i = 0; i < rmp->num_flows; i++) {
		char namebuf[32];
		snprintf(namebuf, sizeof(namebuf), "conn%d", i);
		struct rtpsim_connection *rtpc = rtpsim_conn_reserve(ri, namebuf);
		OSMO_ASSERT(rtpc);
		OSMO_ASSERT(rtpsim_conn_connect(rtpc) == 0);
		OSMO_ASSERT(rtpsim_conn_start(rtpc, CODEC_GSM_FR) == 0);
	}

#ifdef USE_REGISTERED_FILES
	/* register all our file descriptors; seems to fail on 5.8.x ? */
	int fds[NUM_FLOWS_PER_WORKER];
	for (i = 0; i < ri->connections_size; i++) {
		if (!rtpc) {
			fds[i] = -1;
			continue;
		}
		rtpc = ri->connections[i];
		fds[i] = rtpc->fd;
	}
	printf("Registering %d files\n", i);
	rc = io_uring_register_files(&ri->ring, fds, i);
	printf("rc = %d: %s\n", rc, strerror(-rc));
	OSMO_ASSERT(rc == 0);
#endif

#ifdef USE_REGISTERED_BUFFERS
	/* register two large buffers for Rx and Tx; assign per-connection
	 * buffers within those two registered buffers */
	void *largebuf_tx = talloc_zero_size(ri, rmp->num_flows * BUF_SIZE);
	void *largebuf_rx = talloc_zero_size(ri, rmp->num_flows * BUF_SIZE);
	struct iovec iov[2] = {
		[TX_BUF_IDX] = {
			.iov_base = largebuf_tx,
			.iov_len = rmp->num_flows * BUF_SIZE,
		},
		[RX_BUF_IDX] = {
			.iov_base = largebuf_rx,
			.iov_len = rmp->num_flows * BUF_SIZE,
		},
	};
	printf("Registering buffers for %d sockets\n", i);
	rc = io_uring_register_buffers(&ri->ring, iov, ARRAY_SIZE(iov));
	printf("rc = %d: %s\n", rc, strerror(-rc));
	OSMO_ASSERT(rc == 0);
	for (i = 0; i < ri->connections_size; i++) {
		rtpc = ri->connections[i];
		if (!rtpc)
			continue;
		rtpc->tx.buf = largebuf_tx + (i * BUF_SIZE);
		rtpc->rx.buf = largebuf_rx + (i * BUF_SIZE);
	}
#endif

#ifdef USE_CQ_THREAD
	/* start a separate completion thread instead of handling completions in-line */
	pthread_t complete;
	rc = pthread_create(&complete, NULL, reap_completion, ri);
	OSMO_ASSERT(rc >= 0);
#endif

	/* start timerfd every 20ms */
	ri->timerfd = timerfd_create(CLOCK_MONOTONIC, 0);
	OSMO_ASSERT(ri->timerfd >= 0);
	struct itimerspec its = (struct itimerspec) {
		.it_interval = { 0, 20*1000*1000 },
		.it_value = { 0, 20*1000*1000 },
	};
	rc = timerfd_settime(ri->timerfd, 0, &its, NULL);
	OSMO_ASSERT(rc == 0);

	/* start transmitting */

	while (1) {
		/* the assumption here is that every flow wants to write 50
		 * packets per second, so we try try to submit one write for each
		 * flow every 20ms */
		unsigned int submit_granularity = rmp->num_flows/50;
		/* number of 20ms timer expirations */
		uint64_t num_exp;
		unsigned int t;

		if (submit_granularity <= 0)
			submit_granularity = 1;

		/* read from timerfd to pace the 20ms inter packet interval */
		rc = read(ri->timerfd, &num_exp, sizeof(num_exp));
		OSMO_ASSERT(rc == sizeof(num_exp));

		rate_ctr_add(&ri->ctrg->ctr[RTP_INST_TIMERS_TOTAL], num_exp);
		if (num_exp != 1) {
			fputc('X', stdout);
			rate_ctr_add(&ri->ctrg->ctr[RTP_INST_TIMERS_LATE], num_exp-1);
		} else {
			fputc('.', stdout);
		}
		fflush(stdout);

		for (t = 0; t < num_exp; t++) {
			for (i = 0; i < ri->connections_size; i++) {
				rtpc = ri->connections[i];
				if (!rtpc)
					continue;
				if (rtpc->tx.enabled)
					rtpsim_conn_tx_frame(rtpc);
				if (rtpc->rx.enabled)
					rtpsim_conn_rx_prep(rtpc);
				if ((i % submit_granularity) == 0) {
					int pending = io_uring_submit(&ri->ring);

#ifndef USE_CQ_THREAD
					for (int j = 0; j < pending; j++) {
						struct io_uring_cqe *cqe;
						int rc;

						rc = io_uring_wait_cqe(&ri->ring, &cqe);
						OSMO_ASSERT(rc >= 0);
						handle_completion(ri, cqe);
					}
#endif /* USE_CQ_THREAD */
				}
			}
		}
	}

}

static void *rtpsim_worker_thread(void *_rmp)
{
	rtpsim_main((struct rtpsim_instance_cfg *)_rmp);
	return NULL;
}

int main(int argc, char **argv)
{
	pthread_t worker[NR_WORKERS];
	struct rtpsim_instance_cfg rmp[NR_WORKERS];
	int i;

	osmo_init_logging2(NULL, NULL);

	for (i = 0; i < NR_WORKERS; i++) {
		int rc;
		rmp[i].ctx = talloc_named(NULL, 0, "rtpsim%d", i);
		rmp[i].num = i;
		rmp[i].num_flows = NUM_FLOWS_PER_WORKER;
		rmp[i].base_port = 10000 + i * (2 * rmp[i].num_flows);
		rc = pthread_create(&worker[i], NULL, rtpsim_worker_thread, &rmp[i]);
		OSMO_ASSERT(rc >= 0);
	}

	for (i = 0; i < NR_WORKERS; i++) {
		pthread_join(worker[i], NULL);
	}
}

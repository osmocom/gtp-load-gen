/* GTP-U traffic/load generator.  Generates a configurable amount of UDP/IP flows
 * wrapped in a configurable number of GTP tunnels (TEIDs) to a configurable number
 * of remote GSNs.
 *
 * The general idea is to create one thread per local GTP endpoint (socket), and then
 * generate GTP traffic using io_uring.
 *
 * (C) 2021 by Harald Welte <laforge@osmocom.org>
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <netinet/in.h>

#include <liburing.h>

#include <osmocom/core/sockaddr_str.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/utils.h>

struct gtp1u_hdr {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	uint8_t pn:1, s:1, e:1, spare:1, pt:1, version:3;
#else
	uint8_t version:3, pt:1, spare:1, e:1, s:1, pn:1;
#endif
	uint8_t type;
	uint16_t length;
	uint32_t tei;
};

/* one local GTP endpoint */
struct gtp_endpoint {
	struct io_uring ring;
	int fd;

	struct {
		/* locally bound GTP-U socket address/port */
		struct osmo_sockaddr_str local;
	} config;
};


const uint8_t pkt_buf[1024];

static int gtp_ep_open_bind(struct gtp_endpoint *gep)
{

	struct osmo_sockaddr sa_local;
	int rc;

	osmo_sockaddr_str_to_sockaddr(&gep->config.local, &sa_local.u.sas);

	rc = osmo_sock_init_osa(SOCK_DGRAM, IPPROTO_UDP, &sa_local, NULL, OSMO_SOCK_F_BIND);
	if (rc < 0)
		exit(1);

	gep->fd = rc;

	return 0;
}

static void gtp_ep_write_prepare(struct gtp_endpoint *gep)
{
	struct io_uring_sqe *sqe;

	/* all static as they need to exist until async completion */
	static const struct sockaddr_in dest_addr = {
		.sin_family = AF_INET,
		//.sin_addr = { 0x0100a0cf },
		.sin_addr = { 0x0100007f },
		.sin_port = 1234,
	};
	static const struct gtp1u_hdr gtp_hdr = {
		.version = 1,
		.type = 0xff,
		.length = sizeof(pkt_buf),
		.tei = 0xabcd0000,
	};
	static struct iovec iov[2] = {
#if 1
		{
			.iov_base = &gtp_hdr,
			.iov_len = sizeof(gtp_hdr),
		}, 
#endif
		{
			.iov_base = &pkt_buf,
			.iov_len = sizeof(pkt_buf),
		}
	};
	static struct msghdr msgh ={
		.msg_name = &dest_addr,
		.msg_namelen = sizeof(dest_addr),
		.msg_iov = iov,
		.msg_iovlen = ARRAY_SIZE(iov),
		.msg_control = NULL,
		.msg_controllen = 0,
		.msg_flags = 0,
	};

#if 1
	sqe = io_uring_get_sqe(&gep->ring);
	OSMO_ASSERT(sqe);
	sqe->user_data = 0;

	io_uring_prep_sendmsg(sqe, gep->fd, &msgh, 0);
#else
	sendmsg(gep->fd, &msgh, 0);
#endif
}


void foo(void)
{
	struct gtp_endpoint gep;
	int rc;

	memset(&gep, 0, sizeof(gep));;
	gep.config.local = (struct osmo_sockaddr_str) {
		.af = AF_INET,
		//.ip = "192.168.100.149",
		.ip = "127.0.0.1",
		.port = 5555,
	};

	rc = io_uring_queue_init(4096, &gep.ring, 0);
	OSMO_ASSERT(rc >= 0);

	gtp_ep_open_bind(&gep);
	while (1) {
		for (int j = 0; j < 4000; j++) {
			gtp_ep_write_prepare(&gep);
		}

		int pending = io_uring_submit(&gep.ring);

#if 1
		for (int j = 0; j < pending; j++) {
			struct io_uring_cqe *cqe;
			int rc;

			rc = io_uring_wait_cqe(&gep.ring, &cqe);
			OSMO_ASSERT(rc >= 0);
			//handle_completion(&gep, cqe);
			io_uring_cqe_seen(&gep.ring, cqe);
		}
#endif

	}
}

int main(int argc, char **argv)
{
	foo();
}

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
#include <pthread.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/select.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/sockaddr_str.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/application.h>

#include "checksum.h"

/* doesn't work as registered buffers only work with read/write, but we need to use
 * sendmsg so we can pass a destination address along.  We'd have to switch to connected
 * sockets (and hence less remote GSNs) if we wanted to do this */
//#define USE_REGISTERED_BUFFERS

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

/* global list of local GTP endpoints */
static LLIST_HEAD(g_gtp_endpoints);

/* one local GTP endpoint */
struct gtp_endpoint {
	/* entry in global list of GTP endpoints */
	struct llist_head list;

	/* GSNs reachable via this endpoint */
	struct llist_head gsns;

	struct io_uring ring;
	int fd;
	/* the worker thread implementing this endpoint */
	pthread_t worker;

#ifdef USE_REGISTERED_BUFFERS
	uint8_t *largebuf;
	unsigned int largebuf_size;
	/* next un-allocated chunk of largebuf */
	unsigned int largebuf_next;
#endif

	struct {
		/* locally bound GTP-U socket address/port */
		struct osmo_sockaddr_str local;
	} config;
};

/* one peer GSN inside a GTP endpoint */
struct gtp_peer_gsn {
	/* entry in per-endpoint list of GSNs */
	struct llist_head list;
	/* endpoint through which this peer is reachable */
	struct gtp_endpoint *ep;

	/* tunnels to this GSN */
	struct llist_head tunnels;

	struct {
		/* address of that GSN */
		struct osmo_sockaddr_str remote_addr;
	} config;

	/* cached remote address so we don't have to re-encode it all the time */
	struct sockaddr_storage dest_addr;
};

/* one GTP tunnel towards a remote GSN */
struct gtp_tunnel {
	/* entry in per-GSN list of tunnels */
	struct llist_head list;
	/* GSN through which this tunnel is reachable */
	struct gtp_peer_gsn *gsn;


	/* flows through this tunnel */
	struct llist_head flows;

	struct {
		uint32_t teid;
	} config;

	/* cached GTP header so we don't have to re-encode it all the time */
	struct gtp1u_hdr gtp_hdr;
};

/* one IP flow inside a GTP tunnel */
struct gtp_tunnel_ip_flow {
	/* entry in per-tunnel list of flows */
	struct llist_head list;
	/* tunnel through which this flow is sent */
	struct gtp_tunnel *tun;

	struct {
		struct osmo_sockaddr_str local;
		struct osmo_sockaddr_str remote;
	} config;

	/* those cannot be on the stack as they must live until completion */
	struct iovec iov[1];
	struct msghdr msgh;

	/* flow-private packet buffer */
	uint8_t *pkt_buf;

	bool in_progress;
};

/****************************************************************************
 * Worker Thread
 ****************************************************************************/

#define NUM_FLOWS_PER_WORKER	4000
#define BUF_SIZE		1024

/* create an endpoint, bind it locally, do not yet start the related thread */
struct gtp_endpoint *gtp_endpoint_create(void *ctx, const struct osmo_sockaddr_str *local_addr,
					 unsigned int max_flows)
{
	struct gtp_endpoint *ep = talloc_zero(ctx, struct gtp_endpoint);
	int rc;
	OSMO_ASSERT(ep);

	printf("Creating GTP endpoint at local " OSMO_SOCKADDR_STR_FMT "\n",
		OSMO_SOCKADDR_STR_FMT_ARGS(local_addr));

	INIT_LLIST_HEAD(&ep->gsns);
	memcpy(&ep->config.local, local_addr, sizeof(ep->config.local));
	ep->fd = -1;

	rc = io_uring_queue_init(NUM_FLOWS_PER_WORKER, &ep->ring, 0);
	OSMO_ASSERT(rc >= 0);

	llist_add_tail(&ep->list, &g_gtp_endpoints);

#ifdef USE_REGISTERED_BUFFERS
	ep->largebuf_size = max_flows * BUF_SIZE;
	ep->largebuf = talloc_zero_size(ep, ep->largebuf_size);
	OSMO_ASSERT(ep->largebuf);
	struct iovec iov[1] = {
		{
			.iov_base = ep->largebuf,
			.iov_len = ep->largebuf_size,
		}
	};
	printf("Registering buffer\n");
	rc = io_uring_register_buffers(&ep->ring, iov, ARRAY_SIZE(iov));
	OSMO_ASSERT(rc == 0);
#endif

	return ep;
}

#ifdef USE_REGISTERED_BUFFERS
uint8_t *gtp_endpoint_largebuf_get(struct gtp_endpoint *ep)
{
	uint8_t *cur = ep->largebuf + ep->largebuf_next;
	ep->largebuf_next += BUF_SIZE;
	OSMO_ASSERT(cur <= ep->largebuf + ep->largebuf_size);
	return cur;
}
#endif

/* transmit one packet for a given flow */
static void gtpgen_tx_one(struct gtp_tunnel_ip_flow *flow)
{
	struct gtp_tunnel *tun = flow->tun;
	struct gtp_peer_gsn *gsn = tun->gsn;
	struct gtp_endpoint *ep = gsn->ep;
	struct io_uring_sqe *sqe;

	//fputc('S', stdout);
#if 1
	sqe = io_uring_get_sqe(&ep->ring);
	OSMO_ASSERT(sqe);
	flow->in_progress = true;
#ifdef USE_REGISTERED_BUFFERS
#error not supported in sendmsg
#else
	io_uring_prep_sendmsg(sqe, ep->fd, &flow->msgh, 0);
#endif
	io_uring_sqe_set_data(sqe, flow);
#else
	sendmsg(gep->fd, &flow->msgh, 0);
#endif
}

/* number of packets per submit */
#define SWEET_SPOT	4000

static void gtpgen_handle_completion(struct gtp_endpoint *ep, struct io_uring_cqe *cqe)
{
	struct gtp_tunnel_ip_flow *flow = (struct gtp_tunnel_ip_flow *) cqe->user_data;

	//fputc('C', stdout);

	flow->in_progress = false;
}

static void *gtpgen_worker_thread(void *_ep)
{
	struct gtp_endpoint *gep = (struct gtp_endpoint *) _ep;
	struct osmo_sockaddr sa_local;
	int rc;

	/* create and bind socket */
	osmo_sockaddr_str_to_sockaddr(&gep->config.local, &sa_local.u.sas);
	rc = osmo_sock_init_osa(SOCK_DGRAM, IPPROTO_UDP, &sa_local, NULL, OSMO_SOCK_F_BIND);
	if (rc < 0)
		exit(1);
	gep->fd = rc;

	while (1) {
		struct gtp_peer_gsn *gsn;
		uint32_t num_submitted = 0;
		int num_pending;

		/* prepare transmit submissions */
		while (num_submitted < SWEET_SPOT) {
			llist_for_each_entry(gsn, &gep->gsns, list) {
				struct gtp_tunnel *tun;
				llist_for_each_entry(tun, &gsn->tunnels, list) {
					struct gtp_tunnel_ip_flow *flow;
					llist_for_each_entry(flow, &tun->flows, list) {
						//if (!flow->in_progress) {
						{
							gtpgen_tx_one(flow);
							num_submitted++;
						}
					}
				}
			}
		}

		/* actually submit; determines completions  */
		num_pending = io_uring_submit(&gep->ring);

		/* process all completions */
		for (int j = 0; j < num_pending; j++) {
			struct io_uring_cqe *cqe;
			int rc;

			rc = io_uring_wait_cqe(&gep->ring, &cqe);
			OSMO_ASSERT(rc >= 0);
			gtpgen_handle_completion(gep, cqe);
			io_uring_cqe_seen(&gep->ring, cqe);
		}
	}

}


/****************************************************************************
 * Data structures / code on main thread
 ****************************************************************************/

/* start an endpoint; creates thread and starts transmitting packets */
void gtp_endpoint_start(struct gtp_endpoint *ep)
{
	int rc;

	rc = pthread_create(&ep->worker, NULL, gtpgen_worker_thread, ep);
	OSMO_ASSERT(rc >= 0);
}

struct gtp_peer_gsn *gtp_peer_gsn_create(struct gtp_endpoint *ep, const struct osmo_sockaddr_str *remote_addr)
{
	struct gtp_peer_gsn *gsn = talloc_zero(ep, struct gtp_peer_gsn);
	int rc;

	OSMO_ASSERT(gsn);

	printf("  Creating GSN endpoint at remote " OSMO_SOCKADDR_STR_FMT "\n",
		OSMO_SOCKADDR_STR_FMT_ARGS(remote_addr));

	INIT_LLIST_HEAD(&gsn->tunnels);
	memcpy(&gsn->config.remote_addr, remote_addr, sizeof(gsn->config.remote_addr));

	llist_add_tail(&gsn->list, &ep->gsns);
	gsn->ep = ep;

	/* convert to sockaddr_storage for later use */
	rc = osmo_sockaddr_str_to_sockaddr(remote_addr, &gsn->dest_addr);
	OSMO_ASSERT(rc == 0);

	return gsn;
}

struct gtp_tunnel *gtp_tunnel_create(struct gtp_peer_gsn *gsn, uint32_t teid)
{
	struct gtp_tunnel *tun = talloc_zero(gsn, struct gtp_tunnel);
	OSMO_ASSERT(tun);

	printf("    Creating GTP tunnel for TEID 0x%08x\n", teid);

	INIT_LLIST_HEAD(&tun->flows);
	tun->config.teid = teid;

	llist_add_tail(&tun->list, &gsn->tunnels);
	tun->gsn = gsn;

	/* fill GTP header */
	tun->gtp_hdr = (struct gtp1u_hdr) {
		.pn = 0,
		.s = 0,
		.e = 0,
		.spare = 0,
		.pt = 1,
		.version = 1,
		.type = 0xff,	/* G-PDU */
		.length = 0,	/* filled in later */
		.tei = htonl(tun->config.teid),
	};

	return tun;
}

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/in.h>
#include <netinet/udp.h>

struct gtp_tunnel_ip_flow *gtp_tunnel_ip_flow_create(struct gtp_tunnel *tun,
						     const struct osmo_sockaddr_str *local,
						     const struct osmo_sockaddr_str *remote)
{
	struct gtp_tunnel_ip_flow *flow = talloc_zero(tun, struct gtp_tunnel_ip_flow);
	struct gtp_peer_gsn *gsn = tun->gsn;
	OSMO_ASSERT(flow);

	llist_add_tail(&flow->list, &tun->flows);
	flow->tun = tun;

	flow->in_progress = false;
	memcpy(&flow->config.local, local, sizeof(flow->config.local));
	memcpy(&flow->config.remote, remote, sizeof(flow->config.remote));

#ifdef USE_REGISTERED_BUFFERS
	flow->pkt_buf = gtp_endpoint_largebuf_get(gsn->ep);
#else
	flow->pkt_buf = talloc_zero_size(flow, BUF_SIZE);
	OSMO_ASSERT(flow->pkt_buf);
#endif

	/* copy over the GTP header from the tunnel */
	struct gtp1u_hdr *gtp_hdr = (struct gtp1u_hdr *) flow->pkt_buf;
	memcpy(gtp_hdr, &flow->tun->gtp_hdr, sizeof(*gtp_hdr));
	uint8_t *cur = flow->pkt_buf + sizeof(*gtp_hdr);

	/* FIXME: randomize this */
	unsigned int udp_len = 1024;

	struct iphdr *iph;
	struct ip6_hdr *ip6h;
	struct udphdr *uh;

	if (local->af == AF_INET) {
		struct in_addr saddr, daddr;

		iph = (struct iphdr *) cur;
		cur += sizeof(*iph);

		osmo_sockaddr_str_to_in_addr(&flow->config.local, &saddr);
		osmo_sockaddr_str_to_in_addr(&flow->config.remote, &daddr);

		iph->ihl = 5;
		iph->version = 4;
		iph->tos = 0;
		iph->tot_len = htons(udp_len + sizeof(struct udphdr) + sizeof(*iph));
		iph->id = 0;
		iph->frag_off = 0;
		iph->ttl = 32;
		iph->protocol = IPPROTO_UDP;
		iph->saddr = saddr.s_addr;
		iph->daddr = daddr.s_addr;
		iph->check = ip_fast_csum(iph, iph->ihl);
	} else {
		ip6h = (struct ip6_hdr *) flow->pkt_buf + sizeof(*gtp_hdr);
		cur += sizeof(*ip6h);

		//ip6h->ip6_flow = ; // TODO
		ip6h->ip6_plen = htons(udp_len + sizeof(struct udphdr) + sizeof(*ip6h));
		ip6h->ip6_nxt = IPPROTO_UDP;
		ip6h->ip6_hlim = 32;
		osmo_sockaddr_str_to_in6_addr(&flow->config.local, &ip6h->ip6_src);
		osmo_sockaddr_str_to_in6_addr(&flow->config.remote, &ip6h->ip6_dst);
	}

	uh = (struct udphdr *) cur;
	cur += sizeof(*uh);

	uh->source = htons(local->port);
	uh->dest = htons(remote->port);
	uh->len = htons(udp_len);
	uh->check = 0; // TODO

	gtp_hdr->length = htons(udp_len + (cur - flow->pkt_buf) - sizeof(*gtp_hdr));

	/* initialize this once, so we have it ready for each transmit */
	flow->msgh.msg_name = &gsn->dest_addr;
	flow->msgh.msg_namelen = sizeof(gsn->dest_addr);
	flow->msgh.msg_iov = flow->iov;
	flow->msgh.msg_iovlen = ARRAY_SIZE(flow->iov);
	flow->msgh.msg_control = NULL;
	flow->msgh.msg_controllen = 0;
	flow->msgh.msg_flags = 0;

	flow->iov[0].iov_base = flow->pkt_buf;
	flow->iov[0].iov_len = udp_len + (cur - flow->pkt_buf);

	return flow;
}



static void init_flows(void *ctx, unsigned int num_eps, unsigned int num_gsns, unsigned int num_tuns,
			unsigned int num_flows)
{
	for (int i = 0; i < num_eps; i++) {
		struct osmo_sockaddr_str gtp_local_addr;
		struct gtp_endpoint *ep;

		osmo_sockaddr_str_from_str(&gtp_local_addr, "127.0.0.1", 10000+i);

		ep = gtp_endpoint_create(ctx, &gtp_local_addr, NUM_FLOWS_PER_WORKER);
		OSMO_ASSERT(ep);

		for (int j = 0; j < num_gsns; j++) {
			struct osmo_sockaddr_str gtp_remote_addr;
			struct gtp_peer_gsn *gsn;
			char strbuf[64];

			sprintf(strbuf, "127.0.0.%u", 1+j);
			osmo_sockaddr_str_from_str(&gtp_remote_addr, strbuf, 2152);

			gsn = gtp_peer_gsn_create(ep, &gtp_remote_addr);
			OSMO_ASSERT(gsn);

			for (int k = 0; k < num_tuns; k++) {
				struct gtp_tunnel *tun;

				tun = gtp_tunnel_create(gsn, (i << 24) | (j << 16) | k);
				OSMO_ASSERT(tun);

				for (int l = 0; l < num_flows; l++) {
					struct osmo_sockaddr_str ip_local_addr, ip_remote_addr;
					sprintf(strbuf, "192.168.222.%u", 1+l);
					osmo_sockaddr_str_from_str(&ip_local_addr, strbuf, 10000);

					sprintf(strbuf, "10.255.255.%u", 1+l);
					osmo_sockaddr_str_from_str(&ip_remote_addr, strbuf, 53);

					gtp_tunnel_ip_flow_create(tun, &ip_local_addr, &ip_remote_addr);
				}
			}
		}

		gtp_endpoint_start(ep);
	}
}

int main(int argc, char **argv)
{
	void *g_ctx = talloc_named_const(NULL, 1, "gtpgen");

	osmo_init_logging2(g_ctx, NULL);

	init_flows(g_ctx, 2, 4, 100, 10);

	while (1) {
		osmo_select_main(0);
	}
}

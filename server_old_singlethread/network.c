#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <fcntl.h>
#include <signal.h>
#include <netdb.h>
#include <sched.h>
#include <stdarg.h>

#include <rte_eal.h>
#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_net.h>
#include <rte_flow.h>
#include <rte_cycles.h>

#include "network.h"
#include "framebuffer.h"
#include "llist.h"
#include "util.h"

#define RX_BURST_SIZE 128
#define NB_MBUF (1024 * 8)
#define MBUF_CACHE_SIZE 128

static volatile int force_quit;

static uint16_t port_id;
static uint16_t nr_cores = 1; // TODO Increase if nic supports it
struct rte_mempool *mbuf_pool;
struct rte_flow *flow;

static inline void print_ether_addr(const char *what, struct ether_addr *eth_addr)
{
	char buf[ETHER_ADDR_FMT_SIZE];
	ether_format_addr(buf, ETHER_ADDR_FMT_SIZE, eth_addr);
	printf("%s%s", what, buf);
}

static inline void print_ip6_addr(const char *what, uint8_t *addr) {
	printf("%s %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
		what, addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7],     addr[8], addr[9], addr[10], addr[11], addr[12], addr[13], addr[14], addr[15]);
}

static void signal_handler(int signum) {
	if (signum == SIGINT || signum == SIGTERM) {
		printf("\n\nSignal %d received, preparing to exit...\n",
				signum);
		force_quit = 1;
	}
}

static void init_port(void) {
	int ret;
	uint16_t i;
	struct rte_eth_conf port_conf = {
		.rxmode = {
			.split_hdr_size = 0,
			// .mq_mode	= ETH_MQ_RX_RSS,
			.max_rx_pkt_len = ETHER_MAX_LEN,
			// .offloads =
			// 	DEV_RX_OFFLOAD_CHECKSUM    |
			// 	DEV_RX_OFFLOAD_JUMBO_FRAME |
			// 	DEV_RX_OFFLOAD_VLAN_STRIP,
		},
		// .rx_adv_conf = {
		// 	.rss_conf = {
		// 		.rss_key = NULL,
		// 		.rss_hf = ETH_RSS_IP | ETH_RSS_UDP |
		// 			ETH_RSS_TCP | ETH_RSS_SCTP,
		// 	},
		// },
		// .txmode = {
		// 	.offloads =
				// DEV_TX_OFFLOAD_VLAN_INSERT |
				// DEV_TX_OFFLOAD_IPV4_CKSUM  |
				// DEV_TX_OFFLOAD_UDP_CKSUM   |
				// DEV_TX_OFFLOAD_TCP_CKSUM   |
				// DEV_TX_OFFLOAD_SCTP_CKSUM  |
				// DEV_TX_OFFLOAD_TCP_TSO     |
		// },
	};
	struct rte_eth_txconf txq_conf;
	struct rte_eth_rxconf rxq_conf;
	struct rte_eth_dev_info dev_info;

	rte_eth_dev_info_get(port_id, &dev_info);
	port_conf.txmode.offloads &= dev_info.tx_offload_capa;
	printf(":: initializing port: %d\n", port_id);
	printf(":: configuring port: %d\n", port_id);
	ret = rte_eth_dev_configure(port_id,
				nr_cores, nr_cores, &port_conf);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE,
			":: cannot configure device: err=%d, port=%u\n",
			ret, port_id);
	}

	printf(":: setting up RX queues for port: %d\n", port_id);
	rxq_conf = dev_info.default_rxconf;
	rxq_conf.offloads = port_conf.rxmode.offloads;
	/* only set Rx queues: something we care only so far */
	for (i = 0; i < nr_cores; i++) {
		ret = rte_eth_rx_queue_setup(port_id, i, 512,
				     rte_eth_dev_socket_id(port_id),
				     &rxq_conf,
				     mbuf_pool);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
				":: Rx queue setup failed: err=%d, port=%u\n",
				ret, port_id);
		}
	}

	printf(":: setting up TX queue for port: %d\n", port_id);
	txq_conf = dev_info.default_txconf;
	txq_conf.offloads = port_conf.txmode.offloads;

	for (i = 0; i < nr_cores; i++) {
		ret = rte_eth_tx_queue_setup(port_id, i, 512,
				rte_eth_dev_socket_id(port_id),
				&txq_conf);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
				":: Tx queue setup failed: err=%d, port=%u\n",
				ret, port_id);
		}
	}

	printf(":: Enabeling promiscuous-mode for port: %d\n", port_id);
	rte_eth_promiscuous_enable(port_id);
	printf(":: Starting port: %d\n", port_id);
	ret = rte_eth_dev_start(port_id);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE,
			"rte_eth_dev_start:err=%d, port=%u\n",
			ret, port_id);
	}

	printf(":: Asserting link is up for port: %d\n", port_id);
	// TODO assert_link_status();

	printf(":: initializing port: %d done\n", port_id);
}

struct args
{
	int queue_id;
	struct fb *fb;
};

void *dpdk_thread(struct args *args) {

	int queue_id = args->queue_id;
	struct fb *fb = args->fb;

	struct rte_mbuf *mbufs[RX_BURST_SIZE];
	struct ether_hdr *eth_hdr;
	struct ipv4_hdr *ipv4_hdr;
	struct ipv6_hdr *ipv6_hdr;
	struct rte_flow_error error;
	uint16_t nb_rx;
	uint16_t i, j;
	uint16_t x, y;
	uint32_t rgb;

	uint32_t log_counter = 0;

	while (!force_quit) {

		log_counter++;
		if (log_counter > 10000000) {
			struct rte_eth_stats eth_stats;
			RTE_ETH_FOREACH_DEV(i) {
				rte_eth_stats_get(i, &eth_stats);
				printf("Total number of packets received %lu, dropped rx full %lu and rest= %lu, %lu, %lu\n", eth_stats.ipackets, eth_stats.imissed, eth_stats.ierrors, eth_stats.rx_nombuf, eth_stats.q_ipackets[0]);
			}
			log_counter = 0;
		}

		// for (i = 0; i < nr_queues; i++) {
			nb_rx = rte_eth_rx_burst(port_id, queue_id, mbufs, RX_BURST_SIZE);
			if (nb_rx) {
				for (j = 0; j < nb_rx; j++) {
					struct rte_mbuf *m = mbufs[j];

					eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);
					// print_ether_addr("src=", &eth_hdr->s_addr);
					// print_ether_addr(" - dst=", &eth_hdr->d_addr);
					// printf(" - queue=0x%x", (unsigned int)i);

					if (eth_hdr->ether_type == rte_be_to_cpu_16(ETHER_TYPE_IPv6)) {
						// printf("Found IPv6: ");
						ipv6_hdr = rte_pktmbuf_mtod_offset(m, struct ipv6_hdr *, sizeof(struct ether_hdr));

						// if (ipv6_hdr->proto == 58) { // ICMP6
							//int icmp_type = *(&m + (sizeof(struct ether_hdr)));
							// uint8_t *icmp_type = rte_pktmbuf_mtod_offset(m, uint8_t*, sizeof(struct ether_hdr) + sizeof(struct ipv6_hdr));
							// printf("Detected ICMP6 (Type: %u)", *icmp_type);
							// TODO Reply to ICMP6
						// }
						// Continuing without any restriction, client can send whatever type he wants

						uint8_t *dst = ipv6_hdr->dst_addr;
						// print_ip6_addr(" IpV6: src: ", ipv6_hdr->src_addr);
						// print_ip6_addr(" IpV6: dst: ", ipv6_hdr->dst_addr);

						x = (dst[8] << 8) + dst[9];
						y = (dst[10] << 8) + dst[11];
						rgb = (dst[12] << 24) + (dst[13] << 16) + (dst[14] << 8);
						//printf(" --- x: %d y: %d rgb: %08x ---\n", x, y, rgb);
						fb_set_pixel(fb, x, y, rgb);

					} else if (eth_hdr->ether_type == rte_be_to_cpu_16(ETHER_TYPE_IPv4)) {
						// printf("Found IPv4: ");

						ipv4_hdr = rte_pktmbuf_mtod_offset(m, struct ipv4_hdr *, sizeof(struct ether_hdr));
						// printf(" IPv4 src: %x dst: %x\n", ipv4_hdr->src_addr, ipv4_hdr->dst_addr);
					} else {
						printf("Unkown protocol: %d", eth_hdr->ether_type);
					}

					rte_pktmbuf_free(m);
				}
			}
		// }
	}


	struct rte_eth_stats eth_stats;
	RTE_ETH_FOREACH_DEV(i) {
		rte_eth_stats_get(i, &eth_stats);
		printf("Total number of packets received %lu, dropped rx full %lu and rest= %lu, %lu, %lu\n", eth_stats.ipackets, eth_stats.imissed, eth_stats.ierrors, eth_stats.rx_nombuf, eth_stats.q_ipackets[0]);
	}


	/* closing and releasing resources */
	rte_flow_flush(port_id, &error);
	rte_eth_dev_stop(port_id);
	rte_eth_dev_close(port_id);

	return NULL;
}

int net_listen(int argc, char** argv, struct fb* fb) {
	int ret;
	uint16_t nr_ports;

	ret = rte_eal_init(argc, argv); // Give the EAL no CLI-parameter, so length is 1 (nothing). But still passing the original CLI-parameters
	if (ret < 0)
		rte_exit(EXIT_FAILURE, ":: invalid EAL arguments\n");

	force_quit = 0;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	nr_ports = rte_eth_dev_count_avail();
	if (nr_ports == 0)
		rte_exit(EXIT_FAILURE, ":: no Ethernet ports found\n");
	port_id = 0;
	if (nr_ports != 1) {
		printf(":: warn: %d ports detected, but we use only one: port %u\n",
			nr_ports, port_id);
	}
	mbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", NB_MBUF, MBUF_CACHE_SIZE, 0,
					    RTE_MBUF_DEFAULT_BUF_SIZE,
					    rte_socket_id());
	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");

	init_port();

	printf("Initialized all ports\n");

	// pthread_t dpdk_thread_reference;
	// if(pthread_create(&dpdk_thread_reference, NULL, dpdk_thread, fb)) {
	// 	fprintf(stderr, "Error creating dpdk_thread thread\n");
	// 	return -1;
	// }
	// printf("Created dpdk thread.\n");

	unsigned int core_id_counter;
	for (core_id_counter = 0; core_id_counter < nr_cores; core_id_counter++) {
		struct args args;
		args.fb=fb;
		args.queue_id = core_id_counter;

		rte_eal_remote_launch(dpdk_thread, &args, 3);
		core_id_counter++;
	}

	printf("Created dpdk threads.\n");

	return 0;
}

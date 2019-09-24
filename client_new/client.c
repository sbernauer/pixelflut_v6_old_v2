#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <getopt.h>
#include <signal.h>

#include <rte_common.h>
#include <rte_eal.h>
#include <rte_log.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>

#define MAX_RX_QUEUE_PER_LCORE 16
#define MAX_TIMER_PERIOD 86400 /* 1 day max */
#define BURST_SIZE 32
#define NB_MBUF (1024 * 8)
#define MBUF_CACHE_SIZE 128
#define PACKET_DESCRIPTORS 1024
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */


static uint64_t timer_period = 1; /* default period is 1 second */

static volatile bool force_quit;
static uint32_t port_mask = 0;
static unsigned int cores_per_port = 1;
static unsigned int queues_per_core = 1;

struct rte_mempool *mbuf_pool;

/* print usage */
static void
print_usage()
{
    printf("\npixelflut_v6_client [EAL options] -- -p PORTMASK\n"
           "  -p PORTMASK: hexadecimal bitmask of ports to configure (for example 0x3 for the first 2 ports)\n"
           "  -c NUMBER: number of cores per port (default is 1)\n"
           "  -q NUMBER: number of queus per core (default is 1)\n"
           "  -T PERIOD: statistics will be refreshed each PERIOD seconds (0 to disable, 1 default, %u maximum)\n", MAX_TIMER_PERIOD);
}

static inline void print_ether_addr(const char *what, struct ether_addr *eth_addr)
{
    char buf[ETHER_ADDR_FMT_SIZE];
    ether_format_addr(buf, ETHER_ADDR_FMT_SIZE, eth_addr);
    printf("%s%s", what, buf);
}

static int
parse_portmask(const char *portmask)
{
    char *end = NULL;
    unsigned long pm;

    /* parse hexadecimal string */
    pm = strtoul(portmask, &end, 16);
    if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
        return -1;

    if (pm == 0)
        return -1;

    return pm;
}

static unsigned int
parse_nqueue(const char *q_arg)
{
    char *end = NULL;
    unsigned long n;

    /* parse hexadecimal string */
    n = strtoul(q_arg, &end, 10);
    if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0'))
        return 0;
    if (n == 0)
        return 0;
    if (n >= MAX_RX_QUEUE_PER_LCORE)
        return 0;

    return n;
}

static int
parse_timer_period(const char *q_arg)
{
    char *end = NULL;
    int n;

    /* parse number string */
    n = strtol(q_arg, &end, 10);
    if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0'))
        return -1;
    if (n >= MAX_TIMER_PERIOD)
        return -1;

    return n;
}


/* Parse the argument given in the command line of the application */
static int
parse_args(int argc, char **argv)
{
    int timer_secs;
    int opt;

    // Reset getopt
    optind = 1;

    while ((opt = getopt(argc, argv, "p:c:q:T:w:h:r:s:l:f:d?")) != -1) {
        switch (opt) {

        case('w'):
        case('h'):
        case('r'):
        case('s'):
        case('l'):
        case('f'):
        case('d'):
            // Parameter that goes to network.c
            break;

        case 'p':
            port_mask = parse_portmask(optarg);
            if (port_mask == 0) {
                printf("invalid portmask\n");
                print_usage();
                return -1;
            }
            break;

        case 'c':
            cores_per_port = parse_nqueue(optarg);
            if (cores_per_port == 0) {
                printf("invalid number of cores per port\n");
                print_usage();
                return -1;
            }
            break;

        case 'q':
            queues_per_core = parse_nqueue(optarg);
            if (queues_per_core == 0) {
                printf("invalid number of queues per core\n");
                print_usage();
                return -1;
            }
            break;

        case 'T':
            timer_secs = parse_timer_period(optarg);
            if (timer_secs < 0) {
                printf("invalid timer period\n");
                print_usage();
                return -1;
            }
            timer_period = timer_secs;
            break;

        default:
            print_usage();
            return -1;
        }
    }

    return 0;
}

#define CHECK_INTERVAL 100  /* 100ms */
#define MAX_REPEAT_TIMES 10  /* 9s (90 * 100ms) in total */

static void
assert_link_status(unsigned int port_id)
{
    struct rte_eth_link link;
    uint8_t rep_cnt = MAX_REPEAT_TIMES;

    memset(&link, 0, sizeof(link));
    do {
        rte_eth_link_get(port_id, &link);
        if (link.link_status == ETH_LINK_UP)
            break;
        printf(".");
        fflush(stdout);
        rte_delay_ms(CHECK_INTERVAL);
    } while (!force_quit && --rep_cnt);

    if (link.link_status == ETH_LINK_DOWN)
        rte_exit(EXIT_FAILURE, ":: error: link at port %u is still down\n", port_id);
    else
        printf("Port%d Link Up. Speed %u Mbps - %s\n", port_id, link.link_speed, (link.link_duplex == ETH_LINK_FULL_DUPLEX) ? ("full-duplex") : ("half-duplex\n"));
}

static void init_port(unsigned int port_id) {
    int ret;
    uint16_t i;
    struct rte_eth_conf port_conf = {
        .rxmode = {
            .split_hdr_size = 0,
            // .mq_mode = ETH_MQ_RX_RSS,
            .max_rx_pkt_len = ETHER_MAX_LEN,
            // .offloads =
            //  DEV_RX_OFFLOAD_CHECKSUM    |
            //  DEV_RX_OFFLOAD_JUMBO_FRAME |
            //  DEV_RX_OFFLOAD_VLAN_STRIP,
        },
        // .rx_adv_conf = {
        //  .rss_conf = {
        //      .rss_key = NULL,
        //      .rss_hf = ETH_RSS_IP | ETH_RSS_UDP |
        //          ETH_RSS_TCP | ETH_RSS_SCTP,
        //  },
        // },
        // .txmode = {
        //  .offloads =
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
    ret = rte_eth_dev_configure(port_id, cores_per_port * queues_per_core, 1, &port_conf); // port_id, nb_rx_queue, nb_tx_queue, eth_conf
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, ":: cannot configure device: err=%d, port=%u\n", ret, port_id);
    }

    printf(":: setting up 1 RX queue for port: %d\n", port_id);
    rxq_conf = dev_info.default_rxconf;
    rxq_conf.offloads = port_conf.rxmode.offloads;

    /* only set Rx queues: something we care only so far */
    for (i = 0; i < 1; i++) {
        ret = rte_eth_rx_queue_setup(port_id, i, PACKET_DESCRIPTORS, rte_eth_dev_socket_id(port_id), &rxq_conf, mbuf_pool);
        if (ret < 0) {
            rte_exit(EXIT_FAILURE, ":: Rx queue setup failed: err=%d, port=%u\n", ret, port_id);
        }
    }

    printf(":: setting up %u TX queues for port: %d\n", cores_per_port * queues_per_core, port_id);
    txq_conf = dev_info.default_txconf;
    txq_conf.offloads = port_conf.txmode.offloads;

    /* Only one queue */
    for (i = 0; i < cores_per_port * queues_per_core; i++) {
        ret = rte_eth_tx_queue_setup(port_id, i, PACKET_DESCRIPTORS, rte_eth_dev_socket_id(port_id), &txq_conf);
        if (ret < 0) {
            rte_exit(EXIT_FAILURE, ":: Tx queue setup failed: err=%d, port=%u\n", ret, port_id);
        }
    }


    printf(":: Enabeling promiscuous-mode for port: %d\n", port_id);
    rte_eth_promiscuous_enable(port_id);
    printf(":: Starting port: %d\n", port_id);
    ret = rte_eth_dev_start(port_id);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%d, port=%u\n", ret, port_id);
    }

    printf(":: Asserting link is up for port: %d\n", port_id);
    assert_link_status(port_id);

    printf(":: initializing port: %d done\n", port_id);
}

struct worker_thread_args
{
    int port_id;
    int start_queue_id;
};

void *worker_thread(struct worker_thread_args *args) {
    printf("worker_thread\n");

    // Read args
    int port_id = args->port_id;
    int start_queue_id = args->start_queue_id;

    struct rte_mbuf *mbufs_transmit[BURST_SIZE];
    struct rte_flow_error error;
    uint16_t nb_tx;
    uint16_t i, queue_id;

    uint32_t log_counter = 0;

    struct ether_hdr *eth_hdr;
    struct ipv6_hdr *ipv6_hdr;

    struct ether_addr daddr;
    daddr.addr_bytes[0] = 0x00;
    daddr.addr_bytes[1] = 0x1b;
    daddr.addr_bytes[2] = 0x21;
    daddr.addr_bytes[3] = 0x8b;
    daddr.addr_bytes[4] = 0xe5;
    daddr.addr_bytes[5] = 0x18;

    struct ether_addr saddr;
    saddr.addr_bytes[0] = 0x00;
    saddr.addr_bytes[1] = 0x1b;
    saddr.addr_bytes[2] = 0x21;
    saddr.addr_bytes[3] = 0x70;
    saddr.addr_bytes[4] = 0x8a;
    saddr.addr_bytes[5] = 0x88;

    srand(time(NULL));
    int x = 100;
    int y = 100;
    uint32_t rgb = rand();


    while (!force_quit) {


        if(rte_pktmbuf_alloc_bulk(mbuf_pool, mbufs_transmit, BURST_SIZE)!=0) {
            printf("Allocation problem\n");
        }
        for(i  = 0; i < BURST_SIZE; i++) {
            //eth_hdr = rte_pktmbuf_mtod(mbufs_transmit[i], struct ether_hdr *);
            eth_hdr = (struct ether_hdr *)rte_pktmbuf_append(mbufs_transmit[i], sizeof(struct ether_hdr) + sizeof(struct ipv6_hdr) + 8); // TODO Maybe update: Added 8 bytes UDP payload
            eth_hdr->ether_type = htons(ETHER_TYPE_IPv6);
            rte_memcpy(&(eth_hdr->s_addr), &saddr, sizeof(struct ether_addr));
            rte_memcpy(&(eth_hdr->d_addr), &daddr, sizeof(struct ether_addr));

            ipv6_hdr = rte_pktmbuf_mtod_offset(mbufs_transmit[i], struct ipv6_hdr *, sizeof(struct ether_hdr));
            ipv6_hdr->vtc_flow = htonl(6 << 28); // IP version 6
            ipv6_hdr->hop_limits = 0xff;
            ipv6_hdr->proto = 0x11; // UDP
            ipv6_hdr->payload_len = 0x0800; // 8 byte, but applied endian conversion

            // Destination /64 IPv6 network
            ipv6_hdr->dst_addr[0] = 0x40;
            ipv6_hdr->dst_addr[1] = 0x00;
            ipv6_hdr->dst_addr[2] = 0x00;
            ipv6_hdr->dst_addr[3] = 0x42;
            ipv6_hdr->dst_addr[4] = 0;
            ipv6_hdr->dst_addr[5] = 0;
            ipv6_hdr->dst_addr[6] = 0;
            ipv6_hdr->dst_addr[7] = 0;

            ipv6_hdr->src_addr[0] = 0xfe;
            ipv6_hdr->src_addr[1] = 0x80;
            ipv6_hdr->src_addr[2] = 0;
            ipv6_hdr->src_addr[3] = 0;
            ipv6_hdr->src_addr[4] = 0;
            ipv6_hdr->src_addr[5] = 0;
            ipv6_hdr->src_addr[6] = 0;
            ipv6_hdr->src_addr[7] = 0;
            ipv6_hdr->src_addr[8] = 0;
            ipv6_hdr->src_addr[9] = 0;
            ipv6_hdr->src_addr[10] = 0;
            ipv6_hdr->src_addr[11] = 0;
            ipv6_hdr->src_addr[12] = 0;
            ipv6_hdr->src_addr[13] = 0;
            ipv6_hdr->src_addr[14] = 0;
            ipv6_hdr->src_addr[15] = 0x01;

            // X Coordinate
            ipv6_hdr->dst_addr[8] = x >> 8;
            ipv6_hdr->dst_addr[9] = x;

            // Y Coordinate
            ipv6_hdr->dst_addr[10] = y >> 8;
            ipv6_hdr->dst_addr[11] = y;

            // Color in rgb
            ipv6_hdr->dst_addr[12] = rgb >> 24;
            ipv6_hdr->dst_addr[13] = rgb >> 16;
            ipv6_hdr->dst_addr[14] = rgb >> 8;
            ipv6_hdr->dst_addr[15] = 0;

            // UDO Header
            ipv6_hdr->dst_addr[16] = 0; // Source port in UDP
            ipv6_hdr->dst_addr[17] = 13;
            ipv6_hdr->dst_addr[18] = 0; // Destination port in UDP
            ipv6_hdr->dst_addr[19] = 42;
            ipv6_hdr->dst_addr[20] = 0; // Length
            ipv6_hdr->dst_addr[21] = 0;
            ipv6_hdr->dst_addr[22] = 0; // Checksum (manditory at IPv6)
            ipv6_hdr->dst_addr[23] = 0;

            x++;
            if (x > 900) {
                x = 100;
                y++;
                if (y > 700) {
                    y = 100;
                    //srand(time(NULL));
                    rgb = rand();
                }
            }
        }
        do {
            nb_tx = rte_eth_tx_burst(port_id, queue_id, mbufs_transmit, BURST_SIZE);
            //printf("Send %u packets to port %u\n", nb_tx, portid);
        } while(nb_tx == 0);

        if (unlikely(nb_tx < BURST_SIZE)) {
            //printf("ERROR cant send %lu packets.\n", BURST_SIZE - nb_tx);
            uint16_t buf;

            for (buf = nb_tx; buf < BURST_SIZE; buf++)
                rte_pktmbuf_free(mbufs_transmit[buf]);
        }

        // Dump one packet
        // rte_pktmbuf_dump(stdout, pkts_burst[0], 1000);

        // // Read back
        // const uint16_t nb_rx = rte_eth_rx_burst(portid, 0, pkts_read, BURST_SIZE);
        // for (int i = 0; i < nb_rx; i++) {
        //     rte_pktmbuf_free(pkts_read[i]);
        // }

        log_counter++;
        if (unlikely(log_counter > 10000)) {
            log_counter = 0;

            struct rte_eth_stats eth_stats;
            RTE_ETH_FOREACH_DEV(i) {
                rte_eth_stats_get(i, &eth_stats);
                printf("Total number of packets for port %u: send %lu packets (%lu bytes), received %lu packets (%lu bytes), dropped rx %lu and rest= %lu, %lu, %lu\n", i, eth_stats.opackets, eth_stats.obytes, eth_stats.ipackets, eth_stats.ibytes, eth_stats.imissed, eth_stats.ierrors, eth_stats.rx_nombuf, eth_stats.q_ipackets[0]);
            }
        }


        // /*
        //  * Read packet from RX queues
        //  */
        // for (i = 0; i < qconf->n_rx_port; i++) {

        //  portid = qconf->rx_port_list[i];
        //  nb_rx = rte_eth_rx_burst(portid, 0,
        //               pkts_burst, MAX_PKT_BURST);

        //  port_statistics[portid].rx += nb_rx;

        //  for (j = 0; j < nb_rx; j++) {
        //      m = pkts_burst[j];
        //      rte_prefetch0(rte_pktmbuf_mtod(m, void *));
        //      l2fwd_simple_forward(m, portid);
        //  }
        // }
    }


    struct rte_eth_stats eth_stats;
    RTE_ETH_FOREACH_DEV(i) {
        rte_eth_stats_get(i, &eth_stats);
        printf("Total number of packets for port %u received %lu, dropped rx full %lu and rest= %lu, %lu, %lu\n", i, eth_stats.ipackets, eth_stats.imissed, eth_stats.ierrors, eth_stats.rx_nombuf, eth_stats.q_ipackets[0]);
    }


    /* closing and releasing resources */
    rte_flow_flush(port_id, &error);
    rte_eth_dev_stop(port_id);
    rte_eth_dev_close(port_id);

    return NULL;
}

int
main(int argc, char** argv)
{
    int ret;
    uint16_t nb_ports, port_id;

    /* init EAL */
    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");

    argc -= ret;
    argv += ret;

    /* parse application arguments (after the EAL ones) */
    ret = parse_args(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Invalid pixelflut_v6_client arguments\n");

    printf("DEBUG: port_mask: 0x%x\n", port_mask);
    printf("DEBUG: cores_per_port: %u\n", cores_per_port);
    printf("DEBUG: queues_per_core: %u\n", queues_per_core);
    if (port_mask == 0) {
        printf("==========================\nWARNING: No port enabled, enable them with the option -p\nThere will be no pixels drawn, testing purpose only\n==========================\n");
    }

    /* Check if any port is present */
    nb_ports = rte_eth_dev_count_avail();
    printf("Found %u ports\n", nb_ports);
    // if (nb_ports == 0)
    //     rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");

    /* check port mask to possible port mask */
    if (port_mask & ~((1 << nb_ports) - 1))
        rte_exit(EXIT_FAILURE, "Invalid portmask; possible (0x%x)\n",
            (1 << nb_ports) - 1);

    mbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", NB_MBUF, MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");

    struct ether_addr mac;
    RTE_ETH_FOREACH_DEV(port_id) {
        /* skip ports that are not enabled */
        if ((port_mask & (1 << port_id)) == 0)
            continue;

        rte_eth_macaddr_get(0, &mac);
        printf("\nPort %u, MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n", port_id, mac.addr_bytes[0], mac.addr_bytes[1], mac.addr_bytes[2], mac.addr_bytes[3], mac.addr_bytes[4], mac.addr_bytes[5]);

        init_port(port_id);
    }

    printf("\nInitialized all ports, launching threads\n");


    unsigned int core_id_counter = 1;
    RTE_ETH_FOREACH_DEV(port_id) {
        /* skip ports that are not enabled */
        if ((port_mask & (1 << port_id)) == 0)
            continue;

        unsigned int queue_id_counter = 0;
        unsigned int i;
        for (i = 0; i < cores_per_port; i++) {
            printf("Launching on port %u, core %u and queue %u - %u (inclusive)\n", port_id, core_id_counter, queue_id_counter, queue_id_counter + queues_per_core - 1);

            struct worker_thread_args args;
            args.port_id = port_id;
            args.start_queue_id = queue_id_counter;

            if (!rte_lcore_is_enabled(core_id_counter)) {
                rte_exit(EXIT_FAILURE, "Lcore %u is not enabled, so cant start worker_thread on it. Maybe you have to few cores enables with the EAL-option (-l / -c) or on your system. I need one master core (id: 0) and a lcore for every started worker_thread.\n");
            }

            rte_eal_remote_launch(worker_thread, &args, core_id_counter);
            printf("Launched\n");

            queue_id_counter += queues_per_core;
            core_id_counter++;
        }
    }
    printf("Launched all threads\n");


    int lcore_id, portid;
    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        if (rte_eal_wait_lcore(lcore_id) < 0) {
            ret = -1;
            break;
        }
    }

    RTE_ETH_FOREACH_DEV(portid) {
        if ((port_mask & (1 << portid)) == 0)
            continue;
        printf("Closing port %d...", portid);
        rte_eth_dev_stop(portid);
        rte_eth_dev_close(portid);
        printf(" Done\n");
    }
    printf("Bye...\n");


    // unsigned int core_id_counter;
    // unsigned int queue_id_counter;

    // for (core_id_counter = 0; core_id_counter < nr_cores; core_id_counter++) {


    // for (core_id_counter = 0; core_id_counter < nr_cores; core_id_counter++) {
    //     struct thread_args args;
    //     args.fb=fb;
    //     args.queue_ids = core_id_counter;

    //     rte_eal_remote_launch(dpdk_thread, &args, 3);
    //     core_id_counter++;
    // }

    // while(!force_quit) {
    //     sleep(1);
    // }

    return 0;
}

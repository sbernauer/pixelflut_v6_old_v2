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
#define RX_BURST_SIZE 32
#define NB_MBUF (1024 * 8)
#define MBUF_CACHE_SIZE 128

static uint64_t timer_period = 10; /* default period is 10 seconds */

static volatile bool force_quit;
static uint32_t port_mask = 0;
static unsigned int rx_cores_per_port = 1;
static unsigned int rx_queues_per_core = 1;

struct rte_mempool *mbuf_pool;

/* print usage */
static void
print_usage()
{
    printf("\npixelflut_v6_client [EAL options] -- -p PORTMASK\n"
           "  -p PORTMASK: hexadecimal bitmask of ports to configure\n"
           "  -c NQ: number of cores per port (default is 1)\n"
           "  -q NQ: number of queus per core (default is 1)\n"
           "  -T PERIOD: statistics will be refreshed each PERIOD seconds (0 to disable, 1 default, 86400 maximum)\n");
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

    while ((opt = getopt(argc, argv, "p: c: q: T:")) != EOF) {

        switch (opt) {
        case 'p':
            port_mask = parse_portmask(optarg);
            if (port_mask == 0) {
                printf("invalid portmask\n");
                print_usage();
                return -1;
            }
            break;

        case 'c':
            rx_cores_per_port = parse_nqueue(optarg);
            if (rx_cores_per_port == 0) {
                printf("invalid number of cores per port\n");
                print_usage();
                return -1;
            }
            break;

        case 'q':
            rx_queues_per_core = parse_nqueue(optarg);
            if (rx_queues_per_core == 0) {
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

static void
signal_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\n\nSignal %d received, preparing to exit...\n",
                signum);
        force_quit = true;
    }
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
    ret = rte_eth_dev_configure(port_id, rx_cores_per_port * rx_queues_per_core, 1, &port_conf); // port_id, nb_rx_queue, nb_tx_queue, eth_conf
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, ":: cannot configure device: err=%d, port=%u\n", ret, port_id);
    }

    printf(":: setting up %u RX queues for port: %d\n", rx_cores_per_port * rx_queues_per_core, port_id);
    rxq_conf = dev_info.default_rxconf;
    rxq_conf.offloads = port_conf.rxmode.offloads;

    /* only set Rx queues: something we care only so far */
    for (i = 0; i < rx_cores_per_port * rx_queues_per_core; i++) {
        ret = rte_eth_rx_queue_setup(port_id, i, 512, rte_eth_dev_socket_id(port_id), &rxq_conf, mbuf_pool);
        if (ret < 0) {
            rte_exit(EXIT_FAILURE, ":: Rx queue setup failed: err=%d, port=%u\n", ret, port_id);
        }
    }

    printf(":: setting up 1 TX queue for port: %d\n", port_id);
    txq_conf = dev_info.default_txconf;
    txq_conf.offloads = port_conf.txmode.offloads;

    /* Only one queue */
    for (i = 0; i < 1; i++) {
        ret = rte_eth_tx_queue_setup(port_id, i, 512, rte_eth_dev_socket_id(port_id), &txq_conf);
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

    force_quit = false;
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* parse application arguments (after the EAL ones) */
    ret = parse_args(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Invalid pixelflut_v6_client arguments\n");

    printf("DEBUG: port_mask: 0x%x\n", port_mask);
    printf("DEBUG: rx_cores_per_port: %u\n", rx_cores_per_port);
    printf("DEBUG: rx_queues_per_core: %u\n", rx_queues_per_core);
    if (port_mask == 0) {
        printf("==========================\nWARNING: No port enabled, enable them with the option -p\nThere will be no pixels drawn, testing purpose only\n==========================\n");
    }

    /* Check if any port is present */
    nb_ports = rte_eth_dev_count_avail();
    if (nb_ports == 0)
        rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");

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

    printf("All ports initialized\n");

}

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <getopt.h>
#include <signal.h>

#include <rte_eal.h>

#define MAX_RX_QUEUE_PER_LCORE 16
#define MAX_TIMER_PERIOD 86400 /* 1 day max */

static uint64_t timer_period = 10; /* default period is 10 seconds */

static volatile bool force_quit;
static uint32_t l2fwd_enabled_port_mask = 0;
static unsigned int l2fwd_rx_cores_per_port = 1;
static unsigned int l2fwd_rx_queues_per_core = 1;

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
            l2fwd_enabled_port_mask = parse_portmask(optarg);
            if (l2fwd_enabled_port_mask == 0) {
                printf("invalid portmask\n");
                print_usage();
                return -1;
            }
            break;

        case 'q':
            l2fwd_rx_cores_per_port = parse_nqueue(optarg);
            if (l2fwd_rx_cores_per_port == 0) {
                printf("invalid  number of cores per port\n");
                print_usage();
                return -1;
            }
            break;

        case 'r':
            l2fwd_rx_queues_per_core = parse_nqueue(optarg);
            if (l2fwd_rx_queues_per_core == 0) {
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

int
main(int argc, char** argv)
{
    /* init EAL */
    int ret;
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
}
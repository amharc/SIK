#include "common.h"
#include "rbt.h"
#include "mdns.h"
#include "udp-client.h"
#include "udp-server.h"
#include "telnet.h"
#include "tcp.h"
#include "icmp-client.h"

#include <signal.h>

static void ignore_sigpipe(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_IGN;
    if(sigemptyset(&sa.sa_mask) < 0 || sigaction(SIGPIPE, &sa, 0) < 0)
        die("Unable to block SIGPIPE");
}

int main(int argc, char **argv) {
    pthread_t udp_server, udp_client, telnet, tcp, icmp_client;

    srand(time(NULL));

    struct mdns_data mdns_data = {
        .interval = 10,
        .ssh = false
    };

    struct udp_server_data udp_server_data = {
        .port = 3382
    };

    struct udp_client_data udp_client_data = {
        .interval = 1,
        .port = 3382
    };

    struct telnet_data telnet_data = {
        .port = 3637,
        .interval = 1000000000
    };

    struct tcp_data tcp_data = {
        .interval = 1
    };

    struct icmp_client_data icmp_client_data = {
        .interval = 1
    };

    int c;
    float fval;
    char *endpos;
    while(-1 != (c = getopt(argc, argv, "u:U:t:T:v:s"))) {
        switch(c) {
            case 'u':
                udp_client_data.port = udp_server_data.port = strtoul(optarg, &endpos, 10);
                if(endpos != optarg + strlen(optarg))
                    die("Illegal UDP port number: %s", optarg);
                break;
            case 'U':
                telnet_data.port = strtoul(optarg, &endpos, 10);
                if(endpos != optarg + strlen(optarg))
                    die("Illegal telnet port number: %s", optarg);
                break;
            case 't':
                icmp_client_data.interval = tcp_data.interval = udp_client_data.interval = strtoul(optarg, &endpos, 10);
                if(endpos != optarg + strlen(optarg))
                    die("Illegal integer period: %s", optarg);
                break;
            case 'T':
                mdns_data.interval = strtoul(optarg, &endpos, 10);
                if(endpos != optarg + strlen(optarg))
                    die("Illegal integer period: %s", optarg);
                break;
            case 'v':
                fval = strtof(optarg, &endpos);
                if(endpos != optarg + strlen(optarg))
                    die("Illegal real period: %s", optarg);
                telnet_data.interval = fval * 1000 * 1000 * 1000;
            case 's':
                mdns_data.ssh = true;
                break;
            case '?':
                return EXIT_FAILURE;
            default:
                die("Unexpected option (a bug in getopt/)");
        }
    }

    if(optind != argc)
        die("Unexpected argument");

    rb_init();
    ignore_sigpipe();

    int r;
    r = pthread_create(&udp_server, NULL, &start_udp_server, &udp_server_data);
    if(r != 0)
        die("Unable to start the UDP server thread: %d (%s)", r, strerror(r));

    r = pthread_create(&udp_client, NULL, &start_udp_client, &udp_client_data);
    if(r != 0)
        die("Unable to start the UDP client thread: %d (%s)", r, strerror(r));

    r = pthread_create(&telnet, NULL, &start_telnet, &telnet_data);
    if(r != 0)
        die("Unable to start the telnet thread: %d (%s)", r, strerror(r));

    r = pthread_create(&tcp, NULL, &start_tcp, &tcp_data);
    if(r != 0)
        die("Unable to start the TCP thread: %d (%s)", r, strerror(r));

    r = pthread_create(&icmp_client, NULL, &start_icmp_client, &icmp_client_data);
    if(r != 0)
        die("Unable to start the ICMP thread: %d (%s)", r, strerror(r));

    start_mdns(&mdns_data);
}

#include "udp-client.h"
#include "rbt.h"

struct udp_sender_data {
    in_port_t port;
    int sock;
    unsigned interval;
};

struct udp_receiver_data {
    int sock;
};

static void udp_send(struct host *host, void *_data) {
    struct udp_sender_data *restrict data = _data;
    uint64_t now = gettime();

    if(host->udp.valid_till >= now) {
        socklen_t addrlen = sizeof(struct sockaddr_in);
        now = htobe64(now);

        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(data->port);
        addr.sin_addr = host->addr;

        ssize_t len = sendto(data->sock, &now, sizeof(uint64_t), 0,
                (const struct sockaddr*) &addr, addrlen);

        if(len != sizeof(uint64_t))
            die("Unable to send a UDP query packet");
    }
}

static _Noreturn void* start_udp_client_sender(void *_data) {
    struct udp_sender_data *restrict data = _data;

    while(true) {
        rb_read_lock();
        rb_foreach(udp_send, _data);
        rb_unlock();

        usleep(data->interval * 1000 * 1000);
    }
}

static _Noreturn void* start_udp_client_receiver(void *_data) {
    struct udp_receiver_data *restrict data = _data;

    while(true) {
        struct sockaddr_in addr;
        socklen_t addrlen = sizeof(struct sockaddr_in);
        uint64_t buf[2];

        ssize_t len = recvfrom(data->sock, buf, sizeof(buf), 0,
                (struct sockaddr*) &addr, &addrlen);

        if(len < 0)
            die("Unable to receive a UDP packet");

        uint64_t now = gettime();

        if(len != sizeof(buf) || addr.sin_family != AF_INET) {
            continue; // Silently ignore
        }

        rb_read_lock();
        struct host *host = rb_find(&addr.sin_addr); 
        if(host != NULL) {
            int r = pthread_mutex_lock(&host->mutex);
            if(r != 0)
                die("Unable to lock host mutex: %d (%s)", r, strerror(r));
            host->udp.delays[host->udp.current++] = now - be64toh(buf[0]);
            host->udp.current %= QUERIES_COUNT;
            r = pthread_mutex_unlock(&host->mutex);
            if(r != 0)
                die("Unable to unlock host mutex: %d (%s)", r, strerror(r));
        }
        rb_unlock();      
    }
}

_Noreturn void* start_udp_client(void *_data) {
    struct udp_client_data *restrict data = _data;

    struct udp_sender_data *sender_data = malloc(sizeof(struct udp_sender_data));
    if(!sender_data)
        die("Unable to allocate memory");

    struct udp_receiver_data *receiver_data = malloc(sizeof(struct udp_receiver_data));
    if(!receiver_data)
        die("Unable to allocate memory");

    sender_data->port = data->port;
    sender_data->interval = data->interval;

    int sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if(sock < 0)
        die("Unable to create a socket for the UDP client");

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(struct sockaddr_in));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = 0;

    if(0 != bind(sock, (const struct sockaddr*) &addr, sizeof(addr)))
        die("Unable to bind to an address for the UDP client");

    sender_data->sock = sock;
    receiver_data->sock = sock;

    pthread_t sender;

    int ret;
    ret = pthread_create(&sender, NULL, &start_udp_client_sender, sender_data);
    if(ret != 0)
        die("Unable to create UDP client sender thread: %d (%s)", ret, strerror(ret));

    start_udp_client_receiver(receiver_data);
}

#ifndef _HOST_H
#define _HOST_H

#include "common.h"

#define QUERIES_COUNT 10
#define ICMP_BACKLOG 20

struct udp_or_tcp_host {
    uint64_t valid_till;

    // zero means NULL
    uint64_t delays[QUERIES_COUNT];
    unsigned int current; 
};

struct icmp_request {
    bool valid;
    uint64_t when;
    uint16_t seq;
};

struct icmp_host {
    struct icmp_request requests[ICMP_BACKLOG];
    unsigned char request_current;
    uint16_t seq;

    uint64_t delays[QUERIES_COUNT];
    unsigned int current; 
};

struct host {
    struct in_addr addr;
    struct udp_or_tcp_host udp;
    struct udp_or_tcp_host tcp;
    struct icmp_host icmp;

    pthread_mutex_t mutex;
};

#endif

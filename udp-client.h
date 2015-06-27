#ifndef _UDP_CLIENT_H
#define _UDP_CLIENT_H

#include "common.h"

struct udp_client_data {
    unsigned interval;
    in_port_t port;
};

_Noreturn void* start_udp_client(void *data);

#endif // _UDP_CLIENT_H

#ifndef _UDP_SERVER_H
#define _UDP_SERVER_H

#include "common.h"

struct udp_server_data {
    in_port_t port;
};

_Noreturn void* start_udp_server(void *udp_data);

#endif // _UDP_SERVER_H

#ifndef _TELNET_H
#define _TELNET_H

#include "common.h"

struct telnet_data {
    in_port_t port;
    uint64_t interval;
};

_Noreturn void* start_telnet(void *data);

#endif // _TELNET_H

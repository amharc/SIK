#ifndef _ICMP_CLIENT_H
#define _ICMP_CLIENT_H

#include "common.h"

struct icmp_client_data {
    unsigned interval;
};

_Noreturn void* start_icmp_client(void *data);

#endif // _ICMP_CLIENT_H

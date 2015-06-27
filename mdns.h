#ifndef _MDNS_H
#define _MDNS_H

#include "common.h"

struct mdns_data {
    unsigned interval;
    bool ssh;
};

_Noreturn void* start_mdns(void *data);

#endif // _MDNS_H

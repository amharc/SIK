#ifndef _TCP_H
#define _TCP_H

#include "common.h"

struct tcp_data {
    unsigned interval;
};

_Noreturn void* start_tcp(void *data);

#endif // _TCP_H

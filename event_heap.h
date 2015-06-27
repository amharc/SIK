#ifndef _EVENT_HEAP
#define _EVENT_HEAP

#include "common.h"

void heap_init();

void heap_push(uint64_t when, void (*fun)(void*), void *data);

_Noreturn void* start_heap_runner(void *ignored);

#endif

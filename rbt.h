#ifndef _RBT_H
#define _RBT_H

#include "host.h"

void rb_init(void);
void rb_read_lock(void);
void rb_write_lock(void);
void rb_unlock(void);

void rb_insert(const struct host *host);
void rb_delete(const struct in_addr *addr);
struct host* rb_find(const struct in_addr *addr);
void rb_foreach(void (*fun)(struct host*, void*), void *data);
size_t rb_count(void);

#endif

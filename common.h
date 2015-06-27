#ifndef _COMMON_H
#define _COMMON_H

//#define _POSIX_C_SOURCE 20041212
#define _DEFAULT_SOURCE
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <fcntl.h>
#include <errno.h>

#ifdef __linux__
#define PACKET_INFO
#define LINUX
#   include <endian.h>
#else // BSDs
#define FREEBSD
#define PACKET_INFO
#   include <machine/endian.h>
#   include <sys/endian.h>
#   include <net/if_dl.h>
#endif

/* Report an error */
_Noreturn void die(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

/* Returns the number of microseconds since the Epoch */
uint64_t gettime(void);

#endif // _COMMON_H

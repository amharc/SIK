#include "common.h"

#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

_Noreturn void die(const char *fmt, ...) {
    va_list fmt_args;
    int err = errno;

    fprintf(stderr, "An error has occurred, exiting: ");
    va_start(fmt_args, fmt);
    vfprintf(stderr, fmt, fmt_args);
    va_end(fmt_args);
    fprintf(stderr, "\n");

    if(err != 0)
        fprintf(stderr, "Error code: %d (%s)\n", err, strerror(err));

    exit(EXIT_FAILURE);
}

uint64_t gettime(void) {
    struct timespec tp;
    if(clock_gettime(CLOCK_REALTIME, &tp) < 0)
        die("Unable to get the current time");
    return (uint64_t) tp.tv_sec * 1000000llu + tp.tv_nsec / 1000;
}

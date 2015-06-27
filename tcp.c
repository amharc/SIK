#include "tcp.h"
#include "host.h"
#include "rbt.h"

#include <signal.h>
#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/thread.h>
#include <event2/bufferevent.h>
#include <event2/util.h>

#define SSH_PORT 22

struct connection_attempt {
    struct in_addr addr;
    uint64_t at;
};

struct tcp_sender_data {
    unsigned interval; 
    struct event_base *base;
};

static void event_cb(struct bufferevent *restrict bev, short what, void *_attempt) {
    struct connection_attempt *restrict attempt = _attempt;

    if(what & BEV_EVENT_CONNECTED) {
        uint64_t now = gettime();
        rb_read_lock();
        struct host *host = rb_find(&attempt->addr);
        if(host) {
            int r = pthread_mutex_lock(&host->mutex);
            if(r != 0)
                die("Unable to lock host mutex: %d (%s)", r, strerror(r));
            host->tcp.delays[host->tcp.current++] = now - attempt->at;
            host->tcp.current %= QUERIES_COUNT;
            r = pthread_mutex_unlock(&host->mutex);
            if(r != 0)
                die("Unable to unlock host mutex: %d (%s)", r, strerror(r));
        }
        rb_unlock();
    }

    bufferevent_free(bev);
    free(attempt);
}

static void ping_one(struct host *restrict host, void *_base) {
    struct event_base *base = _base;

    uint64_t now = gettime();

    if(now >= host->tcp.valid_till)
       return;

    struct bufferevent *bev = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
    if(!bev)
        die("Unable to create a buffer event");

    struct connection_attempt *att = malloc(sizeof(struct connection_attempt));
    if(!att)
        die("Unable to allocate memory");

    att->addr = host->addr;
    att->at = now;

    bufferevent_setcb(bev, NULL, NULL, event_cb, att);

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr = host->addr;
    addr.sin_port = htons(SSH_PORT);

    if(bufferevent_socket_connect(bev, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
        die("Unable to connect");
        free(att);
        bufferevent_free(bev);
    }
}

static _Noreturn void* start_tcp_sender(void *_data) {
    struct tcp_sender_data *restrict data = _data;

    while(true) {
        rb_read_lock();
        rb_foreach(&ping_one, data->base);
        rb_unlock();
        usleep(data->interval * 1000 * 1000);
    }
}

static void none(evutil_socket_t sock, short ev, void *data) {
    (void) sock;
    (void) ev;
    (void) data;
}

_Noreturn void* start_tcp(void *_data) {
    struct tcp_data *restrict data = _data;

    if(evthread_use_pthreads())
        die("Unable to enable pthreads in evthreads");

    struct event_base *base = event_base_new();
    if(!base)
        die("Unable to create a libevent base");

    // A dummy event, so that libevent would not exit its dispatch loop immediately
    struct event *ev = event_new(base, SIGUSR1, EV_SIGNAL | EV_PERSIST, none, NULL);
    if(!ev)
        die("Unable to create a dummy event");
    if(0 != evtimer_add(ev, NULL))
        die("Unable to register the dummy event");

    struct tcp_sender_data sender_data = {
        .interval = data->interval,
        .base = base
    };

    pthread_t sender;
    int r = pthread_create(&sender, NULL, &start_tcp_sender, &sender_data);
    if(r)
        die("Unable to create TCP sender thread: %d (%s)", r, strerror(r));

    if(0 != event_base_dispatch(base))
        die("Unable to run the dispatch loop");

    die("The dispatch loop has ended prematurely");
}

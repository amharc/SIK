#include "telnet.h"
#include "host.h"
#include "rbt.h"

#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/util.h>

#define BACKLOG 32
#define MAX_EPOLL 64

#define COLS 80
#define ROWS 24

#define ECHO 1
#define SUPPRESS_GO_AHEAD 3

enum option_status {
    INACTIVE,
    REQUESTED,
    ACTIVE
};

enum ctrl_status {
    CTRL_NONE = 0,
    CTRL_IAC = 255,
    CTRL_WILL = 251,
    CTRL_WONT = 252,
    CTRL_DO = 253,
    CTRL_DONT = 254
};

static const unsigned char hello[] = {CTRL_IAC, CTRL_WILL, ECHO, CTRL_IAC, CTRL_WILL, SUPPRESS_GO_AHEAD};
static const char *clear = "\x1B[2J\x1B[1;1H";
static const char *advance_line = "\x1B[1E";

struct remote {
    struct remote *next, *prev;

    struct sockaddr_in addr;
    int sock;
    struct event_base *base;
    struct bufferevent *bev;
    int cur_line; // -1 if listener socket
    enum option_status echo_status, suppress_go_ahead_status;
    enum ctrl_status ctrl;
};

static struct remote *list_head;

struct hostinfo {
    char *line;
    size_t linelen;
    struct host *host;
    uint64_t avg;
};

static struct hostinfo *list;
static size_t list_cnt;

static pthread_rwlock_t mutex;

static void refresh_one(struct remote *restrict remote) {
    int r;
    r = pthread_rwlock_rdlock(&mutex);
    if(r)
        die("Unable to acquire the telnet rwlock: %d (%s)", r, strerror(r));

    if(0 != bufferevent_write(remote->bev, clear, strlen(clear)))
        die("Unable to send");

    for(size_t i = 0; i < ROWS && remote->cur_line + i < list_cnt; ++i) {
        if(0 != bufferevent_write(remote->bev, list[remote->cur_line + i].line, list[remote->cur_line + i].linelen))
            die("Unable to send");

        if(0 != bufferevent_write(remote->bev, advance_line, strlen(advance_line)))
            die("Unable to send");
    }

    r = pthread_rwlock_unlock(&mutex);
    if(r)
        die("Unable to release the telnet rwlock: %d (%s)", r, strerror(r));
}

static uint64_t average(uint64_t delays[QUERIES_COUNT]) {
    uint64_t sum = 0, counter = 0;
    for(int i = 0; i < QUERIES_COUNT; ++i)
        if(delays[i]) {
            sum += delays[i];
            counter++;
        }

    return counter == 0 ? 0 : sum/counter;
}

static void recalculate_lines_aux(struct host *host, void *data) {
    uint64_t now = *(uint64_t*) data;

    if(host->udp.valid_till < now && host->tcp.valid_till < now)
        return;

    list[list_cnt].host = host;
    list[list_cnt].line = calloc(COLS, sizeof(char));
    if(!list[list_cnt].line)
        die("Unable to allocate memory");

    uint64_t udpdelay = host->udp.valid_till < now ? 0 : average(host->udp.delays);
    uint64_t icmpdelay = host->udp.valid_till < now ? 0 : average(host->icmp.delays);
    uint64_t tcpdelay = host->tcp.valid_till < now ? 0 : average(host->tcp.delays);

    uint64_t sum = udpdelay + icmpdelay + tcpdelay;
    uint64_t cnt = !!udpdelay + !!icmpdelay + !!tcpdelay;

    list[list_cnt].avg = cnt == 0 ? 0 : sum / cnt;

    int cnt_spaces = cnt == 0 ? 0 : sum / cnt / 40;

    if(cnt_spaces > 30)
        cnt_spaces = 30;

    list[list_cnt].linelen = snprintf(list[list_cnt].line, COLS, "%15s\t %*s %6" PRIu64 " %6" PRIu64 " %6" PRIu64,
            inet_ntoa(host->addr), cnt_spaces, "", udpdelay, tcpdelay, icmpdelay);
    list_cnt++;
}

static int compare_hostinfo(const void *_lhs, const void *_rhs) {
    const struct hostinfo *lhs = _lhs, *rhs = _rhs;

    if(lhs->avg < rhs->avg)
        return 1;
    else if(lhs->avg == rhs->avg)
        return 0;
    else
        return -1;
}

static void recalculate_lines() {
    int r;
    r = pthread_rwlock_wrlock(&mutex);
    if(r)
        die("Unable to acquire the telnet rwlock: %d (%s)", r, strerror(r));

    for(size_t i = 0; i < list_cnt; ++i)
        free(list[i].line);

    list_cnt = 0;

    rb_write_lock(); // Gain exclusive access
    size_t cnt = rb_count();
    list = realloc(list, cnt * sizeof(struct hostinfo));
    if(cnt && !list)
        die("Unable to allocate memory");
    uint64_t now = gettime();
    rb_foreach(recalculate_lines_aux, &now);
    rb_unlock();

    qsort(list, list_cnt, sizeof(struct hostinfo), &compare_hostinfo);

    r = pthread_rwlock_unlock(&mutex);
    if(r)
        die("Unable to release the telnet rwlock: %d (%s)", r, strerror(r));
}

static void refresh(evutil_socket_t sock, short ev, void *data) {
    (void) sock;
    (void) ev;
    (void) data;

    recalculate_lines();

    for(struct remote *ptr = list_head; ptr; ptr = ptr->next)
        refresh_one(ptr);
}

static void register_timer(struct telnet_data *restrict data, struct event_base *restrict base) {
    struct timeval tv = {
        .tv_sec = data->interval / 1000000000,
        .tv_usec = data->interval % 1000000000
    };
    
    struct event *ev = event_new(base, 0, EV_PERSIST, refresh, data);
    if(!ev)
        die("Unable to create the telnet timer event");
    if(0 != evtimer_add(ev, &tv))
        die("Unable to register the telnet timer event");
}

static void beep(struct bufferevent *restrict bev) {
    if(0 != bufferevent_write(bev, "\a", 1))
        die("Unable to beep :)");
}

static void handle_do(struct bufferevent *restrict bev, unsigned char c, enum option_status *restrict status) {
    unsigned char buf[3];

    switch(*status) {
        case INACTIVE:
            buf[0] = CTRL_IAC;
            buf[1] = CTRL_WILL;
            buf[2] = c;
            if(0 != bufferevent_write(bev, buf, 3))
                die("Unable to write to the telnet socket");
            /* fall-through */
        case REQUESTED:
            *status = ACTIVE;
            break;
        case ACTIVE:
            beep(bev);
    }
}

static void process_char(struct bufferevent *restrict bev, struct remote *restrict remote, unsigned char c) {
    unsigned char buf[3];

    switch(remote->ctrl) {
        case CTRL_NONE:
            switch(c) {
                case 'q':
                case 'Q':
                    remote->cur_line--;
                    if(remote->cur_line < 0)
                        remote->cur_line = 0;
                    refresh_one(remote);
                    return;
                case 'a':
                case 'A':
                    remote->cur_line++;
                    refresh_one(remote);
                    return;
                case CTRL_IAC:
                    remote->ctrl = CTRL_IAC;
                    return;
                default:
                    beep(bev);
                    return;
            }
        case CTRL_IAC:
            switch(c) {
                case CTRL_WILL:
                case CTRL_WONT:
                case CTRL_DO:
                case CTRL_DONT:
                    remote->ctrl = c;
                    return;
                default:
                    beep(bev);
                    remote->ctrl = CTRL_NONE;
                    return;
            }
        case CTRL_WILL:
            remote->ctrl = CTRL_NONE;
            buf[0] = CTRL_IAC;
            buf[1] = CTRL_DONT;
            buf[2] = c;
            if(0 != bufferevent_write(bev, buf, 3))
                die("Unable to write to the telnet socket");
            return;
        case CTRL_WONT:
            remote->ctrl = CTRL_NONE;
            return;
        case CTRL_DO:
            remote->ctrl = CTRL_NONE;
            switch(c) {
                case ECHO:
                    handle_do(bev, c, &remote->echo_status);
                    return;
                case SUPPRESS_GO_AHEAD:
                    handle_do(bev, c, &remote->suppress_go_ahead_status);
                    return;
                default:
                    buf[0] = CTRL_IAC;
                    buf[1] = CTRL_WONT;
                    buf[2] = c;
                    if(0 != bufferevent_write(bev, buf, 3))
                        die("Unable to write to the telnet socket");
                    return;
            }
        case CTRL_DONT:
            remote->ctrl = CTRL_NONE;
            switch(c) {
                case ECHO:
                    remote->echo_status = INACTIVE;
                    return;
                case SUPPRESS_GO_AHEAD:
                    remote->echo_status = INACTIVE;
                    return;
                default:
                    return;
            }
    }
}

static void process_input(struct bufferevent *restrict bev, void *_remote) {
    struct remote *restrict remote = _remote;
    while(true) {
        char buf[256];
        size_t len = bufferevent_read(bev, buf, sizeof(buf));
        if(len <= 0)
            break;
        for(size_t i = 0; i < len; ++i)
            process_char(bev, remote, buf[i]);
    }
}

static void process_events(struct bufferevent *restrict bev, short what, void *_remote) {
    struct remote *restrict remote = _remote;

    if((what & BEV_EVENT_EOF) || (what & BEV_EVENT_ERROR)) {
        if(remote->next)
            remote->next->prev = remote->prev;

        if(remote->prev)
            remote->prev->next = remote->next;
        else
            list_head = remote->next;

        bufferevent_free(bev);
        free(remote);
    }
}

static void accept_conn(evutil_socket_t master, short ev, void *restrict _base) {
    (void) ev;

    struct event_base *base = _base;
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);

    evutil_socket_t sock = accept(master, (struct sockaddr*) &addr, &addrlen);
    if(sock < 0)
        die("Unable to accept a connection");

    if(evutil_make_socket_nonblocking(sock))
        die("Unable to make the telnet client socket nonblocking");

    struct remote *rem = calloc(1, sizeof(struct remote));
    if(!rem)
        die("Unable to allocate memory for the next client");

    rem->sock = sock;
    rem->base = base;
    rem->bev = bufferevent_socket_new(base, sock, BEV_OPT_CLOSE_ON_FREE);

    if(!rem->bev)
        die("Unable to create a buffer event");

    rem->next = list_head;
    if(list_head)
        list_head->prev = rem;
    list_head = rem;

    bufferevent_setcb(rem->bev, process_input, NULL, process_events, rem);

    if(0 != bufferevent_enable(rem->bev, EV_READ | EV_PERSIST))
        die("Unable to enable the buffer");

    rem->echo_status = rem->suppress_go_ahead_status = REQUESTED;
    if(0 != bufferevent_write(rem->bev, hello, sizeof(hello)))
        die("Unable to greet a telnet client");

    refresh_one(rem);
}

static void register_listener(struct telnet_data *restrict data, struct event_base *restrict base) {
    evutil_socket_t sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(sock < 0 ||
            evutil_make_listen_socket_reuseable(sock) ||
            evutil_make_socket_nonblocking(sock))
        die("Unable to prepare the telnet socket");

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(data->port);
    if(0 != bind(sock, (struct sockaddr*) &addr, sizeof(addr)))
        die("Unable to bind the telnet socket");

    if(0 != listen(sock, BACKLOG))
        die("Unable to listen for telnet connections");

    struct event *ev = event_new(base, sock, EV_READ | EV_PERSIST, accept_conn, base);
    if(!ev)
        die("Unable to create the telnet listener event");

    if(0 != event_add(ev, NULL))
        die("Unable to register the telnet listener event");
}

_Noreturn void* start_telnet(void *_data) {
    struct telnet_data *restrict data = _data;
    struct event_base *base = event_base_new();
    if(!base)
        die("Unable to create a libevent base");

    int r;
    r = pthread_rwlock_init(&mutex, NULL);
    if(r)
        die("Unable to create telnet rwlock: %d (%s)", r, strerror(r));

    recalculate_lines();
    register_timer(data, base);
    register_listener(data, base);

    if(0 != event_base_dispatch(base))
        die("Unable to run the dispatch loop");

    die("The dispatch loop has ended prematurely");
}

#define _GNU_SOURCE
#include "mdns.h"
#include "rbt.h"
#include "common.h"
#include "event_heap.h"

#define HOSTNAMELEN 32
#define BUFSIZE 1000
#define PORT 5353

#define A 1
#define PTR 12
#define UNICAST (1 << 15)
#define IN 1

static const char *udp_domain = "\x0b_opoznienia\x04_udp\x05local";
static const char *tcp_domain = "\x04_ssh\x04_tcp\x05local";

static int name_counter;
static char udppattern[255];
static char tcppattern[255];

static uint64_t name_uncertain_till;

struct __attribute__((__packed__)) mdns_packet {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
    char payload[1];
};

struct mdns_timer_data {
    struct sockaddr_in multiaddr;
    unsigned interval;
    int sock;
};

struct mdns_receiver_data {
    struct sockaddr_in multiaddr;
    unsigned interval;
    int sock;
    bool ssh;
};

struct mdns_query {
    uint16_t namelen;
    const char *name;
    uint16_t class, type;
};

struct mdns_response {
    uint16_t namelen;
    const char *name;
    uint16_t class, type, len;
    uint32_t ttl;
    const char *data;
};

struct mdns_parts {
    uint16_t id;
    uint16_t querycnt, responsecnt;
    struct mdns_query *queries;
    struct mdns_response *responses;
};

struct mdns_heap_event {
    int sock;
    struct sockaddr_in *multiaddr;
    struct mdns_parts *parts;
    bool response;
};

#define MKPUSH(type) \
    static inline void push_ ## type(char *restrict buf, size_t *restrict pos, size_t limit, type data) { \
        if(*pos + sizeof(type) < limit) { \
            memcpy(buf + *pos, &data, sizeof(type)); \
            *pos += sizeof(type); \
        } \
    }

MKPUSH(uint8_t)
MKPUSH(uint16_t)
MKPUSH(uint32_t)

static void renew_name(uint64_t interval) {
    char hostname[HOSTNAMELEN];

    if(0 != gethostname(hostname, sizeof(hostname)))
        die("Unable to get the hostname");

    hostname[HOSTNAMELEN - 1] = 0;

    uint8_t len = strlen(hostname);
    if(name_counter != 0)
        len += snprintf(hostname + len, HOSTNAMELEN - len - 1, "_%d", name_counter);

    udppattern[0] = tcppattern[0] = len;
    strcpy(udppattern + 1, hostname);
    strcpy(tcppattern + 1, hostname);

    strcpy(udppattern + 1 + len, udp_domain);
    strcpy(tcppattern + 1 + len, tcp_domain);

    name_counter++;
    // There are too many hosts with the same hostname. Start assigning random identifiers
    if(name_counter > 3)
        name_counter += rand() % 31;
    name_uncertain_till = gettime() + interval * 1000 * 1000; 

    fprintf(stderr, "Host name set to %s\n", hostname);
}


static void mdns_send(int sock, struct sockaddr_in *restrict multiaddr,
        struct mdns_parts *restrict parts, bool response) {
    char buf[BUFSIZE];
    size_t pos = 0;
    push_uint16_t(buf, &pos, BUFSIZE, parts->id); // ID
    if(response)
        push_uint8_t(buf, &pos, BUFSIZE, 0x80); // Flags
    else
        push_uint8_t(buf, &pos, BUFSIZE, 0x00); // Flags
    push_uint8_t(buf, &pos, BUFSIZE, 0x00); // Flags
    push_uint16_t(buf, &pos, BUFSIZE, htons(parts->querycnt)); // Question count
    push_uint16_t(buf, &pos, BUFSIZE, htons(parts->responsecnt)); // Answer count
    push_uint16_t(buf, &pos, BUFSIZE, 0); // Authority count: 0
    push_uint16_t(buf, &pos, BUFSIZE, 0); // Additional count: 0

    for(uint16_t idx = 0; idx < parts->querycnt; ++idx) {
        uint16_t len = parts->queries[idx].namelen;
        if(pos + len > BUFSIZE) {
            fprintf(stderr, "Ignoring a too long packet...\n");
            return;
        }
        memcpy(buf + pos, parts->queries[idx].name, len);
        pos += len;

        push_uint16_t(buf, &pos, BUFSIZE, htons(parts->queries[idx].type));
        push_uint16_t(buf, &pos, BUFSIZE, htons(parts->queries[idx].class));
    }

    for(uint16_t idx = 0; idx < parts->responsecnt; ++idx) {
        uint16_t len = parts->responses[idx].namelen;
        if(pos + len > BUFSIZE) {
            fprintf(stderr, "Ignoring a too long packet...\n");
            return;
        }
        memcpy(buf + pos, parts->responses[idx].name, len);
        pos += len;

        push_uint16_t(buf, &pos, BUFSIZE, htons(parts->responses[idx].type));
        push_uint16_t(buf, &pos, BUFSIZE, htons(parts->responses[idx].class));
        push_uint32_t(buf, &pos, BUFSIZE, htonl(parts->responses[idx].ttl));
        push_uint16_t(buf, &pos, BUFSIZE, htons(parts->responses[idx].len));
        len = parts->responses[idx].len;
        if(pos + len > BUFSIZE) {
            fprintf(stderr, "Ignoring a too long packet...\n");
            return;
        }
        memcpy(buf + pos, parts->responses[idx].data, len);
        pos += len;
    }

    if(pos < BUFSIZE) { // did not truncate        
        ssize_t sent = sendto(sock, buf, pos, 0,
                (struct sockaddr *) multiaddr, sizeof(struct sockaddr_in));
        if(sent < 0 || (size_t) sent != pos)
            die("Unable to send a MDNS query");
    }
}

static _Noreturn void* start_mdns_timer(void *_data) {
    struct mdns_timer_data *restrict data = _data;
    struct mdns_query queries[2] = { 
        {
            .namelen = strlen(udp_domain) + 1,
            .name = udp_domain,
            .type = PTR,
            .class = IN
        },
        {
            .namelen = strlen(tcp_domain) + 1,
            .name = tcp_domain,
            .type = PTR,
            .class = IN
        }
    };

    struct mdns_parts parts[2] = {
        {
            .id = 0,
            .querycnt = 1,
            .queries = &queries[0],
            .responsecnt = 0,
            .responses = NULL
        },
        {
            .id = 0,
            .querycnt = 1,
            .queries = &queries[1],
            .responsecnt = 0,
            .responses = NULL
        }
    };

    while(true) {
        mdns_send(data->sock, &data->multiaddr, &parts[0], false);
        mdns_send(data->sock, &data->multiaddr, &parts[1], false);

        usleep(data->interval * 1000 * 1000);
    }
}

// Returns -1 in case of failure
static ssize_t concat_name_at(const char *restrict buf, size_t *restrict pos, size_t limit, char *restrict to, size_t tolimit) {
    size_t written = 0;
    size_t myptr = 0;

    while(*pos < limit && written < tolimit) {
        uint8_t len = * (uint8_t*) (buf + *pos);
        if(len == 0) {
            ++*pos;
            to[written++] = 0;
            break;
        }
        else if(len < 64) {
            if(written + len + 1 > tolimit)
                return -1;
            if(*pos + len > limit)
                return -1;

            to[written++] = len;
            ++*pos;
            memcpy(to + written, buf + *pos, len);
            *pos += len;
            written += len;
        }
        else { // A compressed name
            if(*pos == limit - 1)
                return -1;
            if(*pos < 128 + 64)
                return -1;
            uint16_t offset = (len - 64 - 128) * 255 + *(uint8_t*) (buf + *pos + 1);
            limit = *pos;
            *pos += 2;
            myptr = offset;
            pos = &myptr;
        }
    }

    return written;
}

static bool match(const char *restrict name, size_t namelen, const char *restrict test) {
    size_t testlen = strlen(test);
    if(namelen < testlen)
        return false;
    return memcmp(name + namelen - 1 - testlen, test, testlen) == 0;
}

static void mdns_heap_handler(void *_data) {
    struct mdns_heap_event *restrict data = _data;
    mdns_send(data->sock, data->multiaddr, data->parts, data->response);

    free(data->parts->queries);
    free(data->parts->responses);
    free(data->parts);
    free(data);
}

static struct host* get_host(struct in_addr addr) {
    struct host *ptr;
    // Note: the current thread is the only writer, so we don't need to apply a read lock here
    ptr = rb_find(&addr);
    
    if(ptr != NULL)
        return ptr;

    fprintf(stderr, "Host %s discovered\n", inet_ntoa(addr));

    struct host new;
    memset(&new, 0, sizeof(struct host));
    int r = pthread_mutex_init(&new.mutex, NULL);
    if(r != 0)
        die("Unable to create host-related mutex");
    new.addr = addr;

    rb_write_lock();
    rb_insert(&new);
    rb_unlock();

    return rb_find(&addr);
}

static void handle_mdns_response(struct mdns_receiver_data *data, struct mdns_packet *packet,
        size_t packetlen, bool multicast) {
    size_t pos = (char*) &((struct mdns_packet*) NULL)->payload - (char*) NULL;
    char name[1024];
    const char *rawpacket = (const char*) packet;

    struct mdns_query queries[1024];
    size_t querycnt = 0;

    uint16_t qdcount = ntohs(packet->qdcount);
    uint16_t ancount = ntohs(packet->ancount);

    if(!multicast) // We never request unicast responses
        return;

    for(size_t qd_idx = 0; qd_idx < qdcount; qd_idx++) {
        ssize_t namelen = concat_name_at(rawpacket, &pos, packetlen, name, sizeof(name));
        if(namelen < 0)
            return;
        pos += 2; // QTYPE
        pos += 2; // QCLASS
    }

    for(size_t an_idx = 0; an_idx < ancount && pos < packetlen; an_idx++) {
        ssize_t namelen = concat_name_at(rawpacket, &pos, packetlen, name, sizeof(name));
        if(namelen < 0)
            goto handle_mdns_response_free; // A malicious packet, probably
        if(pos + 12 > packetlen)
            goto handle_mdns_response_free; // No space for TYPE, CLASS, TTL and RDLENGTH

        uint16_t type = ntohs(*(uint16_t*) (rawpacket + pos));
        pos += 2;

        uint16_t class = ntohs(*(uint16_t*) (rawpacket + pos));
        pos += 2;

        uint32_t ttl = ntohl(*(uint32_t*) (rawpacket + pos));
        pos += 4;

        uint16_t rdlength = ntohs(*(uint16_t*) (rawpacket + pos));
        pos += 2;

        if(pos + rdlength > packetlen)
            goto handle_mdns_response_free; // no space for RDATA

        if(type == A && class == IN) {
            if(rdlength != 4)
                goto handle_mdns_response_free;
            struct in_addr addr;
            addr.s_addr = *(uint32_t*) (rawpacket + pos);

            bool isudp = match(name, namelen, udp_domain);
            bool istcp = match(name, namelen, tcp_domain);

            if(match(name, namelen, udppattern) || match(name, namelen, tcppattern)) {
                // A name conflict has occurred, try another name
                renew_name(data->interval);
                continue;
            }

            if(isudp || istcp) {
                struct host *host = get_host(addr);
                uint64_t now = gettime();
                uint64_t till = now + ttl * 1000 * 1000;
                
                if(isudp) {
                    if(host->udp.valid_till < now) {
                        memset(host->udp.delays, 0, sizeof(host->udp.delays));
                        memset(host->icmp.delays, 0, sizeof(host->icmp.delays));
                        memset(host->icmp.requests, 0, sizeof(host->icmp.requests));
                    }
                    if(host->udp.valid_till < till)
                        host->udp.valid_till = till;
                }

                if(istcp) {
                    if(host->tcp.valid_till < now)
                        memset(host->tcp.delays, 0, sizeof(host->tcp.delays));
                    if(host->tcp.valid_till < till)
                        host->tcp.valid_till = till;
                }
            }
        }
        else if(type == PTR && class == IN) {
            size_t bck_pos = pos;
            namelen = concat_name_at(rawpacket, &bck_pos, packetlen, name, sizeof(name));
            if(namelen < 0)
                goto handle_mdns_response_free;

            if(!match(name, namelen, udp_domain) && !match(name, namelen, tcp_domain))
                continue;

            char *newname = malloc(namelen);
            if(!newname)
                die("Unable to allocate memory");
            memcpy(newname, name, namelen);
            struct mdns_query q = {
                .namelen = namelen,
                .name = newname,
                .type = A,
                .class = IN
            };
            queries[querycnt++] = q;
        }

        pos += rdlength;
    }

    if(querycnt > 0) {
        struct mdns_parts parts = {
            .id = 0,
            .querycnt = querycnt,
            .queries = queries,
            .responsecnt = 0,
            .responses = NULL
        };

        mdns_send(data->sock, &data->multiaddr, &parts, false);

    }

handle_mdns_response_free:
    for(size_t i = 0; i < querycnt; ++i)
        free((void*)queries[i].name);
}

static void handle_mdns_query(struct mdns_receiver_data *data, struct sockaddr_in *peer,
        struct mdns_packet *packet, size_t packetlen,
        unsigned interface_index, bool expect_multicast, bool send_multicast,
        bool received_multicast, bool is_legacy) {
    if(name_uncertain_till >= gettime())
        return; // Do not answer queries while not sure about the uniqueness of our name

    size_t pos = (char*) &((struct mdns_packet*) NULL)->payload - (char*) NULL;
    char name[1024];
    const char *rawpacket = (const char*) packet;

    const uint64_t a = expect_multicast ? A : A | UNICAST;
    const uint64_t ptr = expect_multicast ? PTR : PTR | UNICAST;

    bool add_udp_ptr = false, add_tcp_ptr = false, add_udp_a = false, add_tcp_a = false;

    for(size_t qd_idx = 0; qd_idx < ntohs(packet->qdcount); qd_idx++) {
        ssize_t namelen = concat_name_at(rawpacket, &pos, packetlen, name, sizeof(name));
        if(namelen < 0)
            return;

        if(pos + 2 * 2 > packetlen)
            return; // No space for TYPE and CLASS

        uint16_t type = ntohs(*(uint16_t*) (rawpacket + pos));
        pos += 2;

        uint16_t class = ntohs(*(uint16_t*) (rawpacket + pos));
        pos += 2;

        if(class != IN)
            continue;

        add_udp_ptr |= type == ptr && strncmp(name, udp_domain, namelen) == 0;
        add_tcp_ptr |= type == ptr && strncmp(name, tcp_domain, namelen) == 0;

        add_udp_a |= type == a && strncmp(name, udppattern, namelen) == 0;
        add_tcp_a |= type == a && strncmp(name, tcppattern, namelen) == 0;
    }

    struct mdns_query queries[4];
    struct mdns_response responses[256];

    bool use_dynamic = send_multicast;

    struct mdns_query *dyn_queries = use_dynamic ? calloc(4, sizeof(struct mdns_query)) : NULL;
    struct mdns_response *dyn_responses = use_dynamic ? calloc(256, sizeof(struct mdns_response)) : NULL;
    if(use_dynamic && (!dyn_queries || !dyn_responses))
        die("Unable to allocate memory");

    uint16_t responsecnt = 0, dynresponsecnt = 0, querycnt = 0, dynquerycnt = 0;
    uint32_t ttl = 2 * data->interval;

    add_tcp_ptr &= data->ssh;
    add_tcp_a &= data->ssh;

    if(add_udp_ptr) {
        struct mdns_query q = {
            .namelen = strlen(udp_domain) + 1,
            .name = udp_domain,
            .type = ptr,
            .class = IN
        };
        if(use_dynamic)
            dyn_queries[dynquerycnt++] = q;
        else
            queries[querycnt++] = q;

        struct mdns_response r = {
            .namelen = strlen(udp_domain) + 1,
            .name = udp_domain,
            .type = ptr,
            .class = IN,
            .ttl = ttl,
            .len = strlen(udppattern) + 1,
            .data = udppattern
        };
        if(use_dynamic)
            dyn_responses[dynresponsecnt++] = r;
        else
            responses[responsecnt++] = r;
    }

    if(add_tcp_ptr) {
        struct mdns_query q = {
            .namelen = strlen(tcp_domain) + 1,
            .name = tcp_domain,
            .type = ptr,
            .class = IN
        };
        if(use_dynamic)
            dyn_queries[dynquerycnt++] = q;
        else
            queries[querycnt++] = q;

        struct mdns_response r = {
            .namelen = strlen(tcp_domain) + 1,
            .name = tcp_domain,
            .type = ptr,
            .class = IN,
            .ttl = ttl,
            .len = strlen(tcppattern) + 1,
            .data = tcppattern
        };
        if(use_dynamic)
            dyn_responses[dynresponsecnt++] = r;
        else
            responses[responsecnt++] = r;
    }

    struct ifaddrs *ifs = NULL;
    if(add_udp_a || add_tcp_a) {
        if(0 != getifaddrs(&ifs))
            die("Unable to get interface addresses");

        char interface_name[IF_NAMESIZE];
        if(!if_indextoname(interface_index, interface_name))
            die("Unable to convert the interface index %u to a name\n", interface_index);

        if(!received_multicast) {
            // fallback search
            bool same_subnet = false;
            for(struct ifaddrs *curif = ifs; curif && !same_subnet; curif = curif->ifa_next) {
                if(curif->ifa_addr == NULL)
                    continue;

                if(curif->ifa_addr->sa_family != AF_INET)
                    continue;

                if(strcmp(curif->ifa_name, interface_name))
                    continue;
                
                struct sockaddr_in *myaddr = (struct sockaddr_in*) curif->ifa_addr;
                struct sockaddr_in *mask = (struct sockaddr_in*) curif->ifa_netmask;

                same_subnet |= (myaddr->sin_addr.s_addr & mask->sin_addr.s_addr) == (peer->sin_addr.s_addr & mask->sin_addr.s_addr);
            }

            if(!same_subnet) {
                freeifaddrs(ifs);
                free(dyn_queries);
                free(dyn_responses);
                return;
            }
        }

        for(struct ifaddrs *curif = ifs; curif; curif = curif->ifa_next) {
            if(curif->ifa_addr == NULL)
                continue;

            if(curif->ifa_addr->sa_family != AF_INET)
                continue;

            if(strcmp(curif->ifa_name, interface_name))
                continue;

            if(add_udp_a) {
                struct mdns_response r = {
                    .namelen = strlen(udppattern) + 1,
                    .name = udppattern,
                    .type = a,
                    .class = IN,
                    .ttl = ttl,
                    .len = 4,
                    .data = (char*) &((struct sockaddr_in*) curif->ifa_addr)->sin_addr.s_addr
                };
                responses[responsecnt++] = r;
            }

            if(add_tcp_a) {
                struct mdns_response r = {
                    .namelen = strlen(tcppattern) + 1,
                    .name = tcppattern,
                    .type = a,
                    .class = IN,
                    .ttl = ttl,
                    .len = 4,
                    .data = (char*) &((struct sockaddr_in*) curif->ifa_addr)->sin_addr.s_addr
                };
                responses[responsecnt++] = r;
            }
        }
    }

    if(add_udp_a) {
        struct mdns_query q = {
            .namelen = strlen(udppattern) + 1,
            .name = udppattern,
            .type = a,
            .class = IN
        };
        queries[querycnt++] = q;
    }

    if(add_tcp_a) {
        struct mdns_query q = {
            .namelen = strlen(tcppattern) + 1,
            .name = tcppattern,
            .type = a,
            .class = IN,
        };
        queries[querycnt++] = q;
    }

    if(use_dynamic) {
        if(dynresponsecnt > 0) {
            struct mdns_parts *parts = calloc(1, sizeof(struct mdns_parts));
            if(!parts)
                die("Unable to allocate memory");
            parts->querycnt = is_legacy ? dynquerycnt : 0;
            parts->queries = dyn_queries;
            parts->responsecnt = dynresponsecnt;
            parts->responses = dyn_responses;
            parts->id = is_legacy ? packet->id : 0;

            struct mdns_heap_event *event = calloc(1, sizeof(struct mdns_heap_event));
            if(!event)
                die("Unable to allocate memory");

            event->sock = data->sock;
            event->multiaddr = send_multicast ? &data->multiaddr : peer;
            event->parts = parts;
            event->response = true;

            heap_push(gettime() + (20 + rand() % 100) * 1000, &mdns_heap_handler, event);
        }
        else {
            free(dyn_responses);
            free(dyn_queries);
        }
    }

    struct mdns_parts parts = {
        .querycnt = is_legacy ? querycnt : 0,
        .queries = queries,
        .responsecnt = responsecnt,
        .responses = responses,
        .id = is_legacy ? packet->id : 0,
    };

    if(responsecnt > 0)
        mdns_send(data->sock, send_multicast ? &data->multiaddr : peer, &parts, true);

    if(ifs)
        freeifaddrs(ifs);
}

static _Noreturn void* start_mdns_receiver(void *_data) {
    struct mdns_receiver_data *restrict data = _data;
    char in[BUFSIZE];


    while(true) {
#ifdef FREEBSD
        char control[16 * (CMSG_SPACE(sizeof(struct in_addr))
                + (CMSG_SPACE(sizeof(struct sockaddr_dl))))];
#elif defined LINUX
        char control[16 * CMSG_SPACE(sizeof(struct in_pktinfo))];
#endif

        struct sockaddr_in remote_addr;
        socklen_t remote_addrlen = sizeof(struct sockaddr_in);

        struct iovec iovec = {
            .iov_base = in,
            .iov_len = BUFSIZE,
        };

        struct msghdr msghdr = {
            .msg_name = &remote_addr,
            .msg_namelen = remote_addrlen,
            .msg_iov = &iovec,
            .msg_iovlen = 1,
#ifdef PACKET_INFO
            .msg_control = control,
            .msg_controllen = sizeof(control),
#else
            .msg_control = NULL,
            .msg_controllen = 0
#endif
            .msg_flags = 0
        };

        ssize_t recv = recvmsg(data->sock, &msghdr, 0);
        if(recv < 0)
            die("Unable to receive a MDNS message");

        if((size_t) recv < sizeof(struct mdns_packet))
            continue;

        struct in_addr destination = data->multiaddr.sin_addr;
        int interface_index = 0;

#ifdef PACKET_INFO
        for(struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msghdr); cmsg; cmsg = CMSG_NXTHDR(&msghdr, cmsg)) {
#ifdef FREEBSD
            if(cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_RECVDSTADDR)
                destination = *(struct in_addr*) CMSG_DATA(cmsg);
            if(cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_RECVIF)
                interface_index = ((struct sockaddr_dl*) CMSG_DATA(cmsg))->sdl_index;
#elif defined LINUX
            if(cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO) {
                struct in_pktinfo *pktinfo = CMSG_DATA(cmsg);
                destination = pktinfo->ipi_addr;
                interface_index = pktinfo->ipi_ifindex;
            }
#endif
        }
#endif
        bool multicast_dst = destination.s_addr == data->multiaddr.sin_addr.s_addr;
        bool legacy = remote_addr.sin_port != htons(5353);
        bool multicast = multicast_dst && !legacy;

        struct mdns_packet *packet = (struct mdns_packet*) in;

        if(*((char*)&packet->flags) & 128) {
            if(multicast)
                handle_mdns_response(data, packet, recv, multicast);
        }
        else {
            handle_mdns_query(data, &remote_addr, packet,
                    recv, interface_index, true, multicast, multicast_dst, legacy);
            handle_mdns_query(data, &remote_addr, packet,
                    recv, interface_index, false, false, multicast_dst, legacy);
        }
    }
}

_Noreturn void* start_mdns(void *_data) {
    struct mdns_data *restrict data = _data;

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(0 > sock)
        die("Unable to create socket for MDNS");

    int optval = 1;
    if(0 != setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (void*) &optval, sizeof(optval)))
        die("Unable to set the MDNS socket to broadcast mode");

    optval = 255;
    if(0 != setsockopt(sock, IPPROTO_IP, IP_TTL, (void*) &optval, sizeof(optval)))
        die("Unable to set the TTL value on the MDNS socket");

    u_char charoptval = 255;
    if(0 != setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL, (void*) &charoptval, sizeof(charoptval)))
        die("Unable to set the multicast TTL value on the MDNS socket");

    charoptval = 0;
    if(0 != setsockopt(sock, IPPROTO_IP, IP_MULTICAST_LOOP, (void*) &charoptval, sizeof(charoptval)))
        die("Unable to disable multicast loopback on the MDNS socket");

    optval = 1;
    if(0 != setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void*) &optval, sizeof(optval)))
        die("Unable to allow address reuse on the MDNS socket");

#ifdef FREEBSD
    optval = 1;
    if(0 != setsockopt(sock, IPPROTO_IP, IP_RECVDSTADDR, (void*) &optval, sizeof(optval)))
        die("Unable to set the RECVDSTADDR flag");

    optval = 1;
    if(0 != setsockopt(sock, IPPROTO_IP, IP_RECVIF, (void*) &optval, sizeof(optval)))
        die("Unable to set the RECVIF flag");
#endif

#ifdef LINUX
    optval = 1;
    if(0 != setsockopt(sock, IPPROTO_IP, IP_PKTINFO, (void*) &optval, sizeof(optval)))
        die("Unable to set the PKTINFO flag");
#endif

    struct ip_mreq mreq;
    struct in_addr multicast_addr;
    if(1 != inet_aton("224.0.0.251", &multicast_addr))
        die("Unable to translate 224.0.0.251 into binary form");
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    mreq.imr_multiaddr = multicast_addr;
    
    if(0 != setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (void*) &mreq, sizeof(mreq)))
        die("Unable to join the MDNS multicast group");

    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(struct sockaddr_in));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(PORT);
    if(0 != bind(sock, (struct sockaddr*) &addr, sizeof(addr)))
        die("Unable to bind the MDNS socket to :5353");

    addr.sin_family = AF_INET;
    addr.sin_addr = multicast_addr;
    addr.sin_port = htons(PORT);

    struct mdns_receiver_data receiver_data = {
        .sock = sock,
        .interval = data->interval,
        .ssh = data->ssh,
        .multiaddr = addr
    };

    renew_name(data->interval);

    pthread_t receiver, heap_runner;

    int r = pthread_create(&receiver, NULL, &start_mdns_receiver, &receiver_data);
    if(r != 0)
        die("Unable to create the MDNS receiver thread: %d (%s)", r, strerror(r));

    heap_init();

    r = pthread_create(&heap_runner, NULL, &start_heap_runner, NULL);
    if(r != 0)
        die("Unable to create the heap runner thread: %d (%s)", r, strerror(r));

    struct mdns_timer_data timer_data = {
        .sock = sock,
        .multiaddr = addr,
        .interval = data->interval
    };
    start_mdns_timer(&timer_data);
}

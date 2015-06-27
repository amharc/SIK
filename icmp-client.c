#include "icmp-client.h"
#include "rbt.h"

#include <netinet/ip_icmp.h>

struct icmp_sender_data {
    int sock;
    unsigned interval;
};

struct icmp_receiver_data {
    int sock;
};

static const char icmp_payload[] = {0x34, 0x72, 0x08, 0x03};

#define ICMP_HEADER_LEN 8u
#define ICMP_TYPE 0x13
#define BUFSIZE (ICMP_HEADER_LEN+4u)

/* The following code is copied from the iputils package */

#if BYTE_ORDER == LITTLE_ENDIAN
# define ODDBYTE(v)	(v)
#elif BYTE_ORDER == BIG_ENDIAN
# define ODDBYTE(v)	((unsigned short)(v) << 8)
#else
# define ODDBYTE(v)	htons((unsigned short)(v) << 8)
#endif

unsigned short
in_cksum(const unsigned short *addr, register int len, unsigned short csum)
{
	register int nleft = len;
	const unsigned short *w = addr;
	register unsigned short answer;
	register int sum = csum;

	/*
	 *  Our algorithm is simple, using a 32 bit accumulator (sum),
	 *  we add sequential 16 bit words to it, and at the end, fold
	 *  back all the carry bits from the top 16 bits into the lower
	 *  16 bits.
	 */
	while (nleft > 1)  {
		sum += *w++;
		nleft -= 2;
	}

	/* mop up an odd byte, if necessary */
	if (nleft == 1)
		sum += ODDBYTE(*(unsigned char *)w); /* le16toh() may be unavailable on old systems */

	/*
	 * add back carry outs from top 16 bits to low 16 bits
	 */
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;				/* truncate to 16 bits */
	return (answer);
}

/* End of code copied from the iputils package */

static void icmp_send(struct host *host, void *_data) {
    struct icmp_sender_data *data = _data;
    uint64_t now = gettime();

    if(host->udp.valid_till >= now) {
        socklen_t addrlen = sizeof(struct sockaddr_in);

        char buf[BUFSIZE];
        memset(buf, 0, sizeof(buf));
        struct icmp *icmp = (struct icmp*) buf;
        icmp->icmp_type = ICMP_ECHO;
        icmp->icmp_code = 0;
        icmp->icmp_id = ICMP_TYPE;
        icmp->icmp_seq = ntohs(host->icmp.seq);
        memcpy(buf + ICMP_HEADER_LEN, icmp_payload, sizeof(icmp_payload));
        icmp->icmp_cksum = 0;
        icmp->icmp_cksum = in_cksum((unsigned short*) icmp, BUFSIZE, 0);

        int r = pthread_mutex_lock(&host->mutex);
        if(r != 0)
            die("Unable to lock host mutex: %d (%s)", r, strerror(r));
        host->icmp.requests[host->icmp.request_current].valid = true;
        host->icmp.requests[host->icmp.request_current].seq = host->icmp.seq++;
        host->icmp.requests[host->icmp.request_current].when = gettime();
        host->icmp.request_current = (host->icmp.request_current + 1) % ICMP_BACKLOG;
        r = pthread_mutex_unlock(&host->mutex);
        if(r != 0)
            die("Unable to unlock host mutex: %d (%s)", r, strerror(r));

        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(0);
        addr.sin_addr = host->addr;

        ssize_t len = sendto(data->sock, buf, BUFSIZE, 0,
                (const struct sockaddr*) &addr, addrlen);

        if(len != BUFSIZE)
            die("Unable to send an ICMP query packet");
    }
}

static _Noreturn void* start_icmp_client_sender(void *_data) {
    struct icmp_sender_data *restrict data = _data;

    while(true) {
        rb_read_lock();
        rb_foreach(icmp_send, _data);
        rb_unlock();

        usleep(data->interval * 1000 * 1000);
    }
}

static _Noreturn void* start_icmp_client_receiver(void *_data) {
    struct icmp_receiver_data *restrict data = _data;

    while(true) {
        struct sockaddr_in addr;
        socklen_t addrlen = sizeof(struct sockaddr_in);

        char buf[BUFSIZE + 128];

        ssize_t len = recvfrom(data->sock, buf, sizeof(buf), 0,
                (struct sockaddr*) &addr, &addrlen);

        if(len < 0)
            die("Unable to receive an ICMP packet");

        uint64_t now = gettime();

        if(addr.sin_family != AF_INET) {
            continue; // Silently ignore
        }

        struct ip *ip = (struct ip*) buf;

        size_t ip_header_len = ip->ip_hl << 2;
        struct icmp *icmp = (struct icmp*) (buf + ip_header_len);

        if((size_t) len != ip_header_len + BUFSIZE || icmp->icmp_type != ICMP_ECHOREPLY || icmp->icmp_id != ICMP_TYPE ||
                memcmp(buf + ip_header_len + ICMP_HEADER_LEN, icmp_payload, sizeof(icmp_payload)))
            continue;

        rb_read_lock();
        struct host *host = rb_find(&addr.sin_addr); 
        if(host != NULL) {
            int r = pthread_mutex_lock(&host->mutex);
            if(r != 0)
                die("Unable to lock host-related mutex: %d (%s)", r, strerror(r));

            size_t idx = 0;
            for(idx = 0; idx < ICMP_BACKLOG; ++idx)
                if(host->icmp.requests[idx].valid && host->icmp.requests[idx].seq == ntohs(icmp->icmp_seq))
                    break;

            r = pthread_mutex_unlock(&host->mutex);
            if(r != 0)
                die("Unable to lock host-related mutex: %d (%s)", r, strerror(r));

            if(idx == ICMP_BACKLOG)
                continue; // A stray packet

            uint64_t sent = host->icmp.requests[idx].when;
            host->icmp.delays[host->icmp.current++] = now - sent;
            host->icmp.current %= QUERIES_COUNT;
        }
        rb_unlock();      
    }
}

_Noreturn void* start_icmp_client(void *_data) {
    struct icmp_client_data *restrict data = _data;

    struct icmp_sender_data *sender_data = malloc(sizeof(struct icmp_sender_data));
    if(!sender_data)
        die("Unable to allocate memory");

    struct icmp_receiver_data *receiver_data = malloc(sizeof(struct icmp_receiver_data));
    if(!receiver_data)
        die("Unable to allocate memory");

    sender_data->interval = data->interval;

    int sock = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
    if(sock < 0)
        die("Unable to create a socket for the ICMP client");

    sender_data->sock = sock;
    receiver_data->sock = sock;

    pthread_t sender;

    int ret = 0;
    ret = pthread_create(&sender, NULL, &start_icmp_client_sender, sender_data);
    if(ret != 0)
        die("Unable to create ICMP client sender thread: %d (%s)", ret, strerror(ret));

    start_icmp_client_receiver(receiver_data);
}

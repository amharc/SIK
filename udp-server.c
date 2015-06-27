#include "udp-server.h"
#include "common.h"

_Noreturn void* start_udp_server(void *_data) {
    struct udp_server_data *restrict data = _data;

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if(sock < 0)
        die("Unable to create a UDP server socket");

    struct sockaddr_in server_address;
    memset(&server_address, 0, sizeof(struct sockaddr_in));
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = htonl(INADDR_ANY);
    server_address.sin_port = htons(data->port);

    if(bind(sock, (struct sockaddr *) &server_address,
                (socklen_t) sizeof(server_address)) < 0)
        die("Unable to bind the UDP server socket to port %d\n", data->port);

    while(true) {
        uint64_t data[2];
        struct sockaddr_in addr;
        socklen_t addrlen = sizeof(addr);

        ssize_t len = recvfrom(sock, data, sizeof(uint64_t), 0,
                (struct sockaddr*) &addr, &addrlen);

        if(len < 0)
            die("Unable to receive UDP packet");
        else if(len != sizeof(uint64_t))
            continue;

        data[1] = htobe64(gettime());
        
        len = sendto(sock, data, sizeof(data), 0, (struct sockaddr*) &addr, addrlen);

        if(len < 0)
            die("Unable to send UDP reply packet");
    }
}

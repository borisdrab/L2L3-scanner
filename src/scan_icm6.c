#define _DEFAULT_SOURCE

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/icmp6.h>

#include "scan_icm6.h"


int scan_icmpv6(const char *ip, int timeout, host_result_t *result) {
    int raw_socket_fd;

    unsigned char send_buffer[64];
    unsigned char receiver_buffer[1024];

    struct icmp6_hdr *icmp6_header;
    struct sockaddr_in6 target_addr;
    struct timeval receive_timeout;
    ssize_t received;

    if (ip == NULL || result == NULL) {
        return -1;
    }

    strncpy(result->ip, ip, sizeof(result->ip) - 1);
    result->ip[sizeof(result->ip) - 1] = '\0';
    result->icmp_ok = 0;

    raw_socket_fd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    if (raw_socket_fd < 0) {
        return 0;
    }

    memset(send_buffer, 0, sizeof(send_buffer));

    icmp6_header = (struct icmp6_hdr *)send_buffer;

    icmp6_header->icmp6_type = ICMP6_ECHO_REQUEST;
    icmp6_header->icmp6_code = 0;
    icmp6_header->icmp6_id = htons((unsigned short)getpid());
    icmp6_header->icmp6_seq = htons(1);


    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin6_family = AF_INET6;

    if (inet_pton(AF_INET6, ip, &target_addr.sin6_addr) != 1) {
        fprintf(stderr, "Error: Invalid IPv6 address %s\n", ip);
        close(raw_socket_fd);
        return -1;
    }

    receive_timeout.tv_sec = timeout / 1000;
    receive_timeout.tv_usec = (timeout % 1000) * 1000;

    if (setsockopt(raw_socket_fd, SOL_SOCKET, SO_RCVTIMEO, &receive_timeout, sizeof(receive_timeout)) < 0) {
        close(raw_socket_fd);
        return 0;
    }

    if (sendto(raw_socket_fd, send_buffer, sizeof(send_buffer), 0, (struct sockaddr *)&target_addr, sizeof(target_addr)) < 0) {
        close(raw_socket_fd);
        return 0;
    }


    for (;;) {
        struct sockaddr_in6 source_addr;
        socklen_t source_addr_len = sizeof(source_addr);

        received = recvfrom(raw_socket_fd, receiver_buffer, sizeof(receiver_buffer), 0, (struct sockaddr *)&source_addr, &source_addr_len);

        struct icmp6_hdr *icmp6_reply;
        icmp6_reply = (struct icmp6_hdr *)receiver_buffer;

        if (received < 0) {
            close(raw_socket_fd);
            return 0;
        }


        if ((size_t)received < sizeof(struct icmp6_hdr)) {
            continue;
        }


        if (icmp6_reply->icmp6_type == ICMP6_ECHO_REQUEST) {
            continue;
        }

        if (memcmp(&source_addr.sin6_addr, &target_addr.sin6_addr, sizeof(struct in6_addr)) != 0) {
            continue;
        }

        if (icmp6_reply->icmp6_type == ICMP6_ECHO_REPLY && ntohs(icmp6_reply->icmp6_id) == (unsigned short)getpid() && ntohs(icmp6_reply->icmp6_seq) == 1) {
            result->icmp_ok = 1;
            break;
        }
    }

    close(raw_socket_fd);
    return 0;

}
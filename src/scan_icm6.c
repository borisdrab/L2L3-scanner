#define _DEFAULT_SOURCE

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/icmp6.h>

#include "scan_icm6.h"

// new helper function for reimplementation
static host_result_t *find_result_by_ip(host_result_t *results, int spread_count, const char *ip) {

    for (int index = 0; index < spread_count; index++) {
        if (strcmp(results[index].ip, ip) == 0) {
            return &results[index];
        }
    }
    return NULL;
}

int open_icmpv6_socket(int timeout) {

    int raw_socket_fd;
    struct timeval receive_timeout;

    raw_socket_fd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    if (raw_socket_fd < 0) {
        return -1;
    }

    // timeout computation
    receive_timeout.tv_sec = timeout / 1000;
    receive_timeout.tv_usec = (timeout % 1000) * 1000;

    if (setsockopt(raw_socket_fd, SOL_SOCKET, SO_RCVTIMEO, &receive_timeout, sizeof(receive_timeout)) < 0) {
        close(raw_socket_fd);
        return -1;
    }

    return raw_socket_fd;
}

int send_icmpv6_request(int raw_socket_fd, const char *ip) {

    unsigned char send_buffer[64];
    struct sockaddr_in6 target_addr;
    struct icmp6_hdr *icmp6_header;

    if (ip == NULL) {
        return -1;
    }

    memset(send_buffer, 0, sizeof(send_buffer));
    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin6_family = AF_INET6;

    if (inet_pton(AF_INET6, ip, &target_addr.sin6_addr) != 1) {     // convert textual ipv6 address to binary form
        return -1;
    }

    // construct icmpv6 echo request packet
    icmp6_header = (struct icmp6_hdr *)send_buffer;
    icmp6_header->icmp6_type = ICMP6_ECHO_REQUEST;
    icmp6_header->icmp6_code = 0;
    icmp6_header->icmp6_id = htons((unsigned short)getpid());
    icmp6_header->icmp6_seq = htons(1);

    if (sendto(raw_socket_fd, send_buffer, sizeof(send_buffer), 0, (struct sockaddr *)&target_addr, sizeof(target_addr)) < 0) {
        return -1;
    }

    return 0;
}

int receive_icmpv6_replies(int raw_socket_fd, host_result_t *results, int result_count, int timeout) {

    unsigned char receiver_buffer[1024];
    ssize_t received_bytes;
    struct timeval start_time, current_time;

    if (results == NULL) {
        return -1;
    }

    gettimeofday(&start_time, NULL);    // start timeout window

    for (;;) {

        if (stop_requested) {
            break;
        }

        long elapsed_ms;

        gettimeofday(&current_time, NULL);
        elapsed_ms = (current_time.tv_sec - start_time.tv_sec) * 1000L + (current_time.tv_usec - start_time.tv_usec) / 1000L;  // elapsed time since start

        if (elapsed_ms >= timeout) {
            break;
        }

        struct sockaddr_in6 source_addr;
        socklen_t source_addr_len = sizeof(source_addr);

        received_bytes = recvfrom(raw_socket_fd, receiver_buffer, sizeof(receiver_buffer), 0, (struct sockaddr *)&source_addr, &source_addr_len);

        if (received_bytes < 0) {
            continue;
        }

        if ((size_t)received_bytes < sizeof(struct icmp6_hdr)) {
            continue;
        }

        struct icmp6_hdr *icmp6_reply = (struct icmp6_hdr *)receiver_buffer;

        if (icmp6_reply->icmp6_type != ICMP6_ECHO_REPLY) {
            continue;
        }

        if (ntohs(icmp6_reply->icmp6_id) != (unsigned short)getpid()) {
            continue;
        }

        if (ntohs(icmp6_reply->icmp6_seq) != 1) {
            continue;
        }

        char reply_ip[INET6_ADDRSTRLEN];

        // convert source ipv6 address to string form
        if (inet_ntop(AF_INET6, &source_addr.sin6_addr, reply_ip, sizeof(reply_ip)) == NULL) {
            continue;
        }

        // match reply with corresponding result entry
        host_result_t *result = find_result_by_ip(results, result_count, reply_ip);
        if (result == NULL) {
            continue;
        }

        result->icmp_ok = 1;
    }

    return 0;
}

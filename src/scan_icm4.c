#define _DEFAULT_SOURCE

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>

#include "scan_icm4.h"


// helper function for packet checksum 
unsigned short icmp_checksum(void *data, int len) {

    unsigned short *buf = data;
    unsigned int summary = 0;

    for (summary = 0; len > 1; len -= 2) {
        summary += *buf++;
    }

    if(len == 1) {
        summary += *(unsigned char*)buf;
    }

    summary = (summary >> 16) + (summary & 0xFFFF);
    summary += (summary >> 16);

    return (unsigned short)(~summary);      // bitwise not

}

// new helper function for reimplementation
static host_result_t *find_result_by_ip(host_result_t *results, int spread_count, const char *ip) {

    for (int index = 0; index < spread_count; index++) {
        if (strcmp(results[index].ip, ip) == 0) {
            return &results[index];
        }
    }
    return NULL;

}

int open_icmpv4_socket(int timeout) {

    int raw_socket_fd;
    struct timeval receive_timeout;

    // open raw socket for icmpv4
    raw_socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
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

int send_icmpv4_request(int raw_socket_fd, const char *ip) {

    struct sockaddr_in target_addr;
    unsigned char send_buffer[64];
    struct icmphdr *icmp_header;

    if(ip == NULL) {
        return -1;
    }

    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;

    if(inet_pton(AF_INET, ip, &target_addr.sin_addr) != 1) { 
        return -1;
    }

    memset(send_buffer, 0, sizeof(send_buffer));

    // construct icmpv4 echo request packet
    icmp_header = (struct icmphdr *)send_buffer;
    icmp_header->type = ICMP_ECHO;
    icmp_header->code = 0;
    icmp_header->un.echo.id = htons((unsigned short)getpid());
    icmp_header->un.echo.sequence = htons(1);
    icmp_header->checksum = 0;
    icmp_header->checksum = icmp_checksum(send_buffer, sizeof(send_buffer));

    // send icmpv4 echo request
    if (sendto(raw_socket_fd, send_buffer, sizeof(send_buffer), 0, (struct sockaddr *)&target_addr, sizeof(target_addr)) < 0) {
        return -1;
    }
    return 0;

}

int receive_icmpv4_replies(int raw_socket_fd, host_result_t *results, int result_count, int timeout) {

    unsigned char receive_buffer[1024];
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
        elapsed_ms = (current_time.tv_sec - start_time.tv_sec) * 1000L + (current_time.tv_usec - start_time.tv_usec) / 1000L;   // elapsed time since start

        if (elapsed_ms >= timeout) {
            break;
        }

        received_bytes = recvfrom(raw_socket_fd, receive_buffer, sizeof(receive_buffer), 0, NULL, NULL);

        if (received_bytes < 0) {
            continue;
        }

        if ((size_t)received_bytes < sizeof(struct iphdr)) {        // if ip header is present
            continue;
        }

        struct iphdr *ip_header = (struct iphdr *)receive_buffer;
        int ip_header_len = ip_header->ihl * 4;

        if ((size_t)received_bytes < (size_t)(ip_header_len + (int)sizeof(struct icmphdr))) {
            continue;
        }

        struct icmphdr *icmp_reply = (struct icmphdr *)(receive_buffer + ip_header_len);

        if (icmp_reply->type != ICMP_ECHOREPLY) {             // accept only echo reply
            continue;
        }

        if (ntohs(icmp_reply->un.echo.id) != (unsigned short)getpid()) {
            continue;
        }

        if (ntohs(icmp_reply->un.echo.sequence) != 1) {
            continue;
        }

        struct in_addr reply_addr;
        char reply_ip[INET_ADDRSTRLEN];

        reply_addr.s_addr = ip_header->saddr;

        if(inet_ntop(AF_INET, &reply_addr, reply_ip, sizeof(reply_ip)) == NULL) {
            continue;
        }

        // match reply with the corresponding result entry
        host_result_t *result = find_result_by_ip(results, result_count, reply_ip);
        if (result == NULL) {
            continue;
        }

        result->icmp_ok = 1;
    }

    return 0;
}

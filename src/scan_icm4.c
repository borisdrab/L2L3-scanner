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

    return (unsigned short)(~summary); // bitwise not

}

int scan_icmpv4(const char *ip, int timeout, host_result_t *result){
    int raw_socket_fd;
    struct sockaddr_in target_addr;
    struct timeval receive_timeout;

    unsigned char send_buffer[64];
    unsigned char receive_buffer[1024];

    struct icmphdr *icmp_header;
    ssize_t received_bytes;


    if(ip == NULL || result == NULL) {
        return -1;
    }

    strcpy(result->ip, ip);
    result->icmp_ok = 0;        //from scan_result

    raw_socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (raw_socket_fd < 0) {
        perror("socket");
        return -1;
    }

    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;

    if(inet_pton(AF_INET, ip, &target_addr.sin_addr) != 1) {
        fprintf(stderr, "Error: invalid IPv4 address %s\n", ip);
        close(raw_socket_fd);
        return -1;
    }

    receive_timeout.tv_sec = timeout / 1000;
    receive_timeout.tv_usec = (timeout % 1000) * 1000;

    if (setsockopt(raw_socket_fd, SOL_SOCKET, SO_RCVTIMEO, &receive_timeout, sizeof(receive_timeout)) < 0) {
        perror("setsockopt SO_RCVTIMEO");
        close(raw_socket_fd);
        return -1;
    }

    printf("ICMPv4 socket opened for %s\n", ip);

    memset(send_buffer, 0, sizeof(send_buffer));

    icmp_header = (struct icmphdr *)send_buffer;

    icmp_header->type = ICMP_ECHO;
    icmp_header->code = 0;
    icmp_header->un.echo.id = htons((unsigned short)getpid());
    icmp_header->un.echo.sequence = htons(1);
    icmp_header->checksum = 0;

    icmp_header->checksum = icmp_checksum(send_buffer, sizeof(send_buffer));

    printf("ICMP packet prepared for %s\n", ip);

    if (sendto(raw_socket_fd, send_buffer, sizeof(send_buffer), 0, (struct sockaddr *)&target_addr, sizeof(target_addr)) < 0) {
        perror("sendto");
        close(raw_socket_fd);
        return -1;
    }

    printf("ICMP request send to %s\n", ip);

    received_bytes = recvfrom(raw_socket_fd, receive_buffer, sizeof(receive_buffer), 0, NULL, NULL);

    if (received_bytes < 0) {
        close(raw_socket_fd);
        return 0;
    }

    printf("Received %zd bytes\n", received_bytes);

    if ((size_t)received_bytes < sizeof(struct iphdr) + sizeof(struct icmphdr)) {
        close(raw_socket_fd);
        return 0;
    }

    struct iphdr *ip_header;
    struct icmphdr *icmp_reply;

    ip_header = (struct iphdr *)receive_buffer;

    icmp_reply = (struct icmphdr *)(receive_buffer + ip_header->ihl * 4);

    if (icmp_reply->type == ICMP_ECHOREPLY && ntohs(icmp_reply->un.echo.id) == (unsigned short)getpid() && ntohs(icmp_reply->un.echo.sequence) == 1) {
        result->icmp_ok = 1;
        printf("ICMP reply received from %s\n", ip);
    }


    close(raw_socket_fd);
    return 0;
}

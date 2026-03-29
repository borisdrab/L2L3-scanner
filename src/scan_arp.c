#define _DEFAULT_SOURCE

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <linux/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/if_arp.h>

#include "scan_arp.h"
#include "interface.h"

typedef struct {
    unsigned char dst_mac_addr[6];
    unsigned char src_mac_addr[6];
    unsigned short ethertype;
} __attribute__((packed)) ethernet_header_t;

typedef struct {
    unsigned short hardware_type;
    unsigned short protocol_type;
    unsigned char mac_len;
    unsigned char ip_len;
    unsigned short operation;
    unsigned char sender_hardware_addr[6];
    unsigned char sender_protocol_addr[4];
    unsigned char target_hardware_addr[6];
    unsigned char target_protocol_addr[4];

} __attribute__((packed)) arp_header_t;

int scan_arp_ipv4(const char *ip, const char *interface, int timeout, host_result_t *result) {
    int raw_socket_fd;
    struct ifreq interface_request;
    struct sockaddr_ll socket_address;
    interface_info_t interface_info;
    struct in_addr sender_ip_addr;
    struct in_addr target_ip_addr;
    

    unsigned char arp_frame[sizeof(ethernet_header_t) + sizeof(arp_header_t)];
    unsigned char receive_buffer[2048];
    ssize_t received_bytes;
    ethernet_header_t *ethernet_header = (ethernet_header_t *)arp_frame;
    arp_header_t *arp_header = (arp_header_t *)(arp_frame + sizeof(ethernet_header_t));

    struct timeval receive_timeout;

    if (ip == NULL || interface == NULL || result == NULL) {
        return -1;
    }

    strncpy(result->ip, ip, sizeof(result->ip) - 1);
    result->ip[sizeof(result->ip) - 1] = '\0';
    result->arpndp_ok = 0;
    result->icmp_ok = 0;
    result->mac[0] = '\0';

    if (get_interface_info(interface, &interface_info) != 0) {
        fprintf(stderr, "Error: failed to get interface info\n");
        return -1;
    }

    if (inet_pton(AF_INET, interface_info.ip, &sender_ip_addr) != 1) {
        fprintf(stderr, "Error: invalid interface IP\n");
        return -1;
    }

    if (inet_pton(AF_INET, ip, &target_ip_addr) != 1) {
        fprintf(stderr, "Error: invalid target IP\n");
        return -1;
    }

    raw_socket_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (raw_socket_fd < 0) {
        return 0;
    }

    memset(&interface_request, 0, sizeof(interface_request));
    strncpy(interface_request.ifr_name, interface, IFNAMSIZ - 1);
    interface_request.ifr_name[IFNAMSIZ - 1] = '\0';

    if (ioctl(raw_socket_fd, SIOCGIFINDEX, &interface_request) < 0) {
        close(raw_socket_fd);
        return 0;
    }

    receive_timeout.tv_sec = timeout / 1000;
    receive_timeout.tv_usec = (timeout % 1000) * 1000;

    if(setsockopt(raw_socket_fd, SOL_SOCKET, SO_RCVTIMEO, &receive_timeout, sizeof(receive_timeout)) < 0) {
        close(raw_socket_fd);
        return 0;
    }

    memset(&socket_address, 0, sizeof(socket_address));
    socket_address.sll_family = AF_PACKET;
    socket_address.sll_ifindex = interface_request.ifr_ifindex;
    socket_address.sll_halen = 6;
    memset(socket_address.sll_addr, 0xff, 6);

    memset(arp_frame, 0, sizeof(arp_frame));

    memset(ethernet_header->dst_mac_addr, 0xff, 6);
    memcpy(ethernet_header->src_mac_addr, interface_info.mac_addr, 6);
    ethernet_header->ethertype = htons(ETH_P_ARP);

    arp_header->hardware_type = htons(ARPHRD_ETHER);
    arp_header->protocol_type = htons(ETH_P_IP);
    arp_header->mac_len = 6;
    arp_header->ip_len = 4;
    arp_header->operation = htons(ARPOP_REQUEST);

    memcpy(arp_header->sender_hardware_addr, interface_info.mac_addr, 6);
    memcpy(arp_header->sender_protocol_addr, &sender_ip_addr.s_addr, 4);

    memset(arp_header->target_hardware_addr, 0x00, 6);
    memcpy(arp_header->target_protocol_addr, &target_ip_addr.s_addr, 4);

    if (sendto(raw_socket_fd, arp_frame, sizeof(arp_frame), 0, (struct sockaddr *)&socket_address, sizeof(socket_address)) < 0) {
        close(raw_socket_fd);
        return 0;
    }


    for (;;) {
        ethernet_header_t *recv_eth_hdr;
        arp_header_t *receive_arp_hdr;

        received_bytes = recvfrom(raw_socket_fd, receive_buffer, sizeof(receive_buffer), 0, NULL, NULL);

        if (received_bytes < 0) {
            close(raw_socket_fd);
            return 0;
        }

        if ((size_t)received_bytes < sizeof(ethernet_header_t) + sizeof(arp_header_t)) {
            continue;
        }

        recv_eth_hdr = (ethernet_header_t *)receive_buffer;
        receive_arp_hdr = (arp_header_t *)(receive_buffer + sizeof(ethernet_header_t));

        if (ntohs(recv_eth_hdr->ethertype) != ETH_P_ARP) {
            continue;
        }

        if (ntohs(receive_arp_hdr->operation) != ARPOP_REPLY) {
            continue;
        }

        if (memcmp(receive_arp_hdr->sender_protocol_addr, &target_ip_addr.s_addr, 4) != 0) {
            continue;
        }

        if (memcmp(receive_arp_hdr->target_protocol_addr, &sender_ip_addr.s_addr, 4) != 0) {
            continue;
        }

        if (memcmp(receive_arp_hdr->sender_hardware_addr, interface_info.mac_addr, 6) == 0) {
            continue;
        }

        snprintf(result->mac, sizeof(result->mac),
            "%02x-%02x-%02x-%02x-%02x-%02x",
            receive_arp_hdr->sender_hardware_addr[0],
            receive_arp_hdr->sender_hardware_addr[1],
            receive_arp_hdr->sender_hardware_addr[2],
            receive_arp_hdr->sender_hardware_addr[3],
            receive_arp_hdr->sender_hardware_addr[4],
            receive_arp_hdr->sender_hardware_addr[5]
        );

        result->arpndp_ok = 1;

        close(raw_socket_fd);
        return 0;

    }

        close(raw_socket_fd);
        return 0;
}
#define _DEFAULT_SOURCE

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <linux/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

#include <sys/ioctl.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>

#include "scan_ndp.h"
#include "interface.h"

// compouning ipv6 packet header, checksum  inspired by the standart 
static void build_solicited_node_multicast_ip(const struct in6_addr *target_ip, struct in6_addr *multicast_ip) {
    memset(multicast_ip, 0, sizeof(*multicast_ip));

    multicast_ip->s6_addr[0] = 0xff;
    multicast_ip->s6_addr[1] = 0x02;
    multicast_ip->s6_addr[11] = 0x01;
    multicast_ip->s6_addr[12] = 0xff;

    multicast_ip->s6_addr[13] = target_ip->s6_addr[13];
    multicast_ip->s6_addr[14] = target_ip->s6_addr[14];
    multicast_ip->s6_addr[15] = target_ip->s6_addr[15];
}

static void build_solicited_node_multicast_mac(const struct in6_addr *target_ip, unsigned char multicast_mac[6]) {

    multicast_mac[0] = 0x33;
    multicast_mac[1] = 0x33;
    multicast_mac[2] = 0xff;
    multicast_mac[3] = target_ip->s6_addr[13];
    multicast_mac[4] = target_ip->s6_addr[14];
    multicast_mac[5] = target_ip->s6_addr[15];
}

static unsigned short compute_checksum(const void *data, size_t len) {
    const unsigned short *ptr = (const unsigned short *)data;
    unsigned int summary = 0;

    while(len > 1) {
        summary += *ptr++;
        len -= 2;
    }

    if (len == 1) {
        summary += *((const unsigned char *)ptr);
    } 

    while (summary >> 16) {
        summary = (summary & 0xFFFF) + (summary >> 16);
    }

    return (unsigned short)(~summary);
}

static unsigned short compute_icmpv6_checksum(const struct in6_addr *src, const struct in6_addr *dst, const void *icmpv6_data, size_t icmpv6_len) {
    unsigned char buffer[512];
    unsigned char *ptr = buffer;
    uint32_t upper_layer_len = htonl((uint32_t)icmpv6_len);
    uint32_t next_header = htonl(IPPROTO_ICMPV6);

    if (sizeof(struct in6_addr) + sizeof(struct  in6_addr) + 4 + 4 + icmpv6_len > sizeof(buffer)) {
        return 0;
    }

    memset (buffer, 0, sizeof(buffer));

    memcpy (ptr, src, sizeof(struct in6_addr));
    ptr += sizeof(struct in6_addr);
    
    memcpy (ptr, dst, sizeof(struct in6_addr));
    ptr += sizeof(struct in6_addr);
    
    memcpy (ptr, &upper_layer_len, sizeof(upper_layer_len));
    ptr += sizeof(upper_layer_len);

    memcpy (ptr, &next_header, sizeof(next_header));
    ptr += sizeof(next_header);
    
    memcpy (ptr, icmpv6_data, icmpv6_len);
    ptr += icmpv6_len;

    return compute_checksum(buffer, (size_t)(ptr - buffer));

}

typedef struct  {
    uint8_t type;
    uint8_t length;
    unsigned char mac[6];
} __attribute__((packed)) ndp_source_link_layer_option_t;

int scan_ndp_ipv6(const char *ip, const char *interface, int timeout, host_result_t *result){

    int raw_socket_fd;
    unsigned char multicast_mac[6];
    char multicast_ip_str[INET6_ADDRSTRLEN];

    struct in6_addr solicited_node_multicast_ip;
    struct ifreq interface_request;
    struct sockaddr_ll socket_address;
    interface_info_t interface_info;
    struct in6_addr target_ip_addr;
    struct timeval receive_timeout;

    ndp_source_link_layer_option_t *source_mac_option;
    ssize_t sent_bytes;

    unsigned char receive_buffer[256];
    ssize_t received_bytes;

    if(ip == NULL || interface == NULL || result == NULL) {
        return -1;
    }

    strcpy(result->ip, ip);

    result->arpndp_ok = 0;
    result->mac[0] = '\0';

    if(get_interface_info(interface, &interface_info) != 0) {
        fprintf(stderr, "Error: failed to get interface info\n");
        return -1;
    }

    printf("Interface IPv6 for NDP: %s\n", interface_info.ipv6);

    if (inet_pton(AF_INET6, ip, &target_ip_addr) != 1) {
        fprintf(stderr, "Error: invalid IPv6 address %s\n", ip);
        return -1;
    }

    build_solicited_node_multicast_ip(&target_ip_addr, &solicited_node_multicast_ip);
    build_solicited_node_multicast_mac(&target_ip_addr, multicast_mac);


    unsigned char send_buffer[128];
    memset(send_buffer, 0, sizeof(send_buffer));

    struct ethhdr *ethernet_header;
    struct ip6_hdr *ipv6_header;

    ethernet_header = (struct ethhdr *)send_buffer;
    ipv6_header = (struct ip6_hdr *)(send_buffer + sizeof(struct ethhdr));

    memcpy(ethernet_header->h_dest, multicast_mac, 6);
    memcpy(ethernet_header->h_source, interface_info.mac_addr, 6);
    ethernet_header->h_proto = htons(ETH_P_IPV6);

    printf("Ethernet frame prepared\n");

    ipv6_header->ip6_flow = htonl((6 << 28));
    ipv6_header->ip6_hlim = 255;
    ipv6_header->ip6_nxt = IPPROTO_ICMPV6;
    ipv6_header->ip6_dst = solicited_node_multicast_ip;

    printf("IPv6 header prepared\n");

    struct icmp6_hdr *icmp6_header;
    struct nd_neighbor_solicit *neighbor_solicitation;

    icmp6_header = (struct icmp6_hdr *)(send_buffer + sizeof(struct ethhdr) + sizeof(struct ip6_hdr));

    icmp6_header->icmp6_type = ND_NEIGHBOR_SOLICIT;
    icmp6_header->icmp6_code = 0;
    icmp6_header->icmp6_cksum = 0;

    neighbor_solicitation = (struct nd_neighbor_solicit *)icmp6_header;
    neighbor_solicitation->nd_ns_target = target_ip_addr;

    ipv6_header->ip6_plen = htons(sizeof(struct nd_neighbor_solicit));

    if(inet_pton(AF_INET6, interface_info.ipv6, &ipv6_header->ip6_src) != 1) {
        fprintf(stderr, "Error: invalid interface IPv6 address %s\n", interface_info.ipv6);
        return -1;
    }

    printf("ICMPv6 Neighbor solicitation prepared\n");

    source_mac_option = (ndp_source_link_layer_option_t *)(send_buffer + sizeof(struct ethhdr) + sizeof(struct ip6_hdr) + sizeof(struct nd_neighbor_solicit));

    source_mac_option->type = 1;
    source_mac_option->length = 1;
    memcpy(source_mac_option->mac, interface_info.mac_addr, 6);

    ipv6_header->ip6_plen = htons(sizeof(struct nd_neighbor_solicit) + sizeof(ndp_source_link_layer_option_t));
    icmp6_header->icmp6_cksum = compute_icmpv6_checksum(&ipv6_header->ip6_src, &ipv6_header->ip6_dst, icmp6_header, sizeof(struct nd_neighbor_solicit) + sizeof(ndp_source_link_layer_option_t));

    printf("ICMPv6 checksum compute\n");

    printf("Source Link-Layer Address option prepared\n");


    if (inet_ntop(AF_INET6, &solicited_node_multicast_ip, multicast_ip_str, sizeof(multicast_ip_str)) == NULL) {
        fprintf(stderr, "Error: failed to convert multicast IPv6 address\n");
        return -1;
    }

    printf("Solicited-node multicast IPv6: %s\n", multicast_ip_str);
    printf("Multicast MAC: %02x-%02x-%02x-%02x-%02x-%02x\n",
            multicast_mac[0],
            multicast_mac[1],
            multicast_mac[2],
            multicast_mac[3],
            multicast_mac[4],
            multicast_mac[5]);
       

    raw_socket_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IPV6));
    if (raw_socket_fd < 0) {
        perror("socket");
        return -1;
    }

    memset(&interface_request, 0, sizeof(interface_request));
    strncpy(interface_request.ifr_name, interface, IFNAMSIZ - 1);
    interface_request.ifr_name[IFNAMSIZ - 1] = '\0';

    if(ioctl(raw_socket_fd, SIOCGIFINDEX, &interface_request) < 0) {
        perror("ioctl SIOCGIFINDEX");
        close(raw_socket_fd);
        return -1;
    }

    // counting timeout
    receive_timeout.tv_sec = timeout / 1000;
    receive_timeout.tv_usec = (timeout % 1000) * 1000;

    if (setsockopt(raw_socket_fd, SOL_SOCKET, SO_RCVTIMEO, &receive_timeout, sizeof(receive_timeout)) < 0) {
        perror("setsockopt SO_RCVTIMEO");
        close(raw_socket_fd);
        return -1;
    }

    memset(&socket_address, 0, sizeof(socket_address));
    socket_address.sll_family = AF_PACKET;
    socket_address.sll_ifindex = interface_request.ifr_ifindex;
    socket_address.sll_halen = 6;

    memcpy(socket_address.sll_addr, multicast_mac, 6);
    sent_bytes = sendto(raw_socket_fd, send_buffer, sizeof(struct ethhdr) + sizeof(struct ip6_hdr) + sizeof(struct nd_neighbor_solicit) + sizeof(ndp_source_link_layer_option_t), 0, (struct sockaddr *)&socket_address, sizeof(socket_address));

    if (sent_bytes < 0) {
        perror("sendto");
        close(raw_socket_fd);
        return -1;
    }

    printf("NDP Neigbor Solicitation sent to %s\n", ip);
    printf("NDP socket opened for %s\n", ip);
    printf("Interface index %d\n", interface_request.ifr_ifindex);


    for (;;) {                                                                                  // logic likewise in ipv4
        received_bytes = recvfrom(raw_socket_fd, receive_buffer, sizeof(receive_buffer), 0, NULL, NULL);

        if (received_bytes < 0) {
            close(raw_socket_fd);
            return 0;
        }

        printf("Received %zd bytes\n", received_bytes);

        if ((size_t)received_bytes < sizeof(struct ethhdr)) {
            continue;
        }
        struct ethhdr *received_ethernet_header = (struct ethhdr *)receive_buffer;

        if (ntohs(received_ethernet_header->h_proto) != ETH_P_IPV6) {
            continue;
        }

        if ((size_t)received_bytes < sizeof(struct ethhdr) + sizeof(struct ip6_hdr)) {
            continue;
        }
        struct ip6_hdr *received_ipv6_header = (struct ip6_hdr *)(receive_buffer + sizeof(struct ethhdr));

        if (received_ipv6_header->ip6_nxt != IPPROTO_ICMPV6) {
            continue;
        }

        if((size_t)received_bytes < sizeof(struct ethhdr) + sizeof(struct ip6_hdr) + sizeof(struct nd_neighbor_advert)) {
            continue;
        }
        struct icmp6_hdr *icmp6_reply = (struct icmp6_hdr *)(receive_buffer + sizeof(struct ethhdr) + sizeof(struct ip6_hdr));

        printf("NDP ICMPv6 type=%d code=%d\n", icmp6_reply->icmp6_type, icmp6_reply->icmp6_code);

        if (icmp6_reply->icmp6_type != ND_NEIGHBOR_ADVERT) {
            continue;
        }
        struct nd_neighbor_advert *neighbor_advert = (struct nd_neighbor_advert *)(receive_buffer + sizeof(struct ethhdr) + sizeof(struct ip6_hdr));

        if(memcmp(&neighbor_advert->nd_na_target, &target_ip_addr, sizeof(struct in6_addr)) != 0) {
            continue;
        }
        unsigned char *source_mac = received_ethernet_header->h_source;

        snprintf(result->mac, sizeof(result->mac), 
                "%02x-%02x-%02x-%02x-%02x-%02x",
                source_mac[0],
                source_mac[1],
                source_mac[2],
                source_mac[3],
                source_mac[4],
                source_mac[5]
                );

        result->arpndp_ok = 1;

        printf("NDP reply received from %s\n", ip);

        close(raw_socket_fd);
        return 0;
    }
}               // clear debug prints !!!!!!!!

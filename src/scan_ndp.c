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

typedef struct {
    uint8_t type;
    uint8_t length;
    unsigned char mac[6];
} __attribute__((packed)) ndp_source_link_layer_option_t;

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

// build multicast mac addres
static void build_solicited_node_multicast_mac(const struct in6_addr *target_ip, unsigned char multicast_mac[6]) {

    multicast_mac[0] = 0x33;
    multicast_mac[1] = 0x33;
    multicast_mac[2] = 0xff;
    multicast_mac[3] = target_ip->s6_addr[13];
    multicast_mac[4] = target_ip->s6_addr[14];
    multicast_mac[5] = target_ip->s6_addr[15];
}

// compute generic internet checksum
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

// compute icmpv6 checksum including ipv6 pseudo-header
static unsigned short compute_icmpv6_checksum(const struct in6_addr *src, const struct in6_addr *dst, const void *icmpv6_data, size_t icmpv6_len) {

    unsigned char buffer[512];
    unsigned char *ptr = buffer;
    uint32_t upper_layer_len = htonl((uint32_t)icmpv6_len);
    uint32_t next_header = htonl(IPPROTO_ICMPV6);

    if (sizeof(struct in6_addr) + sizeof(struct  in6_addr) + 4 + 4 + icmpv6_len > sizeof(buffer)) {
        return 0;
    }

    memset (buffer, 0, sizeof(buffer));

    // ipv6 pseudo-header
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

// find result entry corresponding to given ipv6 addr
static host_result_t *find_result_by_ip(host_result_t *results, int spread_count, const char *ip) {

    for (int index = 0; index < spread_count; index++) {
        if (strcmp(results[index].ip, ip) == 0) {
            return &results[index];
        }
    }
    return NULL;

}

int open_ndp_socket(const char *interface, int timeout, interface_info_t *interface_info, int *interface_index) {

    int raw_socket_fd;
    struct ifreq interface_request;
    struct timeval receive_timeout;

    if(interface == NULL || interface_info == NULL || interface_index == NULL) {
        return -1;
    }

    if(get_interface_info(interface, interface_info) != 0) {
        fprintf(stderr, "Error: failed to get interface info\n");
        return -1;
    }

    // open raw ether socket
    raw_socket_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IPV6));
    if (raw_socket_fd < 0) {
        return -1;
    }

    // interface index
    memset(&interface_request, 0, sizeof(interface_request));
    strncpy(interface_request.ifr_name, interface, IFNAMSIZ - 1);
    interface_request.ifr_name[IFNAMSIZ - 1] = '\0';

    if(ioctl(raw_socket_fd, SIOCGIFINDEX, &interface_request) < 0) {
        close(raw_socket_fd);
        return -1;
    }

    *interface_index = interface_request.ifr_ifindex;

    // counting timeout
    receive_timeout.tv_sec = timeout / 1000;
    receive_timeout.tv_usec = (timeout % 1000) * 1000;

    if (setsockopt(raw_socket_fd, SOL_SOCKET, SO_RCVTIMEO, &receive_timeout, sizeof(receive_timeout)) < 0) {
        close(raw_socket_fd);
        return -1;
    }

    return raw_socket_fd;
    
}

int send_ndp_request(int raw_socket_fd, const char *target_ip, const interface_info_t *interface_info, int interface_index) {

    struct in6_addr target_ip_addr;
    struct in6_addr multicast_ip;
    unsigned char multicast_mac[6];
    struct sockaddr_ll socket_address;

    unsigned char send_buffer[128];
    memset(send_buffer, 0, sizeof(send_buffer));

    if (target_ip == NULL || interface_info == NULL) {
        return -1;
    }

    if (inet_pton(AF_INET6, target_ip, &target_ip_addr) != 1) {
        return -1;
    }

    build_solicited_node_multicast_ip(&target_ip_addr, &multicast_ip);
    build_solicited_node_multicast_mac(&target_ip_addr, multicast_mac);

    struct ethhdr *ethernet_header = (struct ethhdr *)send_buffer;
    struct ip6_hdr *ipv6_header = (struct ip6_hdr *)(send_buffer + sizeof(struct ethhdr));
    struct icmp6_hdr *icmp6_header = (struct icmp6_hdr *)(send_buffer + sizeof(struct ethhdr) + sizeof(struct ip6_hdr));
    struct nd_neighbor_solicit *neighbor_solicit = (struct nd_neighbor_solicit *)icmp6_header;

    // ethernet header
    memcpy(ethernet_header->h_dest, multicast_mac, 6);
    memcpy(ethernet_header->h_source, interface_info->mac_addr, 6);
    ethernet_header->h_proto = htons(ETH_P_IPV6);

    // ipv6 header
    ipv6_header->ip6_flow = htonl((6 << 28));
    ipv6_header->ip6_hlim = 255;
    ipv6_header->ip6_nxt = IPPROTO_ICMPV6;
    ipv6_header->ip6_dst = multicast_ip;

    if(inet_pton(AF_INET6, interface_info->ipv6, &ipv6_header->ip6_src) != 1) {
        return -1;
    }

    // ipv6 neighbor solicitation
    icmp6_header->icmp6_type = ND_NEIGHBOR_SOLICIT;
    icmp6_header->icmp6_code = 0;
    icmp6_header->icmp6_cksum = 0;

    neighbor_solicit->nd_ns_target = target_ip_addr;

    ndp_source_link_layer_option_t * source_mac_option =
        (ndp_source_link_layer_option_t *)(send_buffer + sizeof(struct ethhdr) + sizeof(struct ip6_hdr) + sizeof(struct nd_neighbor_solicit));

    source_mac_option->type = 1;
    source_mac_option->length = 1;
    memcpy(source_mac_option->mac, interface_info->mac_addr, 6);

    ipv6_header->ip6_plen = htons(sizeof(struct nd_neighbor_solicit) + sizeof(ndp_source_link_layer_option_t));
    icmp6_header->icmp6_cksum = compute_icmpv6_checksum(&ipv6_header->ip6_src, &ipv6_header->ip6_dst, icmp6_header, sizeof(struct nd_neighbor_solicit) + sizeof(ndp_source_link_layer_option_t));

    // prepare socket address
    memset(&socket_address, 0, sizeof(socket_address));
    socket_address.sll_family = AF_PACKET;
    socket_address.sll_ifindex = interface_index;
    socket_address.sll_halen = 6;
    memcpy(socket_address.sll_addr, multicast_mac, 6);

    if(sendto(raw_socket_fd, send_buffer, sizeof(struct ethhdr) + sizeof(struct ip6_hdr) + sizeof(struct nd_neighbor_solicit) + sizeof(ndp_source_link_layer_option_t), 
        0, (struct sockaddr *)&socket_address, sizeof(socket_address)) < 0) {
            return -1;
    }

    return 0;
}

int receive_ndp_replies(int raw_socket_fd, host_result_t *results, int result_count, int timeout) {

    unsigned char receive_buffer[256];
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

        received_bytes = recvfrom(raw_socket_fd, receive_buffer, sizeof(receive_buffer), 0, NULL, NULL);

        if (received_bytes < 0) {
            continue;
        }

        if ((size_t)received_bytes < sizeof(struct ethhdr)) {
            continue;
        }

        struct ethhdr *received_ethernet_header = (struct ethhdr *)receive_buffer;

        // filter only ipv6 frames
        if (ntohs(received_ethernet_header->h_proto) != ETH_P_IPV6) {
            continue;
        }

        if ((size_t)received_bytes < sizeof(struct ethhdr) + sizeof(struct ip6_hdr) + sizeof(struct nd_neighbor_advert)) {
            continue;
        }

        struct icmp6_hdr *icmp6_reply = (struct icmp6_hdr *)(receive_buffer + sizeof(struct ethhdr) + sizeof(struct ip6_hdr));
        if (icmp6_reply->icmp6_type != ND_NEIGHBOR_ADVERT) {
            continue;
        }

        struct nd_neighbor_advert *nd_neighbor_advert = (struct nd_neighbor_advert *)(receive_buffer + sizeof(struct ethhdr) + sizeof(struct ip6_hdr));

        char reply_ip[INET6_ADDRSTRLEN];
        if (inet_ntop(AF_INET6, &nd_neighbor_advert->nd_na_target, reply_ip, sizeof(reply_ip)) == NULL) {
            continue;
        }

        host_result_t *result = find_result_by_ip(results, result_count, reply_ip);
        if (result == NULL) {
            continue;
        }

        unsigned char *source_mac = received_ethernet_header->h_source;
        snprintf(result->mac, sizeof(result->mac),         // fromat sender mac address to output buffer
            "%02x-%02x-%02x-%02x-%02x-%02x",
            source_mac[0],
            source_mac[1],
            source_mac[2],
            source_mac[3],
            source_mac[4],
            source_mac[5]
        );
        
        result->arpndp_ok = 1;
    }

    return 0;
}

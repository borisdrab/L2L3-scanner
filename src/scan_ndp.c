#define _DEFAULT_SOURCE

#include <stdio.h>
#include <string.h>
#include "scan_ndp.h"
#include <arpa/inet.h>


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

//**TBD********

int scan_ndp_ipv6(const char *ip, const char *interface, int timeout, host_result_t *result){
    return -1;
}

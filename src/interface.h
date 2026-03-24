#ifndef INTERFACE_H
#define INTERFACE_H

#include <netinet/in.h>

typedef struct {
    char name[64];
    char ip[INET_ADDRSTRLEN];
    char ipv6[INET6_ADDRSTRLEN];
    unsigned char mac_addr[6];
} interface_info_t;

int get_interface_info(const char *ifname, interface_info_t *info);

#endif

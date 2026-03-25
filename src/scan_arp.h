#ifndef SCAN_ARP_H
#define SCAN_ARP_H

#include "scan_result.h"

int scan_arp_ipv4(
    const char *ip,
    const char *interface,
    int timeout,
    host_result_t *result
);

#endif
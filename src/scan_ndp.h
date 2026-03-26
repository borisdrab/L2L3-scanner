#ifndef SCAN_NDP_H
#define SCAN_NDP_H

#include "scan_result.h"

int scan_ndp_ipv6(const char *ip, const char *interface, int timeout, host_result_t *result);

#endif
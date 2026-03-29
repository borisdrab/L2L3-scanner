#ifndef SCAN_ICM6_H
#define SCAN_ICM6_H

#include "scan_result.h"

int scan_icmpv6(const char *ip, int timeout, host_result_t *result);

#endif
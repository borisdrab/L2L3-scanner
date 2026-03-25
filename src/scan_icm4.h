#ifndef SCAN_ICM4_H
#define SCAN_ICM4_H

#include "scan_result.h"

int scan_icmpv4(const char *ip, int timeout, host_result_t *result);

#endif
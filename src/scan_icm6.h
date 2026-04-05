#ifndef SCAN_ICM6_H
#define SCAN_ICM6_H

#include "scan_result.h"

// new functions for reimplementation
int open_icmpv6_socket(int timeout);
int send_icmpv6_request(int raw_socket_fd, const char *ip);
int receive_icmpv6_replies(int raw_socket_fd, host_result_t *results, int result_count, int timeout);

#endif

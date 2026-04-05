#ifndef SCAN_ICM4_H
#define SCAN_ICM4_H

#include "scan_result.h"

// new functions for reimplementation
int open_icmpv4_socket(int timeout);
int send_icmpv4_request(int raw_socket_fd, const char *ip);
int receive_icmpv4_replies(int raw_socket_fd, host_result_t *results, int result_count, int timeout);

#endif

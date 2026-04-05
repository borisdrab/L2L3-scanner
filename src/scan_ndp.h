#ifndef SCAN_NDP_H
#define SCAN_NDP_H

#include "scan_result.h"
#include "interface.h"

// new functions for reimplementation
int open_ndp_socket(const char *interface, int timeout, interface_info_t *interface_info, int *interface_index);
int send_ndp_request(int raw_socket_fd, const char *target_ip, const interface_info_t *interface_info, int interface_index);
int receive_ndp_replies(int raw_socket_fd, host_result_t *results, int result_count, int timeout);

#endif

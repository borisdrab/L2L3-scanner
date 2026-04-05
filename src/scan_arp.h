#ifndef SCAN_ARP_H
#define SCAN_ARP_H

#include "scan_result.h"
#include "interface.h"

// new functions for reimplementation
int open_arp_socket(const char *interface, int timeout, interface_info_t *interface_info, int *interface_index);
int send_arp_request(int raw_socket_fd, const char *target_ip, const interface_info_t *interface_info, int interface_index);
int receive_arp_replies(int raw_socket_fd, host_result_t *results, int result_count, const interface_info_t *interface_info, const char *sender_ip, int timeout);

#endif

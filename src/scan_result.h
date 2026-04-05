#ifndef SCAN_RESULT_H
#define SCAN_RESULT_H

#include "subnet.h"
#include <signal.h>

extern volatile sig_atomic_t stop_requested;  // for signal ctrl + c

typedef struct {
    char ip[MAX_IP_STR_LEN];

    int arpndp_ok;              // flag for both arp and ndp
    char mac[18];

    int icmp_ok;
} host_result_t;

#endif

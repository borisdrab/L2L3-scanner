#include "subnet.h"

#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>

int detect_ip_version(const char *ip_str) {
    struct in_addr addr4;
    struct in6_addr addr6;

    if(inet_pton(AF_INET, ip_str, &addr4) == 1) {
        return 4;
    }
    if(inet_pton(AF_INET6, ip_str, &addr6) == 1) {
        return 6;
    }

    return 0;
}

int split_subnet(const char *subnet_str, parsed_subnet_t *result) {
    char buffer[MAX_IP_STR_LEN];
    char *slash;
    char *prefix_str;
    char *end;
    long prefix_val;

    if(subnet_str == NULL || result == NULL) {
        return 0;
    }

    strncpy(buffer, subnet_str, sizeof(buffer) -1);
    buffer[sizeof(buffer) - 1] = '\0';

    slash = strchr(buffer,'/');
    if (slash == NULL) {
        return 0;
    }

    *slash = '\0';
    prefix_str = slash + 1;

    if(buffer[0] == '\0'){
        return 0;
    }

     if(prefix_str[0] == '\0'){
        return 0;
    }

    result->form_version = detect_ip_version(buffer);
    if(result->form_version == 0){
        return 0;
    }

    prefix_val = strtol(prefix_str, &end, 10);
    if (*end != '\0') {
        return 0;
    }

    if (result->form_version == 4) {
        if (prefix_val < 0 || prefix_val > 32) {
            return 0;
        }

    } else if (result->form_version == 6) {
        if (prefix_val < 0 || prefix_val > 128) {
            return 0;
        }
    }

    strncpy(result->ip, buffer, sizeof(result->ip)-1);
    result->ip[sizeof(result->ip) - 1] = '\0';
    result->prefix = (int)prefix_val;

    return 1;
}


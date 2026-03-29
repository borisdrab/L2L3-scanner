#include "subnet.h"

#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

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

int normalize_subnet(parsed_subnet_t *subnet) {
    if (subnet == NULL) {
        return 0;
    }

    if (subnet->form_version == 4) {
        struct in_addr addr;
        uint32_t ip_host_order;
        uint32_t mask;
        uint32_t network_host_order;

        // converting adress to binary
        if (inet_pton(AF_INET, subnet->ip, &addr) != 1) {
            return 0;
        }

        ip_host_order = ntohl(addr.s_addr);

        if(subnet->prefix == 0) {
            mask = 0;
        } else {
            mask = 0xFFFFFFFFu << (32 - subnet->prefix);
        }

        network_host_order = ip_host_order & mask;
        addr.s_addr = htonl(network_host_order);

        if (inet_ntop(AF_INET, &addr, subnet->ip, MAX_IP_STR_LEN) == NULL) {
            return 0;
        }

        return 1;
    }

    if (subnet->form_version == 6) {
        struct in6_addr addr6;
        int full_bytes;
        int remaining_bits;

        // converting adress to binary
        if (inet_pton(AF_INET6, subnet->ip, &addr6) != 1) {
            return 0;
        } 

        full_bytes = subnet->prefix / 8;
        remaining_bits = subnet->prefix % 8;

        // nulling the host part
        for (int index = full_bytes + (remaining_bits ? 1 : 0); index < 16; index++) {
            addr6.s6_addr[index] = 0;
        }

        //prefix ends in the middle of a byte
        if (remaining_bits != 0 && full_bytes < 16) {
            unsigned char mask = (unsigned char)(0xFF << (8 - remaining_bits));
            addr6.s6_addr[full_bytes] &= mask;
        }

        if (inet_ntop(AF_INET6, &addr6, subnet->ip, MAX_IP_STR_LEN) == NULL) {
            return 0;
        }

        return 1;
    }

    return 0;

}

long long count_hosts(const parsed_subnet_t *subnet) {
    if (subnet == NULL) {
        return -1;
    }

    if (subnet->form_version == 4) {
        int host_bits;
        long long block_size;
        
        host_bits = 32 - subnet->prefix;
        block_size = 1LL << host_bits;

        if (subnet->prefix == 32) {
            return 1;
        }

        if (subnet->prefix == 31) {
            return 2;
        }

        return block_size - 2; //network, broadcast
    }

    if (subnet->form_version == 6) {
        int host_bits;
        long long block_size;

        host_bits = 128 - subnet->prefix;

        if (host_bits < 0) {
            return -1;
        }

        if (host_bits == 0) {
            return 1;
        }

        if (host_bits > 16) {
            return -1;
        }

        block_size = 1LL << host_bits;

        if (block_size > MAX_IPV6_HOSTS) {
            return -1;
        }

        return block_size;
    }

    return -1;
}

int generate_ipv4_hosts(const parsed_subnet_t *subnet, char hosts[][MAX_IP_STR_LEN], int max_hosts) {
    struct in_addr addr;
    uint32_t ip_host_order;
    uint32_t mask;
    uint32_t network_host_order;
    uint32_t broadcast_host_order;
    uint32_t block_size;

    int generated = 0;

    if (subnet == NULL || hosts == NULL || max_hosts <= 0) {
        return -1;
    }

    if (subnet->form_version != 4) {
        return -1;
    }

    if (inet_pton(AF_INET, subnet->ip, &addr) != 1) {
        return -1;
    }

    ip_host_order = ntohl(addr.s_addr);

    if (subnet->prefix == 32) {
        if (inet_ntop(AF_INET, &addr, hosts[0], MAX_IP_STR_LEN) == NULL) {
            return -1;
        }

        return 1;
    }


    if (subnet->prefix == 0) {
        mask = 0;
    } else {
        mask = 0xFFFFFFFFu << (32 - subnet->prefix);    
    }

    network_host_order = ip_host_order & mask;

    block_size = 1u << (32 - subnet->prefix);
    broadcast_host_order = network_host_order + block_size - 1;

    if (subnet->prefix == 31) {
        for (uint32_t ip = network_host_order; ip <= broadcast_host_order; ip++) {
            struct in_addr current_addr;

            if (generated >= max_hosts) {
                break;
            } 
        
            current_addr.s_addr = htonl(ip);

            if (inet_ntop(AF_INET, &current_addr, hosts[generated],MAX_IP_STR_LEN) == NULL){
                return -1;
            }

            generated++;
        }

        return generated;
    }

    for (uint32_t ip = network_host_order + 1; ip < broadcast_host_order; ip++) {
        struct in_addr current_addr;

        if (generated >= max_hosts) {
            break;
        } 
        
        current_addr.s_addr = htonl(ip);

        if (inet_ntop(AF_INET, &current_addr, hosts[generated],MAX_IP_STR_LEN) == NULL){
            return -1;
        }

        generated++;
    }
    return generated;
}

int generate_ipv6_hosts(const parsed_subnet_t *subnet, char hosts[][MAX_IP_STR_LEN], int max_hosts) {
    struct in6_addr base_addr;
    int host_bits;
    long long total_hosts;

    if (subnet == NULL || hosts == NULL || max_hosts <= 0) {
        return -1;
    }

    if (subnet->form_version != 6) {
        return -1;
    }

    if (inet_pton(AF_INET6, subnet->ip, &base_addr) != 1) {
        return -1;
    }

    host_bits = 128 - subnet->prefix;

    if (host_bits < 0) {
        return -1;
    }

    if (host_bits > 16) {
        return -1;
    }

    total_hosts = 1LL << host_bits;

    if (total_hosts > MAX_IPV6_HOSTS) {
        return -1;
    }

    if (total_hosts > max_hosts) {
        total_hosts = max_hosts;
    }

    for (int index = 0; index < total_hosts; index++) {
        struct in6_addr current_addr = base_addr;

        current_addr.s6_addr[14] += (index >> 8) & 0xFF;
        current_addr.s6_addr[15] += index & 0xFF;

        if (current_addr.s6_addr[15] < (index & 0xFF)) {
            current_addr.s6_addr[14] ++;
        }

        if (inet_ntop(AF_INET6, &current_addr, hosts[index], MAX_IP_STR_LEN) == NULL) {
            return -1;
        }
    }
    return (int)total_hosts;
}

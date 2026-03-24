#ifndef SUBNET_H
#define SUBNET_H

#define MAX_IP_STR_LEN 128

typedef struct {
    int form_version;
    char ip[MAX_IP_STR_LEN];
    int prefix;
} parsed_subnet_t;


int detect_ip_version(const char *ip_str);
int split_subnet(const char *subnet_str, parsed_subnet_t *result);
int normalize_subnet(parsed_subnet_t *subnet);
long long count_hosts(const parsed_subnet_t *subnet);
int generate_ipv4_hosts(const parsed_subnet_t *subnet, char hosts[][MAX_IP_STR_LEN], int max_hosts);

#endif
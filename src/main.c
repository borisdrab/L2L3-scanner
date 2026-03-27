#include <stdio.h>
#include <string.h>

#include <ifaddrs.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>

#include "args.h"
#include "interface.h"
#include "subnet.h"
#include "scan_arp.h"
#include "scan_result.h"
#include "scan_icm4.h"
#include "scan_ndp.h"

void print_help(void) {
    printf("Usage:\n");
    printf("./ipk-L2L3-scan -i INTERFACE [-s SUBNET] [-w TIMEOUT] [-h | --help]\n");
    printf("./ipk-L2L3-scan -i\n");

    printf("./ipk-L2L3-scan -h\n");
    printf("./ipk-L2L3-scan --help\n");
}

void print_interfaces(void){
    struct ifaddrs *ifaddr, *ifa;

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) {
            continue;
        }

        int family = ifa->ifa_addr->sa_family;
        if (family == AF_INET) {                //TODO add ipv6
            printf("%s\n", ifa->ifa_name);
        }
    }

    freeifaddrs(ifaddr);
}

int main (int argc, char *argv[]){
    program_args_t args = {0};

    if (parse_args(argc, argv, &args) != 0) {
        return 1;
    }

    if (args.show_help) {
        print_help();
        return 0;
    }

    if (args.list_interfaces) {
        print_interfaces();
        return 0;
    }

    interface_info_t iface;

    if (get_interface_info(args.interface, &iface) != 0) {
        fprintf(stderr, "Erorr: failed to get interface info\n");
        return 1;
    }

    printf("IP: %s\n", iface.ip);

    printf(
        "MAC: %02x-%02x-%02x-%02x-%02x-%02x\n",
        iface.mac_addr[0],
        iface.mac_addr[1],
        iface.mac_addr[2],
        iface.mac_addr[3],
        iface.mac_addr[4],
        iface.mac_addr[5]
    );

    printf("Scanning ranges:\n");

    for (int index = 0; index < args.subnet_count; index++) {
        parsed_subnet_t subnet;
        long long host_count;

        if (!split_subnet(args.subnets[index], &subnet)) {
            fprintf(stderr, "Error: invalid subnet '%s'\n", args.subnets[index]);
            return 1;
        }

        if (!normalize_subnet(&subnet)) {
            fprintf(stderr, "Error: failed to normalize subnet '%s'\n", args.subnets[index]);
            return 1;
        }

        host_count = count_hosts(&subnet);
        printf("%s/%d %lld\n", subnet.ip, subnet.prefix, host_count);

        if (subnet.form_version == 4) {
            char hosts[1024][MAX_IP_STR_LEN];

            int generated = generate_ipv4_hosts(&subnet, hosts, 1024);

            if (generated < 0) {
                fprintf(stderr, "Error: failed to generate hosts\n");
                return 1;
            }

            for (int jndex = 0; jndex < generated; jndex++) {
                host_result_t result;

                memset(&result, 0, sizeof(result));
                strcpy(result.ip, hosts[jndex]);

                scan_arp_ipv4(
                    hosts[jndex],
                    args.interface,
                    args.timeout_in_ms,
                    &result
                );

                scan_icmpv4(
                    hosts[jndex],
                    args.timeout_in_ms,
                    &result
                );

                if (result.arpndp_ok) {
                    printf("%s arp OK %s icmp %s\n", result.ip, result.mac, result.icmp_ok ? "OK" : "FAIL");
                } else {
                    printf("%s arp FAIL icmp %s\n", result.ip, result.icmp_ok ? "OK" : "FAIL");
                }
            }
        }
        else if (subnet.form_version == 6) {

            if (host_count < 0 || host_count > MAX_IPV6_HOSTS) {
                fprintf(stderr, "Error: unsupported ipv6 range %s/%d\n", subnet.ip, subnet.prefix);
                continue;
            }

            char (*hosts)[MAX_IP_STR_LEN] = malloc((size_t)host_count * sizeof(*hosts));
            if (hosts == NULL) {
                fprintf(stderr, "Error: failed to alloc memory for hosts\n");
                return 1;
            }

            int generated = generate_ipv6_hosts(&subnet, hosts, (int)host_count);

            if (generated < 0) {
                fprintf(stderr, "Error: failed to generate hosts\n");
                free(hosts);
                continue;
            }

            for (int jndex = 0; jndex < generated; jndex++) {

                host_result_t result;

                memset(&result, 0, sizeof(result));
                strcpy(result.ip, hosts[jndex]);

                scan_ndp_ipv6(
                    hosts[jndex],
                    args.interface,
                    args.timeout_in_ms,
                    &result
                );

                if (result.arpndp_ok) {
                    printf("%s ndp OK %s\n", result.ip, result.mac);
                } else {
                    printf("%s ndp FAIL\n", result.ip);
                }
            }
            free(hosts);
        }
    }
    return 0;
}

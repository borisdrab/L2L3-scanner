#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <ifaddrs.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <unistd.h>

#include <signal.h> // include needed for signal termination

#include "args.h"
#include "interface.h"
#include "subnet.h"
#include "scan_arp.h"
#include "scan_result.h"
#include "scan_icm4.h"
#include "scan_icm6.h"
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
    char printed[128][IF_NAMESIZE];
    int printed_count = 0;

    if (getifaddrs(&ifaddr) == -1) {
        return;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        int already_printed = 0;

        if (ifa->ifa_addr == NULL) {
            continue;
        }

        if (ifa->ifa_addr->sa_family != AF_INET) {
            continue;
        }

        for (int i = 0; i < printed_count; i++) {
            if (strcmp(printed[i], ifa->ifa_name) == 0) {
                already_printed = 1;
                break;
            }
        }

        if (already_printed) {
            continue;
        }

        printf("%s\n", ifa->ifa_name);

        strncpy(printed[printed_count], ifa->ifa_name, IF_NAMESIZE - 1);
        printed[printed_count][IF_NAMESIZE - 1] = '\0';
        printed_count++;

    }

    freeifaddrs(ifaddr);
}

volatile sig_atomic_t stop_requested = 0;           //flag for the signal

void handle_signal(int stop_sign) {
    (void)stop_sign;
    stop_requested = 1;
}

int main (int argc, char *argv[]){
    program_args_t args = {0};
    interface_info_t iface;

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

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

    if (get_interface_info(args.interface, &iface) != 0) {
        fprintf(stderr, "Error: failed to get interface info\n");
        return 1;
    }

    for (int i = 0; i < args.subnet_count; i++) {               // for correct formatting
        parsed_subnet_t subnet;

        if (stop_requested) {
            fprintf(stderr, "Interrupted by user\n");
            break;
        }

        if (!split_subnet(args.subnets[i], &subnet)) {
            fprintf(stderr, "Error: invalid subnet '%s'\n", args.subnets[i]);
            return 1;
        }

        if (!normalize_subnet(&subnet)) {
            fprintf(stderr, "Error: failed to normalize subnet '%s'\n", args.subnets[i]);
            return 1;
        }
    }

    printf("Scanning ranges:\n");

    for (int index = 0; index < args.subnet_count; index++) {
        parsed_subnet_t subnet;
        long long host_count;

        if (stop_requested) {
            fprintf(stderr, "Interrupted by user\n");
            break;
        }

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
    }

    printf("\n");

    for (int index = 0; index < args.subnet_count; index++) {
        parsed_subnet_t subnet;
        long long host_count;

        if (stop_requested) {                               // repetetively used for correct format
            fprintf(stderr, "Interrupted by user\n");
            break;
        }

        if (!split_subnet(args.subnets[index], &subnet)) {                          
            fprintf(stderr, "Error: invalid subnet '%s'\n", args.subnets[index]);
            return 1;
        }

        if (!normalize_subnet(&subnet)) {
            fprintf(stderr, "Error: failed to normalize subnet '%s'\n", args.subnets[index]);
            return 1;
        }

        host_count = count_hosts(&subnet);

        if (subnet.form_version == 4) {
            char (*hosts)[MAX_IP_STR_LEN] = malloc((size_t)host_count * sizeof(*hosts));

            if (hosts == NULL){
                fprintf(stderr, "Error: failed to alloc memory for hosts\n");
                return 1;
            }

            int generated = generate_ipv4_hosts(&subnet, hosts, (int)host_count);

            if (generated < 0) {
                fprintf(stderr, "Error: failed to generate hosts\n");
                free(hosts);
                return 1;
            }

            // new functionality for reimplementation
            host_result_t results[generated];
            memset(results, 0, sizeof(results));

            for (int jndex = 0; jndex < generated; jndex++) {
                strncpy(results[jndex].ip, hosts[jndex], sizeof(results[jndex].ip) - 1);
                results[jndex].ip[sizeof(results[jndex].ip) - 1] = '\0';
            }

            interface_info_t interface_info;
            int interface_index;
            int arp_fd = open_arp_socket(args.interface, args.timeout_in_ms, &interface_info, &interface_index);
            int icmpv4_fd = open_icmpv4_socket(args.timeout_in_ms);

            if (arp_fd < 0 || icmpv4_fd < 0) {  // either socket didnt open 
                if (arp_fd >= 0) {
                    close(arp_fd);
                }
                if (icmpv4_fd >= 0){
                    close(icmpv4_fd);
                }
                free(hosts);
                fprintf(stderr, "Error: failed to open scan socket\n");
                return 1;
            }

            for (int kndex = 0; kndex < generated; kndex++) {
                if (stop_requested) {
                    fprintf(stderr, "Interrupted by user\n");
                    break;
                }

                send_arp_request(arp_fd, hosts[kndex], &interface_info, interface_index);
                send_icmpv4_request(icmpv4_fd, hosts[kndex]);
            }
            
            receive_arp_replies(arp_fd, results, generated, &interface_info, interface_info.ip, args.timeout_in_ms);
            receive_icmpv4_replies(icmpv4_fd, results, generated, args.timeout_in_ms);

            close(arp_fd);
            close(icmpv4_fd);

            for (int lndex = 0; lndex < generated; lndex++){
                if (results[lndex].arpndp_ok) {
                    printf("%s arp OK (%s), icmpv4 %s\n",
                    results[lndex].ip,
                    results[lndex].mac,
                    results[lndex].icmp_ok ? "OK" : "FAIL");
                } else {
                    printf("%s arp FAIL, icmpv4 %s\n",
                    results[lndex].ip,
                    results[lndex].icmp_ok ? "OK" : "FAIL");
                }

            }
            free(hosts);
        }

        else if (subnet.form_version == 6) {

            if (stop_requested) {
                fprintf(stderr, "Interrupted by user\n");
                break;
            }

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

                if (stop_requested) {
                    fprintf(stderr, "Interrupted by user\n");
                    break;
                }

                memset(&result, 0, sizeof(result));

                scan_ndp_ipv6(
                    hosts[jndex],
                    args.interface,
                    args.timeout_in_ms,
                    &result
                );

                scan_icmpv6(
                    hosts[jndex],
                    args.timeout_in_ms,
                    &result
                );

                if (result.arpndp_ok) {
                    printf("%s ndp OK (%s), icmpv6 %s\n",
                    result.ip,
                    result.mac,
                    result.icmp_ok ? "OK" : "FAIL");
                } else {
                    printf("%s ndp FAIL, icmpv6 %s\n",
                    result.ip,
                    result.icmp_ok ? "OK" : "FAIL");
                }
            }
            free(hosts);
        }
    }
    return 0;
}

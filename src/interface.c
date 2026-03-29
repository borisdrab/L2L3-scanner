#define _DEFAULT_SOURCE

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>

#include "interface.h"

int get_interface_info(const char *ifname, interface_info_t *info) {
    struct ifaddrs *interfaces = NULL;
    struct ifaddrs *current_interface = NULL;
    int socket_file_descriptor;
    struct ifreq interface_request;

    if (ifname == NULL || info == NULL) {
        return -1;
    }

    memset(info, 0, sizeof(*info));
    strncpy(info->name, ifname, sizeof(info->name) - 1);
    info->name[sizeof(info->name) - 1] = '\0';

    if (getifaddrs(&interfaces) == -1) {
        return -1;
    }

    for (current_interface = interfaces; current_interface != NULL; current_interface = current_interface->ifa_next) {
        if (current_interface->ifa_addr == NULL) {
            continue;
        }

        if (strcmp(current_interface->ifa_name, ifname) != 0) {
            continue;
        }

        if (current_interface->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *ipv4_addr = (struct sockaddr_in *)current_interface->ifa_addr;
            char candidate_ip[INET_ADDRSTRLEN];

            if (inet_ntop(AF_INET, &ipv4_addr->sin_addr, candidate_ip, sizeof(candidate_ip)) == NULL) {
                freeifaddrs(interfaces);
                return -1;
            }

            // prefer non-link-local ipv4, 169.254.x.x only as fallback 
            if (strncmp(candidate_ip, "169.254.", 8) != 0) {
                strncpy(info->ip, candidate_ip, sizeof(info->ip) - 1);
                info->ip[sizeof(info->ip) - 1] = '\0';
            }

            else if (info->ip[0] == '\0') {
                strncpy(info->ip, candidate_ip, sizeof(info->ip) - 1);
                info->ip[sizeof(info->ip) - 1] = '\0';
            }
        }
        else if (current_interface->ifa_addr->sa_family == AF_INET6) {
            struct sockaddr_in6 *ipv6_addr = (struct sockaddr_in6 *)current_interface->ifa_addr;

            if (IN6_IS_ADDR_LOOPBACK(&ipv6_addr->sin6_addr)) {
                continue;
            }

            if (IN6_IS_ADDR_LINKLOCAL(&ipv6_addr->sin6_addr)) {
                if (inet_ntop(AF_INET6, &ipv6_addr->sin6_addr, info->ipv6, sizeof(info->ipv6)) == NULL) {
                    freeifaddrs(interfaces);
                    return -1;
                }

                break;
            }

            if (info->ipv6[0] == '\0') {
                if (inet_ntop(AF_INET6, &ipv6_addr->sin6_addr, info->ipv6, sizeof(info->ipv6)) == NULL) {
                    freeifaddrs(interfaces);
                    return -1;
                }
            }
        }
    }

    freeifaddrs(interfaces);

    socket_file_descriptor = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_file_descriptor < 0) {
        return -1;
    }

    memset(&interface_request, 0, sizeof(interface_request));
    strncpy(interface_request.ifr_name, ifname, IFNAMSIZ - 1);
    interface_request.ifr_name[IFNAMSIZ - 1] = '\0';

    if (ioctl(socket_file_descriptor, SIOCGIFHWADDR, &interface_request) < 0) {
        close(socket_file_descriptor);
        return -1;
    }

    memcpy(info->mac_addr, interface_request.ifr_hwaddr.sa_data, 6);

    close(socket_file_descriptor);
    return 0;
}
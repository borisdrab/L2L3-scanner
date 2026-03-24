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
    struct ifaddrs *interf = NULL;
    struct ifaddrs *c_interfac = NULL;
    int sockfd;
    struct ifreq interfac_r;

    if (ifname == NULL || info == NULL) {
        return -1;
    }

    memset(info, 0, sizeof(*info));
    strncpy(info->name, ifname, sizeof(info->name) - 1);
    info->name[sizeof(info->name) - 1] = '\0';

    if (getifaddrs(&interf) == -1) {
        return -1;
    }

    for (c_interfac = interf; c_interfac != NULL; c_interfac = c_interfac->ifa_next) {
        if (c_interfac->ifa_addr == NULL) {
            continue;
        }

        if (strcmp(c_interfac->ifa_name, ifname) != 0) {
            continue;
        }

        if (c_interfac->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *ipv4_addr = (struct sockaddr_in *)c_interfac->ifa_addr;

            if (inet_ntop(AF_INET, &ipv4_addr->sin_addr, info->ip, sizeof(info->ip)) == NULL) {
                freeifaddrs(interf);
                return -1;
            }
        }
        else if (c_interfac->ifa_addr->sa_family == AF_INET6) {
            struct sockaddr_in6 *ipv6_addr = (struct sockaddr_in6 *)c_interfac->ifa_addr;

            if (IN6_IS_ADDR_LOOPBACK(&ipv6_addr->sin6_addr)) {
                continue;
            }

            if (info->ipv6[0] == '\0') {
                if (inet_ntop(AF_INET6, &ipv6_addr->sin6_addr, info->ipv6, sizeof(info->ipv6)) == NULL) {
                    freeifaddrs(interf);
                    return -1;
                }
            }
        }
    }

    freeifaddrs(interf);

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return -1;
    }

    memset(&interfac_r, 0, sizeof(interfac_r));
    strncpy(interfac_r.ifr_name, ifname, IFNAMSIZ - 1);
    interfac_r.ifr_name[IFNAMSIZ - 1] = '\0';

    if (ioctl(sockfd, SIOCGIFHWADDR, &interfac_r) < 0) {
        close(sockfd);
        return -1;
    }

    memcpy(info->mac_addr, interfac_r.ifr_hwaddr.sa_data, 6);

    close(sockfd);
    return 0;
}
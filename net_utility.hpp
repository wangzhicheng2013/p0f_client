#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <net/if.h>
#include <netdb.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <linux/ethtool.h>
#include <ctype.h>
#include <string>
#include <vector>
#include "single_instance.hpp"
struct  netcard_info {
    std::string name;
    std::string ip;
};
enum class NETCARD_STATUS {
    UP,
    DOWN
};
class net_utility {
public:
    void get_mac_str(unsigned long mac_val, std::string &mac_str) {
        static const char *convert_format = "%02x:%02x:%02x:%02x:%02x:%02x";
        char buf[24] = "";
        snprintf(buf, sizeof(buf), convert_format, (mac_val >> 40) & 0xff,
                                                           (mac_val >> 32) & 0xff,
                                                           (mac_val >> 24) & 0xff,
                                                           (mac_val >> 16) & 0xff,
                                                           (mac_val >> 8) & 0xff,
                                                           mac_val & 0xff);
        mac_str = buf;
    }
    inline void get_ipv4_addr(uint32_t ip, std::string &addr) {
        char buf[64] = "";
        snprintf(buf, sizeof(buf), "%u.%u.%u.%u", ((ip >> 24) & 0xFF), 
                                                      ((ip >> 16) & 0xFF),
                                                      ((ip >> 8) & 0xFF), 
                                                      ((ip >> 0) & 0xFF));
        addr = buf;
    }
    bool get_netcard_info(std::vector<netcard_info>&infos) {
        int sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock_fd < 0) {
            return false;
        }
        infos.clear();
        unsigned char buf[1024] = "";
        struct ifconf ifc = { 0 };
        ifc.ifc_len = sizeof(buf);
        ifc.ifc_buf = (caddr_t)buf;
        if (ioctl(sock_fd, SIOCGIFCONF, &ifc) < 0 ) {
            close(sock_fd);
            return false;
        }
        struct ifreq *ifr = (struct ifreq *)buf;
        int netcard_size = ifc.ifc_len / sizeof(struct ifreq);
        netcard_info info;
        for (int i = 0;i < netcard_size;i++) {
            info.name = ifr->ifr_name;
            info.ip = inet_ntoa(((struct sockaddr_in *)&(ifr->ifr_addr))->sin_addr);
            ++ifr;
            infos.emplace_back(info);
        }
        close(sock_fd);
        return !infos.empty();
    }
    NETCARD_STATUS get_netcard_status(const char *eth_name) {
        int sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock_fd < 0) {
            return NETCARD_STATUS::DOWN;
        }
        struct ifreq ifr = { 0 };
        strncpy(ifr.ifr_name, eth_name, sizeof(ifr.ifr_name) - 1);
        if (ioctl(sock_fd, SIOCGIFFLAGS, &ifr) < 0 ) {
            close(sock_fd);
            return NETCARD_STATUS::DOWN;
        }
        close(sock_fd);
        if (ifr.ifr_flags & IFF_RUNNING) {
            return NETCARD_STATUS::UP;
        }
        return NETCARD_STATUS::DOWN;
    }
    bool netcard_link_detected(const char *eth_name) {
        int sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock_fd < 0) {
            return false;
        }
        struct ethtool_value e_value = { 0 };
        struct ifreq ifr = { 0 };
        e_value.cmd = 0x000000A;
        strncpy(ifr.ifr_name, eth_name, sizeof(ifr.ifr_name) - 1);
        ifr.ifr_data = (caddr_t)(&e_value);
        if (ioctl(sock_fd,  0x8946, &ifr) < 0 ) {       //  SIOCETHTOOL
            close(sock_fd);
            return false;
        }
        close(sock_fd);
        return e_value.data;
    }
    bool parse_addr4(const char *ip_str, uint8_t *ret) {
        if (!ip_str || !ret) {
            return false;
        }
        uint32_t a1 = 0;
        uint32_t a2 = 0;
        uint32_t a3 = 0;
        uint32_t a4 = 0;
        if (sscanf(ip_str, "%u.%u.%u.%u", &a1, &a2, &a3, &a4) != 4) {
            return false;
        }
        if (a1 > 255 || a2 > 255 || a3 > 255 || a4 > 255) {
            return false;
        }
        ret[0] = a1;
        ret[1] = a2;
        ret[2] = a3;
        ret[3] = a4;
        return true;
    }
    bool parse_addr6(const char *ip_str, uint8_t *ret) {
        if (!ip_str || !ret) {
            return false;
        }
        uint32_t seg = 0;
        uint32_t val = 0;
        while (*ip_str) {
            if (8 == seg) {
                return false;
            }
            if (sscanf(ip_str, "%x", &val) != 1 || val > 65535) {
                return false;
            }
            ret[seg * 2] = val >> 8;
            ret[seg * 2 + 1] = val;
            seg++;
            while (isxdigit(*ip_str)) {
                ip_str++;
            }
            if (*ip_str) {
                ip_str++;
            }
        }
        if (seg != 8) {
            return false;
        }
        return true;
    }
};

#define  G_NET_UTILITY single_instance<net_utility>::instance()
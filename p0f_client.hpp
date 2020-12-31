#pragma once
#include <signal.h>
#include <iostream>
#include "types.h"
#include "config.h"
#include "alloc-inl.h"
#include "debug.h"
#include "api.h"
#include "net_utility.hpp"
struct p0f_dev_info {
    void dump_info() {
        std::cout << "os_name = " << os_name << std::endl;
        std::cout << "os_flavor = " << os_flavor << std::endl;
        std::cout << "os_match_quality = " << os_match_quality << std::endl;
        std::cout << "os_match_quality_des = " << os_match_quality_des << std::endl;
        std::cout << "magic = " << magic << std::endl;
        std::cout << "status = " << status << std::endl;
        std::cout << "first_seen = " << first_seen << std::endl;
        std::cout << "last_seen = " << last_seen << std::endl;
        std::cout << "total_conn = " << total_conn << std::endl;
        std::cout << "uptime_min = " << uptime_min << std::endl;
        std::cout << "up_mod_days = " << up_mod_days << std::endl;
        std::cout << "last_nat = " << last_nat << std::endl;
        std::cout << "last_chg = " << last_chg << std::endl;
        printf("bad_sw = %d\n", bad_sw);
        std::cout << "http_name = " << http_name << std::endl;
        std::cout << "http_flavor = " << http_flavor << std::endl;
        std::cout << "link_type = " << link_type << std::endl;
        std::cout << "language = " << language << std::endl;             
    }
    std::string os_name;
    std::string os_flavor;
    uint8_t os_match_quality = 0;
    std::string os_match_quality_des;
    uint32_t magic = 0;                   // Must be P0F_RESP_MAGIC             
    uint32_t status = 0;                  // P0F_STATUS
    uint32_t first_seen = 0;              // First seen (unix time)       
    uint32_t last_seen = 0;               // Last seen (unix time)
    uint32_t total_conn = 0;              // Total connections seen
    uint32_t uptime_min = 0;              // Last uptime (minutes) 
    uint32_t up_mod_days = 0;             // Uptime modulo (days)
    uint32_t last_nat = 0;                // NAT / LB last detected (unix time)
    uint32_t last_chg = 0;                // OS chg last detected (unix time)
    short distance = 0;                   // System distance
    uint8_t bad_sw = 0;                   // Host is lying about U-A / Server
    std::string http_name;                // Name of detected HTTP app
    std::string http_flavor;              // Flavor of detected HTTP app
    std::string link_type;                // Link type
    std::string language;                 // Language          
};
class p0f_client {
public:
    p0f_client() = default;
    virtual ~p0f_client() {
        close_socket();
    }
public:
    bool init() {
        signal(SIGPIPE, SIG_IGN);
        return connect_server();
    }
    inline void close_socket() {
        if (sock_fd_ >= 0) {
            close(sock_fd_);
        }
    }
    inline bool connect_server() {
        close_socket();
        sock_fd_ = socket(PF_UNIX, SOCK_STREAM, 0);
        if (sock_fd_ < 0) {
            return false;
        }
        if (!un_.sun_path[0]) {
            un_.sun_family = AF_UNIX;
            strncpy(un_.sun_path, socket_path_, sizeof(un_.sun_path) - 1);
        }
        if (connect(sock_fd_, (struct sockaddr *)&un_, sizeof(un_)) < 0) {
            std::cerr << "client connect failed for ipc path:" << socket_path_ << std::endl;
            return false;
        }
        return true;
    }
    inline void set_socket_path(const char *path) {
        socket_path_ = path;
    }
    bool get_dev_info(const char *host_ip, p0f_dev_info &info) {
        struct p0f_api_query api_query = { 0 };
        struct p0f_api_response api_response = { 0 };
        if (!G_NET_UTILITY.parse_addr4(host_ip, api_query.addr)) {
            std::cerr << "parse ipv4 for ip:" << host_ip << " failed." << std::endl;
            return false;
        }
        api_query.addr_type = P0F_ADDR_IPV4;
        api_query.magic = P0F_QUERY_MAGIC;
        if (false == interact_with_p0f_server(api_query, api_response)) {
            return false;
        }
        get_response_from_p0f_server(api_response, info);
        return true;
    }
private:
    bool interact_with_p0f_server(const struct p0f_api_query &api_query, struct p0f_api_response &api_response) {
        int len = write(sock_fd_, &api_query, sizeof(struct p0f_api_query));
        if (len < 0) {
            std::cerr << "p0f server disconnect reconnect now." << std::endl;
            if (!connect_server()) {
                return false;
            }
            len = write(sock_fd_, &api_query, sizeof(struct p0f_api_query));
        }
        if (len != sizeof(struct p0f_api_query)) {
            // try to send again
            len = write(sock_fd_, &api_query, sizeof(struct p0f_api_query));
            if (len != sizeof(struct p0f_api_query)) {
                std::cerr << "send request to p0f server failed." << std::endl;
                return false;
            }
        }
        if (read(sock_fd_, &api_response, sizeof(struct p0f_api_response)) != sizeof(struct p0f_api_response)) {
            std::cerr << "recv response from p0f server failed." << std::endl;
            return false;
        }
        if (api_response.magic != P0F_RESP_MAGIC) {
            std::cerr << "invalid response magic:" << api_response.magic << std::endl;
            return false;
        }
        if (P0F_STATUS_BADQUERY == api_response.status) {
            std::cerr << "P0f did not understand the query" << std::endl;
            return false;
        }
        if (P0F_STATUS_NOMATCH == api_response.status) {
            std::cerr << "no matching host ip in p0f cache" << std::endl;
            return false;
        }
        return true;
    }
    void get_response_from_p0f_server(const struct p0f_api_response &api_response, p0f_dev_info &dev_info) {
        dev_info.first_seen = api_response.first_seen;
        dev_info.last_seen = api_response.last_seen;
        dev_info.total_conn = api_response.total_conn;
        if (api_response.os_name[0]) {
            dev_info.os_name = (char *)api_response.os_name;
            dev_info.os_flavor = (char *)api_response.os_flavor;
            dev_info.os_match_quality = api_response.os_match_q;
            if (api_response.os_match_q & P0F_MATCH_GENERIC) {
                dev_info.os_match_quality_des = "generic";
            }
            else if (api_response.os_match_q & P0F_MATCH_FUZZY) {
                dev_info.os_match_quality_des = "fuzzy";
            }
            else {
                dev_info.os_match_quality_des = "unknown";
            }
        }
        if (api_response.http_name[0]) {
            dev_info.http_name = (char *)api_response.http_name;
        }
        if (api_response.http_flavor[0]) {
            dev_info.http_flavor = (char *)api_response.http_flavor;
        }
        dev_info.bad_sw = api_response.bad_sw;
        if (api_response.link_type[0]) {
            dev_info.link_type = (char *)api_response.link_type;
        }
        if (api_response.language[0]) {
            dev_info.language = (char *)api_response.language;
        }
        dev_info.distance = api_response.distance;
        dev_info.last_nat = api_response.last_nat;
        dev_info.last_chg = api_response.last_chg;
        dev_info.uptime_min = api_response.uptime_min;
        dev_info.up_mod_days = api_response.up_mod_days;
    }
private:
    int sock_fd_ = -1;
    struct sockaddr_un un_ = { 0 };
private:
    const char *socket_path_ = "./ipc.socket";
    static const int BUFF_SIZE = 1024;
};
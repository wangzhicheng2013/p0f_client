#include "p0f_client.hpp"
// server run as:./p0f -i ens192 -p -s /home/wangbin/test/xyz.socket
int main() {
    const char *ip_str = "10.50.21.129";
    p0f_client client;
    client.set_socket_path("/home/wangbin/test/xyz.socket");
    if (!client.init()) {
        return -1;
    }
    int LOOP = 100000;
    // 3.571s
    for (int i = 0;i < LOOP;i++) {  
        p0f_dev_info info;
        client.get_dev_info(ip_str, info);
        //info.dump_info();
    }
    
    return 0;
}
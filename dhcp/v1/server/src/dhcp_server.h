#ifndef DHCP_SERVER_H
#define DHCP_SERVER_H

#include <string>
#include <vector>
#include <map>
#include <chrono>
#include <netinet/in.h> 
#include "dhcp_common.h" 
#include "common_config_parser.h" 

struct LeaseInfo {
    uint32_t ip_address;         
    std::string mac_address_str; 
    std::chrono::steady_clock::time_point expiry_time; 
    uint32_t xid_associated;
};

struct ServerConfig {
    std::string server_ip_str;
    std::string subnet_mask_str;
    std::string router_str;
    std::string dns_server_str;
    std::string ip_pool_start_str;
    std::string ip_pool_end_str;
    uint32_t lease_time_sec;
    std::string bind_interface; 

    uint32_t server_ip_net;    
    uint32_t subnet_mask_net;  
    uint32_t router_ip_net;    
    uint32_t dns_ip_net;       
    uint32_t ip_pool_start_host;
    uint32_t ip_pool_end_host; 

    ServerConfig();
    bool load(const std::string& config_filename);
};


class DHCPServer {
public:
    DHCPServer();
    ~DHCPServer();

    bool initialize(const std::string& config_filename = "server.conf");
    void run();

private:
    int sock_fd = -1;
    ServerConfig config;

    std::map<std::string, LeaseInfo> leased_ips;
    std::map<uint32_t, std::pair<std::string, uint32_t>> offered_ips;
    std::map<std::string, uint32_t> last_discover_xids;


    void log(const std::string& message);
    std::string get_interface_ip(const std::string& interface_name); 

    size_t add_option(uint8_t* options_ptr, DhcpOption option_code, uint8_t len, const void* data);
    size_t add_option_byte(uint8_t* options_ptr, DhcpOption option_code, uint8_t value);
    size_t add_option_dword(uint8_t* options_ptr, DhcpOption option_code, uint32_t value_host_order); 
    const uint8_t* find_option(const dhcp_packet* packet, size_t packet_len, DhcpOption option_code, uint8_t& len);
    DhcpMessageType get_message_type(const dhcp_packet* packet, size_t packet_len);

    void cleanup_expired_leases_and_offers();
    uint32_t find_available_ip(const std::string& client_mac_str, uint32_t client_xid);
    bool is_ip_leased_or_offered(uint32_t ip_net_order);

    void process_packet(const uint8_t* buffer, size_t len, const struct sockaddr_in& client_addr);
    void handle_discover(const dhcp_packet* request, size_t request_len, const struct sockaddr_in& client_addr);
    void handle_request(const dhcp_packet* request, size_t request_len, const struct sockaddr_in& client_addr);
    void handle_decline(const dhcp_packet* request, size_t request_len);
    void handle_release(const dhcp_packet* request, size_t request_len);
    // void handle_inform(const dhcp_packet* request, size_t request_len, const struct sockaddr_in& client_addr);

    void send_offer(const dhcp_packet* discover_request, uint32_t offered_ip_net);
    void send_ack(const dhcp_packet* client_request, uint32_t assigned_ip_net);
    void send_nak(const dhcp_packet* client_request, const struct sockaddr_in& client_addr);
};

#endif // DHCP_SERVER_H
#ifndef DHCP_CLIENT_H
#define DHCP_CLIENT_H

#include <string>
#include <vector>
#include <chrono>
#include <random>
#include "dhcp_common.h" 
#include "common_config_parser.h" 

enum class ReceiveResult {
    SUCCESS,
    TIMEOUT,
    PACKET_IGNORED,
    ERROR
};

enum class ClientState { 
    INIT,
    SELECTING,
    REQUESTING,
    BOUND,
    RENEWING,
    REBINDING
};

class DHCPClient {
public:
    DHCPClient();
    ~DHCPClient();

    bool load_config_and_init_mac(const std::string& config_filename);
    bool initialize_socket();
    void run();

private:
    int sock_fd = -1;
    ClientState state = ClientState::INIT;

    uint8_t client_mac[6];
    uint32_t transaction_id = 0;
    std::mt19937 rng;

    uint32_t leased_ip = 0;
    uint32_t server_id = 0; 
    uint32_t lease_time_sec = 0;
    std::chrono::steady_clock::time_point lease_obtained_time;
    uint32_t subnet_mask = 0;
    uint32_t router_ip = 0;
    uint32_t dns_ip = 0;

    std::string config_client_mac_str;
    std::string config_dhcp_server_ip_str; 
    int config_response_timeout_sec = 2;   
    int config_max_discover_attempts = 5;  

    void log(const std::string& message);

    size_t add_option(uint8_t* options_ptr, DhcpOption option_code, uint8_t len, const void* data);
    size_t add_option_byte(uint8_t* options_ptr, DhcpOption option_code, uint8_t value);
    size_t add_option_dword(uint8_t* options_ptr, DhcpOption option_code, uint32_t value_net_order);
    const uint8_t* find_option(const dhcp_packet* packet, size_t packet_len, DhcpOption option_code, uint8_t& len);
    DhcpMessageType get_message_type(const dhcp_packet* packet, size_t packet_len);

    bool send_dhcp_message(dhcp_packet& packet, size_t packet_len, const std::string& dest_ip, int dest_port);
    bool send_discover();
    bool send_request(uint32_t requested_ip_addr, uint32_t server_ip_addr);
    bool send_renew_request(); 

    ReceiveResult receive_and_process(int timeout_sec);
};

#endif // DHCP_CLIENT_H
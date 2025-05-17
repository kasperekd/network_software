#include "dhcp_client.h"

#include <net/if.h>
#include <netinet/in.h>  
#include <sys/ioctl.h>   
#include <sys/socket.h>  
#include <unistd.h>      

#include <iostream> 
#include <thread>

DHCPClient::DHCPClient() {
    std::random_device rd;
    rng.seed(rd());
}

DHCPClient::~DHCPClient() {
    if (sock_fd >= 0) {
        close(sock_fd);
        log("Socket closed for MAC: " + mac_to_string(client_mac));
    }
}

void DHCPClient::log(const std::string& message) {
    if (client_mac[0] != 0 || client_mac[1] != 0 || client_mac[2] != 0) {
        std::cout << "[CLIENT MAC: " << mac_to_string(client_mac) << "] "
                  << message << std::endl;
    } else {
        std::cout << "[CLIENT] " << message << std::endl;
    }
}

bool DHCPClient::load_config_and_init_mac(const std::string& config_filename) {
    log("Loading client configuration from " + config_filename + "...");
    auto config_map = parse_config_file(config_filename);

    std::string default_mac_fallback =
        "00:00:00:00:00:00";  // дефолт
    int default_timeout = 2;
    int default_max_attempts = 5;

    if (config_map.empty() && !std::ifstream(config_filename).good()) {
        std::cerr << "[CLIENT_CONFIG] WARNING: Config file '" << config_filename
                  << "' not found or empty. MAC must be valid." << std::endl;
        config_client_mac_str =
            "";  // FIXME: Приведет к ошибке ниже, если MAC обязателен
    } else {
        config_client_mac_str = get_config_string(config_map, "client_mac", "");
    }
    // Остальные параметры конфига
    config_dhcp_server_ip_str =
        get_config_string(config_map, "dhcp_server_ip", "");
    config_response_timeout_sec =
        get_config_int(config_map, "response_timeout_sec", default_timeout);
    config_max_discover_attempts = get_config_int(
        config_map, "max_discover_attempts", default_max_attempts);

    if (config_client_mac_str.empty()) {
        std::cerr << "[CLIENT_CONFIG] CRITICAL: 'client_mac' not specified or "
                     "empty in "
                  << config_filename << ". Cannot proceed." << std::endl;
        return false;
    }

    if (!string_to_mac(config_client_mac_str, this->client_mac)) {
        std::cerr << "[CLIENT_CONFIG] CRITICAL: Invalid MAC address format in "
                     "config: "
                  << config_client_mac_str << ". Cannot proceed." << std::endl;
        return false;
    }
    log("Initialized Client MAC Address: " + mac_to_string(this->client_mac) +
        " (from " + config_filename + ")");

    std::cout << "[CLIENT_CONFIG] Configured DHCP Server IP (direct): "
              << (config_dhcp_server_ip_str.empty() ? "Broadcast"
                                                    : config_dhcp_server_ip_str)
              << std::endl;
    std::cout << "[CLIENT_CONFIG] Response Timeout: "
              << config_response_timeout_sec << "s" << std::endl;
    std::cout << "[CLIENT_CONFIG] Max Discover Attempts: "
              << config_max_discover_attempts << std::endl;
    return true;
}

bool DHCPClient::initialize_socket() {
    log("Initializing DHCP Client socket...");
    sock_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock_fd < 0) {
        perror("socket creation failed");
        return false;
    }
    log("Socket created.");

    int broadcast_enable = 1;
    if (setsockopt(sock_fd, SOL_SOCKET, SO_BROADCAST, &broadcast_enable,
                   sizeof(broadcast_enable)) < 0) {
        perror("setsockopt SO_BROADCAST failed");
        close(sock_fd);
        sock_fd = -1;
        return false;
    }
    log("SO_BROADCAST enabled.");

    int reuse_addr_enable = 1;
    if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &reuse_addr_enable,
                   sizeof(reuse_addr_enable)) < 0) {
        perror("setsockopt SO_REUSEADDR failed");
        close(sock_fd);
        sock_fd = -1;
        return false;
    }
    log("SO_REUSEADDR enabled.");

    struct sockaddr_in client_addr_bind;
    memset(&client_addr_bind, 0, sizeof(client_addr_bind));
    client_addr_bind.sin_family = AF_INET;
    client_addr_bind.sin_port = htons(DHCP_CLIENT_PORT);
    client_addr_bind.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(sock_fd, (struct sockaddr*)&client_addr_bind,
             sizeof(client_addr_bind)) < 0) {
        perror("bind failed");
        close(sock_fd);
        sock_fd = -1;
        return false;
    }
    log("Bound to 0.0.0.0:" + std::to_string(DHCP_CLIENT_PORT));
    return true;
}

size_t DHCPClient::add_option(uint8_t* options_ptr, DhcpOption option_code,
                              uint8_t len, const void* data) {
    *options_ptr++ = static_cast<uint8_t>(option_code);
    *options_ptr++ = len;
    if (data && len > 0) { 
        memcpy(options_ptr, data, len);
    }
    return len + 2;
}

size_t DHCPClient::add_option_byte(uint8_t* options_ptr, DhcpOption option_code,
                                   uint8_t value) {
    return add_option(options_ptr, option_code, 1, &value);
}

size_t DHCPClient::add_option_dword(uint8_t* options_ptr,
                                    DhcpOption option_code,
                                    uint32_t value_net_order) {
    return add_option(options_ptr, option_code, 4, &value_net_order);
}

const uint8_t* DHCPClient::find_option(const dhcp_packet* packet,
                                       size_t packet_len,
                                       DhcpOption option_code, uint8_t& len) {
    len = 0;
    if (packet_len <
        offsetof(dhcp_packet, options) + sizeof(DHCP_MAGIC_COOKIE) + 1) {
        return nullptr;
    }
    // Magic cookie уже проверен в receive_and_process до вызова
    // get_message_type

    const uint8_t* options_ptr = packet->options;
    const uint8_t* end_ptr =
        reinterpret_cast<const uint8_t*>(packet) +
        packet_len;
    while (options_ptr < end_ptr &&
           *options_ptr != static_cast<uint8_t>(DhcpOption::End)) {
        uint8_t current_code_val = *options_ptr;
        if (current_code_val == static_cast<uint8_t>(DhcpOption::Pad)) {
            options_ptr++;
            continue;
        }
        if (options_ptr + 1 >= end_ptr)
            return nullptr;  // Не хватает байта для длины

        options_ptr++;  
        uint8_t current_len =
            *options_ptr++; 

        if (options_ptr + current_len > end_ptr) return nullptr;

        if (current_code_val == static_cast<uint8_t>(option_code)) {
            len = current_len;
            return options_ptr;
        }
        options_ptr += current_len;
    }
    return nullptr;
}

DhcpMessageType DHCPClient::get_message_type(const dhcp_packet* packet,
                                             size_t packet_len) {
    uint8_t len = 0;
    const uint8_t* data =
        find_option(packet, packet_len, DhcpOption::MessageType, len);
    if (data && len == 1) {
        return static_cast<DhcpMessageType>(*data);
    }
    return static_cast<DhcpMessageType>(0);  // Invalid
}

bool DHCPClient::send_discover() {
    log("Sending DHCPDISCOVER...");
    transaction_id = std::uniform_int_distribution<uint32_t>{}(rng);
    log("Using XID: " + std::to_string(transaction_id));

    dhcp_packet discover_pkt;
    memset(&discover_pkt, 0, sizeof(discover_pkt));
    discover_pkt.op = 1;     // BOOTREQUEST
    discover_pkt.htype = 1;  // Ethernet
    discover_pkt.hlen = 6;
    discover_pkt.xid = htonl(transaction_id);
    discover_pkt.flags = htons(BOOTP_BROADCAST);
    memcpy(discover_pkt.chaddr, client_mac, sizeof(client_mac));
    memcpy(discover_pkt.magic_cookie, DHCP_MAGIC_COOKIE,
           sizeof(DHCP_MAGIC_COOKIE));

    uint8_t* options_ptr = discover_pkt.options;
    options_ptr +=
        add_option_byte(options_ptr, DhcpOption::MessageType,
                        static_cast<uint8_t>(DhcpMessageType::DHCPDISCOVER));
    *options_ptr++ = static_cast<uint8_t>(DhcpOption::End);

    size_t packet_len = reinterpret_cast<uint8_t*>(options_ptr) -
                        reinterpret_cast<uint8_t*>(&discover_pkt);
    return send_dhcp_message(discover_pkt, packet_len, "255.255.255.255",
                             DHCP_SERVER_PORT);
}

bool DHCPClient::send_dhcp_message(dhcp_packet& packet, size_t packet_len,
                                   const std::string& dest_ip, int dest_port) {
    sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(dest_port);
    if (inet_pton(AF_INET, dest_ip.c_str(), &dest_addr.sin_addr) <= 0) {
        log("Invalid destination IP address: " + dest_ip);
        return false;
    }

    log("Sending packet (" + std::to_string(packet_len) + " bytes) to " +
        dest_ip + ":" + std::to_string(dest_port));
    ssize_t sent_bytes =
        sendto(sock_fd, &packet, packet_len, 0, (struct sockaddr*)&dest_addr,
               sizeof(dest_addr));

    if (sent_bytes < 0) {
        perror("sendto failed");
        return false;
    }
    if (static_cast<size_t>(sent_bytes) != packet_len) {
        log("Warning: sendto sent " + std::to_string(sent_bytes) +
            " bytes, expected " + std::to_string(packet_len));
    }

    return true;
}

bool DHCPClient::send_request(uint32_t requested_ip_addr,
                              uint32_t server_ip_addr) {
    log("Sending DHCPREQUEST for IP " + ip_to_string(requested_ip_addr) +
        " to Server " + ip_to_string(server_ip_addr));

    dhcp_packet request_pkt;
    memset(&request_pkt, 0, sizeof(request_pkt));
    request_pkt.op = 1;  // BOOTREQUEST
    request_pkt.htype = 1;
    request_pkt.hlen = 6;
    request_pkt.xid = htonl(transaction_id);
    request_pkt.flags = htons(BOOTP_BROADCAST);
    memcpy(request_pkt.chaddr, client_mac, sizeof(client_mac));
    memcpy(request_pkt.magic_cookie, DHCP_MAGIC_COOKIE,
           sizeof(DHCP_MAGIC_COOKIE));

    // Add options
    uint8_t* options_ptr = request_pkt.options;
    options_ptr += add_option_byte(options_ptr, DhcpOption::MessageType,
                                   DhcpMessageType::DHCPREQUEST);
    options_ptr +=
        add_option_dword(options_ptr, DhcpOption::RequestedIP,
                         requested_ip_addr);  // Already network order
    options_ptr += add_option_dword(options_ptr, DhcpOption::ServerIdentifier,
                                    server_ip_addr);  // Already network order
    *options_ptr++ = static_cast<uint8_t>(DhcpOption::End);

    size_t packet_len = sizeof(dhcp_packet) - sizeof(request_pkt.options) +
                        (options_ptr - request_pkt.options);

    // Request is broadcast
    return send_dhcp_message(request_pkt, packet_len, "255.255.255.255",
                             DHCP_SERVER_PORT);
}

bool DHCPClient::send_renew_request() {
    log("Sending DHCPREQUEST (Renew) for IP " + ip_to_string(leased_ip) +
        " to Server " + ip_to_string(server_id));

    dhcp_packet request_pkt;
    memset(&request_pkt, 0, sizeof(request_pkt));
    request_pkt.op = 1;  // BOOTREQUEST
    request_pkt.htype = 1;
    request_pkt.hlen = 6;
    request_pkt.xid = htonl(transaction_id); 
    request_pkt.flags =
        htons(BOOTP_BROADCAST);     
    request_pkt.ciaddr = leased_ip;  
    memcpy(request_pkt.chaddr, client_mac, sizeof(client_mac));
    memcpy(request_pkt.magic_cookie, DHCP_MAGIC_COOKIE,
           sizeof(DHCP_MAGIC_COOKIE));

    uint8_t* options_ptr = request_pkt.options;
    options_ptr += add_option_byte(options_ptr, DhcpOption::MessageType,
                                   DhcpMessageType::DHCPREQUEST);
    options_ptr += add_option_dword(options_ptr, DhcpOption::ServerIdentifier,
                                    server_id);  //
    *options_ptr++ = static_cast<uint8_t>(DhcpOption::End);

    size_t packet_len = sizeof(dhcp_packet) - sizeof(request_pkt.options) +
                        (options_ptr - request_pkt.options);


    return send_dhcp_message(request_pkt, packet_len, "255.255.255.255",
                             DHCP_SERVER_PORT);
    
}

void DHCPClient::run() {
    if (sock_fd < 0) {
        log("Client socket not initialized.");
        return;
    }
    log("DHCP Client starting state machine for MAC: " +
        mac_to_string(client_mac));
    int discover_attempts_count = 0;
    int current_discover_timeout = config_response_timeout_sec;
    if (state == ClientState::INIT) {
        std::uniform_int_distribution<int> dist(100, 1000);
        int delay_ms = dist(rng);
        log("Initial start: applying random delay of " +
            std::to_string(delay_ms) +
            "ms for MAC: " + mac_to_string(client_mac));
        std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
    }
    while (true) {
        log("Current State: " + std::to_string(static_cast<int>(state)) +
            " for MAC: " + mac_to_string(client_mac));
        switch (state) {
            case ClientState::INIT:
                if (discover_attempts_count >= config_max_discover_attempts) {
                    log("Max DHCPDISCOVER attempts reached for MAC: " +
                        mac_to_string(client_mac) +
                        ". Exiting client thread/loop.");
                    return;
                }
                this->server_id = 0;
                this->leased_ip = 0;
                if (send_discover()) {
                    state = ClientState::SELECTING;
                    discover_attempts_count++;
                    current_discover_timeout =
                        config_response_timeout_sec * discover_attempts_count;
                    log("Moved to SELECTING state. Discover attempt " +
                        std::to_string(discover_attempts_count) +
                        ". Timeout for OFFER: " +
                        std::to_string(current_discover_timeout) +
                        "s. MAC: " + mac_to_string(client_mac));
                } else {
                    log("Failed to send DHCPDISCOVER. Retrying after 2s delay. "
                        "MAC: " +
                        mac_to_string(client_mac));
                    std::this_thread::sleep_for(std::chrono::seconds(2));
                }
                break;
            case ClientState::SELECTING: {
                auto operation_start_time = std::chrono::steady_clock::now();
                bool processed_successfully = false;
                log("SELECTING: Waiting for DHCPOFFER. Overall timeout: " +
                    std::to_string(current_discover_timeout) +
                    "s. MAC: " + mac_to_string(client_mac));
                while (std::chrono::steady_clock::now() <
                       operation_start_time +
                           std::chrono::seconds(current_discover_timeout)) {
                    auto time_left_chrono =
                        (operation_start_time +
                         std::chrono::seconds(current_discover_timeout)) -
                        std::chrono::steady_clock::now();
                    long time_left_sec =
                        std::chrono::duration_cast<std::chrono::seconds>(
                            time_left_chrono)
                            .count();
                    if (time_left_sec <= 0) break;
                    ReceiveResult result =
                        receive_and_process(static_cast<int>(time_left_sec));
                    if (result == ReceiveResult::SUCCESS) {
                        processed_successfully = true;
                        discover_attempts_count = 0;
                        break;
                    } else if (result == ReceiveResult::TIMEOUT ||
                               result == ReceiveResult::ERROR) {
                        processed_successfully = false;
                        break;
                    }
                    log("SELECTING: Packet ignored, continuing to listen. Time "
                        "left: " +
                        std::to_string(time_left_sec) +
                        "s. MAC: " + mac_to_string(client_mac));
                }
                if (!processed_successfully) {
                    log("SELECTING: Overall timeout or error waiting for "
                        "DHCPOFFER. Retrying Discover. MAC: " +
                        mac_to_string(client_mac));
                    state = ClientState::INIT;
                }
                break;
            }
            case ClientState::REQUESTING:
            case ClientState::RENEWING: {
                auto operation_start_time = std::chrono::steady_clock::now();
                bool processed_successfully = false;
                int ack_nak_operation_timeout = 10;
                log(std::string((state == ClientState::REQUESTING
                                     ? "REQUESTING"
                                     : "RENEWING")) +
                    ": Waiting for DHCPACK/NAK. Overall timeout: " +
                    std::to_string(ack_nak_operation_timeout) +
                    "s. MAC: " + mac_to_string(client_mac));
                while (std::chrono::steady_clock::now() <
                       operation_start_time +
                           std::chrono::seconds(ack_nak_operation_timeout)) {
                    auto time_left_chrono =
                        (operation_start_time +
                         std::chrono::seconds(ack_nak_operation_timeout)) -
                        std::chrono::steady_clock::now();
                    long time_left_sec =
                        std::chrono::duration_cast<std::chrono::seconds>(
                            time_left_chrono)
                            .count();
                    if (time_left_sec <= 0) break;
                    ReceiveResult result =
                        receive_and_process(static_cast<int>(time_left_sec));
                    if (result == ReceiveResult::SUCCESS) {
                        processed_successfully = true;
                        discover_attempts_count = 0;
                        break;
                    } else if (result == ReceiveResult::TIMEOUT ||
                               result == ReceiveResult::ERROR) {
                        processed_successfully = false;
                        break;
                    }
                    log(std::string((state == ClientState::REQUESTING
                                         ? "REQUESTING"
                                         : "RENEWING")) +
                        ": Packet ignored, continuing to listen. Time left: " +
                        std::to_string(time_left_sec) +
                        "s. MAC: " + mac_to_string(client_mac));
                }
                if (!processed_successfully) {
                    log(std::string((state == ClientState::REQUESTING
                                         ? "REQUESTING"
                                         : "RENEWING")) +
                        ": Overall timeout or error waiting for DHCPACK/NAK. "
                        "Restarting DORA. MAC: " +
                        mac_to_string(client_mac));
                    state = ClientState::INIT;
                    discover_attempts_count = 0;
                }
                break;
            }
            case ClientState::BOUND: {
                auto now = std::chrono::steady_clock::now();
                auto elapsed_since_lease =
                    std::chrono::duration_cast<std::chrono::seconds>(
                        now - lease_obtained_time)
                        .count();
                uint32_t t1_time = lease_time_sec / 2;
                if (lease_time_sec == 0) {
                    log("BOUND: Lease time is 0. Forcing RENEW. MAC: " +
                        mac_to_string(client_mac));
                    state = ClientState::INIT;
                    discover_attempts_count = 0;
                    break;
                }
                if (elapsed_since_lease >= t1_time) {
                    log("BOUND: Lease T1 expired (" +
                        std::to_string(elapsed_since_lease) +
                        "s >= " + std::to_string(t1_time) +
                        "s). Entering RENEWING state. MAC: " +
                        mac_to_string(client_mac));
                    if (send_renew_request()) {
                        state = ClientState::RENEWING;
                    } else {
                        log("BOUND: Failed to send renewal DHCPREQUEST. Will "
                            "retry on next check. MAC: " +
                            mac_to_string(client_mac));
                        std::this_thread::sleep_for(std::chrono::seconds(10));
                    }
                } else {
                    log("BOUND: Lease active for " + ip_to_string(leased_ip) +
                        ". Time remaining: " +
                        std::to_string(lease_time_sec - elapsed_since_lease) +
                        "s. MAC: " + mac_to_string(client_mac) +
                        ". Checking again in 10s.");
                    std::this_thread::sleep_for(std::chrono::seconds(10));
                }
                break;
            }
            case ClientState::REBINDING:
                log("Entered REBINDING state (not fully implemented). "
                    "Restarting discovery for MAC: " +
                    mac_to_string(client_mac));
                state = ClientState::INIT;
                discover_attempts_count = 0;
                break;
        }
        log("-------------------- MAC: " + mac_to_string(client_mac) +
            " XID: " + std::to_string(transaction_id) + " STATE: " +
            std::to_string(static_cast<int>(state)) + " --------------------");
        if (state != ClientState::BOUND) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
}

ReceiveResult DHCPClient::receive_and_process(int timeout_sec) {
    // log("Waiting for DHCP packet (timeout: " + std::to_string(timeout_sec) +
    //     "s) for MAC: " + mac_to_string(client_mac) +
    //     " XID: " + std::to_string(transaction_id));
    uint8_t buffer[1500];
    struct sockaddr_in server_addr_from;
    socklen_t server_addr_len = sizeof(server_addr_from);
    struct timeval tv;
    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;
    if (setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        perror("setsockopt SO_RCVTIMEO failed");
        return ReceiveResult::ERROR;
    }
    ssize_t recv_len =
        recvfrom(sock_fd, buffer, sizeof(buffer), 0,
                 (struct sockaddr*)&server_addr_from, &server_addr_len);
    if (recv_len < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            log("Receive timeout for MAC: " + mac_to_string(client_mac));
            return ReceiveResult::TIMEOUT;
        }
        perror("recvfrom failed");
        return ReceiveResult::ERROR;
    }
    char server_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &server_addr_from.sin_addr, server_ip_str,
              INET_ADDRSTRLEN);
    log("Received " + std::to_string(recv_len) + " bytes from " +
        server_ip_str + ":" + std::to_string(ntohs(server_addr_from.sin_port)) +
        " for MAC: " + mac_to_string(client_mac));
    if (recv_len < static_cast<ssize_t>(offsetof(dhcp_packet, options) +
                                        sizeof(DHCP_MAGIC_COOKIE) + 1)) {
        log("Received packet too small (" + std::to_string(recv_len) +
            " bytes). Ignoring. MAC: " + mac_to_string(client_mac));
        return ReceiveResult::PACKET_IGNORED;
    }
    const dhcp_packet* packet = reinterpret_cast<const dhcp_packet*>(buffer);
    if (packet->op != 2) {
        log("Received packet is not a BOOTREPLY (op=" +
            std::to_string(packet->op) +
            "). Ignoring. MAC: " + mac_to_string(client_mac));
        return ReceiveResult::PACKET_IGNORED;
    }
    if (memcmp(packet->magic_cookie, DHCP_MAGIC_COOKIE,
               sizeof(DHCP_MAGIC_COOKIE)) != 0) {
        log("Received packet missing or incorrect magic cookie. Ignoring. "
            "MAC: " +
            mac_to_string(client_mac));
        return ReceiveResult::PACKET_IGNORED;
    }
    if (memcmp(packet->chaddr, client_mac, sizeof(client_mac)) != 0) {
        log("Received packet for different MAC address (" +
            mac_to_string(packet->chaddr) + ", expected " +
            mac_to_string(client_mac) + "). Ignoring.");
        return ReceiveResult::PACKET_IGNORED;
    }
    if (ntohl(packet->xid) != transaction_id) {
        log("Received packet with mismatched XID (Got: " +
            std::to_string(ntohl(packet->xid)) +
            ", Expected: " + std::to_string(transaction_id) +
            "). Ignoring. MAC: " + mac_to_string(client_mac));
        return ReceiveResult::PACKET_IGNORED;
    }
    DhcpMessageType msg_type = get_message_type(packet, recv_len);
    log("Received DHCP Message Type: " +
        std::to_string(static_cast<int>(msg_type)) + " for XID: " +
        std::to_string(transaction_id) + " MAC: " + mac_to_string(client_mac));
    switch (state) {
        case ClientState::SELECTING:
            if (msg_type == DhcpMessageType::DHCPOFFER) {
                log("Received DHCPOFFER for XID: " +
                    std::to_string(transaction_id) +
                    " MAC: " + mac_to_string(client_mac));
                uint32_t offered_ip = packet->yiaddr;
                uint32_t offered_server_id = 0;
                uint8_t len = 0;
                const uint8_t* data = find_option(
                    packet, recv_len, DhcpOption::ServerIdentifier, len);
                if (data && len == 4) {
                    memcpy(&offered_server_id, data, sizeof(offered_server_id));
                    log("Offered IP: " + ip_to_string(offered_ip) +
                        " by Server ID: " + ip_to_string(offered_server_id) +
                        " for XID: " + std::to_string(transaction_id));
                    if (send_request(offered_ip, offered_server_id)) {
                        state = ClientState::REQUESTING;
                        this->server_id = offered_server_id;
                        this->leased_ip = offered_ip;
                        return ReceiveResult::SUCCESS;
                    } else {
                        log("Failed to send DHCPREQUEST. Returning to INIT "
                            "state. MAC: " +
                            mac_to_string(client_mac));
                        state = ClientState::INIT;
                        return ReceiveResult::SUCCESS;
                    }
                } else {
                    log("DHCPOFFER missing Server Identifier. Ignoring. MAC: " +
                        mac_to_string(client_mac));
                    return ReceiveResult::PACKET_IGNORED;
                }
            } else {
                log("In SELECTING state, expected DHCPOFFER, got " +
                    std::to_string(static_cast<int>(msg_type)) +
                    ". Ignoring. MAC: " + mac_to_string(client_mac));
                return ReceiveResult::PACKET_IGNORED;
            }
        case ClientState::REQUESTING:
        case ClientState::RENEWING:
            if (msg_type == DhcpMessageType::DHCPACK) {
                log("Received DHCPACK for XID: " +
                    std::to_string(transaction_id) +
                    " MAC: " + mac_to_string(client_mac));
                uint32_t ack_server_id = 0;
                uint8_t len = 0;
                const uint8_t* data = find_option(
                    packet, recv_len, DhcpOption::ServerIdentifier, len);
                if (data && len == 4) {
                    memcpy(&ack_server_id, data, sizeof(ack_server_id));
                } else {
                    log("DHCPACK missing Server Identifier. Accepting anyway "
                        "for now (MAC: " +
                        mac_to_string(client_mac) + ")");
                }
                if (this->server_id != 0 && ack_server_id != 0 &&
                    ack_server_id != this->server_id) {
                    log("DHCPACK from unexpected server (" +
                        ip_to_string(ack_server_id) + "), expected (" +
                        ip_to_string(this->server_id) +
                        "). Ignoring. MAC: " + mac_to_string(client_mac));
                    return ReceiveResult::PACKET_IGNORED;
                }
                if (ack_server_id != 0) this->server_id = ack_server_id;
                leased_ip = packet->yiaddr;
                lease_time_sec = 0;
                subnet_mask = 0;
                router_ip = 0;
                dns_ip = 0;
                data =
                    find_option(packet, recv_len, DhcpOption::LeaseTime, len);
                if (data && len == 4) {
                    uint32_t time_net;
                    memcpy(&time_net, data, sizeof(time_net));
                    lease_time_sec = ntohl(time_net);
                } else {
                    lease_time_sec = 60;
                    log("Warning: DHCPACK missing Lease Time. Using 60s.");
                }
                if (lease_time_sec == 0) {
                    lease_time_sec = 60;
                    log("Warning: Lease Time is 0. Setting to 60s.");
                }
                data =
                    find_option(packet, recv_len, DhcpOption::SubnetMask, len);
                if (data && len == 4)
                    memcpy(&subnet_mask, data, sizeof(subnet_mask));
                data = find_option(packet, recv_len, DhcpOption::Router, len);
                if (data && len == 4)
                    memcpy(&router_ip, data, sizeof(router_ip));
                data = find_option(packet, recv_len, DhcpOption::DNS, len);
                if (data && len == 4) memcpy(&dns_ip, data, sizeof(dns_ip));
                log("--- Lease Acquired/Renewed for MAC: " +
                    mac_to_string(client_mac) + " ---");
                log("IP Address: " + ip_to_string(leased_ip));
                log("Subnet Mask: " + ip_to_string(subnet_mask));
                log("Router: " + ip_to_string(router_ip));
                log("DNS Server: " + ip_to_string(dns_ip));
                log("Lease Time: " + std::to_string(lease_time_sec) +
                    " seconds");
                log("Server ID: " + ip_to_string(this->server_id));
                log("-----------------------------");
                lease_obtained_time = std::chrono::steady_clock::now();
                state = ClientState::BOUND;
                return ReceiveResult::SUCCESS;
            } else if (msg_type == DhcpMessageType::DHCPNAK) {
                log("Received DHCPNAK. Server rejected request for XID: " +
                    std::to_string(transaction_id) +
                    " MAC: " + mac_to_string(client_mac));
                state = ClientState::INIT;
                return ReceiveResult::SUCCESS;
            } else {
                log(std::string("In ") +
                    (state == ClientState::REQUESTING ? "REQUESTING"
                                                      : "RENEWING") +
                    " state, expected DHCPACK/NAK, got " +
                    std::to_string(static_cast<int>(msg_type)) +
                    ". Ignoring. MAC: " + mac_to_string(client_mac));
                return ReceiveResult::PACKET_IGNORED;
            }
        case ClientState::BOUND:
            log("Received unexpected packet in BOUND state (Type: " +
                std::to_string(static_cast<int>(msg_type)) +
                "). Ignoring. MAC: " + mac_to_string(client_mac));
            return ReceiveResult::PACKET_IGNORED;
        default:
            log("Received packet in unexpected state " +
                std::to_string(static_cast<int>(state)) +
                ". Ignoring. MAC: " + mac_to_string(client_mac));
            return ReceiveResult::PACKET_IGNORED;
    }
    return ReceiveResult::PACKET_IGNORED;
}
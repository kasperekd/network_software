#include "dhcp_server.h"

#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <iostream>
#include <thread>

ServerConfig::ServerConfig()
    : server_ip_str("auto"),
      subnet_mask_str("255.255.255.0"),
      router_str(""),  // По умолчанию будет равен server_ip_str
      dns_server_str("8.8.8.8"),
      ip_pool_start_str("172.20.0.100"),  // для сети Docker 172.20.0.0/16
      ip_pool_end_str("172.20.0.150"),
      lease_time_sec(3600),
      bind_interface("eth0"),
      server_ip_net(0),
      subnet_mask_net(0),
      router_ip_net(0),
      dns_ip_net(0),
      ip_pool_start_host(0),
      ip_pool_end_host(0) {}

static std::string get_interface_ip_static_for_config(
    const std::string& interface_name) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        // perror("get_interface_ip_static_for_config: socket");
        return "";
    }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, interface_name.c_str(), IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    std::string ip_addr_str = "";
    if (ioctl(fd, SIOCGIFADDR, &ifr) == 0) {
        ip_addr_str = inet_ntoa(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr);
    } else {
        // perror("get_interface_ip_static_for_config: ioctl SIOCGIFADDR");
    }
    close(fd);
    return ip_addr_str;
}

bool ServerConfig::load(const std::string& config_filename) {
    std::cout << "[CONFIG] Loading server configuration from "
              << config_filename << "..." << std::endl;
    auto config_map = parse_config_file(config_filename);

    if (config_map.empty() && !std::ifstream(config_filename).good()) {
        std::cout << "[CONFIG] Config file '" << config_filename
                  << "' not found or empty. Using default values." << std::endl;
    } else {
        server_ip_str =
            get_config_string(config_map, "server_ip", server_ip_str);
        subnet_mask_str =
            get_config_string(config_map, "subnet_mask", subnet_mask_str);
        router_str = get_config_string(config_map, "router_ip", router_str);
        dns_server_str =
            get_config_string(config_map, "dns_server", dns_server_str);
        ip_pool_start_str =
            get_config_string(config_map, "ip_pool_start", ip_pool_start_str);
        ip_pool_end_str =
            get_config_string(config_map, "ip_pool_end", ip_pool_end_str);
        lease_time_sec =
            get_config_uint32(config_map, "lease_time_sec", lease_time_sec);
        bind_interface =
            get_config_string(config_map, "bind_interface", bind_interface);
    }

    if (server_ip_str == "auto" || server_ip_str == "0.0.0.0" ||
        server_ip_str.empty()) {
        if (!bind_interface.empty() && bind_interface != "0.0.0.0") {
            std::string detected_ip =
                get_interface_ip_static_for_config(bind_interface);
            if (!detected_ip.empty()) {
                std::cout << "[CONFIG] Auto-detected IP for interface '"
                          << bind_interface << "': " << detected_ip
                          << std::endl;
                server_ip_str = detected_ip;
            } else {
                std::cerr << "[CONFIG] CRITICAL: Could not auto-detect IP for "
                             "interface '"
                          << bind_interface
                          << "' and server_ip is set to auto/empty. Please set "
                             "server_ip manually in "
                          << config_filename << std::endl;
                return false;
            }
        } else if (server_ip_str ==
                   "auto") {  // Если auto, но нет интерфейса для определения
            std::cerr
                << "[CONFIG] CRITICAL: server_ip is 'auto', but no valid "
                   "bind_interface specified for detection (e.g., 'eth0')."
                << std::endl;
            return false;
        }
    }

    if (router_str.empty() && !server_ip_str.empty() &&
        server_ip_str != "0.0.0.0") {
        router_str = server_ip_str;
        std::cout << "[CONFIG] router_ip is empty, defaulting to server_ip: "
                  << router_str << std::endl;
    }

    try {
        server_ip_net = string_to_ip(server_ip_str);
        subnet_mask_net = string_to_ip(subnet_mask_str);
        router_ip_net = string_to_ip(router_str);
        dns_ip_net = string_to_ip(dns_server_str);
        ip_pool_start_host = ntohl(string_to_ip(ip_pool_start_str));
        ip_pool_end_host = ntohl(string_to_ip(ip_pool_end_str));

        if (server_ip_net == 0 && server_ip_str != "0.0.0.0") {
            throw std::runtime_error(
                "Effective server_ip resolved to 0.0.0.0 or was invalid, but "
                "was not explicitly set to '0.0.0.0'.");
        }

        if (ip_pool_start_host > ip_pool_end_host) {
            throw std::runtime_error(
                "ip_pool_start cannot be greater than ip_pool_end.");
        }
        if (lease_time_sec == 0) {
            std::cout << "[CONFIG] Warning: lease_time_sec is 0. Setting to "
                         "default (3600s)."
                      << std::endl;
            lease_time_sec = 3600;
        }
        if (router_ip_net == 0 && !router_str.empty()) {
            std::cout << "[CONFIG] Warning: router_ip '" << router_str
                      << "' is invalid. Router will not be provided."
                      << std::endl;
        }

    } catch (const std::exception& e) {
        std::cerr << "[CONFIG] CRITICAL Error parsing configuration values: "
                  << e.what() << std::endl;
        return false;
    }

    std::cout << "[CONFIG] Effective Server IP: " << server_ip_str << " ("
              << ip_to_string(server_ip_net) << ")" << std::endl;
    std::cout << "[CONFIG] Subnet Mask: " << subnet_mask_str << " ("
              << ip_to_string(subnet_mask_net) << ")" << std::endl;
    std::cout << "[CONFIG] Router: " << router_str << " ("
              << ip_to_string(router_ip_net) << ")" << std::endl;
    std::cout << "[CONFIG] DNS Server: " << dns_server_str << " ("
              << ip_to_string(dns_ip_net) << ")" << std::endl;
    std::cout << "[CONFIG] IP Pool (host order): "
              << ip_to_string(htonl(ip_pool_start_host)) << " - "
              << ip_to_string(htonl(ip_pool_end_host)) << std::endl;
    std::cout << "[CONFIG] Lease Time: " << lease_time_sec << " seconds"
              << std::endl;
    std::cout << "[CONFIG] Bind Interface for server IP detection/binding: "
              << bind_interface << std::endl;
    return true;
}

DHCPServer::DHCPServer() = default;

DHCPServer::~DHCPServer() {
    if (sock_fd >= 0) {
        close(sock_fd);
        log("Server socket closed.");
    }
}

void DHCPServer::log(const std::string& message) {
    std::cout << "[SERVER] " << message << std::endl;
}

bool DHCPServer::initialize(const std::string& config_filename) {
    log("Initializing DHCP Server...");
    if (!config.load(config_filename)) {
        log("CRITICAL: Failed to load server configuration. Aborting.");
        return false;
    }

    sock_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock_fd < 0) {
        perror("DHCPServer::initialize - socket creation failed");
        return false;
    }
    log("Socket created.");

    int broadcast_enable = 1;
    if (setsockopt(sock_fd, SOL_SOCKET, SO_BROADCAST, &broadcast_enable,
                   sizeof(broadcast_enable)) < 0) {
        perror("DHCPServer::initialize - setsockopt SO_BROADCAST failed");
        close(sock_fd);
        sock_fd = -1;
        return false;
    }
    log("SO_BROADCAST enabled.");

    int reuse_addr_enable = 1;
    if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &reuse_addr_enable,
                   sizeof(reuse_addr_enable)) < 0) {
        perror("DHCPServer::initialize - setsockopt SO_REUSEADDR failed");
        close(sock_fd);
        sock_fd = -1;
        return false;
    }
    log("SO_REUSEADDR enabled.");

    struct sockaddr_in server_bind_addr;
    memset(&server_bind_addr, 0, sizeof(server_bind_addr));
    server_bind_addr.sin_family = AF_INET;
    server_bind_addr.sin_port = htons(DHCP_SERVER_PORT);
    server_bind_addr.sin_addr.s_addr =
        htonl(INADDR_ANY);  // Слушаем на всех интерфейсах

    if (bind(sock_fd, (struct sockaddr*)&server_bind_addr,
             sizeof(server_bind_addr)) < 0) {
        perror("DHCPServer::initialize - bind failed");
        close(sock_fd);
        sock_fd = -1;
        return false;
    }
    log("Bound to 0.0.0.0:" + std::to_string(DHCP_SERVER_PORT));
    return true;
}

size_t DHCPServer::add_option(uint8_t* options_ptr, DhcpOption option_code,
                              uint8_t len, const void* data) {
    *options_ptr++ = static_cast<uint8_t>(option_code);
    *options_ptr++ = len;
    if (data && len > 0) {
        memcpy(options_ptr, data, len);
    }
    return len + 2;
}

size_t DHCPServer::add_option_byte(uint8_t* options_ptr, DhcpOption option_code,
                                   uint8_t value) {
    return add_option(options_ptr, option_code, 1, &value);
}

size_t DHCPServer::add_option_dword(uint8_t* options_ptr,
                                    DhcpOption option_code,
                                    uint32_t value_host_order) {
    uint32_t net_value = htonl(value_host_order);
    return add_option(options_ptr, option_code, 4, &net_value);
}

const uint8_t* DHCPServer::find_option(const dhcp_packet* packet,
                                       size_t packet_len, DhcpOption code,
                                       uint8_t& len) {
    if (packet_len < offsetof(dhcp_packet, options)) {
        log("Packet too small to contain options field.");
        return nullptr;
    }

    if (memcmp(packet->magic_cookie, DHCP_MAGIC_COOKIE,
               sizeof(DHCP_MAGIC_COOKIE)) != 0) {
        log("Incorrect magic cookie found.");
        return nullptr;
    }

    // Начинаем поиск с начала поля options
    const uint8_t* options_ptr = packet->options;
    // Конец данных опций = начало опций + (общая длина пакета - смещение
    // начала опций)
    const uint8_t* end_ptr =
        options_ptr + (packet_len - offsetof(dhcp_packet, options));

    log("Searching for option " + std::to_string(static_cast<int>(code)) +
        " in options field...");

    while (options_ptr < end_ptr &&
           *options_ptr != static_cast<uint8_t>(DhcpOption::End)) {
        uint8_t current_code_val = *options_ptr;

        if (current_code_val == static_cast<uint8_t>(DhcpOption::Pad)) {
            options_ptr++;
            continue;
        }

        if (options_ptr + 1 >= end_ptr) {
            log("Option parsing error: Not enough space for option length "
                "byte.");
            return nullptr;  // Некорректный пакет
        }

        options_ptr++;
        uint8_t current_len = *options_ptr++;

        if (options_ptr + current_len > end_ptr) {
            log("Option parsing error: Option length " +
                std::to_string(current_len) + " exceeds packet bounds.");
            return nullptr;  // Некорректный пакет
        }

        if (current_code_val == static_cast<uint8_t>(code)) {
            len = current_len;
            log("Found option " + std::to_string(static_cast<int>(code)) +
                " with length " + std::to_string(len));
            return options_ptr;
        }

        options_ptr += current_len;
    }
    log("Option " + std::to_string(static_cast<int>(code)) +
        " not found or reached End marker.");
    len = 0;
    return nullptr;
}

DhcpMessageType DHCPServer::get_message_type(const dhcp_packet* packet,
                                             size_t packet_len) {
    uint8_t len = 0;
    const uint8_t* data =
        find_option(packet, packet_len, DhcpOption::MessageType, len);
    if (data && len == 1) {
        return static_cast<DhcpMessageType>(*data);
    }
    return static_cast<DhcpMessageType>(0);
}

void DHCPServer::cleanup_expired_leases_and_offers() {
    auto now = std::chrono::steady_clock::now();
    int leases_cleaned = 0;
    int offers_cleaned = 0;

    for (auto it = leased_ips.begin(); it != leased_ips.end();) {
        if (it->second.expiry_time <= now) {
            log("Lease expired for MAC " + it->first + " IP " +
                ip_to_string(it->second.ip_address) + ". Releasing.");
            last_discover_xids.erase(
                it->first);  // Очищаем XID, т.к. аренда кончилась
            it = leased_ips.erase(it);
            leases_cleaned++;
        } else {
            ++it;
        }
    }
    if (leases_cleaned > 0)
        log("Cleaned up " + std::to_string(leases_cleaned) +
            " expired leases.");

    for (auto it = offered_ips.begin(); it != offered_ips.end();) {
        const std::string& mac_in_offer = it->second.first;
        if (leased_ips.count(
                mac_in_offer)) {  // Если для этого MAC уже есть аренда
            // И XID в аренде отличается от XID оффера (значит оффер от старой
            // транзакции)
            if (leased_ips[mac_in_offer].xid_associated != it->first) {
                log("Cleaning up stale offer for MAC " + mac_in_offer +
                    " (XID: " + std::to_string(it->first) +
                    ") as lease already exists.");
                it = offered_ips.erase(it);
                offers_cleaned++;
                continue;
            }
        }
        // TODO: Добавить таймаут для офферов, если они не были приняты
        ++it;
    }
    if (offers_cleaned > 0)
        log("Cleaned up " + std::to_string(offers_cleaned) + " stale offers.");
}

uint32_t DHCPServer::find_available_ip(const std::string& client_mac_str,
                                       uint32_t client_xid_host) {
    auto it_lease = leased_ips.find(client_mac_str);
    if (it_lease != leased_ips.end()) {
        if (it_lease->second.expiry_time > std::chrono::steady_clock::now()) {
            log("Client " + client_mac_str +
                " (XID: " + std::to_string(client_xid_host) +
                ") already has active lease for IP " +
                ip_to_string(it_lease->second.ip_address) +
                ". Offering same IP.");
            return it_lease->second.ip_address;
        } else {
            log("Client " + client_mac_str + " had expired lease for IP " +
                ip_to_string(it_lease->second.ip_address) +
                ". Removing old lease.");
            leased_ips.erase(it_lease);
        }
    }
    // Проверяем, нет ли уже активного оффера для этой транзакции (XID + MAC)
    // Это на случай, если DISCOVER пришел повторно, а OFFER уже был сделан.
    auto it_offer = offered_ips.find(client_xid_host);
    if (it_offer != offered_ips.end() &&
        it_offer->second.first == client_mac_str) {
        log("Client " + client_mac_str +
            " (XID: " + std::to_string(client_xid_host) +
            ") already has an active offer for IP " +
            ip_to_string(it_offer->second.second) + ". Offering same IP.");
        return it_offer->second.second;
    }

    for (uint32_t current_ip_h = config.ip_pool_start_host;
         current_ip_h <= config.ip_pool_end_host; ++current_ip_h) {
        uint32_t current_ip_n = htonl(current_ip_h);
        if (!is_ip_leased_or_offered(current_ip_n)) {
            // TODO: ARP check
            log("Found available IP: " + ip_to_string(current_ip_n) +
                " for MAC " + client_mac_str +
                " (XID: " + std::to_string(client_xid_host) + ")");
            return current_ip_n;
        }
    }
    log("No available IP addresses in the pool for MAC " + client_mac_str);
    return 0;
}

bool DHCPServer::is_ip_leased_or_offered(uint32_t ip_net_order) {
    auto now = std::chrono::steady_clock::now();
    for (const auto& pair : leased_ips) {
        if (pair.second.ip_address == ip_net_order &&
            pair.second.expiry_time > now) {
            return true;
        }
    }
    for (const auto& pair : offered_ips) {
        // Ключ - XID, значение - пара {MAC, IP}
        if (pair.second.second == ip_net_order) {
            // TODO: Можно добавить проверку свежести оффера, если хранить
            // timestamp
            return true;
        }
    }
    return false;
}

void DHCPServer::process_packet(const uint8_t* buffer, size_t len,
                                const sockaddr_in& client_addr) {
    if (len < sizeof(dhcp_packet) - sizeof(dhcp_packet::options)) {
        log("Received packet too small (" + std::to_string(len) +
            " bytes). Ignoring.");
        return;
    }

    const dhcp_packet* packet = reinterpret_cast<const dhcp_packet*>(buffer);

    if (packet->op != 1) {  // BOOTREQUEST
        log("Received packet is not a BOOTREQUEST (op=" +
            std::to_string(packet->op) + "). Ignoring.");
        return;
    }
    if (memcmp(packet->magic_cookie, DHCP_MAGIC_COOKIE,
               sizeof(DHCP_MAGIC_COOKIE)) != 0) {
        log("Received packet missing or incorrect magic cookie. Ignoring.");
        return;
    }

    DhcpMessageType msg_type = get_message_type(packet, len);

    switch (msg_type) {
        case DhcpMessageType::DHCPDISCOVER:
            handle_discover(packet, len, client_addr);
            break;
        case DhcpMessageType::DHCPREQUEST:
            handle_request(packet, len, client_addr);
            break;
        case DhcpMessageType::DHCPDECLINE:
            log("Received DHCPDECLINE from MAC: " +
                mac_to_string(packet->chaddr) +
                ". Marking IP as potentially conflicted.");
            break;
        case DhcpMessageType::DHCPRELEASE:
            log("Received DHCPRELEASE from MAC: " +
                mac_to_string(packet->chaddr));
            {
                std::string mac_str = mac_to_string(packet->chaddr);
                auto it = leased_ips.find(mac_str);
                if (it != leased_ips.end()) {
                    log("Releasing lease for IP " +
                        ip_to_string(it->second.ip_address));
                    leased_ips.erase(it);
                } else {
                    log("DHCPRELEASE from " + mac_str +
                        " with no active lease found.");
                }
            }
            break;
        case DhcpMessageType::DHCPINFORM:
            log("Received DHCPINFORM (not fully supported). Ignoring.");
            break;
        default:
            log("Received unknown or unsupported DHCP message type: " +
                std::to_string(static_cast<int>(msg_type)));
            break;
    }
}

void DHCPServer::handle_discover(const dhcp_packet* request, size_t request_len,
                                 const struct sockaddr_in& client_addr_from) {
    (void)request_len;       // Пока не используется для доп. проверок
    (void)client_addr_from;  // Для отправки ответа используется широковещание

    std::string client_mac_str = mac_to_string(request->chaddr);
    uint32_t client_xid_host = ntohl(request->xid);

    log("Received DHCPDISCOVER from MAC: " + client_mac_str +
        ", XID: " + std::to_string(client_xid_host));

    auto current_offer_it = offered_ips.find(client_xid_host);
    if (current_offer_it != offered_ips.end() &&
        current_offer_it->second.first == client_mac_str) {
        log("Duplicate DHCPDISCOVER (XID: " + std::to_string(client_xid_host) +
            ") for existing offer to MAC " + client_mac_str +
            ". Resending DHCPOFFER for IP " +
            ip_to_string(current_offer_it->second.second));
        send_offer(request, current_offer_it->second.second);
        return;
    }
    // Если XID другой, но MAC тот же, это новая попытка, старый оффер (если
    // был) можно удалить. Очистим старые офферы для этого MAC, если XID новый.
    for (auto it = offered_ips.begin(); it != offered_ips.end();) {
        if (it->second.first == client_mac_str &&
            it->first != client_xid_host) {
            log("Found old offer for MAC " + client_mac_str + " with XID " +
                std::to_string(it->first) +
                ". Removing it due to new DISCOVER with XID " +
                std::to_string(client_xid_host));
            it = offered_ips.erase(it);
        } else {
            ++it;
        }
    }

    uint32_t offered_ip_net =
        find_available_ip(client_mac_str, client_xid_host);
    if (offered_ip_net == 0) {
        log("No IP available to offer to MAC " + client_mac_str + " for XID " +
            std::to_string(client_xid_host));
        return;
    }

    offered_ips[client_xid_host] = {client_mac_str, offered_ip_net};
    log("Offering IP " + ip_to_string(offered_ip_net) + " to MAC " +
        client_mac_str + " (XID: " + std::to_string(client_xid_host) + ")");
    send_offer(request, offered_ip_net);
}

void DHCPServer::send_offer(const dhcp_packet* discover_request,
                            uint32_t offered_ip_net) {
    dhcp_packet offer_pkt;
    memset(&offer_pkt, 0, sizeof(offer_pkt));
    offer_pkt.op = 2;  // BOOTREPLY
    offer_pkt.htype = 1;
    offer_pkt.hlen = 6;
    offer_pkt.xid = discover_request->xid;
    offer_pkt.flags = discover_request->flags;
    offer_pkt.yiaddr = offered_ip_net;
    offer_pkt.siaddr = config.server_ip_net;
    memcpy(offer_pkt.chaddr, discover_request->chaddr,
           sizeof(offer_pkt.chaddr));
    memcpy(offer_pkt.magic_cookie, DHCP_MAGIC_COOKIE,
           sizeof(DHCP_MAGIC_COOKIE));

    uint8_t* opt_ptr = offer_pkt.options;
    opt_ptr +=
        add_option_byte(opt_ptr, DhcpOption::MessageType,
                        static_cast<uint8_t>(DhcpMessageType::DHCPOFFER));
    opt_ptr += add_option_dword(
        opt_ptr, DhcpOption::ServerIdentifier,
        ntohl(config.server_ip_net));  // add_option_dword ожидает хостовый
                                       // порядок
    opt_ptr +=
        add_option_dword(opt_ptr, DhcpOption::LeaseTime, config.lease_time_sec);
    opt_ptr +=
        add_option(opt_ptr, DhcpOption::SubnetMask, 4, &config.subnet_mask_net);
    if (config.router_ip_net !=
        0) {  // Добавляем шлюз, только если он сконфигурирован
        opt_ptr +=
            add_option(opt_ptr, DhcpOption::Router, 4, &config.router_ip_net);
    }
    if (config.dns_ip_net !=
        0) {  // Добавляем DNS, только если он сконфигурирован
        opt_ptr += add_option(opt_ptr, DhcpOption::DNS, 4, &config.dns_ip_net);
    }
    *opt_ptr++ = static_cast<uint8_t>(DhcpOption::End);

    size_t offer_len = reinterpret_cast<uint8_t*>(opt_ptr) -
                       reinterpret_cast<uint8_t*>(&offer_pkt);

    struct sockaddr_in broadcast_addr;
    memset(&broadcast_addr, 0, sizeof(broadcast_addr));
    broadcast_addr.sin_family = AF_INET;
    broadcast_addr.sin_port = htons(DHCP_CLIENT_PORT);
    inet_pton(AF_INET, "255.255.255.255", &broadcast_addr.sin_addr);

    log("Sending DHCPOFFER to 255.255.255.255:" +
        std::to_string(DHCP_CLIENT_PORT) + " for XID " +
        std::to_string(ntohl(discover_request->xid)));
    ssize_t sent_bytes =
        sendto(sock_fd, &offer_pkt, offer_len, 0,
               (struct sockaddr*)&broadcast_addr, sizeof(broadcast_addr));
    if (sent_bytes < 0) {
        perror("sendto DHCPOFFER failed");
    } else {
        log("DHCPOFFER sent (" + std::to_string(sent_bytes) + " bytes).");
    }
}

void DHCPServer::handle_request(const dhcp_packet* request, size_t request_len,
                                const struct sockaddr_in& client_addr_from) {
    std::string client_mac_str = mac_to_string(request->chaddr);
    uint32_t client_xid_host = ntohl(request->xid);
    log("Received DHCPREQUEST from MAC: " + client_mac_str +
        ", XID: " + std::to_string(client_xid_host));

    uint8_t opt_len = 0;
    uint32_t requested_ip_opt_net = 0;
    uint32_t server_id_opt_net = 0;

    const uint8_t* opt_data_req_ip =
        find_option(request, request_len, DhcpOption::RequestedIP, opt_len);
    if (opt_data_req_ip && opt_len == 4) {
        memcpy(&requested_ip_opt_net, opt_data_req_ip,
               sizeof(requested_ip_opt_net));
        log("Requested IP option (50) found: " +
            ip_to_string(requested_ip_opt_net));
    }

    const uint8_t* opt_data_srv_id = find_option(
        request, request_len, DhcpOption::ServerIdentifier, opt_len);
    if (opt_data_srv_id && opt_len == 4) {
        memcpy(&server_id_opt_net, opt_data_srv_id, sizeof(server_id_opt_net));
        log("Server Identifier option (54) found: " +
            ip_to_string(server_id_opt_net));
    }

    uint32_t client_current_ip_net = request->ciaddr;
    uint32_t ip_to_confirm_net;
    bool is_selecting_state =
        (client_current_ip_net == 0);  // Если ciaddr=0, то это SELECTING

    if (is_selecting_state) {  // SELECTING state
        if (requested_ip_opt_net == 0) {
            log("DHCPREQUEST (SELECTING) missing Option 50. Sending NAK.");
            send_nak(request, client_addr_from);
            offered_ips.erase(client_xid_host);
            return;
        }
        if (server_id_opt_net == 0) {  // В SELECTING ServerID обязателен
            log("DHCPREQUEST (SELECTING) missing Option 54. Sending NAK.");
            send_nak(request, client_addr_from);
            offered_ips.erase(client_xid_host);
            return;
        }
        if (server_id_opt_net != config.server_ip_net) {
            log("DHCPREQUEST (SELECTING) for different server (" +
                ip_to_string(server_id_opt_net) + "). Ignoring.");
            // Не NAK, просто игнорируем, если это не наш сервер
            return;
        }
        ip_to_confirm_net = requested_ip_opt_net;

        auto offer_it = offered_ips.find(client_xid_host);
        if (offer_it == offered_ips.end() ||
            offer_it->second.first != client_mac_str ||
            offer_it->second.second != ip_to_confirm_net) {
            log("DHCPREQUEST (SELECTING) XID " +
                std::to_string(client_xid_host) + " for IP " +
                ip_to_string(ip_to_confirm_net) +
                " does not match active offer. Sending NAK.");
            send_nak(request, client_addr_from);
            if (offer_it != offered_ips.end())
                offered_ips.erase(offer_it);  // Удаляем неверный оффер
            return;
        }
        log("DHCPREQUEST (SELECTING) matches offer for IP " +
            ip_to_string(ip_to_confirm_net));

    } else {  // RENEWING or REBINDING state
        ip_to_confirm_net = client_current_ip_net;
        if (requested_ip_opt_net != 0 &&
            requested_ip_opt_net != ip_to_confirm_net) {
            log("Warning: Option 50 (" + ip_to_string(requested_ip_opt_net) +
                ") mismatches ciaddr (" + ip_to_string(ip_to_confirm_net) +
                ") in RENEW/REBIND. Using ciaddr.");
        }
        if (server_id_opt_net != 0 &&
            server_id_opt_net != config.server_ip_net) {
            log("DHCPREQUEST (RENEW/REBIND) for different server (" +
                ip_to_string(server_id_opt_net) + "). Ignoring.");
            return;
        }

        auto lease_it = leased_ips.find(client_mac_str);
        if (lease_it == leased_ips.end() ||
            lease_it->second.ip_address != ip_to_confirm_net) {
            log("DHCPREQUEST (RENEW/REBIND) for IP " +
                ip_to_string(ip_to_confirm_net) + " by MAC " + client_mac_str +
                " - no active lease found for this MAC/IP combination. Sending "
                "NAK.");
            send_nak(request, client_addr_from);
            return;
        }
        log("DHCPREQUEST (RENEW/REBIND) matches existing lease for IP " +
            ip_to_string(ip_to_confirm_net));
    }

    // Если дошли сюда, запрос в целом валиден для обработки
    log("Granting/Renewing lease for IP " + ip_to_string(ip_to_confirm_net) +
        " to MAC " + client_mac_str);
    auto now = std::chrono::steady_clock::now();
    leased_ips[client_mac_str] = {
        ip_to_confirm_net, client_mac_str,
        now + std::chrono::seconds(config.lease_time_sec),
        client_xid_host  // Сохраняем XID текущей транзакции, подтвердившей
                         // аренду
    };

    if (is_selecting_state) {
        offered_ips.erase(client_xid_host);
    }
    last_discover_xids.erase(client_mac_str);  // DORA завершен успешно

    send_ack(request, ip_to_confirm_net);
}

void DHCPServer::send_ack(const dhcp_packet* client_request,
                          uint32_t assigned_ip_net) {
    dhcp_packet ack_pkt;
    memset(&ack_pkt, 0, sizeof(ack_pkt));
    ack_pkt.op = 2;
    ack_pkt.htype = 1;
    ack_pkt.hlen = 6;
    ack_pkt.xid = client_request->xid;
    ack_pkt.flags = client_request->flags;
    ack_pkt.ciaddr =
        client_request
            ->ciaddr;  // Важно для клиента, если он обновляет и проверяет
    ack_pkt.yiaddr = assigned_ip_net;
    ack_pkt.siaddr = config.server_ip_net;
    memcpy(ack_pkt.chaddr, client_request->chaddr, sizeof(ack_pkt.chaddr));
    memcpy(ack_pkt.magic_cookie, DHCP_MAGIC_COOKIE, sizeof(DHCP_MAGIC_COOKIE));

    uint8_t* opt_ptr = ack_pkt.options;
    opt_ptr += add_option_byte(opt_ptr, DhcpOption::MessageType,
                               static_cast<uint8_t>(DhcpMessageType::DHCPACK));
    opt_ptr += add_option_dword(opt_ptr, DhcpOption::ServerIdentifier,
                                ntohl(config.server_ip_net));
    opt_ptr +=
        add_option_dword(opt_ptr, DhcpOption::LeaseTime, config.lease_time_sec);
    opt_ptr +=
        add_option(opt_ptr, DhcpOption::SubnetMask, 4, &config.subnet_mask_net);
    if (config.router_ip_net != 0)
        opt_ptr +=
            add_option(opt_ptr, DhcpOption::Router, 4, &config.router_ip_net);
    if (config.dns_ip_net != 0)
        opt_ptr += add_option(opt_ptr, DhcpOption::DNS, 4, &config.dns_ip_net);
    *opt_ptr++ = static_cast<uint8_t>(DhcpOption::End);

    size_t ack_len = reinterpret_cast<uint8_t*>(opt_ptr) -
                     reinterpret_cast<uint8_t*>(&ack_pkt);

    struct sockaddr_in target_addr;
    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(DHCP_CLIENT_PORT);
    inet_pton(AF_INET, "255.255.255.255",
              &target_addr.sin_addr);  // Отправляем ACK широковещательно

    log("Sending DHCPACK to 255.255.255.255:" +
        std::to_string(DHCP_CLIENT_PORT) + " for XID " +
        std::to_string(ntohl(client_request->xid)));
    ssize_t sent_bytes =
        sendto(sock_fd, &ack_pkt, ack_len, 0, (struct sockaddr*)&target_addr,
               sizeof(target_addr));
    if (sent_bytes < 0) {
        perror("sendto DHCPACK failed");
    } else {
        log("DHCPACK sent (" + std::to_string(sent_bytes) +
            "). Lease confirmed for " + mac_to_string(client_request->chaddr));
    }
}

void DHCPServer::send_nak(const dhcp_packet* client_request,
                          const struct sockaddr_in& client_addr_from) {
    (void)client_addr_from;  // NAK всегда broadcast
    log("Sending DHCPNAK to MAC: " + mac_to_string(client_request->chaddr) +
        " XID: " + std::to_string(ntohl(client_request->xid)));

    dhcp_packet nak_pkt;
    memset(&nak_pkt, 0, sizeof(nak_pkt));
    nak_pkt.op = 2;
    nak_pkt.htype = 1;
    nak_pkt.hlen = 6;
    nak_pkt.xid = client_request->xid;
    memcpy(nak_pkt.chaddr, client_request->chaddr, sizeof(nak_pkt.chaddr));
    nak_pkt.siaddr = config.server_ip_net;  // Идентификатор нашего сервера
    memcpy(nak_pkt.magic_cookie, DHCP_MAGIC_COOKIE, sizeof(DHCP_MAGIC_COOKIE));

    uint8_t* opt_ptr = nak_pkt.options;
    opt_ptr += add_option_byte(opt_ptr, DhcpOption::MessageType,
                               static_cast<uint8_t>(DhcpMessageType::DHCPNAK));
    opt_ptr += add_option_dword(opt_ptr, DhcpOption::ServerIdentifier,
                                ntohl(config.server_ip_net));
    *opt_ptr++ = static_cast<uint8_t>(DhcpOption::End);

    size_t nak_len = reinterpret_cast<uint8_t*>(opt_ptr) -
                     reinterpret_cast<uint8_t*>(&nak_pkt);

    struct sockaddr_in broadcast_addr;
    memset(&broadcast_addr, 0, sizeof(broadcast_addr));
    broadcast_addr.sin_family = AF_INET;
    broadcast_addr.sin_port = htons(DHCP_CLIENT_PORT);
    inet_pton(AF_INET, "255.255.255.255", &broadcast_addr.sin_addr);

    ssize_t sent_bytes =
        sendto(sock_fd, &nak_pkt, nak_len, 0, (struct sockaddr*)&broadcast_addr,
               sizeof(broadcast_addr));
    if (sent_bytes < 0) {
        perror("sendto DHCPNAK failed");
    } else {
        log("DHCPNAK sent (" + std::to_string(sent_bytes) + " bytes).");
    }
}

void DHCPServer::handle_decline(const dhcp_packet* request,
                                size_t request_len) {
    std::string client_mac_str = mac_to_string(request->chaddr);
    log("Received DHCPDECLINE from MAC: " + client_mac_str +
        ", XID: " + std::to_string(ntohl(request->xid)));

    uint8_t opt_len = 0;
    uint32_t declined_ip_net = 0;
    const uint8_t* opt_data =
        find_option(request, request_len, DhcpOption::RequestedIP, opt_len);
    if (opt_data && opt_len == 4) {
        memcpy(&declined_ip_net, opt_data, sizeof(declined_ip_net));
    } else if (request->ciaddr !=
               0) {  // ciaddr может содержать IP, который клиент проверял
        declined_ip_net = request->ciaddr;
    }

    if (declined_ip_net != 0) {
        log("Client " + client_mac_str +
            " declined IP address: " + ip_to_string(declined_ip_net));
        // TODO: Пометить этот IP как "занятый конфликтом" на некоторое время
        // Можно удалить его из пула доступных или добавить в специальный список
        // "плохих" IP Пока просто удалим активные офферы и аренды для этого IP
        // и MAC
        offered_ips.erase(
            ntohl(request->xid));  // Удаляем оффер, если он был по этому XID
        auto lease_it = leased_ips.find(client_mac_str);
        if (lease_it != leased_ips.end() &&
            lease_it->second.ip_address == declined_ip_net) {
            log("Removing lease for declined IP " +
                ip_to_string(declined_ip_net) + " for MAC " + client_mac_str);
            leased_ips.erase(lease_it);
        }
        // Можно добавить IP в какой-нибудь blacklist на время
    } else {
        log("DHCPDECLINE from " + client_mac_str +
            " did not specify which IP was declined (no Option 50 or ciaddr).");
    }
}

void DHCPServer::handle_release(const dhcp_packet* request,
                                size_t request_len) {
    std::string client_mac_str = mac_to_string(request->chaddr);
    log("Received DHCPRELEASE from MAC: " + client_mac_str +
        ", XID: " + std::to_string(ntohl(request->xid)));

    uint32_t client_ip_to_release = request->ciaddr;
    if (client_ip_to_release == 0) {
        log("DHCPRELEASE from " + client_mac_str +
            " is missing ciaddr. Cannot process.");
        return;
    }

    uint8_t opt_len = 0;
    uint32_t server_id_opt_net = 0;
    const uint8_t* opt_data_srv_id = find_option(
        request, request_len, DhcpOption::ServerIdentifier, opt_len);
    if (opt_data_srv_id && opt_len == 4) {
        memcpy(&server_id_opt_net, opt_data_srv_id, sizeof(server_id_opt_net));
        if (server_id_opt_net != config.server_ip_net) {
            log("DHCPRELEASE for server " + ip_to_string(server_id_opt_net) +
                ", not this server (" + ip_to_string(config.server_ip_net) +
                "). Ignoring.");
            return;
        }
    }  // Если опции нет, но RELEASE пришел юникастом на наш IP, то
       // обрабатываем.

    auto lease_it = leased_ips.find(client_mac_str);
    if (lease_it != leased_ips.end() &&
        lease_it->second.ip_address == client_ip_to_release) {
        log("Releasing IP " + ip_to_string(client_ip_to_release) + " for MAC " +
            client_mac_str);
        leased_ips.erase(lease_it);
        last_discover_xids.erase(
            client_mac_str);  // Также очищаем историю XID для этого MAC
        offered_ips.erase(
            ntohl(request->xid));  // И офферы, если вдруг были с этим XID
    } else {
        log("DHCPRELEASE from " + client_mac_str + " for IP " +
            ip_to_string(client_ip_to_release) +
            ", but no matching active lease found. Ignoring.");
    }
}

void DHCPServer::run() {
    if (sock_fd < 0) {
        log("Server not initialized properly.");
        return;
    }
    log("DHCP Server started. Waiting for messages on port " +
        std::to_string(DHCP_SERVER_PORT) + "...");

    uint8_t buffer[1500];
    struct sockaddr_in client_addr_from_run;
    socklen_t client_addr_len_run = sizeof(client_addr_from_run);

    std::chrono::steady_clock::time_point last_cleanup_time =
        std::chrono::steady_clock::now();
    const std::chrono::seconds cleanup_interval(15);

    while (true) {
        auto now = std::chrono::steady_clock::now();
        if (now - last_cleanup_time >= cleanup_interval) {
            // log("Performing periodic cleanup of leases and offers...");
            cleanup_expired_leases_and_offers();
            last_cleanup_time = now;
        }

        struct timeval tv;
        tv.tv_sec = 5;  // Таймаут для recvfrom
        tv.tv_usec = 0;
        if (setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
            perror("DHCPServer::run - setsockopt SO_RCVTIMEO failed");
            std::this_thread::sleep_for(std::chrono::seconds(1));
            continue;
        }

        ssize_t recv_len = recvfrom(sock_fd, buffer, sizeof(buffer), 0,
                                    (struct sockaddr*)&client_addr_from_run,
                                    &client_addr_len_run);

        if (recv_len < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;  // Таймаут
            }
            perror("DHCPServer::run - recvfrom failed");
            std::this_thread::sleep_for(std::chrono::seconds(1));
            continue;
        }

        char client_ip_str_display[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr_from_run.sin_addr,
                  client_ip_str_display, INET_ADDRSTRLEN);
        log("Received " + std::to_string(recv_len) + " bytes from " +
            client_ip_str_display + ":" +
            std::to_string(ntohs(client_addr_from_run.sin_port)));

        process_packet(buffer, static_cast<size_t>(recv_len),
                       client_addr_from_run);
        log("----------------------------------------");
    }
}
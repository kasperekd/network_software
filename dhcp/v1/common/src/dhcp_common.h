#ifndef DHCP_COMMON_H
#define DHCP_COMMON_H

#include <cstdint>
#include <string>
#include <vector>
#include <cstring> 
#include <arpa/inet.h> 
#include <sstream>   
#include <iomanip>   
#include <algorithm> 
#include <cstddef>   

#pragma pack(push, 1)
struct dhcp_packet {
    uint8_t op;
    uint8_t htype;
    uint8_t hlen;
    uint8_t hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    uint32_t ciaddr;
    uint32_t yiaddr;
    uint32_t siaddr;
    uint32_t giaddr;
    uint8_t chaddr[16];
    uint8_t sname[64];
    uint8_t file[128];
    uint8_t magic_cookie[4];
    uint8_t options[308]; 
};
#pragma pack(pop)


enum DhcpOption : uint8_t { 
    Pad = 0,
    SubnetMask = 1,
    Router = 3,
    DNS = 6,
    HostName = 12, 
    DomainName = 15, 
    RequestedIP = 50,
    LeaseTime = 51,
    MessageType = 53,
    ServerIdentifier = 54,
    ParameterRequestList = 55, 
    End = 255
};

enum DhcpMessageType : uint8_t { 
    DHCPDISCOVER = 1,
    DHCPOFFER = 2,
    DHCPREQUEST = 3,
    DHCPDECLINE = 4,
    DHCPACK = 5,
    DHCPNAK = 6,
    DHCPRELEASE = 7,
    DHCPINFORM = 8
};

// --- Constants ---
const int DHCP_SERVER_PORT = 67;
const int DHCP_CLIENT_PORT = 68;
const uint8_t DHCP_MAGIC_COOKIE[] = {99, 130, 83, 99};
const uint16_t BOOTP_BROADCAST = 0x8000;

inline std::string ip_to_string(uint32_t ip_net_order) {
    struct in_addr addr;
    addr.s_addr = ip_net_order;
    return inet_ntoa(addr);
}

inline uint32_t string_to_ip(const std::string& ip_str) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str.c_str(), &addr) <= 0) {
        return 0;
    }
    return addr.s_addr;
}

inline std::string mac_to_string(const uint8_t* mac_array) {
    std::stringstream ss;
    for (int i = 0; i < 6; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(mac_array[i]);
        if (i < 5) ss << ":";
    }
    return ss.str();
}

inline bool string_to_mac(const std::string& mac_str, uint8_t* mac_array) {
    if (sscanf(mac_str.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &mac_array[0], &mac_array[1], &mac_array[2],
               &mac_array[3], &mac_array[4], &mac_array[5]) == 6) {
        return true;
    }
    if (mac_str.length() == 12) {
         bool success = true;
         for(int i=0; i < 6; ++i) {
             std::string byte_str = mac_str.substr(i*2, 2);
             char* end_ptr;
             long val = strtol(byte_str.c_str(), &end_ptr, 16);
             if (*end_ptr != '\0' || val < 0 || val > 255) {
                 success = false;
                 break;
             }
             mac_array[i] = static_cast<uint8_t>(val);
         }
         if(success) return true;
    }
    memset(mac_array, 0, 6);
    return false;
}

#endif // DHCP_COMMON_H
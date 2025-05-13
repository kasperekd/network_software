#include "dhcp_server.h"
#include <iostream>
#include <string>

int main(int argc, char* argv[]) {
    std::string config_file = "server.conf"; 
    if (argc > 1) {
        config_file = argv[1];
        std::cout << "[MAIN SERVER] Using config file from argument: " << config_file << std::endl;
    } else {
        std::cout << "[MAIN SERVER] No config file argument provided, using default '" << config_file << "'" << std::endl;
    }

    DHCPServer server_instance;

    if (!server_instance.initialize(config_file)) {
        std::cerr << "[MAIN SERVER] Failed to initialize DHCP server with config " << config_file << ". Exiting." << std::endl;
        return 1;
    }

    server_instance.run(); 

    return 0;
}
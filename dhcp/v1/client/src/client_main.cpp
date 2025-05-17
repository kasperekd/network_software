#include "dhcp_client.h" 
#include <iostream>      
#include <string>

int main(int argc, char* argv[]) {
    std::string config_file = "client.conf";
    if (argc > 1) {
        config_file = argv[1]; 
        std::cout << "[MAIN CLIENT] Using config file from argument: " << config_file << std::endl;
    } else {
        std::cout << "[MAIN CLIENT] No config file argument provided, using default '" << config_file << "'" << std::endl;
    }

    DHCPClient client_instance; 

    if (!client_instance.load_config_and_init_mac(config_file)) {
        std::cerr << "[MAIN CLIENT] Failed to load client configuration from " << config_file << ". Exiting." << std::endl;
        return 1;
    }

    if (!client_instance.initialize_socket()) {
        std::cerr << "[MAIN CLIENT] Failed to initialize client socket. Exiting." << std::endl;
        return 1;
    }

    client_instance.run();

    return 0;
}
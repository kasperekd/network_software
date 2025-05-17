#ifndef COMMON_CONFIG_PARSER_H
#define COMMON_CONFIG_PARSER_H

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <string>

static inline std::string trim_string(const std::string& s) {
    auto wsfront = std::find_if_not(s.begin(), s.end(),
                                    [](int c) { return std::isspace(c); });
    auto wsback = std::find_if_not(s.rbegin(), s.rend(), [](int c) {
                      return std::isspace(c);
                  }).base();
    return (wsback <= wsfront ? std::string() : std::string(wsfront, wsback));
}

static std::map<std::string, std::string> parse_config_file(
    const std::string& filename) {
    std::map<std::string, std::string> config_map;
    std::ifstream config_file(filename);

    if (!config_file.is_open()) {
        std::cerr << "[CONFIG_PARSER] Error: Could not open config file: "
                  << filename << std::endl;
        return config_map;
    }

    std::string line;
    int line_number = 0;
    while (std::getline(config_file, line)) {
        line_number++;
        line = trim_string(line);

        if (line.empty() || line[0] == '#' || line[0] == ';') {
            continue;
        }

        std::size_t delimiter_pos = line.find('=');
        if (delimiter_pos == std::string::npos) {
            std::cerr << "[CONFIG_PARSER] Warning: Invalid line in " << filename
                      << " (line " << line_number << "): " << line
                      << " (missing '=')" << std::endl;
            continue;
        }

        std::string key = trim_string(line.substr(0, delimiter_pos));
        std::string value = trim_string(line.substr(delimiter_pos + 1));

        if (key.empty()) {
            std::cerr << "[CONFIG_PARSER] Warning: Empty key in " << filename
                      << " (line " << line_number << "): " << line << std::endl;
            continue;
        }

        config_map[key] = value;
    }

    config_file.close();
    return config_map;
}

static std::string get_config_string(
    const std::map<std::string, std::string>& config_map,
    const std::string& key, const std::string& default_value) {
    auto it = config_map.find(key);
    if (it != config_map.end()) {
        return it->second;
    }
    return default_value;
}

static int get_config_int(const std::map<std::string, std::string>& config_map,
                          const std::string& key, int default_value) {
    auto it = config_map.find(key);
    if (it != config_map.end()) {
        try {
            return std::stoi(it->second);
        } catch (const std::invalid_argument& ia) {
            std::cerr
                << "[CONFIG_PARSER] Warning: Invalid integer value for key '"
                << key << "': " << it->second << ". Using default."
                << std::endl;
        } catch (const std::out_of_range& oor) {
            std::cerr << "[CONFIG_PARSER] Warning: Integer value out of range "
                         "for key '"
                      << key << "': " << it->second << ". Using default."
                      << std::endl;
        }
    }
    return default_value;
}

static uint32_t get_config_uint32(
    const std::map<std::string, std::string>& config_map,
    const std::string& key, uint32_t default_value) {
    auto it = config_map.find(key);
    if (it != config_map.end()) {
        try {
            unsigned long val = std::stoul(it->second);
            if (val > UINT32_MAX) {
                std::cerr << "[CONFIG_PARSER] Warning: Uint32 value out of "
                             "range for key '"
                          << key << "': " << it->second << ". Using default."
                          << std::endl;
                return default_value;
            }
            return static_cast<uint32_t>(val);
        } catch (const std::invalid_argument& ia) {
            std::cerr
                << "[CONFIG_PARSER] Warning: Invalid uint32 value for key '"
                << key << "': " << it->second << ". Using default."
                << std::endl;
        } catch (const std::out_of_range& oor) {
            std::cerr << "[CONFIG_PARSER] Warning: Uint32 value out of range "
                         "for key '"
                      << key << "': " << it->second << ". Using default."
                      << std::endl;
        }
    }
    return default_value;
}

#endif  // COMMON_CONFIG_PARSER_H
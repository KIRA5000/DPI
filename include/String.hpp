#pragma once

#include <string>
#include <vector>
#include <sstream>
#include <cstdint>

#include <arpa/inet.h> 

class StringOperations {
    StringOperations() = default;
    StringOperations(const StringOperations&) = delete;
    StringOperations& operator=(const StringOperations&) = delete;

public:

    static StringOperations& getInstance() {
        static StringOperations instance;
        return instance;
    }

    std::vector<std::string> parse(const std::string& str, char delimiter) {
        std::vector<std::string> tokens;
        std::string token;
        std::istringstream tokenStream(str);

        while (std::getline(tokenStream, token, delimiter)) {
            tokens.push_back(token);
        }
        return tokens;
    }

    std::string decIPv4ToString(uint32_t ip) {
        char buf[16];
        snprintf(buf, sizeof(buf), "%u.%u.%u.%u", (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);

        return std::string(buf);
    }

    std::string decIPv6ToString(const uint8_t addr[16]) {
        char buf[INET6_ADDRSTRLEN];
        const void* src = static_cast<const void*>(addr);

        if (inet_ntop(AF_INET6, src, buf, sizeof(buf)) == nullptr) {
            throw std::system_error(errno, std::generic_category(), "inet_ntop(AF_INET6) failed");
        }

        return std::string(buf);
    }
};
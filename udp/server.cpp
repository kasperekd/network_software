#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <sstream>
#include <thread>
#include <unordered_map>
#include <vector>

#include "crc32.h"

#define RESET "\033[0m"
#define RED "\033[31m"
#define GREEN "\033[32m"
#define YELLOW "\033[33m"
#define BLUE "\033[34m"
#define CYAN "\033[36m"

namespace fs = std::filesystem;

struct PacketHeader {
    uint32_t packetNumber;
    uint32_t totalPackets;
    uint32_t dataSize;
    uint32_t crc32;
};

struct ClientID {
    std::string ip;
    uint16_t port;
    bool operator==(const ClientID& other) const {
        return ip == other.ip && port == other.port;
    }
};

struct ClientIDHash {
    size_t operator()(const ClientID& id) const {
        return std::hash<std::string>()(id.ip) ^
               (std::hash<uint16_t>()(id.port) << 16);
    }
};

struct ClientState {
    std::vector<std::vector<char>> packets;
    std::string filename;
    uint32_t totalPackets = 0;
    size_t totalDataSize = 0;
    std::chrono::steady_clock::time_point startTime;
    int droppedPackets = 0;
    int crcErrors = 0;
    std::vector<std::string> errorBuffer;
    // FIXME Не всегда получается удачным вариантом, но пока можно оставить
    int displayLine = -1;
};

class UDPServer {
   public:
    UDPServer(int lossCount, const std::vector<uint32_t>& lossPackets)
        : lossPackets(lossPackets) {
        lossCounters.resize(lossPackets.size(), 1);
    }
    ~UDPServer() {
        stopProgress = true;
        if (progressThread.joinable()) {
            progressThread.join();
        }
        close(sockfd);
    }

    void run() {
        sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        if (sockfd < 0) throw std::runtime_error("Socket creation failed");

        sockaddr_in serverAddr{};
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_addr.s_addr = INADDR_ANY;
        serverAddr.sin_port = htons(0);

        if (bind(sockfd, reinterpret_cast<sockaddr*>(&serverAddr),
                 sizeof(serverAddr)) < 0)
            throw std::runtime_error("Bind failed");

        socklen_t addrLen = sizeof(serverAddr);
        getsockname(sockfd, reinterpret_cast<sockaddr*>(&serverAddr), &addrLen);
        std::cout << "Server started on port: " << ntohs(serverAddr.sin_port)
                  << std::endl;

        startProgressThread();  // поток с прогресс баром

        while (true) {
            char buffer[65536];
            sockaddr_in clientAddr{};
            socklen_t clientAddrLen = sizeof(clientAddr);
            ssize_t recvLen = recvfrom(sockfd, buffer, sizeof(buffer), 0,
                                       reinterpret_cast<sockaddr*>(&clientAddr),
                                       &clientAddrLen);

            if (recvLen < (ssize_t)sizeof(PacketHeader)) continue;

            PacketHeader* header = reinterpret_cast<PacketHeader*>(buffer);
            char* data = buffer + sizeof(PacketHeader);
            size_t dataSize = recvLen - sizeof(PacketHeader);

            uint32_t receivedCRC = header->crc32;
            uint32_t calculatedCRC = calculateCRC32(data, header->dataSize);
            if (receivedCRC != calculatedCRC) {
                std::lock_guard<std::mutex> lock(clientsMutex);
                auto& state = clients[{inet_ntoa(clientAddr.sin_addr),
                                       ntohs(clientAddr.sin_port)}];
                state.crcErrors++;
                state.errorBuffer.push_back(
                    RED + std::string("[ERROR] CRC mismatch in packet ") +
                    std::to_string(header->packetNumber) + " | CRC errors: " +
                    std::to_string(state.crcErrors) + RESET);
                continue;
            }

            std::string clientIP(inet_ntoa(clientAddr.sin_addr));
            uint16_t clientPort = ntohs(clientAddr.sin_port);
            ClientID clientID = {clientIP, clientPort};

            std::lock_guard<std::mutex> lock(clientsMutex);
            auto& state = clients[clientID];

            if (state.packets.empty()) {
                state.packets.resize(header->totalPackets);
                state.totalPackets = header->totalPackets;
                state.filename = "received_file";
                state.startTime = std::chrono::steady_clock::now();
                state.totalDataSize = 0;
                state.droppedPackets = 0;
                state.crcErrors = 0;
                state.errorBuffer.clear();
                std::cerr << "\n"
                          << GREEN << "Started receiving file from " << clientIP
                          << ":" << clientPort << " (" << header->totalPackets
                          << " packets)" << RESET << "\n";
            }

            if (header->packetNumber >= state.totalPackets) continue;

            if (!state.packets[header->packetNumber].empty()) {
                sendACK(clientAddr, header->packetNumber);
                continue;
            }

            bool dropPacket = false;
            for (size_t i = 0; i < lossPackets.size(); ++i) {
                if (lossPackets[i] == header->packetNumber &&
                    lossCounters[i] > 0) {
                    lossCounters[i]--;
                    dropPacket = true;
                    break;
                }
            }

            if (dropPacket) {
                state.droppedPackets++;
                state.errorBuffer.push_back(
                    YELLOW + std::string("[DROPPED] Packet ") +
                    std::to_string(header->packetNumber) +
                    " (as per loss rule) | Dropped total: " +
                    std::to_string(state.droppedPackets) + RESET);
                continue;
            }

            state.packets[header->packetNumber].assign(data,
                                                       data + header->dataSize);
            state.totalDataSize += header->dataSize;
            sendACK(clientAddr, header->packetNumber);

            bool complete = true;
            for (const auto& pkt : state.packets) {
                if (pkt.empty()) {
                    complete = false;
                    break;
                }
            }

            if (complete) {
                std::string clientPortS = std::to_string(clientPort);
                fs::path outputFilename =
                    fs::path(state.filename).filename().string() + "_from_" +
                    clientIP + " " + clientPortS;
                std::ofstream outFile(outputFilename, std::ios::binary);
                for (const auto& pkt : state.packets) {
                    outFile.write(pkt.data(), pkt.size());
                }

                // Ожидаем завершения отрисовки, чтобы не пересеклись строки
                std::unique_lock<std::mutex> lock(clientsMutex);
                auto now = std::chrono::steady_clock::now();
                double totalTimeSec =
                    std::chrono::duration<double>(now - state.startTime)
                        .count();
                double finalSpeedMBps =
                    (state.totalDataSize / 1024.0 / 1024.0) / totalTimeSec;

                // очистка строки клиента и результат
                int clientLine = state.displayLine;
                setCursorPosition(clientLine);
                std::cerr << "\033[K" << GREEN
                          << "File received successfully from " << clientIP
                          << ":" << clientPort << RESET << "\n";

                std::cerr << "\r\033[KTotal size: "
                          << (state.totalDataSize / 1024) << " KB | "
                          << "Time: " << totalTimeSec << " s | "
                          << "Final speed: " << CYAN << finalSpeedMBps << RESET
                          << " MB/s | " << YELLOW
                          << "Dropped: " << state.droppedPackets << RESET
                          << " | " << RED << "CRC errors: " << state.crcErrors
                          << RESET << "\n";

                clients.erase(clientID);
            }
        }
    }

   private:
    struct ACKPacket {
        uint32_t packetNumber;
    };

    int sockfd = -1;
    std::unordered_map<ClientID, ClientState, ClientIDHash> clients;
    std::mutex clientsMutex;

    std::vector<uint32_t> lossPackets;
    std::vector<int> lossCounters;
    int currentDisplayLine = 0;

    std::thread progressThread;
    std::atomic<bool> stopProgress{false};

    void setCursorPosition(int line) {
        std::cerr << "\033[" << line + 1 << ";0H";
    }

    void updateClientProgress(ClientState& state, int progress,
                              const std::string& bar, double avgSpeedMBps,
                              size_t totalKB, int clientLine) {
        setCursorPosition(clientLine);
        std::cerr << "\033[K";
        std::cerr << "[" << GREEN << bar << RESET << "] " << std::setw(3)
                  << progress << "% | "
                  << "Total: " << totalKB << " KB | "
                  << "Avg speed: " << CYAN << avgSpeedMBps << RESET << " MB/s";
    }

    void sendACK(const sockaddr_in& clientAddr, uint32_t packetNumber) {
        sendto(sockfd, &packetNumber, sizeof(packetNumber), 0,
               reinterpret_cast<const sockaddr*>(&clientAddr),
               sizeof(clientAddr));
    }

    void startProgressThread() {
        progressThread = std::thread([this]() {
            const int BAR_WIDTH = 40;
            while (!stopProgress) {
                std::unique_lock<std::mutex> lock(clientsMutex);
                int line = 0;

                for (auto& [id, state] : clients) {
                    size_t totalReceived = state.totalDataSize;
                    uint32_t totalPackets = state.totalPackets;
                    size_t fileSize = totalPackets * 1400;

                    if (totalPackets == 0) continue;

                    double durationSec =
                        std::chrono::duration<double>(
                            std::chrono::steady_clock::now() - state.startTime)
                            .count();
                    double speedKBps =
                        durationSec > 0 ? (totalReceived / 1024.0) / durationSec
                                        : 0;

                    int progress =
                        totalPackets > 0
                            ? static_cast<int>((state.totalDataSize /
                                                static_cast<double>(fileSize)) *
                                               100)
                            : 0;

                    int filledLength = BAR_WIDTH * progress / 100;
                    std::string bar(filledLength, '#');
                    bar.resize(BAR_WIDTH, ' ');

                    setCursorPosition(line);
                    std::cerr << "\033[K[" << GREEN << bar << RESET << "] "
                              << std::setw(3) << progress << "% | "
                              << "Total: " << (totalReceived / 1024) << " KB | "
                              << "Speed: " << CYAN << speedKBps << RESET
                              << " KB/s";

                    ++line;
                }

                lock.unlock();

                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        });
    }
};

int main(int argc, char* argv[]) {
    int lossCount = 0;
    std::vector<uint32_t> lossPackets;

    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "--loss") {
            if (i + 1 >= argc) {
                std::cerr << "Missing loss packet list after --loss\n";
                return 1;
            }
            std::istringstream iss(argv[++i]);
            std::string token;
            while (std::getline(iss, token, ',')) {
                lossPackets.push_back(std::stoul(token));
            }
        }
    }

    try {
        UDPServer server(0, lossPackets);
        server.run();
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
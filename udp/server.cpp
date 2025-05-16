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
    uint32_t receivedPacketCount = 0;
    size_t totalDataSize = 0;
    std::chrono::steady_clock::time_point startTime;
    int droppedPackets = 0;
    int crcErrors = 0;
    std::vector<std::string> errorBuffer;
    int displayLine = -1;
};

class UDPServer {
   public:
    UDPServer(int lossCount, const std::vector<uint32_t>& lossPacketsArg)
        : lossPackets(lossPacketsArg), currentDisplayLine(1) {
        lossCounters.resize(lossPackets.size(), 0);
        for (size_t i = 0; i < lossCounters.size(); ++i) lossCounters[i] = 1;
    }
    ~UDPServer() {
        stopProgress = true;
        if (progressThread.joinable()) {
            progressThread.join();
        }
        if (sockfd != -1) close(sockfd);
    }

    void run() {
        sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        if (sockfd < 0) throw std::runtime_error("Socket creation failed");

        sockaddr_in serverAddr{};
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_addr.s_addr = INADDR_ANY;
        serverAddr.sin_port = htons(0);

        if (bind(sockfd, reinterpret_cast<sockaddr*>(&serverAddr),
                 sizeof(serverAddr)) < 0) {
            close(sockfd);
            throw std::runtime_error("Bind failed");
        }

        socklen_t addrLen = sizeof(serverAddr);
        getsockname(sockfd, reinterpret_cast<sockaddr*>(&serverAddr), &addrLen);
        std::cout << "Server started on port: " << ntohs(serverAddr.sin_port)
                  << std::endl;

        startProgressThread();

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

            if (header->dataSize != (recvLen - sizeof(PacketHeader))) {
                // std::cerr << "Data size mismatch" << std::endl;
                continue;
            }

            uint32_t receivedCRC = header->crc32;
            uint32_t calculatedCRC = calculateCRC32(data, header->dataSize);

            std::string clientIP(inet_ntoa(clientAddr.sin_addr));
            uint16_t clientPort = ntohs(clientAddr.sin_port);
            ClientID clientID = {clientIP, clientPort};

            std::unique_lock<std::mutex> lock(clientsMutex);
            auto& state = clients[clientID];

            if (receivedCRC != calculatedCRC) {
                if (!state.packets
                         .empty()) {  // Только если уже начали получать
                    state.crcErrors++;
                    state.errorBuffer.push_back(
                        RED + std::string("[ERROR] CRC mismatch in packet ") +
                        std::to_string(header->packetNumber) +
                        " | CRC errors: " + std::to_string(state.crcErrors) +
                        RESET);
                }
                continue;
            }

            if (state.packets.empty() && header->totalPackets > 0) {
                state.packets.resize(header->totalPackets);
                state.totalPackets = header->totalPackets;
                state.filename = "received_file";
                state.startTime = std::chrono::steady_clock::now();
                state.totalDataSize = 0;
                state.receivedPacketCount = 0;
                state.droppedPackets = 0;
                state.crcErrors = 0;
                state.errorBuffer.clear();
                state.displayLine = this->currentDisplayLine++;

                setCursorPosition(state.displayLine);
                std::cerr << "\033[K" << GREEN << "Client " << clientIP << ":"
                          << clientPort << " | Receiving " << state.filename
                          << " (" << header->totalPackets << " packets)"
                          << RESET << std::flush;
            }

            if (header->packetNumber >= state.totalPackets ||
                state.totalPackets == 0) {
                // Пакет вне диапазона или клиент еще не инициализирован
                sendACK(clientAddr,
                        header->packetNumber);  // Отправить ACK на всякий
                                                // случай, если это дубликат
                continue;
            }

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
                    " (rule) | Dropped: " +
                    std::to_string(state.droppedPackets) + RESET);
                continue;
            }

            state.packets[header->packetNumber].assign(data,
                                                       data + header->dataSize);
            state.totalDataSize += header->dataSize;
            state.receivedPacketCount++;
            sendACK(clientAddr, header->packetNumber);

            if (state.receivedPacketCount == state.totalPackets) {
                bool complete =
                    true;  // Дополнительная проверка, хотя receivedPacketCount
                           // должно быть достаточно
                for (const auto& pkt : state.packets) {
                    if (pkt.empty()) {
                        complete = false;
                        break;
                    }
                }

                if (complete) {
                    fs::path baseFilename = fs::path(state.filename).filename();
                    std::string finalFilenameStr = baseFilename.string() +
                                                   "_from_" + clientIP + "_" +
                                                   std::to_string(clientPort);
                    if (baseFilename.has_extension()) {
                        finalFilenameStr = baseFilename.stem().string() +
                                           "_from_" + clientIP + "_" +
                                           std::to_string(clientPort) +
                                           baseFilename.extension().string();
                    }

                    std::ofstream outFile(finalFilenameStr, std::ios::binary);
                    if (outFile.is_open()) {
                        for (const auto& pkt : state.packets) {
                            outFile.write(pkt.data(), pkt.size());
                        }
                        outFile.close();
                    } else {
                        state.errorBuffer.push_back(
                            RED + std::string("Failed to open output file: ") +
                            finalFilenameStr + RESET);
                    }

                    auto now = std::chrono::steady_clock::now();
                    double totalTimeSec =
                        std::chrono::duration<double>(now - state.startTime)
                            .count();
                    double finalSpeedMBps = 0;
                    if (totalTimeSec > 0) {
                        finalSpeedMBps =
                            (state.totalDataSize / 1024.0 / 1024.0) /
                            totalTimeSec;
                    }

                    int clientLine = state.displayLine;
                    setCursorPosition(clientLine);
                    std::cerr << "\033[K" << GREEN << "File "
                              << finalFilenameStr << " received from "
                              << clientIP << ":" << clientPort << RESET << "\n";

                    std::cerr << "Total size: " << (state.totalDataSize / 1024)
                              << " KB | "
                              << "Time: " << std::fixed << std::setprecision(2)
                              << totalTimeSec << " s | "
                              << "Speed: " << CYAN << std::fixed
                              << std::setprecision(2) << finalSpeedMBps << RESET
                              << " MB/s | " << YELLOW
                              << "Dropped: " << state.droppedPackets << RESET
                              << " | " << RED << "CRC: " << state.crcErrors
                              << RESET << "\n";

                    if (!state.errorBuffer.empty()) {
                        std::cerr << "Log for " << clientIP << ":" << clientPort
                                  << ":\n";
                        for (const auto& errMsg : state.errorBuffer) {
                            std::cerr << errMsg << "\n";
                        }
                    }
                    clients.erase(clientID);
                }
            }
            // lock будет освобожден при выходе из области видимости
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
    int currentDisplayLine;

    std::thread progressThread;
    std::atomic<bool> stopProgress{false};

    void setCursorPosition(int line) {
        if (line >= 0) {
            std::cerr << "\033[" << line + 1 << ";0H";
        }
    }

    void sendACK(const sockaddr_in& clientAddr, uint32_t packetNumber) {
        ACKPacket ack;
        ack.packetNumber = packetNumber;
        sendto(sockfd, &packetNumber, sizeof(packetNumber), 0,
               reinterpret_cast<const sockaddr*>(&clientAddr),
               sizeof(clientAddr));
    }

    void startProgressThread() {
        progressThread = std::thread([this] {
            const int BAR_WIDTH = 40;
            while (!stopProgress) {
                std::unique_lock<std::mutex> lock(clientsMutex);

                for (auto it = clients.begin(); it != clients.end(); ++it) {
                    ClientState& state = it->second;
                    const ClientID& id = it->first;

                    if (state.displayLine == -1 || state.totalPackets == 0)
                        continue;

                    // receivedPacketCount уже обновляется в основном потоке
                    uint32_t pktsReceived = state.receivedPacketCount;

                    double durationSec =
                        std::chrono::duration<double>(
                            std::chrono::steady_clock::now() - state.startTime)
                            .count();
                    double speedKBps = 0;
                    if (durationSec > 0.01) {
                        speedKBps =
                            (state.totalDataSize / 1024.0) / durationSec;
                    }

                    int progressPercent = static_cast<int>(
                        (static_cast<double>(pktsReceived) * 100.0) /
                        state.totalPackets);
                    progressPercent =
                        std::min(100, std::max(0, progressPercent));

                    int filledLength = BAR_WIDTH * progressPercent / 100;
                    std::string bar(filledLength, '#');
                    bar.resize(BAR_WIDTH, ' ');

                    setCursorPosition(state.displayLine);
                    std::cerr << "\033[K";
                    std::cerr
                        << "[" << GREEN << bar << RESET << "] " << std::setw(3)
                        << progressPercent << "% | Pkts: " << pktsReceived
                        << "/" << state.totalPackets
                        << " | Total: " << std::setw(7)
                        << (state.totalDataSize / 1024) << " KB | "
                        << "Speed: " << CYAN << std::fixed
                        << std::setprecision(2) << std::setw(7) << speedKBps
                        << RESET << " KB/s" << std::flush;
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
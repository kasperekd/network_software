#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <thread>
#include <vector>

#include "crc32.h"

#define RESET "\033[0m"
#define GREEN "\033[32m"
#define CYAN "\033[36m"

struct PacketHeader {
    uint32_t packetNumber;
    uint32_t totalPackets;
    uint32_t dataSize;
    uint32_t crc32;
};

uint32_t calculateCRC32(const char* data, size_t length);

class UDPClient {
   public:
    UDPClient(const std::string& serverIP, int serverPort) {
        sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        if (sockfd < 0) {
            throw std::runtime_error("Socket creation failed");
        }

        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(serverPort);
        if (inet_pton(AF_INET, serverIP.c_str(), &serverAddr.sin_addr) <= 0) {
            close(sockfd);
            throw std::runtime_error("Invalid address");
        }
    }

    ~UDPClient() { close(sockfd); }

    void sendFile(const std::string& filePath, int delayMs) {
        std::ifstream file(filePath, std::ios::binary);
        if (!file) {
            throw std::runtime_error("Failed to open file");
        }

        file.seekg(0, std::ios::end);
        size_t fileSize = file.tellg();
        file.seekg(0, std::ios::beg);

        const size_t maxDataSize = 1400 - sizeof(PacketHeader);
        size_t totalPackets = (fileSize + maxDataSize - 1) / maxDataSize;

        std::vector<std::vector<char>> packets(totalPackets);
        std::vector<bool> ackReceived(totalPackets, false);
        size_t remaining = totalPackets;

        for (size_t i = 0; i < totalPackets; ++i) {
            packets[i].resize(
                std::min(maxDataSize, fileSize - i * maxDataSize));
            file.read(packets[i].data(), packets[i].size());
        }

        const int BAR_WIDTH = 40;
        auto startTime = std::chrono::steady_clock::now();
        size_t totalSent = 0;
        std::mutex mtx;

        std::cerr << "Sending file '" << filePath << "' to "
                  << inet_ntoa(serverAddr.sin_addr) << ":"
                  << ntohs(serverAddr.sin_port) << "\n";

        std::thread progressThread([&]() {
            while (remaining > 0) {
                std::lock_guard<std::mutex> lock(mtx);
                double durationSec =
                    std::chrono::duration<double>(
                        std::chrono::steady_clock::now() - startTime)
                        .count();

                size_t currentSent = (totalPackets - remaining) * maxDataSize;
                double speedMBps =
                    (currentSent / 1024.0 / 1024.0) / durationSec;

                int progress = static_cast<int>((currentSent * 100) / fileSize);
                int filledLength = BAR_WIDTH * progress / 100;
                std::string bar(filledLength, '#');
                bar.resize(BAR_WIDTH, ' ');

                std::cerr << "\r[" << GREEN << bar << RESET << "] "
                          << std::setw(3) << progress << "% | "
                          << "Total: " << (currentSent / 1024) << " KB | "
                          << "Speed: " << CYAN << speedMBps << RESET
                          << " MB/s     ";
                std::cerr.flush();

                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }

            {
                std::lock_guard<std::mutex> lock(mtx);
                size_t currentSent = fileSize;
                double durationSec =
                    std::chrono::duration<double>(
                        std::chrono::steady_clock::now() - startTime)
                        .count();
                double speedMBps =
                    (currentSent / 1024.0 / 1024.0) / durationSec;

                int progress = 100;
                std::string bar(BAR_WIDTH, '#');

                std::cerr << "\r[" << GREEN << bar << RESET << "] "
                          << std::setw(3) << progress << "% | "
                          << "Total: " << (currentSent / 1024) << " KB | "
                          << "Speed: " << CYAN << speedMBps << RESET
                          << " MB/s     ";
                std::cerr.flush();
            }

            std::cerr << "\nFile sent successfully." << std::endl;
        });

        progressThread.detach();

        std::mutex ackMutex;
        std::condition_variable cv;
        std::thread ackThread([&]() {
            char ackBuffer[sizeof(uint32_t)];
            sockaddr_in fromAddr{};
            socklen_t fromAddrLen = sizeof(fromAddr);
            while (remaining > 0) {
                ssize_t recvLen = recvfrom(
                    sockfd, ackBuffer, sizeof(ackBuffer), 0,
                    reinterpret_cast<sockaddr*>(&fromAddr), &fromAddrLen);
                if (recvLen == sizeof(uint32_t)) {
                    uint32_t ackNumber =
                        *reinterpret_cast<uint32_t*>(ackBuffer);
                    if (ackNumber < totalPackets) {
                        std::lock_guard<std::mutex> lock(ackMutex);
                        if (!ackReceived[ackNumber]) {
                            ackReceived[ackNumber] = true;
                            --remaining;
                        }
                    }
                }
            }
            cv.notify_all();
        });

        ackThread.detach();

        while (remaining > 0) {
            for (size_t i = 0; i < totalPackets; ++i) {
                if (!ackReceived[i]) {
                    sendPacket(i, totalPackets, packets[i]);
                    // FIXME Я не проверял, но может вообще стоит вынести в
                    // условие, чтоб если у нас нулевая задержка, мы не заходили
                    // в функцию вообще
                    std::this_thread::sleep_for(
                        std::chrono::milliseconds(delayMs));
                }
            }
        }

        {
            std::unique_lock<std::mutex> lock(ackMutex);
            cv.wait_for(lock, std::chrono::seconds(1));  // Ждём завершения
        }

        if (ackThread.joinable()) ackThread.join();
        if (progressThread.joinable()) progressThread.join();
    }

   private:
    int sockfd;
    sockaddr_in serverAddr;

    void sendPacket(size_t packetNumber, size_t totalPackets,
                    const std::vector<char>& data) {
        PacketHeader header;
        header.packetNumber = packetNumber;
        header.totalPackets = totalPackets;
        header.dataSize = data.size();
        header.crc32 = calculateCRC32(data.data(), data.size());

        std::vector<char> packet(sizeof(PacketHeader) + data.size());
        std::memcpy(packet.data(), &header, sizeof(PacketHeader));
        std::memcpy(packet.data() + sizeof(PacketHeader), data.data(),
                    data.size());

        sendto(sockfd, packet.data(), packet.size(), 0,
               reinterpret_cast<sockaddr*>(&serverAddr), sizeof(serverAddr));
    }
};

int main(int argc, char* argv[]) {
    if (argc < 4 || argc > 5) {
        std::cerr << "Usage: client <server_ip> <server_port> <file_path> "
                     "[delay_ms]\n";
        return 1;
    }

    std::string serverIP = argv[1];
    int serverPort = std::stoi(argv[2]);
    std::string filePath = argv[3];
    int delayMs = 0;

    if (argc == 5) {
        delayMs = std::stoi(argv[4]);
        if (delayMs < 0) {
            std::cerr << "Delay must be non-negative\n";
            return 1;
        }
    }

    try {
        UDPClient client(serverIP, serverPort);
        client.sendFile(filePath, delayMs);
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
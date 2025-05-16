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

        std::vector<std::vector<char>> packetsData(totalPackets);
        std::vector<bool> ackReceived(totalPackets, false);
        std::atomic<size_t> remainingPackets{totalPackets};
        std::atomic<bool> transferDone{false};

        for (size_t i = 0; i < totalPackets; ++i) {
            packetsData[i].resize(
                std::min(maxDataSize, fileSize - (i * maxDataSize)));
            file.read(packetsData[i].data(), packetsData[i].size());
        }
        file.close();

        const int BAR_WIDTH = 40;
        auto startTime = std::chrono::steady_clock::now();

        std::cerr << "Sending file '" << filePath << "' to "
                  << inet_ntoa(serverAddr.sin_addr) << ":"
                  << ntohs(serverAddr.sin_port) << "\n";

        std::thread progressThread([&]() {
            size_t lastRemaining = totalPackets + 1;
            double lastSpeedMBps = 0.0;
            size_t lastSentKB = 0;
            int lastProgress = -1;

            while (true) {
                size_t currentRemaining = remainingPackets.load();
                bool done = transferDone.load();

                size_t packetsConfirmed = totalPackets - currentRemaining;
                size_t currentSentBytes = 0;
                if (totalPackets > 0) {
                    (packetsConfirmed * fileSize) / totalPackets;
                    if (currentRemaining == 0) {
                        currentSentBytes = fileSize;
                    }
                }

                double durationSec =
                    std::chrono::duration<double>(
                        std::chrono::steady_clock::now() - startTime)
                        .count();

                double speedMBps = 0;
                if (durationSec > 0.01) {
                    speedMBps =
                        (currentSentBytes / 1024.0 / 1024.0) / durationSec;
                } else {
                    speedMBps = lastSpeedMBps;
                }
                lastSpeedMBps = speedMBps;

                int progress = 0;
                if (fileSize > 0) {
                    progress = static_cast<int>(
                        (static_cast<double>(currentSentBytes) * 100.0) /
                        fileSize);
                } else if (totalPackets == 0) {
                    progress = 100;
                }
                progress = std::min(100, std::max(0, progress));

                size_t currentSentKB = currentSentBytes / 1024;

                if (progress != lastProgress || currentSentKB != lastSentKB ||
                    (done && currentRemaining == 0)) {
                    int filledLength = BAR_WIDTH * progress / 100;
                    std::string bar(filledLength, '#');
                    bar.resize(BAR_WIDTH, ' ');

                    std::cerr << "\r[" << GREEN << bar << RESET << "] "
                              << std::setw(3) << progress << "% | "
                              << "Total: " << std::setw(7) << currentSentKB
                              << " KB | "
                              << "Speed: " << CYAN << std::fixed
                              << std::setprecision(2) << std::setw(7)
                              << speedMBps << RESET << " MB/s     "
                              << std::flush;
                    lastProgress = progress;
                    lastSentKB = currentSentKB;
                }

                if (done && currentRemaining == 0) break;

                if (done && currentRemaining != 0 &&
                    lastRemaining == currentRemaining) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(200));
                    if (transferDone.load() &&
                        remainingPackets.load() == lastRemaining)
                        break;
                }
                lastRemaining = currentRemaining;
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }

            double finalDurationSec =
                std::chrono::duration<double>(std::chrono::steady_clock::now() -
                                              startTime)
                    .count();
            double finalSpeedMBps = 0;
            if (finalDurationSec > 0) {
                finalSpeedMBps =
                    (fileSize / 1024.0 / 1024.0) / finalDurationSec;
            }

            std::string finalBar(BAR_WIDTH, '#');
            std::cerr << "\r[" << GREEN << finalBar << RESET << "] "
                      << std::setw(3) << 100 << "% | "
                      << "Total: " << std::setw(7) << (fileSize / 1024)
                      << " KB | "
                      << "Speed: " << CYAN << std::fixed << std::setprecision(2)
                      << std::setw(7) << finalSpeedMBps << RESET << " MB/s     "
                      << std::flush;

            if (remainingPackets.load() == 0) {
                std::cerr << "\nFile sent successfully." << std::endl;
            } else {
                std::cerr << "\nFile transfer incomplete. "
                          << remainingPackets.load() << " packets not ACKed."
                          << std::endl;
            }
        });

        std::mutex ackMutex;
        std::condition_variable cv;

        std::thread ackThread([&]() {
            char ackBuffer[sizeof(uint32_t)];
            sockaddr_in fromAddr{};
            socklen_t fromAddrLen = sizeof(fromAddr);

            struct timeval tv;
            tv.tv_sec = 1;
            tv.tv_usec = 0;
            if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv,
                           sizeof tv) < 0) {
                perror("setsockopt SO_RCVTIMEO failed for ACK");
                transferDone.store(true);
                cv.notify_all();
                return;
            }

            while (remainingPackets.load() > 0 && !transferDone.load()) {
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
                            if (remainingPackets.load() > 0) remainingPackets--;
                            cv.notify_one();
                        }
                    }
                } else if (recvLen < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        continue;
                    }
                    perror("recvfrom error in ackThread");
                    transferDone.store(true);
                    cv.notify_all();
                    break;
                }
            }
            if (remainingPackets.load() == 0 && !transferDone.load()) {
                transferDone.store(true);
                cv.notify_all();
            }
        });

        int noAckRetryCount = 0;
        const int MAX_NO_ACK_RETRIES = 20;
        const int RETRANSMIT_BATCH_SIZE = (totalPackets / 20) + 1;

        while (remainingPackets.load() > 0 && !transferDone.load()) {
            size_t remainingBeforeSendCycle = remainingPackets.load();
            bool packetSentThisCycle = false;
            int sentInBatch = 0;

            for (size_t i = 0; i < totalPackets; ++i) {
                if (transferDone.load()) break;
                bool needsAck;
                {
                    std::lock_guard<std::mutex> lock(ackMutex);
                    needsAck = !ackReceived[i];
                }
                if (needsAck) {
                    sendPacket(i, totalPackets, packetsData[i]);
                    packetSentThisCycle = true;
                    sentInBatch++;
                    if (delayMs > 0) {
                        std::this_thread::sleep_for(
                            std::chrono::milliseconds(delayMs));
                    }

                    if (sentInBatch >= RETRANSMIT_BATCH_SIZE && delayMs == 0) {
                        std::unique_lock<std::mutex> lock(ackMutex);
                        cv.wait_for(lock, std::chrono::milliseconds(10));
                        sentInBatch = 0;
                    }
                }
            }

            if (transferDone.load() || remainingPackets.load() == 0) break;

            if (packetSentThisCycle) {
                std::unique_lock<std::mutex> lock(ackMutex);
                if (cv.wait_for(lock,
                                std::chrono::milliseconds(500 + delayMs * 5)) ==
                    std::cv_status::timeout) {
                    if (remainingPackets.load() == remainingBeforeSendCycle) {
                        noAckRetryCount++;
                    } else {
                        noAckRetryCount = 0;
                    }
                } else {
                    noAckRetryCount = 0;
                }
            } else {
                std::unique_lock<std::mutex> lock(ackMutex);
                cv.wait_for(lock, std::chrono::milliseconds(200));
                if (remainingPackets.load() == 0) break;
            }

            if (noAckRetryCount > MAX_NO_ACK_RETRIES) {
                std::cerr << "\nNo ACKs received for " << noAckRetryCount
                          << " cycles. Aborting transfer." << std::endl;
                transferDone.store(true);
                cv.notify_all();
                break;
            }
        }

        transferDone.store(true);
        cv.notify_all();

        if (ackThread.joinable()) {
            ackThread.join();
        }
        if (progressThread.joinable()) {
            progressThread.join();
        }
    }

   private:
    int sockfd;
    sockaddr_in serverAddr;

    void sendPacket(size_t packetNumber, size_t totalPacketsCount,
                    const std::vector<char>& data) {
        PacketHeader header;
        header.packetNumber = static_cast<uint32_t>(packetNumber);
        header.totalPackets = static_cast<uint32_t>(totalPacketsCount);
        header.dataSize = static_cast<uint32_t>(data.size());
        header.crc32 = calculateCRC32(data.data(), data.size());

        std::vector<char> packetBuffer(sizeof(PacketHeader) + data.size());
        std::memcpy(packetBuffer.data(), &header, sizeof(PacketHeader));
        std::memcpy(packetBuffer.data() + sizeof(PacketHeader), data.data(),
                    data.size());

        sendto(sockfd, packetBuffer.data(), packetBuffer.size(), 0,
               reinterpret_cast<const sockaddr*>(&serverAddr),
               sizeof(serverAddr));
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
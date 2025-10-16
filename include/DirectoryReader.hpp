#pragma once

#include <filesystem>
#include <queue>
#include <thread>
#include <unordered_set>
#include <mutex>

std::mutex fileQueueMutex;
std::queue<std::string> fileQueue;

class DirectoryReader {
    std::unordered_set<std::string> seen;

    DirectoryReader() = default;
    DirectoryReader(const DirectoryReader&) = delete;
    DirectoryReader& operator=(const DirectoryReader&) = delete;

public:

    static DirectoryReader& getInstance() {
        static DirectoryReader instance;
        return instance;
    }

    void watchDirectory(const std::string& directoryPath) {
        while (true) {
            for (auto& entry : std::filesystem::directory_iterator(directoryPath)) {
                std::string file = entry.path().string();

                if ((seen.find(file) == seen.end()) && (entry.path().extension().string() == ".pcap")) {
                    seen.insert(file);
                    fileQueueMutex.lock();
                    fileQueue.push(file);
                    fileQueueMutex.unlock();
                }
            }

            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
};
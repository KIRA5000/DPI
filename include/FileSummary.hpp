#pragma once

#include <mutex>
#include <string>
#include <queue>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <fstream>

#include "PcapHeaders.hpp"

std::mutex summaryQueueMtx;
std::queue<PacketInfo> summaryQueue;

std::mutex fileSummaryMtx;
std::unordered_map<std::string, int> packetCount;
std::unordered_map<std::string, std::pair<long long, long long>> timestamps;
std::unordered_set<std::string> uniqueSessions;

class PacketSummary {
    std::string getKey(const PacketInfo& pInfo) {
        return pInfo.sourceIP + "," + std::to_string(pInfo.sourcePort) + "," + pInfo.destIP +  "," + std::to_string(pInfo.destPort) + "," + std::to_string(pInfo.ethType) + "," + std::to_string(pInfo.transportType);
    }

public:

    void summerize() {
        while (true) {
            PacketInfo pInfo;
            summaryQueueMtx.lock();
            if (summaryQueue.empty()) {
                summaryQueueMtx.unlock();
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }
            else {
                pInfo = summaryQueue.front();
                summaryQueue.pop();
                summaryQueueMtx.unlock();
            }

            std::string key = getKey(pInfo);

            fileSummaryMtx.lock();

            packetCount[key]++;

            std::pair<int, int> timeStampPair;

            if (timestamps.find(key) != timestamps.end()) {
                timeStampPair.first = std::min(pInfo.timestamp, timestamps[key].first);
                timeStampPair.second = std::max(pInfo.timestamp, timestamps[key].second);
            }
            else {
                timeStampPair.first = pInfo.timestamp;                
                timeStampPair.second = pInfo.timestamp;
            }
            
            timestamps[key] = timeStampPair;
            uniqueSessions.insert(key);

            fileSummaryMtx.unlock();
        }
    }

    void publish(std::ofstream& summaryFile) {
        for (const auto& session : uniqueSessions) {
            summaryFile << timestamps[session].first << "," << timestamps[session].second << "," << session << "," << packetCount[session] << "\n";
        }

        packetCount.clear();
        timestamps.clear();
        uniqueSessions.clear();
    }
};
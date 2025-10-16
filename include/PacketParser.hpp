#pragma once

#include <unordered_map>
#include <string>
#include <vector>
#include <queue>
#include <cstdint>

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>

#include "String.hpp"
#include "FileSummary.hpp"


std::mutex readerQueueMtx;
std::vector<std::queue<std::pair<std::vector<uint8_t>, long long>>> readerQueues;
// std::unordered_map<SessionInfo, int> sessions;

class PcapParser {
    int id;

public:
    PcapParser(int id) : id(id) {}

    void parse() {
        while (true) {
            std::pair<std::vector<uint8_t>, long long> packet;
            PacketInfo pInfo;

            readerQueueMtx.lock();
            if (readerQueues[id].empty()) {
                readerQueueMtx.unlock();
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }
            else {
                packet = readerQueues[id].front();
                readerQueues[id].pop();
                readerQueueMtx.unlock();
            }

            uint8_t* ptr = packet.first.data();
            long long timeStamp = packet.second;
            pInfo.timestamp = timeStamp;


            EthHeader* ethHeader = reinterpret_cast<EthHeader*>(ptr);
            uint16_t ethType = ntohs(ethHeader->eth_type);
            pInfo.ethType = ethType;

            ptr += sizeof(EthHeader);

            if (ethType == ETHERTYPE_IP) {
                IPv4Header* ip = reinterpret_cast<IPv4Header*>(ptr);
                size_t ip_header_len = (ip->ihl & 0x0F) * 4;

                pInfo.sourceIP = StringOperations::getInstance().decIPv4ToString(ntohl(ip->saddr));
                pInfo.destIP = StringOperations::getInstance().decIPv4ToString(ntohl(ip->daddr));
                pInfo.transportType = ip->protocol;

                ptr += ip_header_len;
            }
            else if (ethType == ETHERTYPE_IPV6) {
                IPv6Header* ip6 = reinterpret_cast<IPv6Header*>(ptr);
                size_t ip6_header_len = sizeof(IPv6Header);

                pInfo.sourceIP = StringOperations::getInstance().decIPv6ToString(ip6->saddr);
                pInfo.destIP = StringOperations::getInstance().decIPv6ToString(ip6->daddr);
                pInfo.transportType = ip6->next_header;

                ptr += ip6_header_len;
            }

            if (pInfo.transportType == IPPROTO_TCP) {
                TCPHeader* tcp = reinterpret_cast<TCPHeader*>(ptr);
                pInfo.sourcePort = ntohs(tcp->source);
                pInfo.destPort = ntohs(tcp->dest);
            }
            else if (pInfo.transportType == IPPROTO_UDP) {
                UDPHeader* udp = reinterpret_cast<UDPHeader*>(ptr);
                pInfo.sourcePort = ntohs(udp->source);
                pInfo.destPort = ntohs(udp->dest);
            }

            summaryQueueMtx.lock();
            summaryQueue.push(pInfo);
            summaryQueueMtx.unlock();
        }
    }
};
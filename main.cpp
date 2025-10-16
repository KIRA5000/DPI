#include <iostream>

#include <semaphore>

#include "ConfigReader.hpp"
#include "DirectoryReader.hpp"
#include "PacketParser.hpp"

int main(int argc, char* argv[]) {
    std::string inputDir = ConfigReader::getInstance().getValue("General", "PCAP_INPUT_DIRECTORY");
    std::string outputPath = ConfigReader::getInstance().getValue("General", "SUMMARY_OUTPUT_PATH");
    std::string readerThreadCount = ConfigReader::getInstance().getValue("General", "READER_THREAD_COUNT");
    std::string summaryThreadCount = ConfigReader::getInstance().getValue("General", "SUMMARY_THREAD_COUNT");

    std::thread watcher(&DirectoryReader::watchDirectory, &DirectoryReader::getInstance(), inputDir);

    readerQueues.resize(std::stoi(readerThreadCount));

    std::vector<std::thread> readers(std::stoi(readerThreadCount));
    for (int i = 0; i < std::stoi(readerThreadCount); i++) {
        readers.push_back(std::thread(&PcapParser::parse, PcapParser(i)));
    }

    std::vector<std::thread> summarizers(std::stoi(summaryThreadCount));
    for (int i = 0; i < std::stoi(summaryThreadCount); i++) {
        summarizers.push_back(std::thread(&PacketSummary::summerize, PacketSummary()));
    }

    while (true) {
        fileQueueMutex.lock();

        if (!fileQueue.empty()) {
            std::string pcapPath = fileQueue.front();
            fileQueue.pop();
            fileQueueMutex.unlock();

            std::cout << "Processing file: " << pcapPath << std::endl;

            std::ifstream file(pcapPath, std::ios::binary);
            if(!file) {
                std::cerr << "Cannot open file: " << pcapPath << std::endl;
                return -1;
            }

            pcap_file_header gHeader;
            file.read(reinterpret_cast<char*>(&gHeader), sizeof(gHeader));

            // std::cout << "PCAP Global Header:" << std::endl;
            // std::cout << "  Magic Number: 0x" << std::hex << gHeader.magic_number << std::dec << std::endl;
            // std::cout << "  Version: " << gHeader.version_major << "." << gHeader.version_minor << std::endl;
            // std::cout << "  This Zone: " << gHeader.thiszone << std::endl;
            // std::cout << "  Sigfigs: " << gHeader.sigfigs << std::endl;
            // std::cout << "  Snaplen: " << gHeader.snaplen << std::endl;
            // std::cout << "  Network: " << gHeader.network << std::endl;

            int packetCount = 0;
            int readerId = 0;

            while (true) {
                packetCount++;

                pcap_pkthdr pHeader;
                file.read(reinterpret_cast<char*>(&pHeader), sizeof(pcap_pkthdr));
                if (!file) {
                    if (file.eof()) {
                        std::cout << "End of file reached." << std::endl;
                        break;
                    }

                    std::cerr << "Error reading packet header" << std::endl;
                    return -1;
                }

                // std::cout << "Packet Header:" << std::endl;
                // std::cout << "  Timestamp: " << pHeader.ts_sec << "." << pHeader.ts_usec << std::endl;
                // std::cout << "  Included Length: " << pHeader.incl_len << std::endl;
                // std::cout << "  Original Length: " << pHeader.orig_len << std::endl;

                if (pHeader.incl_len < 14) {
                    std::cerr << "Packet too short for Ethernet header." << std::endl;
                    file.seekg(pHeader.incl_len, std::ios::cur);
                    continue;
                }

                std::vector<uint8_t> packet(pHeader.incl_len);
                file.read(reinterpret_cast<char*>(packet.data()), pHeader.incl_len);
                if (!file) {
                    std::cerr << "Error reading packet data" << std::endl;
                    return -1;
                }

                readerQueueMtx.lock();
                readerQueues[readerId % std::stoi(readerThreadCount)].push({packet, pHeader.ts_sec});
                readerQueueMtx.unlock();

                readerId++;
            }

            file.close();
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            std::cout << "Total packets processed: " << packetCount << std::endl;

            int idx = pcapPath.find_last_of("/");

            std::string summaryFilePath = outputPath + pcapPath.substr(idx) + ".csv";
            std::ofstream summaryFile(summaryFilePath);
            if (!summaryFile) {
                std::cerr << "Cannot open summary file: " << summaryFilePath << std::endl;
                return -1;
            }

            summaryFile << "StartTime,EndTime,SourceIP,SourcePort,DestIP,DestPort,EthType,TransportType,PacketCount\n";

            PacketSummary ps;
            ps.publish(summaryFile);
            summaryFile.close();
        } 
        else {
            fileQueueMutex.unlock();
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }

    watcher.join();

    for (int i = 0; i < std::stoi(readerThreadCount); i++) {
        readers[i].join();
    }

    for (int i = 0; i < std::stoi(summaryThreadCount); i++) {
        summarizers[i].join();
    }

    return 0;
}
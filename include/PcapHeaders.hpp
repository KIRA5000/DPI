#pragma once

#include <cstdint>

struct PacketInfo {
    long long timestamp;
    std::string sourceIP;
    std::string destIP;
    int sourcePort;
    int destPort;
    int ethType;
    int transportType;
};

struct pcap_file_header {
    uint32_t magic_number;   // 0xa1b2c3d4
    uint16_t version_major;  // usually 2
    uint16_t version_minor;  // usually 4
    int32_t  thiszone;       // GMT offset (deprecated)
    uint32_t sigfigs;        // accuracy of timestamps
    uint32_t snaplen;        // max capture length
    uint32_t network;        // data link type (1 = Ethernet)

    pcap_file_header() {
        magic_number = 0;
        version_major = 0;
        version_minor = 0;
        thiszone = 0;
        sigfigs = 0;
        snaplen = 0;
        network = 0; // Ethernet
    }
};

struct pcap_pkthdr {
    uint32_t ts_sec;   // timestamp seconds
    uint32_t ts_usec;  // timestamp microseconds
    uint32_t incl_len; // number of bytes saved (<= snaplen)
    uint32_t orig_len; // actual packet length on the wire

    pcap_pkthdr() {
        ts_sec = 0;
        ts_usec = 0;
        incl_len = 0;
        orig_len = 0;
    }
};

struct EthHeader {
    uint8_t dst[6];      // Destination MAC
    uint8_t src[6];      // Source MAC
    uint16_t eth_type;   // Protocol type (IPv4, ARP, etc.)
};

struct IPv4Header {
    uint8_t ihl:4;
    uint8_t version:4;
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol; // TCP=6, UDP=17, ICMP=1
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
};

struct IPv6Header {
    uint32_t ver_tc_flow; // Version, Traffic Class, Flow Label
    uint16_t payload_len;
    uint8_t next_header;  // TCP=6, UDP=17, ICMPv6=58
    uint8_t hop_limit;
    uint8_t saddr[16];
    uint8_t daddr[16];
};

struct TCPHeader {
    uint16_t source;
    uint16_t dest;
    uint32_t seq;
    uint32_t ack_seq;
    uint8_t  doff_res; // Data offset (4 bits) + Reserved (4 bits)
    uint8_t  flags;    // Flags (8 bits)
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
};

struct UDPHeader {
    uint16_t source;
    uint16_t dest;
    uint16_t len;
    uint16_t check;
};
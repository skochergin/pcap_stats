#include <stdint.h>
#include <unordered_map>
#include <string>
#include <unordered_set>
#include <iostream>

enum class PacketProtocol
{
    IPv4,
    NON_IPv4,
    TCP,
    UDP,
    ICMP,
    OTHER_L4
};

enum class PacketFlags
{
    SYN,
    SYN_ACK,
    ACK,
    FIN_ACK,
    RST,
    RST_ACK,
    OTHER
};

struct PcapFileStats
{
    std::string file_name;
    uint32_t total_packets {0};
    uint64_t total_packets_length {0};
    std::unordered_map<uint16_t, uint32_t> distribution_by_packet_length;
    std::unordered_map<PacketProtocol, uint32_t> distribution_by_packet_protocol;
    std::unordered_set<std::string> unique_src_macs;
    std::unordered_set<std::string> unique_dst_macs;
    std::unordered_set<uint32_t> unique_src_ips;
    std::unordered_set<uint32_t> unique_dst_ips;
    std::unordered_set<uint16_t> unique_src_ports;
    std::unordered_set<uint16_t> unique_dst_ports;
    uint32_t total_packets_with_correct_checksum {0};
    uint32_t total_packets_with_incorrect_checksum {0};

    void print_stats()
    {
        std::cout << "File: " << file_name << std::endl
                  << "  Total packets: " << total_packets << std::endl
                  << "  Total packets length: " << total_packets_length << std::endl
                  << "  Distributio by packet length: " << distribution_by_packet_length[0] << std::endl;
    }
};

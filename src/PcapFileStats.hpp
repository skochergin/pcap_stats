#include <stdint.h>
#include <unordered_map>
#include <string>
#include <unordered_set>
#include <iostream>
#include <sstream>

#pragma pack(push, 1)
struct IPv4Header
{
    uint8_t  verhl;
    uint8_t  tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t off;
    uint8_t  ttl;
    uint8_t  proto;
    uint16_t csum;
    uint32_t src_ip;
    uint32_t dst_ip;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct TcpHeader
{
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t  offset;
    uint8_t  flags;
    uint16_t window;
    uint16_t csum;
    uint16_t urgp;
};
#pragma pack(pop)

constexpr uint8_t FLAG_FIN = 0x01; //0000_0001
constexpr uint8_t FLAG_SYN = 0x02; //0000_0010
constexpr uint8_t FLAG_RST = 0x04; //0000_0100
constexpr uint8_t FLAG_RSH = 0x08; //0000_1000
constexpr uint8_t FLAG_ACK = 0x10; //0001_0000
constexpr uint8_t FLAG_SYN_ACK = FLAG_SYN | FLAG_ACK;
constexpr uint8_t FLAG_FIN_ACK = FLAG_FIN | FLAG_ACK;
constexpr uint8_t FLAG_RST_ACK = FLAG_RST | FLAG_ACK;

std::string parse_packet_flags(uint8_t data){
    switch (data)
    {
    case FLAG_SYN:
        return "SYN";
    case FLAG_SYN_ACK:
        return "SYN_ACK";
    case FLAG_ACK:
        return "ACK";
    case FLAG_FIN_ACK:
        return "FIN_ACK";
    case FLAG_RST:
        return "RST";
    case FLAG_RST_ACK:
        return "RST_ACK";
    default:
        return "OTHER";
    }
}

struct DistributionByLength
{
    uint32_t le_64;
    uint32_t between_65_255;
    uint32_t between_256_511;
    uint32_t between_512_1023;
    uint32_t between_1024_1518;
    uint32_t ge1519;

    void add_packet(uint32_t length)
    {
        if(length <= 64)
            le_64++;
        else if(65 <= length && length <= 255)
            between_65_255++;
        else if(256 <= length && length <= 511)
            between_256_511++;
        else if(512 <= length && length <= 1023)
            between_512_1023++;
        else if(1024 <= length && length <= 1518)
            between_1024_1518++;
        else
            ge1519++;
    }

    
};


struct PcapFileStats
{
    std::string file_name;
    uint32_t total_packets {0};
    uint64_t total_packets_length {0};
    DistributionByLength distribution_by_packet_length;
    std::unordered_map<std::string, uint32_t> distribution_by_packet_protocol;
    std::unordered_set<std::string> unique_src_macs;
    std::unordered_set<std::string> unique_dst_macs;
    std::unordered_set<uint32_t> unique_src_ips;
    std::unordered_set<uint32_t> unique_dst_ips;
    std::unordered_set<uint16_t> unique_src_ports;
    std::unordered_set<uint16_t> unique_dst_ports;
    std::unordered_map<std::string, uint32_t> distribution_by_packet_flags;
    uint32_t total_packets_with_correct_checksum {0};
    uint32_t total_packets_with_incorrect_checksum {0};

    void print_stats()
    {
        std::cout << std::endl
                  << "Statistics for file: " << file_name << std::endl
                  << "  Total packets: " << total_packets << std::endl
                  << "  Total packets length: " << total_packets_length << std::endl
                  << print_distribution_by_packet_length(distribution_by_packet_length)
                  << print_distribution_by(distribution_by_packet_protocol, "Distribution by packet protocol")
                  << "  Unique src_mac's: " << unique_src_macs.size() << std::endl
                  << "  Unique dst_mac's: " << unique_dst_macs.size() << std::endl
                  << "  Unique src_ip's: " << unique_src_ips.size() << std::endl
                  << "  Unique dst_ip's: " << unique_dst_ips.size() << std::endl
                  << "  Unique src_port's: " << unique_src_ports.size() << std::endl
                  << "  Unique dst_port's: " << unique_dst_ports.size() << std::endl
                  << print_distribution_by(distribution_by_packet_flags, "Distribution by packet flags")
                  << "--------------------------------------------------------------------" << std::endl;
    }

    std::string print_distribution_by_packet_length(const DistributionByLength& dist)
    {
        std::stringstream ss;
        ss << "  Distribution by packet length: " << std::endl
                << "         <=64: " << dist.le_64 << std::endl
                << "       65-255: " << dist.between_65_255 << std::endl
                << "      256-511: " << dist.between_256_511 << std::endl
                << "     512-1023: " << dist.between_512_1023 << std::endl
                << "    1024-1518: " << dist.between_1024_1518 << std::endl
                << "       >=1519: " << dist.ge1519 << std::endl;
        return ss.str();
    }

    std::string print_distribution_by(const std::unordered_map<std::string, uint32_t>& dist, const std::string& title)
    {
        std::stringstream ss;
        ss << "  " << title << ": " << std::endl;
        for(const auto& pair : dist)
        {
            ss << "    " << pair.first << ": " << pair.second << std::endl;
        }
        return ss.str();
    }

};

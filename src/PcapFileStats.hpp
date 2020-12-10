#pragma once

#include <stdint.h>
#include <unordered_map>
#include <string>
#include <unordered_set>
#include <iostream>
#include <sstream>

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

private:

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

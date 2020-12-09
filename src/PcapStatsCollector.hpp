#include <iostream>
#include <string>
#include <pcap.h>
#include <memory>
#include <functional>

#include "PcapFileStats.hpp"

class PcapStatsCollector
{
public:

    PcapStatsCollector(const std::string& pcap_path) : _pcap_path (pcap_path) {}

    using ProcessingFn = std::function<void(uint8_t*, const pcap_pkthdr*, const uint8_t*)>;

    PcapFileStats process_packets()
    {
        statistics = { .file_name = _pcap_path };
        std::unique_ptr<pcap_t, decltype(&pcap_close)> pcap_descriptor { pcap_open_offline(_pcap_path.c_str(), errbuf), &pcap_close };
        while(pcap_dispatch(pcap_descriptor.get(), 0, [](uint8_t* user, const pcap_pkthdr* pkth, const uint8_t* data) {
            auto* collector = reinterpret_cast<PcapStatsCollector*>(user);
            collector->pcap_loop(pkth, data);
        }, (uint8_t*)this) != 0){}
        return statistics;
    }

private:

    void pcap_loop(const pcap_pkthdr* pkth, const uint8_t* data)
    {
        std::uint32_t packet_len = pkth->caplen;
        statistics.total_packets++;
        statistics.total_packets_length += pkth->caplen;
        statistics.distribution_by_packet_length.add_packet(packet_len);
        
        std::string dst_mac { data, data + 6 };
        std::string src_mac { data + 6, data + 12 };
        statistics.unique_src_macs.emplace(src_mac);
        statistics.unique_dst_macs.emplace(dst_mac);

        uint16_t ether_type = htons(*reinterpret_cast<const uint16_t*>(data+12));

        std::string l3_protocol = (ether_type == 0x0800) ? "IPv4" : "NON_IPv4";
        statistics.distribution_by_packet_protocol[l3_protocol]++;
        if(l3_protocol == "IPv4")
        {
            const IPv4Header* ip_header = reinterpret_cast<const IPv4Header*>(data + 14);
            statistics.unique_src_ips.emplace(ip_header->src_ip);
            statistics.unique_dst_ips.emplace(ip_header->dst_ip);

            std::string l4_protocol = "OTHER_L4";
            if(ip_header->ip_proto == 0x06) l4_protocol = "TCP";
            else if(ip_header->ip_proto == 0x11) l4_protocol = "UDP";
            else if(ip_header->ip_proto == 0x1) l4_protocol = "ICMP";
            statistics.distribution_by_packet_protocol[l4_protocol]++;

            if(l4_protocol == "TCP")
            {
                uint8_t ip_header_length = (ip_header->ip_verhl & 0x0F) * 4;
                std::cout << "ip_header_length: " << (int)ip_header_length << std::endl;

                const TcpHeader* tcp_header = reinterpret_cast<const TcpHeader*>(data + 14 + ip_header_length);
                statistics.unique_src_ports.emplace(tcp_header->src_port);
                statistics.unique_dst_ports.emplace(tcp_header->dst_port);

                std::string flags = parse_packet_flags(tcp_header->flags);
                statistics.distribution_by_packet_flags[flags]++;
            }
        }
        
    }

    char errbuf[PCAP_ERRBUF_SIZE];

    PcapFileStats statistics;

    std::string _pcap_path;

};

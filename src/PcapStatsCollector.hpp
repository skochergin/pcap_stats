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
        statistics.total_packets_length += pkth->caplen; // TODO: ask - len or caplen?
        statistics.distribution_by_packet_length[packet_len]++;
        
        std::string dst_mac { data, data + 6 };
        std::string src_mac { data + 6, data + 12 };
        statistics.unique_src_macs.emplace(src_mac);
        statistics.unique_dst_macs.emplace(dst_mac);

        uint16_t ether_type = htons(*reinterpret_cast<const uint16_t*>(data+12));

        PacketProtocol l3_protocol = (ether_type == 0x0800) ? PacketProtocol::IPv4 : PacketProtocol::NON_IPv4;
        statistics.distribution_by_packet_protocol[l3_protocol]++;
        if(l3_protocol == PacketProtocol::IPv4)
        {
            const uint8_t* ip_header = data + 14;

            PacketProtocol l4_protocol = PacketProtocol::OTHER_L4;
            uint8_t ip_protocol = *(ip_header + 9);
            if(ip_protocol == 0x06) l4_protocol = PacketProtocol::TCP;
            else if(ip_protocol == 0x11) l4_protocol = PacketProtocol::UDP;
            else if(ip_protocol == 0x1) l4_protocol = PacketProtocol::ICMP;
            statistics.distribution_by_packet_protocol[l4_protocol]++;

            const uint8_t* ip_start = ip_header + 12;
            uint32_t src_ip = *((uint32_t*)ip_start);
            uint32_t dst_ip = *((uint32_t*)(ip_start + 4));
            statistics.unique_src_ips.emplace(src_ip);
            statistics.unique_dst_ips.emplace(dst_ip);

            if(l4_protocol == PacketProtocol::TCP)
            {
                const uint8_t* tcp_header = ip_header + 16; //TODO check it
                uint16_t src_port = *((uint16_t*)tcp_header);
                uint16_t dst_port = *((uint16_t*)(tcp_header + 2));
                statistics.unique_src_ports.emplace(src_port);
                statistics.unique_dst_ports.emplace(dst_port));

                uint8_t flags = *(tcp_header + 13); //TODO check it
            }
        }
        
    }

    char errbuf[PCAP_ERRBUF_SIZE];

    PcapFileStats statistics;

    std::string _pcap_path;

};

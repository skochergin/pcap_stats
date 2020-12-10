#include "PcapStatsCollector.h"
#include "PcapFileStats.hpp"
#include "packets.h"

void pcap_loop(uint8_t* user, const pcap_pkthdr* pkth, const uint8_t* data);

void process_pcap_file(const std::string& pcap_path)
{
    PcapFileStats statistics = { .file_name = pcap_path };
    char errbuf[PCAP_ERRBUF_SIZE];
    std::unique_ptr<pcap_t, decltype(&pcap_close)> pcap_descriptor { pcap_open_offline(pcap_path.c_str(), errbuf), &pcap_close };
    while(pcap_dispatch(pcap_descriptor.get(), 0, pcap_loop, (uint8_t*)&statistics) != 0){}
    statistics.print_stats();
}

bool is_checksum_correct(const uint16_t* data, size_t size);

void pcap_loop(uint8_t* user, const pcap_pkthdr* pkth, const uint8_t* data)
{
    PcapFileStats* statistics = (PcapFileStats*)user;
    std::uint32_t packet_len = pkth->caplen;
    statistics->total_packets++;
    statistics->total_packets_length += pkth->caplen;
    statistics->distribution_by_packet_length.add_packet(packet_len);
    
    std::string dst_mac { data, data + 6 };
    std::string src_mac { data + 6, data + 12 };
    statistics->unique_src_macs.emplace(src_mac);
    statistics->unique_dst_macs.emplace(dst_mac);

    uint16_t ether_type = htons(*reinterpret_cast<const uint16_t*>(data+12));

    std::string l3_protocol = (ether_type == 0x0800) ? "IPv4" : "NON_IPv4";
    statistics->distribution_by_packet_protocol[l3_protocol]++;
    if(l3_protocol == "IPv4")
    {
        const IPv4Header* ip_header = reinterpret_cast<const IPv4Header*>(data + 14);
        statistics->unique_src_ips.emplace(ip_header->src_ip);
        statistics->unique_dst_ips.emplace(ip_header->dst_ip);

        std::string l4_protocol = "OTHER_L4";
        if(ip_header->proto == 0x06) l4_protocol = "TCP";
        else if(ip_header->proto == 0x11) l4_protocol = "UDP";
        else if(ip_header->proto == 0x1) l4_protocol = "ICMP";
        statistics->distribution_by_packet_protocol[l4_protocol]++;

        uint8_t ip_header_length = (ip_header->verhl & 0x0F) * 4;
        bool l3_csum_correct = is_checksum_correct(reinterpret_cast<const uint16_t*>(data + 14), ip_header_length/2);

        if(l4_protocol == "TCP")
        {
            const uint8_t* tcp_start = data + 14 + ip_header_length;
            const TcpHeader* tcp_header = reinterpret_cast<const TcpHeader*>(tcp_start);
            statistics->unique_src_ports.emplace(tcp_header->src_port);
            statistics->unique_dst_ports.emplace(tcp_header->dst_port);

            std::string flags = parse_packet_flags(tcp_header->flags);
            statistics->distribution_by_packet_flags[flags]++;
        }
    }
}

bool is_checksum_correct(const uint16_t* data, size_t size)
{
    uint32_t sum = 0;
    for(size_t i=0; i<size; i++)
        sum += ntohs(data[i]);
    return static_cast<uint16_t>(sum+2) == 0xFFFF;
}

uint16_t compute_tcp_checksum(const IPv4Header* ip_header, const uint16_t *payload) 
{
    uint32_t sum = 0;
    uint16_t tcp_len = ntohs(ip_header->total_len) - ((ip_header->verhl & 0x0F) * 4);
    //add the pseudo header 
    //the source ip
    sum += (ip_header->src_ip>>16)&0xFFFF;
    sum += (ip_header->src_ip)&0xFFFF;
    //the dest ip
    sum += (ip_header->dst_ip>>16)&0xFFFF;
    sum += (ip_header->dst_ip)&0xFFFF;
    //protocol and reserved: 6
    sum += htons(IPPROTO_TCP);
    //the length
    sum += htons(tcp_len);

    //add the IP payload
    //initialize checksum to 0
    size_t i = 0;
    while (tcp_len > 1) {
        // if(i != 8)
        sum += *payload;
        payload++;
        tcp_len -= 2;
        i++;
    }
    //if any bytes left, pad the bytes and add
    if(tcp_len > 0) {
        sum += ((*payload)&htons(0xFF00));
    }
    //Fold 32-bit sum to 16 bits: add carrier to result
    // while (sum>>16) {
    //     sum = (sum & 0xffff) + (sum >> 16);
    // }
    // sum = ~sum;
    //set computation result
    return static_cast<uint16_t>(~sum);
}

#include <iostream>
#include <pcap.h>

#include "PcapStatsCollector.hpp"

// void pcap_loop(uint8_t* user, const pcap_pkthdr* pkth, const uint8_t* data){
    // auto *context = reinterpret_cast<PcapContext*>(user);
    // context->sniffer->packet_process(pkth, data);
    // std::cout << "packet" << std::endl;
// }

int main()
{
    std::string file_name = "../pcaps/capt_Safe-Reset_302_pic.pcap";
    PcapStatsCollector collector {file_name};
    auto stats = collector.process_packets();
    stats.print_stats();
}
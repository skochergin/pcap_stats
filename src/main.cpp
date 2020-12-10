#include <iostream>
#include <pcap.h>
#include <filesystem>

#include "PcapStatsCollector.hpp"

int main(int argc, const char* argv[])
{
    if(argc != 2)
    {
        std::cout << "Please specify directory with pcap files as first argument." << std::endl;
        return -1;
    }
    for(const auto& entry : std::filesystem::directory_iterator(argv[1]))
    {
        if(!entry.is_regular_file())
            continue;
        std::string ext = entry.path().extension();
        if(ext == ".pcap" || ext == ".pcapng")
        {
            PcapStatsCollector collector {entry.path()};
            auto stats = collector.process_packets();
            stats.print_stats();
        }
    }
}
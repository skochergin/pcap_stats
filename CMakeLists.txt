cmake_minimum_required(VERSION 3.16)
project(pcap_stats)

set(CMAKE_CXX_STANDARD 17)

add_executable(pcap_stats src/main.cpp src/PcapStatsCollector.cpp)
target_link_libraries(pcap_stats ${LIBRARIES} pcap)
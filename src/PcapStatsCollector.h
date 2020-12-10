#pragma once

#include <iostream>
#include <string>
#include <pcap.h>
#include <memory>
#include <functional>

#include "PcapFileStats.hpp"

void process_pcap_file(const std::string& pcap_path);

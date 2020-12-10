#pragma once

#include <stdint.h>
#include <string>

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

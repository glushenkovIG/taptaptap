#pragma once

#include <stdint.h>

namespace proto
{
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#   define NEED_TO_BSWAP_EVERYTHING() 0
inline uint16_t bswap(uint16_t x) { return x; }
inline uint32_t bswap(uint32_t x) { return x; }
#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#   define NEED_TO_BSWAP_EVERYTHING() 1
inline uint16_t bswap(uint16_t x) { return __builtin_bswap16(x); }
inline uint32_t bswap(uint32_t x) { return __builtin_bswap32(x); }
#else
#   error "Here's a nickel kid..."
#endif

// This represents a value in network byte order (that is, big endian).
template<class T>
struct nbo
{
    T raw;

    T load() const { return bswap(raw); }
    void store(T x) { raw = bswap(x); }
};

struct ipv4_Header
{
#if NEED_TO_BSWAP_EVERYTHING()
    unsigned ihl : 4;
    unsigned ver : 4;
#else
    unsigned ver : 4;
    unsigned ihl : 4;
#endif
    uint8_t tos;
    nbo<uint16_t> len;
    nbo<uint16_t> id;
    nbo<uint16_t> mixed;
    uint8_t ttl;
    uint8_t proto;
    nbo<uint16_t> csum;
    nbo<uint32_t> saddr;
    nbo<uint32_t> daddr;
} __attribute__((packed));

enum
{
    TCP_FIN = 1 << 0,
    TCP_SYN = 1 << 1,
    TCP_RST = 1 << 2,
    TCP_PSH = 1 << 3,
    TCP_ACK = 1 << 4,
    TCP_URG = 1 << 5,
    TCP_ECE = 1 << 6,
    TCP_CWR = 1 << 7,
};

struct tcp_Header
{
    nbo<uint16_t> sport;
    nbo<uint16_t> dport;
    nbo<uint32_t> seq;
    nbo<uint32_t> ack;
#if NEED_TO_BSWAP_EVERYTHING()
    unsigned reserved : 4;
    unsigned data_offset : 4;
#else
    unsigned data_offset : 4;
    unsigned reserved : 4;
#endif
    uint8_t flags;
    nbo<uint16_t> win;
    nbo<uint16_t> csum;
    nbo<uint16_t> urgent_ptr;
} __attribute__((packed));

#undef NEED_TO_BSWAP_EVERYTHING
}

#pragma once

#include <stdint.h>
#include <stdio.h>
#include <exception>
#include <string>

namespace subnet
{

struct Subnet
{
    uint32_t nulladdr;
    uint32_t netmask;

    bool includes(uint32_t addr) const { return (addr & netmask) == nulladdr; }
    uint32_t id_by_addr(uint32_t addr) const { return addr & ~netmask; }
    uint32_t addr_by_id(uint32_t id) const { return nulladdr | id; };
    uint32_t last_addr() const { return ~netmask; }
};

class ParseError : public std::exception
{
    std::string what_;
public:
    ParseError(std::string what) : what_(std::move(what)) {}
    const char *what() const noexcept override { return what_.c_str(); }
};

Subnet parse(const std::string &s)
{
    unsigned seg[4];
    unsigned netbits;
    if (sscanf(s.c_str(), "%u.%u.%u.%u/%u", &seg[0], &seg[1], &seg[2], &seg[3], &netbits) != 5)
        throw ParseError("invalid subnetwork string");
    if (netbits >= 32)
        throw ParseError("invalid subnetwork bit length");

    uint32_t addr = 0;
    for (int i = 0; i < 4; ++i)
        addr = (addr << 8) | seg[i];

    const uint32_t netmask = ~((static_cast<uint32_t>(1) << (32 - netbits)) - 1);
    if (addr & ~netmask)
        throw ParseError("subnetwork IP address is not null address");
    return Subnet{addr, netmask};
}

std::string format(uint32_t addr)
{
    unsigned seg[4];
    for (int i = 0; i < 4; ++i) {
        seg[4 - i - 1] = addr & 0xff;
        addr >>= 8;
    }
    char buf[(3 + 1) * 4];
    snprintf(buf, sizeof(buf), "%u.%u.%u.%u", seg[0], seg[1], seg[2], seg[3]);
    return buf;
}

std::string format(Subnet net, uint32_t id)
{
    const auto netbits = __builtin_popcount(net.netmask);
    return format(net.addr_by_id(id)) + "/" + std::to_string(netbits);
}

}

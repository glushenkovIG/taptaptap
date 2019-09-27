#pragma once

#include "util.hpp"
#include "proto.hpp"
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <exception>
#include <chrono>

namespace dump
{

struct Meta
{
    enum {
        EV_CHUNK,
        EV_CHUNK_URGENT,
        EV_CONN_SRV,
        EV_CONN_CLI,
        EV_KEEPALIVE,

        LAST_EV
    };

    uint16_t ev;
    uint16_t ndata;
    uint32_t saddr;
    uint32_t daddr;
    uint16_t sport;
    uint16_t dport;
    uint32_t ts;

    static Meta make_last()
    {
        return {LAST_EV, 0, 0, 0, 0, 0, 0};
    }
};

void bswap_fields(Meta &m)
{
    m.ev    = proto::bswap(m.ev);
    m.ndata = proto::bswap(m.ndata);
    m.saddr = proto::bswap(m.saddr);
    m.daddr = proto::bswap(m.daddr);
    m.sport = proto::bswap(m.sport);
    m.dport = proto::bswap(m.dport);
    m.ts    = proto::bswap(m.ts);
}

class Corrupted : public std::exception
{
public:
    const char *what() const noexcept override { return "corrupted dump file"; }
};

class Reader
{
    util::UnixFd fd_;

public:
    Reader(util::UnixFd &&fd) : fd_(std::move(fd)) {}

    Meta read(char *data)
    {
        Meta m;
        if (!util::full_read(fd_, &m, sizeof(m), "read() from dump file"))
            return Meta::make_last();
        bswap_fields(m);
        if (m.ev >= Meta::LAST_EV)
            throw Corrupted{};
        if (!util::full_read(fd_, data, m.ndata, "read() from dump file"))
            return Meta::make_last();
        return m;
    }
};

class Writer
{
    util::UnixFd fd_;
    std::chrono::steady_clock::time_point start_;

public:
    Writer(util::UnixFd &&fd)
        : fd_(std::move(fd))
        , start_{std::chrono::steady_clock::now()}
    {}

    void write(Meta m, const char *data)
    {
        const auto diff = std::chrono::steady_clock::now() - start_;
        m.ts = std::chrono::duration_cast<std::chrono::milliseconds>(diff).count();
        const auto ndata = m.ndata;
        bswap_fields(m);
        util::full_write(fd_, &m, sizeof(m), "write() to dump file");
        util::full_write(fd_, data, ndata, "write() to dump file");
    }
};

}

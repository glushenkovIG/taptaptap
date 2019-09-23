#pragma once

#include <map>
#include <utility>
#include <stdint.h>
#include "dump.hpp"
#include "proto.hpp"
#include "log.hpp"

namespace record
{

class Handler
{
    struct Datum
    {
        uint32_t init_seqnum;
        uint64_t nwritten;

        Datum() : init_seqnum{0}, nwritten{0} {}
    };

    struct Conn
    {
        uint32_t saddr;
        uint32_t daddr;
        uint16_t sport;
        uint16_t dport;

        bool operator <(Conn that) const
        {
            if (saddr != that.saddr)
                return saddr < that.saddr;
            if (daddr != that.daddr)
                return daddr < that.daddr;
            if (sport != that.sport)
                return sport < that.sport;
            return dport < that.dport;
        }
    };

    static uint32_t subsat32_(uint32_t a, uint32_t b)
    {
        return a > b ? a - b : 0;
    }

    std::map<Conn, Datum> data_;
    dump::Writer writer_;
    log::Logger logger_;

public:
    Handler(dump::Writer &&writer, log::Logger logger)
        : writer_(std::move(writer))
        , logger_(std::move(logger))
    {}

    bool operator ()(uint32_t src_idx, uint32_t dst_idx, char *pkt, size_t npkt)
    {
        auto ip_hdr = reinterpret_cast<proto::ipv4_Header *>(pkt);
        const auto proto = static_cast<unsigned>(ip_hdr->proto);
        if (proto != 6) {
            logger_.say(log::Level::WARN, "unknown protocol ID: %u", proto);
            return false;
        }
        if (npkt < sizeof(proto::ipv4_Header) + sizeof(proto::tcp_Header)) {
            logger_.say(log::Level::WARN, "invalid packet");
            return false;
        }
        auto tcp_hdr = reinterpret_cast<proto::tcp_Header *>(pkt + 4 * ip_hdr->ihl);
        const Conn conn{
            ip_hdr->saddr.load(),
            ip_hdr->daddr.load(),
            tcp_hdr->sport.load(),
            tcp_hdr->dport.load()};
        Datum &datum = data_[conn];

        if (tcp_hdr->flags & (proto::TCP_RST | proto::TCP_FIN)) {
            data_.erase(conn);
            return true;
        }

        if (tcp_hdr->flags & proto::TCP_SYN) {
            datum.init_seqnum = tcp_hdr->seq.load();
            datum.nwritten = 1;

            const uint16_t ev = (tcp_hdr->flags & proto::TCP_ACK)
                ? dump::Meta::EV_CONN_SRV
                : dump::Meta::EV_CONN_CLI;
            writer_.write(
                dump::Meta{
                    ev,
                    0,
                    ip_hdr->saddr.load(),
                    ip_hdr->daddr.load(),
                    tcp_hdr->sport.load(),
                    tcp_hdr->dport.load(),
                    0},
                nullptr);
        }

        if (!datum.nwritten)
            return true;

        const uint32_t urgent_ptr = (tcp_hdr->flags & proto::TCP_URG)
            ? tcp_hdr->urgent_ptr.load()
            : static_cast<uint32_t>(-1);
        const uint32_t offset = tcp_hdr->seq.load() - datum.init_seqnum;
        const uint32_t nwritten_lo = static_cast<uint32_t>(datum.nwritten);
        if (offset > nwritten_lo) {
            logger_.say(log::Level::WARN, "out-of-order packet");
            return false;
        }
        const uint32_t recent_offset = nwritten_lo - offset;

        const uint32_t payload_offset =
            static_cast<uint32_t>(ip_hdr->ihl) * 4 +
            static_cast<uint32_t>(tcp_hdr->data_offset) * 4;

        char *payload = pkt + payload_offset;
        const uint32_t npayload = npkt - payload_offset;

        char *recent = payload + recent_offset;
        const auto nrecent = subsat32_(npayload, recent_offset);
        const auto nurgent = subsat32_(urgent_ptr + 1, recent_offset);

        if (nurgent)
            writer_.write(
                dump::Meta{
                    dump::Meta::EV_CHUNK_URGENT,
                    static_cast<uint16_t>(nurgent),
                    ip_hdr->saddr.load(),
                    ip_hdr->daddr.load(),
                    tcp_hdr->sport.load(),
                    tcp_hdr->dport.load(),
                    0},
                recent);
        if (nurgent != nrecent)
            writer_.write(
                dump::Meta{
                    dump::Meta::EV_CHUNK,
                    static_cast<uint16_t>(nrecent - nurgent),
                    ip_hdr->saddr.load(),
                    ip_hdr->daddr.load(),
                    tcp_hdr->sport.load(),
                    tcp_hdr->dport.load(),
                    0},
                recent + nurgent
            );

        datum.nwritten += nrecent;
        return true;
    }
};

}

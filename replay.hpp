#pragma once

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <assert.h>
#include <memory>
#include <algorithm>
#include <thread>
#include <map>
#include <set>
#include "proto.hpp"
#include "dump.hpp"
#include "subnet.hpp"
#include "util.hpp"
#include "log.hpp"

namespace replay
{

class Handler
{
    std::vector<util::Pipe> pipes_to_children;
    std::vector<util::Pipe> pipes_from_children;
    size_t simulate_for_idx_;
    log::Logger logger_;

    size_t to_pipe_idx_(size_t idx) const
    {
        assert(idx != simulate_for_idx_);
        return idx < simulate_for_idx_ ? idx : idx - 1;
    }

public:
    Handler(size_t nnodes, size_t simulate_for_idx, log::Logger logger)
        : simulate_for_idx_{simulate_for_idx}
        , logger_(std::move(logger))
    {
        for (size_t i = 1; i < nnodes; ++i) {
            pipes_to_children.emplace_back(util::make_pipe());
            pipes_from_children.emplace_back(util::make_pipe());
        }
    }

    bool operator ()(uint32_t src_idx, uint32_t dst_idx, char *pkt, size_t npkt)
    {
        auto ip_hdr = reinterpret_cast<proto::ipv4_Header *>(pkt);
        const auto proto = static_cast<unsigned>(ip_hdr->proto);
        if (ip_hdr->proto != 6) {
            logger_.say(log::Level::WARN, "unknown protocol ID: %u", proto);
            return false;
        }
        if (npkt < sizeof(proto::ipv4_Header) + sizeof(proto::tcp_Header)) {
            logger_.say(log::Level::WARN, "invalid packet");
            return false;
        }
        if (src_idx != simulate_for_idx_)
            return true;
        if (dst_idx == simulate_for_idx_)
            return true;
        auto tcp_hdr = reinterpret_cast<proto::tcp_Header *>(pkt + 4 * ip_hdr->ihl);
        if ((tcp_hdr->flags & proto::TCP_SYN) && !(tcp_hdr->flags & proto::TCP_ACK)) {
            const auto pipe_idx = to_pipe_idx_(dst_idx);
            const uint16_t port = tcp_hdr->dport.load();

            unsigned char c = static_cast<unsigned char>(port);
            ::write(pipes_to_children[pipe_idx].write_end, &c, 1);
            const auto nread = util::check_retval(
                ::read(pipes_from_children[pipe_idx].read_end, &c, 1),
                "read() from pipe");
            if (!nread) {
                logger_.say(log::Level::FATAL, "child closed the pipe");
                ::abort();
            }
        }
        return true;
    }

    struct ChildPipe
    {
        int read_end;
        int write_end;
    };

    ChildPipe child_pipe(size_t idx) const
    {
        const auto pipe_idx = to_pipe_idx_(idx);
        return {
            static_cast<int>(pipes_to_children[pipe_idx].read_end),
            static_cast<int>(pipes_from_children[pipe_idx].write_end),
        };
    }
};

void read_match(int fd, const char *data, size_t ndata)
{
    char buf[1024];
    size_t nread = 0;
    while (nread != ndata) {
        const ssize_t n = util::check_retval(
            ::read(fd, buf, std::min(ndata - nread, sizeof(buf))),
            "read() from peer");
        if (!n) {
            fprintf(stderr, "E: traffic does not match (leftover).\n");
            abort();
        }
        if (::memcmp(buf, data + nread, n) != 0) {
            fprintf(stderr, "E: traffic does not match.\n");
            abort();
        }
        nread += n;
    }
}

util::UnixFd open_server(uint32_t peer, uint16_t port, Handler::ChildPipe pipe)
{
    util::UnixFd sock{util::check_retval(
        ::socket(AF_INET, SOCK_STREAM, 0),
        "socket"
    )};

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));

    util::check_retval(
        ::bind(sock, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)),
        "bind");
    util::check_retval(
        ::listen(sock, 3),
        "listen");

    {
        unsigned char c;
        if (::read(pipe.read_end, &c, 1) != 1) {
            ::fprintf(stderr, "E: replay child: parent closed the pipe.\n");
            ::abort();
        }
        if (c != static_cast<unsigned char>(port)) {
            ::fprintf(stderr, "E: replay child: inconsistency detected.\n");
            ::abort();
        }
        ::write(pipe.write_end, &c, 1);
    }

    struct sockaddr_in peer_addr;
    socklen_t peer_addr_len = sizeof(peer_addr);
    auto fd = util::UnixFd{util::check_retval(
        ::accept(sock, reinterpret_cast<struct sockaddr *>(&peer_addr), &peer_addr_len),
        "accept"
    )};
    if (peer_addr.sin_addr.s_addr != htonl(peer)) {
        ::fprintf(stderr, "E: replay child: accepted connection from unexpected address.\n");
        ::abort();
    }
    return fd;
}

util::UnixFd open_client(uint32_t peer, uint16_t port)
{
    struct sockaddr_in addr;
    memset(&addr, '\0', sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(peer);

    util::UnixFd sock{util::check_retval(
        ::socket(AF_INET, SOCK_STREAM, 0),
        "socket"
    )};
    while (true) {
        const int ret = ::connect(sock, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr));
        if (ret < 0 && errno == ECONNREFUSED) {
            fprintf(stderr, "I: replay client: connection refused, retrying in 1s...\n");
            std::this_thread::sleep_for(std::chrono::seconds{1});
            continue;
        }
        util::check_retval(ret, "connect");
        return sock;
    }
}

int child_main(
    dump::Reader &reader,
    subnet::Subnet subnet,
    uint32_t my_id,
    uint32_t peer_id,
    bool timed,
    Handler::ChildPipe pipe)
{
    std::unique_ptr<char[]> chunk(new char[65535]);
    const uint32_t my_addr = subnet.addr_by_id(my_id);
    const uint32_t peer_addr = subnet.addr_by_id(peer_id);
    uint32_t last_ts = 0;
    std::chrono::milliseconds to_sleep{0};
    std::map<uint16_t, util::UnixFd> port_to_fd;

    while (true) {
        dump::Meta m = reader.read(chunk.get());
        if (m.ev == dump::Meta::LAST_EV) {
            fprintf(stderr, "I: replay child %d: end of dump.\n",
                    static_cast<int>(my_id));
            return 0;
        }

        const uint32_t ts_diff = m.ts - last_ts;
        to_sleep += std::chrono::milliseconds(ts_diff);
        last_ts = m.ts;

        switch (m.ev) {
        case dump::Meta::EV_CONN_SRV:
            if (m.saddr == my_addr && m.daddr == peer_addr) {
                port_to_fd[m.sport] = open_server(peer_addr, m.sport, pipe);
                to_sleep = std::chrono::milliseconds{0};
            }
            break;

        case dump::Meta::EV_CONN_CLI:
            if (m.saddr == my_addr && m.daddr == peer_addr) {
                port_to_fd[m.sport] = open_client(peer_addr, m.dport);
                to_sleep = std::chrono::milliseconds{0};
            }
            break;

        case dump::Meta::EV_CHUNK:
            if (m.saddr == my_addr && m.daddr == peer_addr) {
                const auto &fd = port_to_fd[m.sport];
                if (timed) {
                    const double nsec =
                        std::chrono::duration_cast<
                            std::chrono::duration<double>
                        >(to_sleep).count();
                    fprintf(stderr, "I: sleeping for %.3f s.\n", nsec);
                    std::this_thread::sleep_for(to_sleep);
                }
                util::full_write(fd, chunk.get(), m.ndata, "write() to peer");
                to_sleep = std::chrono::milliseconds{0};
            } else if (m.saddr == peer_addr && m.daddr == my_addr) {
                const auto &fd = port_to_fd[m.dport];
                read_match(fd, chunk.get(), m.ndata);
                to_sleep = std::chrono::milliseconds{0};
            }
            break;

        case dump::Meta::EV_CHUNK_URGENT:
            fprintf(stderr, "W: urgent data is not supported yet.\n");
            break;

        case dump::Meta::EV_KEEPALIVE:
            break;

        default:
            assert(0);
        }
    }
}

}

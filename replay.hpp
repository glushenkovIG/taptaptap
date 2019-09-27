#pragma once

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <assert.h>
#include <memory>
#include <string>
#include <algorithm>
#include <thread>
#include <map>
#include <set>
#include "proto.hpp"
#include "dump.hpp"
#include "subnet.hpp"
#include "util.hpp"
#include "log.hpp"
#include "subnet.hpp"

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
        //if (npkt < sizeof(proto::ipv4_Header) + sizeof(proto::tcp_Header)) {
        //    logger_.say(log::Level::WARN, "invalid packet");
        //    return false;
        //}
        //if (src_idx != simulate_for_idx_)
        //    return true;
        //if (dst_idx == simulate_for_idx_)
        //    return true;
        //auto tcp_hdr = reinterpret_cast<proto::tcp_Header *>(pkt + 4 * ip_hdr->ihl);
        //if ((tcp_hdr->flags & proto::TCP_SYN) && !(tcp_hdr->flags & proto::TCP_ACK)) {
        //    const auto pipe_idx = to_pipe_idx_(dst_idx);
        //    const uint16_t port = tcp_hdr->dport.load();
        //    util::full_write(pipes_to_children[pipe_idx].write_end, &port, sizeof(port),
        //                     "write() to pipe");
        //    char c;
        //    if (util::check_retval(
        //            ::read(pipes_from_children[pipe_idx].read_end, &c, 1),
        //            "read() from pipe"
        //        ) == 0)
        //    {
        //        logger_.say(log::Level::FATAL, "child closed the pipe");
        //        ::abort();
        //    }
        //}
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

class Child
{
    struct Conn
    {
        uint16_t port_my;
        uint16_t port_peer;

        bool operator <(Conn that) const
        {
            if (port_my != that.port_my)
                return port_my < that.port_my;
            return port_peer < that.port_peer;
        }
    };

    uint32_t my_id_;
    uint32_t peer_id_;
    subnet::Subnet subnet_;
    std::map<uint16_t, util::UnixFd> srv_sock_;
    std::map<Conn, util::UnixFd> conns_;
    log::Logger logger_;
    Handler::ChildPipe pipe_;

    void read_match_(int fd, const char *data, size_t ndata)
    {
        char buf[1024];
        size_t nread = 0;
        while (nread != ndata) {
            const ssize_t n = util::check_retval(
                ::read(fd, buf, std::min(ndata - nread, sizeof(buf))),
                "read() from peer");
            if (!n) {
                logger_.say(log::Level::FATAL, "traffic does not match (leftover)");
                ::abort();
            }
            if (::memcmp(buf, data + nread, n) != 0) {
                logger_.say(log::Level::FATAL, "traffic does not match");
                abort();
            }
            nread += n;
        }
    }

    void prepare_server_(uint16_t port)
    {
        auto it = srv_sock_.find(port);
        if (it != srv_sock_.end())
            return;

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
            ::listen(sock, SOMAXCONN),
            "listen");

        logger_.say(log::Level::VERBOSE, "listening at port %u", static_cast<unsigned>(port));

        srv_sock_[port] = std::move(sock);
    }

    util::UnixFd open_client_(uint32_t peer, uint16_t port)
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
                logger_.say(log::Level::INFO, "connection refused, retrying in 1 s...");
                std::this_thread::sleep_for(std::chrono::seconds{1});
                continue;
            }
            util::check_retval(ret, "connect");
            return sock;
        }
    }

    util::UnixFd accept_(int sock, uint32_t peer)
    {
        struct sockaddr_in peer_addr;
        socklen_t peer_addr_len = sizeof(peer_addr);
        auto fd = util::UnixFd{util::check_retval(
            ::accept(sock, reinterpret_cast<struct sockaddr *>(&peer_addr), &peer_addr_len),
            "accept"
        )};
        if (peer_addr.sin_addr.s_addr != htonl(peer)) {
            logger_.say(log::Level::FATAL, "accepted connection from unexpected address");
            ::abort();
        }
        return fd;
    }

    void read_from_pipe_()
    {
        uint16_t ports[2048];
        const size_t nread = util::check_retval(
            ::read(pipe_.read_end, ports, sizeof(ports)),
            "read() from pipe");
        if (nread % sizeof(uint16_t)) {
            logger_.say(log::Level::FATAL, "truncated read from pipe");
            ::abort();
        }
        for (size_t i = 0; i < nread / sizeof(uint16_t); ++i) {
            prepare_server_(ports[i]);
            ::write(pipe_.write_end, "", 1); // write '\0'
        }
    }

public:
    Child(
            uint32_t my_id,
            uint32_t peer_id,
            subnet::Subnet subnet,
            log::Logger logger,
            Handler::ChildPipe pipe
    )
        : my_id_{my_id}
        , peer_id_{peer_id}
        , subnet_{subnet}
        , logger_(std::move(logger))
        , pipe_(pipe)
    {}

    int main(dump::Reader &reader, bool timed)
    {
        std::unique_ptr<char[]> chunk(new char[65535]);
        const uint32_t my_addr = subnet_.addr_by_id(my_id_);
        const uint32_t peer_addr = subnet_.addr_by_id(peer_id_);

        uint32_t last_ts = 0;
        std::chrono::milliseconds to_sleep{0};

        while (true) {
            dump::Meta m = reader.read(chunk.get());
            if (m.ev == dump::Meta::LAST_EV) {
                logger_.say(log::Level::INFO, "end of dump");
                return 0;
            }

            const uint32_t ts_diff = m.ts - last_ts;
            to_sleep += std::chrono::milliseconds(ts_diff);
            last_ts = m.ts;

            switch (m.ev) {
            case dump::Meta::EV_CONN_SRV:
                if (m.saddr == my_addr && m.daddr == peer_addr) {
                    //read_from_pipe_();
                    prepare_server_(m.sport);
                    Conn conn{m.sport, m.dport};
                    conns_[conn] = accept_(srv_sock_[m.sport], peer_addr);
                    to_sleep = std::chrono::milliseconds{0};
                }
                break;

            case dump::Meta::EV_CONN_CLI:
                if (m.saddr == my_addr && m.daddr == peer_addr) {
                    Conn conn{m.sport, m.dport};
                    conns_[conn] = open_client_(peer_addr, m.dport);
                    to_sleep = std::chrono::milliseconds{0};
                }
                break;

            case dump::Meta::EV_CHUNK:
                if (m.saddr == my_addr && m.daddr == peer_addr) {
                    if (timed) {
                        const auto nsec = std::chrono::duration_cast<
                            std::chrono::duration<double>>(to_sleep).count();
                        logger_.say(log::Level::VERBOSE, "sleeping for %.3f s", nsec);
                        std::this_thread::sleep_for(to_sleep);
                    }
                    Conn conn{m.sport, m.dport};
                    util::full_write(conns_[conn], chunk.get(), m.ndata, "write() to peer");
                    to_sleep = std::chrono::milliseconds{0};

                } else if (m.saddr == peer_addr && m.daddr == my_addr) {
                    Conn conn{m.dport, m.sport};
                    read_match_(conns_[conn], chunk.get(), m.ndata);
                    to_sleep = std::chrono::milliseconds{0};
                }
                break;

            case dump::Meta::EV_CHUNK_URGENT:
                logger_.say(log::Level::WARN, "urgent data");
                break;

            case dump::Meta::EV_KEEPALIVE:
                break;

            default:
                assert(0);
            }
        }
    }
};

}

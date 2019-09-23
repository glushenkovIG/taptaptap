#pragma once

#include <vector>
#include <utility>
#include "container.hpp"
#include "log.hpp"
#include "util.hpp"
#include "subnet.hpp"
#include "proto.hpp"
#include <sys/epoll.h>

namespace router
{

template<class Handler>
class Router
{
    util::UnixFd epfd_;
    std::vector<container::Container> conts_;
    subnet::Subnet subnet_;
    Handler handler_;
    log::Logger logger_;

public:
    Router(
            std::vector<container::Container> &&conts,
            subnet::Subnet subnet,
            Handler &&handler,
            log::Logger logger
    )
        : epfd_{util::UnixFd(util::check_retval(
            epoll_create1(EPOLL_CLOEXEC),
            "epoll_create1")
          )}
        , conts_(std::move(conts))
        , subnet_(subnet)
        , handler_(std::move(handler))
        , logger_(std::move(logger))
    {
        for (size_t i = 0; i < conts_.size(); ++i) {
            union epoll_data d;
            d.u64 = i;
            struct epoll_event ev{EPOLLIN, d};
            util::check_retval(
                ::epoll_ctl(epfd_, EPOLL_CTL_ADD, conts_[i].tun.fd, &ev),
                "epoll_ctl: EPOLL_CTL_ADD");
        }
    }

    void run()
    {
        enum { NEVBUF = 64 };
        struct epoll_event ev_buf[NEVBUF];

        enum { PKT_MAX = 65535 };
        std::unique_ptr<char[]> pkt(new char[PKT_MAX]);

        while (true) {
            const int nevs = util::check_retval(
                ::epoll_wait(epfd_, ev_buf, NEVBUF, -1),
                "epoll_wait");
            for (int i = 0; i < nevs; ++i) {
                if (!(ev_buf[i].events & EPOLLIN))
                    continue;
                const auto cont_idx = ev_buf[i].data.u64;
                const ssize_t n = util::check_retval(
                    ::read(conts_[cont_idx].tun.fd, pkt.get(), PKT_MAX),
                    "read() from TUN fd");
                if (static_cast<size_t>(n) < sizeof(proto::ipv4_Header)) {
                    logger_.say(log::Level::WARN, "invalid packet");
                    continue;
                }
                auto ip_hdr = reinterpret_cast<proto::ipv4_Header *>(pkt.get());
                const uint32_t saddr = ip_hdr->saddr.load();
                const uint32_t daddr = ip_hdr->daddr.load();
                if (!subnet_.includes(saddr) || !subnet_.includes(daddr)) {
                    const auto saddr_str = subnet::format(saddr);
                    const auto daddr_str = subnet::format(daddr);
                    logger_.say(log::Level::WARN, "got packet from %s to %s",
                                saddr_str.c_str(), daddr_str.c_str());
                    continue;
                }
                const uint32_t src_idx = subnet_.id_by_addr(saddr) - 1;
                const uint32_t dst_idx = subnet_.id_by_addr(daddr) - 1;
                if (src_idx >= conts_.size() || dst_idx >= conts_.size()) {
                    logger_.say(log::Level::WARN, "got packet from ID %u to ID %u",
                                src_idx, dst_idx);
                    continue;
                }
                if (!handler_(src_idx, dst_idx, pkt.get(), n))
                    continue;
                util::check_retval(
                    ::write(conts_[dst_idx].tun.fd, pkt.get(), n),
                    "write() to TUN fd");
            }
        }
    }
};

}

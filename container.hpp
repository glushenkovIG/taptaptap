#pragma once

#include "util.hpp"
#include "subnet.hpp"
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sched.h>
#include <string.h>

namespace container
{

struct Tun
{
    util::UnixFd fd;
    std::string iface;
};

Tun open_tun()
{
    static const char *TUN_CTL_FILE = "/dev/net/tun";
    auto fd = util::UnixFd(util::check_retval(
        ::open(TUN_CTL_FILE, O_RDWR | O_CLOEXEC),
        TUN_CTL_FILE));

    struct ifreq ifr;
    memset(&ifr, '\0', sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    util::check_retval(
        ::ioctl(fd, TUNSETIFF, &ifr),
        "ioctl: TUNSETIFF");

    return {std::move(fd), std::string(ifr.ifr_name)};
}

struct Container
{
    Tun tun;
    uint32_t id;
};

Container spawn(subnet::Subnet net, uint32_t addr_id)
{
    util::check_retval(
        ::unshare(CLONE_NEWNET),
        "unshare: CLONE_NEWNET");
    auto tun = open_tun();
    util::checked_spawn({"ip", "link", "set", tun.iface.c_str(), "up"});
    util::checked_spawn({"ip", "link", "set", "lo", "up"});
    const auto subnet_str = subnet::format(net, addr_id);
    util::checked_spawn({"ip", "addr", "add", subnet_str.c_str(), "dev", tun.iface.c_str()});
    return {std::move(tun), addr_id};
}

}

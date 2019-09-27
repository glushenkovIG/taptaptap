#pragma once

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdarg.h>
#include <string>
#include <stdio.h>
#include <sys/wait.h>
#include <system_error>
#include <exception>
#include <memory>

namespace util
{

class UnixFd
{
    int fd_;
public:
    UnixFd() : fd_{-1} {}
    explicit UnixFd(int fd) : fd_{fd} {}

    UnixFd(const UnixFd &) = delete;
    UnixFd(UnixFd &&that) : fd_{that.fd_} { that.fd_ = -1; }
    UnixFd& operator =(const UnixFd &) = delete;

    UnixFd& operator =(UnixFd &&that)
    {
        close();
        fd_ = that.fd_;
        that.fd_ = -1;
        return *this;
    }

    operator int() const { return fd_; }

    void close()
    {
        if (fd_ >= 0)
            ::close(fd_);
        fd_ = -1;
    }

    ~UnixFd() { close(); }
};

template<class T>
T check_retval(T retval, const char *what)
{
    if (retval >= 0)
        return retval;
    const auto saved_errno = errno;
    throw std::system_error(saved_errno, std::generic_category(), what);
}

struct Pipe
{
    util::UnixFd read_end;
    util::UnixFd write_end;
};

Pipe make_pipe()
{
    int pipefds[2];
    check_retval(pipe2(pipefds, O_CLOEXEC), "pipe2");
    return {UnixFd{pipefds[0]}, UnixFd{pipefds[1]}};
}

void full_write(int fd, const void *buf, size_t nbuf, const char *what)
{
    for (size_t nwritten = 0; nwritten < nbuf;) {
        const ssize_t n = check_retval(
            ::write(fd, reinterpret_cast<const char *>(buf) + nwritten, nbuf - nwritten),
            what);
        nwritten += n;
    }
}

bool full_read(int fd, void *buf, size_t nbuf, const char *what)
{
    for (size_t nread = 0; nread < nbuf;) {
        const ssize_t n = check_retval(
            ::read(fd, reinterpret_cast<char *>(buf) + nread, nbuf - nread),
            what);
        if (!n)
            return false;
        nread += n;
    }
    return true;
}

void exec(std::vector<const char *> argv)
{
    argv.push_back(nullptr);
    ::execvp(argv[0], const_cast<char **>(argv.data()));
    ::perror(argv[0]);
    ::_exit(127);
}

template<class Func>
pid_t fork_do(Func &&func)
{
    const pid_t pid = check_retval(::fork(), "fork");
    if (pid == 0)
        // child
        ::_exit(func());
    // parent
    return pid;
}

class CommandFailed : public std::exception
{
public:
    const char *what() const noexcept override { return "command failed"; }
};

void checked_spawn(std::vector<const char *> argv)
{
    const pid_t pid = fork_do([&]() { exec(argv); return 127; });
    int status;
    check_retval(::waitpid(pid, &status, 0), "waitpid");
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        throw CommandFailed{};
}

}

#pragma once

#include <stdio.h>
#include <stdarg.h>
#include <string>
#include "util.hpp"

namespace log
{

enum class Level
{
    DEBUG,
    VERBOSE,
    WARN,
    INFO,
    ERROR,
    FATAL,
};

char level_symbol(Level level)
{
    switch (level) {
    case Level::DEBUG:   return 'D';
    case Level::VERBOSE: return 'V';
    case Level::WARN:    return 'W';
    case Level::INFO:    return 'I';
    case Level::ERROR:   return 'E';
    case Level::FATAL:   return 'F';
    }
    return '?';
}

class Handler
{
    Level level_;

    bool should_log_(Level level) const
    {
        return static_cast<unsigned>(level) >=
               static_cast<unsigned>(level_);
    }

public:
    explicit Handler(Level level)
        : level_{level}
    {
        ::setvbuf(stderr, nullptr, _IOLBF, 8192);
    }

    void vsay(Level level, const char *prefix, const char *fmt, va_list vl) const
    {
        if (!should_log_(level))
            return;
        char buf[1024];
        util::check_retval(::vsnprintf(buf, sizeof(buf), fmt, vl), "vsnprintf");
        if (prefix[0])
            ::fprintf(stderr, "%c: %s: %s\n", level_symbol(level), prefix, buf);
        else
            ::fprintf(stderr, "%c: %s\n", level_symbol(level), buf);
    }
};

class Logger
{
    Handler &handler_;
    std::string prefix_;

    static std::string append_to_prefix_(std::string prefix, std::string ident)
    {
        return prefix.empty() ? ident : prefix + ": " + ident;
    }

public:
    Logger(Handler &handler)
        : handler_{handler}
        , prefix_{} {}

    Logger(const Logger &parent, std::string ident)
        : handler_{parent.handler_}
        , prefix_{append_to_prefix_(parent.prefix_, ident)}
    {}

    __attribute__((format(printf, 3, 4)))
    void say(Level level, const char *fmt, ...) const
    {
        va_list vl;
        va_start(vl, fmt);
        handler_.vsay(level, prefix_.c_str(), fmt, vl);
        va_end(vl);
    }
};

}

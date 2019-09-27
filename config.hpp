#pragma once

#include <string>
#include <fstream>
#include <exception>
#include <string>
#include <stdint.h>

namespace config
{

class InvalidFormat : public std::exception
{
    std::string what_;
public:
    InvalidFormat(uint64_t line, const std::string &what = "invalid format")
        : what_(what + " in config at line " + std::to_string(line))
    {}

    const char *what() const noexcept override { return what_.c_str(); }
};

class OpenError : public std::exception
{
    std::string what_;
public:
    OpenError(const std::string &what) : what_(std::move(what)) {}
    const char *what() const noexcept override { return what_.c_str(); }
};

struct Item
{
    std::string key;
    std::string value;
    uint64_t line;

    operator bool() const { return line != 0; }
};

bool parse_bool(const Item &item)
{
    if (item.value == "yes" || item.value == "true" || item.value == "on" || item.value == "1")
        return true;
    if (item.value == "no" || item.value == "false" || item.value == "off" || item.value == "0")
        return false;
    throw InvalidFormat(item.line, "invalid boolean value");
}

class Reader
{
    std::ifstream stream_;
    uint64_t line_no_;

public:
    Reader(const std::string &path)
        : stream_(path)
        , line_no_{0}
    {
        if (!stream_)
            throw OpenError(path + ": cannot open file");
    }

    Item read()
    {
        const char *WHITESPACE = " \t";
        while (true) {
            std::string line;
            if (!std::getline(stream_, line))
                return Item{"", "", 0};
            ++line_no_;
            if (line.empty() || line[0] == '#')
                continue;

            const auto key_end = line.find_first_of(WHITESPACE);
            if (key_end == std::string::npos || key_end == 0)
                throw InvalidFormat(line_no_);

            auto value_begin = key_end + 1;
            while (line.find_first_of(WHITESPACE, value_begin) == value_begin)
                ++value_begin;
            if (value_begin == line.size())
                throw InvalidFormat(line_no_);

            return {line.substr(0, key_end), line.substr(value_begin), line_no_};
        }
    }
};

}

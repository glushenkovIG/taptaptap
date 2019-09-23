#pragma once

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
        while (true) {
            std::string line;
            if (!std::getline(stream_, line))
                return Item{"", "", 0};
            ++line_no_;
            if (line.empty() || line[0] == '#')
                continue;
            const auto space_pos = line.find(' ');
            if (space_pos >= line.size() || space_pos == 0)
                throw InvalidFormat(line_no_);
            return {line.substr(0, space_pos), line.substr(space_pos + 1), line_no_};
        }
    }
};

}

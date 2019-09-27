#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <utility>
#include "subnet.hpp"
#include "router.hpp"
#include "container.hpp"
#include "dump.hpp"
#include "record.hpp"
#include "replay.hpp"
#include "config.hpp"
#include "log.hpp"

struct Options
{
    bool timed = false;
    std::string subnet;
    std::string dump_file;
    std::vector<std::string> nodes;
};

static void parse_options_or_exit(config::Reader &reader, Options &opts, const log::Logger &logger)
{
    while (auto item = reader.read()) {
        if (item.key == "timed") {
            opts.timed = config::parse_bool(item);
        } else if (item.key == "subnet") {
            opts.subnet = item.value;
        } else if (item.key == "dump_file") {
            opts.dump_file = item.value;
        } else if (item.key == "node") {
            opts.nodes.push_back(item.value);
        } else {
            logger.say(log::Level::FATAL, "unknown key '%s' at line %lu",
                       item.key.c_str(), static_cast<unsigned long>(item.line));
            ::exit(1);
        }
    }
    if (opts.subnet.empty()) {
        logger.say(log::Level::FATAL, "no 'subnet' key");
        ::exit(1);
    }
    if (opts.dump_file.empty()) {
        logger.say(log::Level::FATAL, "no 'dump_file' key");
        ::exit(1);
    }
    if (opts.nodes.size() < 2) {
        logger.say(log::Level::FATAL, "at least two nodes are required");
        ::exit(1);
    }
}

static void run_shell(const std::string &cmd)
{
    util::checked_spawn({"/bin/sh", "-c", cmd.c_str()});
}

static void print_usage_and_exit(const std::string &what = "")
{
    if (!what.empty())
        ::fprintf(stderr, "Error: %s\n", what.c_str());
    ::fprintf(stderr, "USAGE: main record <CONFIG>\n");
    ::fprintf(stderr, "       main replay <CONFIG> <NODE_INDEX>\n");
    ::exit(2);
}

int main(int argc, char **argv)
{
    ::signal(SIGPIPE, SIG_IGN);

    if (argc < 2)
        ::print_usage_and_exit();

    int replay_for_node = -1;
    std::string config_path;

    if (strcmp(argv[1], "record") == 0) {
        if (argc != 3)
            ::print_usage_and_exit();
        config_path = argv[2];

    } else if (strcmp(argv[1], "replay") == 0) {
        if (argc != 4)
            ::print_usage_and_exit();
        config_path = argv[2];
        if (sscanf(argv[3], "%d", &replay_for_node) != 1)
            ::print_usage_and_exit("cannot parse <NODE_INDEX>");
        if (replay_for_node < 0)
            ::print_usage_and_exit("invalid <NODE_INDEX>");

    } else {
        ::print_usage_and_exit();
    }

    log::Handler handler(log::Level::DEBUG);
    log::Logger logger(handler);

    Options opts;
    {
        config::Reader reader(config_path);
        ::parse_options_or_exit(reader, opts, log::Logger(logger, "config"));
    }
    if (replay_for_node >= 0 &&
        static_cast<size_t>(replay_for_node) >= opts.nodes.size())
    {
        logger.say(log::Level::FATAL, "invalid node index");
        return 1;
    }
    const auto subnet = subnet::parse(opts.subnet);
    if (opts.nodes.size() >= subnet.last_addr()) {
        logger.say(log::Level::FATAL, "too many nodes for this subnet");
        return 1;
    }

    if (replay_for_node < 0) {
        dump::Writer writer{util::UnixFd{util::check_retval(
            ::open(
                opts.dump_file.c_str(),
                O_WRONLY | O_TRUNC | O_CREAT | O_CLOEXEC,
                static_cast<mode_t>(0600)),
            opts.dump_file.c_str()
        )}};
        std::vector<container::Container> conts;
        for (size_t i = 0; i < opts.nodes.size(); ++i) {
            conts.push_back(container::spawn(subnet, i + 1));
            ::run_shell(opts.nodes[i]);
        }
        auto router = router::Router<record::Handler>(
            std::move(conts),
            subnet,
            record::Handler(std::move(writer), log::Logger(logger, "record")),
            log::Logger(logger, "router"));
        router.run();

    } else {
        replay::Handler handler(
            opts.nodes.size(),
            replay_for_node,
            log::Logger(logger, "replay"));
        dump::Reader reader{util::UnixFd{util::check_retval(
            ::open(opts.dump_file.c_str(), O_RDONLY | O_CLOEXEC),
            opts.dump_file.c_str()
        )}};
        std::vector<container::Container> conts;
        for (size_t i = 0; i < opts.nodes.size(); ++i) {
            conts.push_back(container::spawn(subnet, i + 1));
            if (i == static_cast<size_t>(replay_for_node)) {
                ::run_shell(opts.nodes[i]);
            } else {
                const auto log_prefix = std::string("replay child for ID ") + std::to_string(i + 1);
                replay::Child child(
                    i + 1,
                    replay_for_node + 1,
                    subnet,
                    log::Logger(logger, log_prefix),
                    handler.child_pipe(i));
                util::fork_do([&]() { return child.main(reader, opts.timed); });
            }
        }
        auto router = router::Router<replay::Handler>(
            std::move(conts),
            subnet,
            std::move(handler),
            log::Logger(logger, "router"));
        router.run();
    }

    ::abort();
}

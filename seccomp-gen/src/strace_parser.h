// SPDX-License-Identifier: MIT
// strace(1) output parser.
//
// Handles:
//   * PID/TID prefixes in both "PID   " and "[pid NNN]" / "NNN  " forms
//     (strace -f -ff, with or without -tt/-ttt timestamps)
//   * "<unfinished ...>" / "<... syscall resumed>" split lines, merged back
//     per (tid, syscall)
//   * thread and child processes (clone/fork/vfork): events carry tid, and
//     phase state is inherited across process creation
//   * "+++ exited +++", "--- SIGXXX ---", "+++ killed +++" noise lines
//   * boot/runtime separation at a user marker (see phaseMarker())
#pragma once

#include "common.h"
#include <iosfwd>
#include <map>
#include <set>

namespace scg {

struct ParseStats {
    uint64_t lines = 0;
    uint64_t events = 0;
    uint64_t unfinished = 0;
    uint64_t resumed = 0;
    uint64_t noiseLines = 0;
    uint64_t parseErrors = 0;
    std::set<int> tids;
    std::set<std::string> unknownSyscalls;
    bool markerSeen = false;
    uint64_t markerLine = 0;
};

struct ParseResult {
    std::vector<SysEvent> events; // in stream order
    ParseStats stats;
    std::vector<std::string> warnings;
};

class StraceParser {
public:
    // marker: a syscall name whose first occurrence flips every task from
    // boot to runtime (e.g. an application "ready" ping). Empty disables it.
    explicit StraceParser(std::string marker = "SECCMP_READY")
        : marker_(std::move(marker)) {}

    ParseResult parse(std::istream& in);

private:
    std::string marker_;

    // Pending "<unfinished ...>" syscalls keyed by tid.
    struct Pending {
        std::string syscall;
        std::string argsText;
        uint64_t startLine = 0;
        int pid = 0;
        int tid = 0;
    };
    std::map<int, Pending> pending_;

    // Runtime phase reached globally once the marker syscall has been seen;
    // per-task boot/runtime state also tracked so children forking before
    // the marker stay in boot until it fires.
    bool globalRuntime_ = false;
    std::map<int, bool> tidRuntime_;

    bool isRuntime(int tid);
    void noteForkLike(const SysEvent& e);
};

// Exposed for unit tests.
std::vector<std::string> splitArgs(const std::string& argsText);
std::optional<ArgValue> parseArgToken(const std::string& raw);
// Parse an strace numeric/symbolic scalar ("12", "AF_INET",
// "SOCK_STREAM|SOCK_CLOEXEC", "0x10", "-1") into a number when possible.
std::optional<uint64_t> parseScalar(const std::string& token);

} // namespace scg

// trace.h — strace output parsing (multi-process / multi-thread aware).
#pragma once
#include <cstdint>
#include <string>
#include <vector>

struct Event {
    int pid = 0;
    std::string name;               // syscall name
    std::string args_str;           // raw argument text
    std::vector<std::string> args;  // top-level split arguments
    std::vector<uint64_t> arg_vals; // resolved numeric values (valid if arg_ok)
    std::vector<bool> arg_ok;
    std::string ret_str;
    int line_no = 0;                // 1-based line number in its source file
    std::string file;               // source file
    std::string raw;                // original line
    int phase = 1;                  // 0 = startup, 1 = runtime (assigned later)
};

struct TraceParseResult {
    std::vector<Event> events;
    int lines_total = 0;
    int lines_parsed = 0;
    int lines_skipped = 0;
    std::vector<std::string> warnings;
};

// Parse one or more strace -f outputs (concatenated in the given order).
TraceParseResult parse_strace_files(const std::vector<std::string>& paths);

// Find the startup/runtime split point. Returns the index of the marker
// event (the LAST startup event), or -1 when no marker is found.
// marker_string: substring matched against the raw line.
// marker_call:   syscall name whose first call is the marker.
int find_marker(const std::vector<Event>& events,
                const std::string& marker_string,
                const std::string& marker_call);

// Resolve a strace value token ("AF_INET", "O_RDONLY|O_CLOEXEC", "0x541B",
// "0644", "-100", "NULL", "key=value") to a number.
bool resolve_value(const std::string& token, uint64_t& out);

// Split a strace argument list on top-level commas (quote/paren aware).
std::vector<std::string> split_args(const std::string& s);

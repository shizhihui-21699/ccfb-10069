// policy.h — policy model, DSL (parse/emit), and policy generation from events.
#pragma once
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "trace.h"

enum class Action { Kill, Errno, Trap, Log, Allow };
enum class Phase { Startup, Runtime, Always };

struct ArgConstraint {
    int arg = 0;                    // argument index (0..5)
    std::vector<uint64_t> values;   // allowed value set (IN semantics)
};

struct Rule {
    std::string syscall;
    Phase phase = Phase::Always;
    Action action = Action::Allow;
    std::vector<ArgConstraint> constraints;
    // statistics (filled during generation, used by the report)
    int count = 0;
    std::set<int> pids;
};

struct Policy {
    std::string arch = "x86_64";
    Action default_action = Action::Kill;
    uint16_t errno_code = 1; // EPERM, used when default_action == Errno
    std::vector<Rule> rules;
};

struct GenInfo {
    int total_events = 0;
    int startup_events = 0;
    int runtime_events = 0;
    std::set<int> pids;
    std::map<int, std::map<std::string, int>> per_pid;
    std::vector<std::string> unknown_syscalls;
    std::vector<std::string> notes; // dropped constraints etc.
    int marker_idx = -1;
    std::string marker_desc;
    bool has_marker = false;
};

// Build a minimal policy from observed events. Events must already carry
// phase assignments (0 startup / 1 runtime).
Policy policy_generate(const std::vector<Event>& events, const std::string& arch,
                       bool use_constraints, GenInfo& info);

// Serialize policy to the secpol DSL.
std::string policy_to_dsl(const Policy& pol, const GenInfo* info);

// Parse the secpol DSL. Returns false and sets err on failure.
bool policy_from_dsl(const std::string& text, Policy& out, std::string& err);

uint32_t action_code(Action a, uint16_t errno_code);
std::string action_str(Action a, uint16_t errno_code);
std::string phase_str(Phase p);

// Format a value for DSL output, preferring constant names appropriate for
// the given syscall/argument (e.g. AF_INET for socket arg0).
std::string fmt_value(const std::string& syscall, int arg, uint64_t v);

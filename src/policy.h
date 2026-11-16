// The policy intermediate representation.
//
// A policy is a set of rules.  Each rule matches a syscall (by name, by group,
// or by number for out-of-table calls) and optionally constrains arguments.
// Rules carry their origin (startup / runtime / both) and a verdict.
//
// Compilation is a pure function of (Policy, Arch): the same policy must give
// byte-identical filters, which is what lets the verifier re-run a generated
// filter against the trace.
#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "syscalls.h"

namespace scgen {

// When a rule applies.
enum class Phase {
  kStartup,  // only during start-up
  kRuntime,  // only after the service is ready
  kAny,      // both
  kBoth,     // an explicit rule covering startup *and* runtime, merged
};

std::string_view PhaseName(Phase phase);

// What happens when a rule matches.
struct Action {
  enum class Kind {
    kAllow,
    kErrno,   // return -errno
    kKill,    // kill the thread
    kKillProcess,
    kTrap,
    kTrace,
    kLog,
    kNotify,  // SECCOMP_RET_USER_NOTIF
  };

  Kind kind = Kind::kAllow;
  uint32_t errno_value = 0;   // for kErrno
  uint32_t trace_data = 0;    // for kTrace / kNotify

  static Action Allow() { return Action{}; }
  static Action Errno(uint32_t errno_value);
  static Action Kill();
  static Action KillProcess();
  static Action Trap();
  static Action Trace(uint32_t data);
  static Action Log();
  static Action Notify(uint32_t data);

  std::string ToString() const;   // "allow", "errno(EPERM)", "kill", ...
  uint32_t ToReturnValue() const; // seccomp return value
  bool is_allow() const { return kind == Kind::kAllow; }
};

// Comparison operators a rule can use on one argument.
enum class CompareOp { kEq, kNe, kLt, kLe, kGt, kGe, kMask, kNotMask, kIn, kNotIn, kRange };

std::string_view CompareOpName(CompareOp op);

struct Compare {
  CompareOp op = CompareOp::kEq;
  // For kEq/.../kRange: the bound(s).  Values are 64-bit because seccomp
  // arguments are; negative constants are stored two's complement.
  uint64_t a = 0;
  uint64_t b = 0;
  // For kIn/kNotIn.
  std::vector<uint64_t> set;

  // For error messages and reports.
  std::string ToString() const;
};

// One argument condition.  `arg` is 0..5.
struct Condition {
  int arg = 0;
  // Bits to keep before comparing; 0 means "compare the whole value".  This is
  // what makes `type & SOCK_TYPE_MASK == SOCK_STREAM` expressible: the socket
  // type shares its word with SOCK_CLOEXEC and SOCK_NONBLOCK.
  uint64_t mask = 0;
  Compare cmp;
  std::string comment;   // the source text, for diagnostics and reports
  bool is_flags = false; // the DSL spelled it as a flag set
  std::string source_file;
  int source_line = 0;
};

struct Rule {
  // Matching.
  std::string syscall;              // name, e.g. "socket"; empty when `syscall_number` is set
  std::optional<int> syscall_number; // explicit number (for calls missing from the table)
  std::vector<std::string> group;   // e.g. "fs_read"; expanded to syscalls
  bool wildcard = false;            // matches every syscall (used by catch-all rules)

  std::vector<Condition> conditions;  // all must hold (AND)

  Phase phase = Phase::kAny;
  Action action;

  // Provenance.
  std::string source_file;
  int source_line = 0;
  std::string note;   // free-form comment from the DSL
  bool generated = false;  // true for rules the generator synthesized
};

// Whether a rule of a given phase applies when the process is in `phase`.
// The startup filter deliberately also admits runtime rules: another thread
// may reach readiness before the second filter is installed on it.
bool RuleAppliesInPhaseForVerification(const Rule& rule, Phase phase);

struct Policy {
  std::vector<Rule> rules;
  // Both filters we emit.  Every policy must define what to do when nothing
  // matches; the DSL defaults to killing the thread.
  Action default_action = Action::Kill();
  std::string name;
  std::vector<std::string> notes;  // file-level documentation
};

// A resolved syscall matcher: either a name or a group.
struct SyscallGroup {
  std::string name;
  std::vector<std::string> members;
  std::string description;
};

// Built-in syscall groups (fs_read, net, thread, process, ...).  Groups only
// contain syscalls present in the 64-bit tables.
const std::vector<SyscallGroup>& BuiltinGroups();
const SyscallGroup* FindGroup(std::string_view name);

// Expands rules with `group` set into concrete rules, and validates every
// referenced syscall against the architecture tables.
struct ResolvedRule {
  std::string syscall;       // resolved name; empty when number-only
  int number = -1;
  const Rule* rule = nullptr;
  const Condition* conditions_owner() const;
};

// Returns every (rule, syscall) pair a policy implies for `arch`.  Unknown
// syscall names are returned as errors.
struct ResolveResult {
  std::vector<std::pair<const Rule*, std::string>> resolved;  // (rule, name)
  std::vector<std::string> errors;
};
ResolveResult ResolvePolicy(const Policy& policy, Arch arch);

// Convenience: does `rule` mention `syscall_name`?  Used by the reports.
bool RuleMentions(const Rule& rule, std::string_view syscall_name, Arch arch);

// Renders a numeric value with the most specific constant name from `prefix`
// (e.g. "O_CLOEXEC" for prefix "O_", 0x80000), falling back to decimal.  Used
// by the policy formatter and by the reports so both speak the same language.
std::string FormatConstantValue(uint64_t value, std::string_view prefix);

// Renders a flag word as the OR of its single-bit constants from `prefix`
// ("SOCK_CLOEXEC|SOCK_NONBLOCK"), falling back to FormatConstantValue when the
// value cannot be decomposed.
std::string RenderFlagWord(uint64_t value, std::string_view prefix);

// Renders an argument condition the way a reviewer should read it, resolving
// constants through the argument's own namespace.
std::string DescribeCondition(const Rule& rule, const Condition& cond);

}  // namespace scgen

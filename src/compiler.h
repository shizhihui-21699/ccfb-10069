// Compiling a policy into seccomp-bpf programs.
//
// Two filters are produced:
//
//   startup filter : installed before the process starts.  It allows the
//                    start-up rules and additionally anything the runtime
//                    rules allow, because the process may reach its ready
//                    point between two syscalls.
//   runtime filter : installed when the process signals readiness.  Only the
//                    runtime rules (plus explicit "phase any" rules) apply.
//
// The split is what lets the start-up filter stay closed during early
// execution while the long-lived filter is as small as possible.
//
// Layout of a generated program:
//
//     ld arch
//     jeq AUDIT_ARCH, ok, kill        ; wrong architecture: kill
//   ok:
//     ld nr
//     ... per-syscall dispatch ...
//     ret default_action
//
// Each syscall's argument conditions are emitted inline: load the argument
// (low and high half, since cBPF is 32-bit), compare, jump to the allow
// target on success, fall through to the deny path on failure.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "bpf.h"
#include "policy.h"
#include "syscalls.h"

namespace scgen {

struct CompileOptions {
  Arch arch = Arch::kX86_64;
  // When true, an unknown syscall number (one that is not in the generated
  // table and not matched by any wildcard rule) is allowed.  Default: killed.
  bool allow_unknown_syscalls = false;
  // Errno returned for syscalls the policy does not mention.  Only used when
  // `default_action` on the policy is an errno; the compiler takes the value
  // from the policy.
  bool emit_comments = true;
};

struct CompiledFilter {
  std::vector<Instruction> program;
  // Which syscalls the filter can allow, for the report.
  std::vector<std::string> allowed;
  // Syscalls it can deny explicitly, with the verdict.
  std::vector<std::pair<std::string, Action>> denied;
  // Syscalls with argument-level restrictions.
  struct ArgRestriction {
    std::string syscall;
    // One entry per rule that restricts this syscall, with the rule's verdict
    // and its conditions joined by " and ".  Keeping a rule's conditions
    // together is what makes "socket: domain == AF_INET and type & 0xf ==
    // SOCK_STREAM" readable; splitting them into separate rows implies they
    // are alternatives.
    struct Clause {
      std::string verdict;   // "allow", "errno(EPERM)", ...
      std::string condition; // "domain == AF_INET and type & 0xf == SOCK_STREAM"
    };
    std::vector<Clause> clauses;
  };
  std::vector<ArgRestriction> restricted;
  int instruction_count = 0;
};

// Compiles the rules that apply in `phase`.  `phase == Phase::kStartup` is for
// the filter installed at exec time; `Phase::kRuntime` for the one installed
// at readiness.
CompiledFilter CompileFilter(const Policy& policy, Phase phase,
                             const CompileOptions& options);

// Human readable summary of what a filter allows and denies, used by the
// report generator.
std::string SummarizeFilter(const CompiledFilter& filter, Arch arch);

}  // namespace scgen

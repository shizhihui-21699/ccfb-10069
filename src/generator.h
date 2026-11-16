// Generating a policy from a trace.
//
// The generator is conservative by design: it widens a constraint only when
// the trace proves it can, and it says so in the report.
//
// Inference rules for argument restrictions:
//
//   * socket(domain): the observed set of AF_* values becomes an `in [...]`
//     list.  If every call used AF_INET, the rule becomes domain == AF_INET.
//   * socket(type): SOCK_CLOEXEC and SOCK_NONBLOCK stay free (they are process
//     hygiene flags); the type nibble becomes an equality per observed value.
//   * setsockopt(level, optname): the observed (level, optname) pairs become a
//     disjunction of rules restricted to those pairs.
//   * openat/newfstatat/faccessat2... (flags): observed flag words are
//     compared with `has` on the flags every call shared, and `lacks` on none.
//   * any other argument: if every observed value is identical, an equality
//     rule is emitted; if the values form a small set, `in [...]`.
//
// Never inferred: anything about a pointer argument beyond what the trace
// printed (the syscall re-reads memory, so a value match proves nothing).
#pragma once

#include <string>
#include <vector>

#include "policy.h"
#include "strace_parser.h"

namespace scgen {

struct GeneratorOptions {
  Arch arch = Arch::kX86_64;
  // Maximum number of observed values we are willing to turn into an `in`
  // list.  Above this the argument is left unconstrained and the report says
  // so.
  int max_in_list = 8;
  // Restrict socket() domains (the case the task asks for).
  bool constrain_socket_domain = true;
  // Restrict flag words (openat, accept4, ...) to the observed bits.
  bool constrain_flags = true;
  // If a syscall only ever appeared with one argument value, pin that value.
  bool pin_single_values = true;
  // Emit rules for syscalls seen only in a forked child as runtime rules of
  // the whole policy (rather than a per-process policy).
  bool merge_all_processes = true;
};

// A process as the generator saw it, for the report.  Threads and forked
// children are listed separately because the reader needs to know that a
// rule came from a worker, not from the main thread.
struct ProcessObservation {
  int pid = 0;
  int created_by_pid = 0;
  std::string created_by_syscall;
  bool is_thread = false;
  bool is_forked_child = false;
  int startup_calls = 0;
  int runtime_calls = 0;
};

struct GenerationStats {
  int startup_syscalls = 0;
  int runtime_syscalls = 0;
  int only_startup = 0;
  int only_runtime = 0;
  int both = 0;
  int argument_restrictions = 0;
  std::vector<std::string> notes;      // why something was left out
  std::vector<std::string> warnings;
};

struct GenerationResult {
  Policy policy;
  GenerationStats stats;
  // Syscalls observed per phase, for the report.
  std::vector<std::string> startup_only;
  std::vector<std::string> runtime_only;
  std::vector<std::string> in_both;
  // Per-syscall observed argument values, for the report's "why" column.
  std::map<std::string, std::vector<std::string>> observed_arguments;
  // Every process in the trace, so the guide can describe the workload.
  std::vector<ProcessObservation> processes;
};

GenerationResult GeneratePolicy(const Trace& trace, const GeneratorOptions& options);

}  // namespace scgen

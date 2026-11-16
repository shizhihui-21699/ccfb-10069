// Verification: replay a trace against a policy.
//
// Two independent checks run over the same trace:
//
//  1. Reference check.  The policy is evaluated directly from the DSL
//     semantics (RuleMatches): no BPF involved.  This is what the policy
//     *means*.
//  2. Filter check.  Every syscall in the trace is fed to the generated BPF
//     program through the interpreter.  This is what the kernel will *do*.
//
// The verifier compares the two.  A disagreement is a compiler bug and is
// reported with the syscall, the arguments and both verdicts.  It also reports
// the cases the person cares about: a recorded syscall the filter denies
// (the service would break) and a denied call the policy allows (the filter is
// stricter than intended, which is acceptable but must be known).
#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "bpf.h"
#include "compiler.h"
#include "policy.h"
#include "strace_parser.h"
#include "syscalls.h"

namespace scgen {

// How a single trace entry is judged.
struct Verdict {
  enum class Source { kReference, kFilter };

  bool allowed = false;
  uint32_t action = 0;          // seccomp return value
  std::string explanation;      // which rule matched, or why nothing did
  const Rule* matched_rule = nullptr;
};

struct CallResult {
  int pid = 0;
  int line = 0;
  std::string syscall;
  std::vector<std::string> args;   // rendered arguments
  Phase phase = Phase::kRuntime;
  Verdict reference;
  Verdict filter;
  bool matches = false;            // reference and filter agree
  bool mismatch_is_error = false;  // filter is *more permissive* than policy
};

struct PhaseReport {
  Phase phase = Phase::kRuntime;
  int calls = 0;
  int allowed = 0;
  int denied = 0;
  // Recorded calls the filter blocks: the service would fail at run time.
  std::vector<CallResult> blocked_recorded;
  // Reference/filter disagreements.
  std::vector<CallResult> mismatches;
  // Denials the policy intends (recorded syscall that the policy also denies).
  int intended_denials = 0;
};

struct VerificationResult {
  bool ok = false;
  PhaseReport startup;
  PhaseReport runtime;
  // Every distinct syscall the filter allows, with the rules responsible.
  std::map<std::string, std::vector<std::string>> allow_explanations;
  std::vector<std::string> errors;
  std::vector<std::string> warnings;
  // Calls the trace contains but the generated tables do not know.
  std::vector<std::string> unknown_syscalls;
  int total_calls = 0;
  // Per-process summaries, so a denial in a worker is attributed correctly.
  struct ProcessSummary {
    int pid = 0;
    std::string comm;
    bool is_thread = false;
    bool is_forked_child = false;
    int created_by_pid = 0;
    std::string created_by_syscall;
    int calls = 0;
    int denials = 0;
  };
  std::vector<ProcessSummary> processes;
};

struct VerifyOptions {
  Arch arch = Arch::kX86_64;
  // Treat a filter that is stricter than the policy as an error too.  The
  // default is to report it as a warning: strictness never breaks the service,
  // but it is usually a bug in the policy text.
  bool strict_on_narrower_filter = false;
};

// Evaluates the policy for one call without involving BPF.
Verdict EvaluatePolicy(const Policy& policy, Phase phase,
                       const std::string& syscall,
                       const std::vector<Argument>& args, Arch arch);

// Builds the struct seccomp_data a kernel would present for this call.
SeccompData BuildSeccompData(const Syscall& call, Arch arch);

// Replays `trace` against both filters.
VerificationResult VerifyTrace(const Trace& trace, const Policy& policy,
                               const std::vector<Instruction>& startup_filter,
                               const std::vector<Instruction>& runtime_filter,
                               const VerifyOptions& options);

// Same, compiling the filters from the policy.
VerificationResult VerifyTrace(const Trace& trace, const Policy& policy,
                               const VerifyOptions& options);

}  // namespace scgen

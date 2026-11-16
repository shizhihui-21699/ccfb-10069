// sctrace: turn an strace log into a minimal seccomp-bpf policy, verify the
// generated filter against the trace, and explain the result.
//
// Subcommands:
//
//   generate   read a trace, infer a policy, verify it, write policy + report
//   verify     replay a trace against an existing policy
//   emit       compile a policy into C source (and optionally a report)
//   dump       print the parsed trace (debugging aid for the parser)
//   explain    print what a policy allows, without a trace
//
// The commands share the pipeline:
//
//   ParseTraceFile -> AssignPhases -> GeneratePolicy -> ParsePolicyDsl
//                  -> CompileFilter (startup, runtime) -> VerifyTrace
//                  -> BuildPolicyGuide / BuildCSource
#pragma once

#include <string>
#include <vector>

namespace scgen {

struct CliOptions {
  std::string command;
  std::string trace_path;
  std::string policy_in;       // --policy
  std::string policy_out;      // --write-policy
  std::string report_out;      // --report
  std::string c_out;           // --c-source
  std::string arch_name = "x86_64";
  std::string ready_syscall;
  std::string ready_after;     // seconds
  std::string ready_after_calls;
  std::string binary_name;
  bool dump_program = false;
  bool print_trace = false;
  bool quiet = false;
  bool fail_on_warning = false;
  int max_in_list = 8;
};

// Runs the CLI.  Returns a process exit code: 0 success, 1 verification
// failure, 2 usage or parse error.
int RunCli(const std::vector<std::string>& args);

}  // namespace scgen

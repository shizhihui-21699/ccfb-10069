// Human-readable reports.
//
// Two documents are produced:
//
//   * the policy guide (Markdown): what the filter allows, what it blocks, why
//     each restriction exists, and what the verification found.  This is the
//     document a reviewer reads before signing off.
//   * the C source: two BPF programs plus install code using
//     seccomp(SECCOMP_SET_MODE_FILTER).
#pragma once

#include <string>
#include <vector>

#include "compiler.h"
#include "generator.h"
#include "policy.h"
#include "strace_parser.h"
#include "verifier.h"

namespace scgen {

struct ReportOptions {
  Arch arch = Arch::kX86_64;
  std::string trace_path;
  std::string binary_name;
  PhaseOptions phase_options;
  bool include_disassembly = false;
};

struct Report {
  std::string markdown;   // the human-readable guide
  std::string c_source;   // the installable filter
};

// Builds the Markdown guide.
std::string BuildPolicyGuide(const Policy& policy, const CompiledFilter& startup,
                             const CompiledFilter& runtime,
                             const VerificationResult& verification,
                             const GenerationResult* generation,
                             const ReportOptions& options);

// Emits the C source with both filters and the install code.
std::string BuildCSource(const Policy& policy, const CompiledFilter& startup,
                         const CompiledFilter& runtime,
                         const ReportOptions& options);

}  // namespace scgen

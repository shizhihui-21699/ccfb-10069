#include "cli.h"

#include <cstdio>
#include <fstream>
#include <iostream>
#include <sstream>

#include "bpf.h"
#include "common.h"
#include "compiler.h"
#include "dsl.h"
#include "generator.h"
#include "report.h"
#include "strace_parser.h"
#include "syscalls.h"
#include "verifier.h"

namespace scgen {
namespace {

const char* kUsage = R"(sctrace - generate and verify seccomp-bpf policies from strace output

Usage:
  sctrace generate --trace FILE [--arch x86_64|aarch64] [options]
  sctrace verify   --trace FILE --policy FILE [options]
  sctrace emit     --policy FILE [--arch ...] [--c-source FILE] [--report FILE]
  sctrace explain  --policy FILE [--arch ...]
  sctrace dump     --trace FILE [options]
  sctrace tables   [--arch ...]

Options:
  --trace FILE             strace -f output to read
  --policy FILE            policy DSL file
  --arch ARCH              x86_64 (default) or aarch64
  --ready-syscall NAME     start-up/runtime boundary is this syscall
  --ready-after SECONDS    boundary is this many seconds into the trace
  --ready-after-calls N    boundary is after N syscalls in the first process
  --write-policy FILE      where to write the generated policy DSL
  --report FILE            where to write the human-readable guide (Markdown)
  --c-source FILE          where to write the installable C source
  --binary-name NAME       name of the traced binary (documentation only)
  --dump-program           include the generated BPF disassembly in the report
  --max-in-list N          largest observed value set turned into 'in [...]'
  --quiet                  only print errors and the final verdict
  --fail-on-warning        exit non-zero when verification has warnings

Exit status: 0 verified, 1 verification failed, 2 usage or parse error.
)";

struct ParsedArgs {
  CliOptions options;
  std::vector<std::string> errors;
};

ParsedArgs ParseArgs(const std::vector<std::string>& args) {
  ParsedArgs parsed;
  size_t i = 0;
  if (i < args.size()) {
    parsed.options.command = args[i++];
  }
  while (i < args.size()) {
    std::string arg = args[i++];
    auto value = [&](const char* what) -> std::string {
      if (i >= args.size()) {
        parsed.errors.push_back(std::string("missing value for ") + what);
        return "";
      }
      return args[i++];
    };
    if (arg == "--trace") {
      parsed.options.trace_path = value("--trace");
    } else if (arg == "--policy") {
      parsed.options.policy_in = value("--policy");
    } else if (arg == "--arch") {
      parsed.options.arch_name = value("--arch");
    } else if (arg == "--ready-syscall") {
      parsed.options.ready_syscall = value("--ready-syscall");
    } else if (arg == "--ready-after") {
      parsed.options.ready_after = value("--ready-after");
    } else if (arg == "--ready-after-calls") {
      parsed.options.ready_after_calls = value("--ready-after-calls");
    } else if (arg == "--write-policy") {
      parsed.options.policy_out = value("--write-policy");
    } else if (arg == "--report") {
      parsed.options.report_out = value("--report");
    } else if (arg == "--c-source") {
      parsed.options.c_out = value("--c-source");
    } else if (arg == "--binary-name") {
      parsed.options.binary_name = value("--binary-name");
    } else if (arg == "--max-in-list") {
      std::string text = value("--max-in-list");
      if (auto v = ParseInteger(text)) {
        parsed.options.max_in_list = static_cast<int>(*v);
      } else {
        parsed.errors.push_back("invalid --max-in-list value: " + text);
      }
    } else if (arg == "--dump-program") {
      parsed.options.dump_program = true;
    } else if (arg == "--print-trace") {
      parsed.options.print_trace = true;
    } else if (arg == "--quiet") {
      parsed.options.quiet = true;
    } else if (arg == "--fail-on-warning") {
      parsed.options.fail_on_warning = true;
    } else if (arg == "--help" || arg == "-h") {
      parsed.options.command = "help";
    } else if (StartsWith(arg, "--")) {
      parsed.errors.push_back("unknown option: " + arg);
    } else {
      parsed.errors.push_back("unexpected argument: " + arg);
    }
  }
  return parsed;
}

std::string ReadFile(const std::string& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) throw Error("cannot open " + path);
  std::ostringstream buffer;
  buffer << in.rdbuf();
  return buffer.str();
}

void WriteFile(const std::string& path, const std::string& content) {
  std::ofstream out(path, std::ios::binary);
  if (!out) throw Error("cannot write " + path);
  out << content;
  if (!out) throw Error("write failed for " + path);
}

PhaseOptions MakePhaseOptions(const CliOptions& options, std::vector<std::string>* errors) {
  PhaseOptions phase;
  phase.ready_syscall = options.ready_syscall;
  if (!options.ready_after.empty()) {
    try {
      phase.ready_after_seconds = std::stod(options.ready_after);
    } catch (...) {
      errors->push_back("invalid --ready-after value: " + options.ready_after);
    }
  }
  if (!options.ready_after_calls.empty()) {
    if (auto v = ParseInteger(options.ready_after_calls)) {
      phase.ready_after_syscalls = static_cast<int>(*v);
    } else {
      errors->push_back("invalid --ready-after-calls value: " +
                        options.ready_after_calls);
    }
  }
  return phase;
}

Arch ResolveArchOrDie(const std::string& name) {
  auto arch = ParseArch(name);
  if (!arch) throw Error("unknown architecture '" + name + "' (use x86_64 or aarch64)");
  return *arch;
}

Policy LoadPolicyOrDie(const std::string& path, Arch arch,
                       std::vector<std::string>* warnings) {
  DslParseResult parsed = ParsePolicyDsl(ReadFile(path), path, arch);
  if (!parsed.errors.empty()) {
    for (const std::string& error : parsed.errors) {
      std::cerr << "error: " << error << "\n";
    }
    throw Error("policy failed to parse");
  }
  for (const std::string& warning : parsed.warnings) {
    std::cerr << "warning: " << warning << "\n";
    if (warnings) warnings->push_back(warning);
  }
  return parsed.policy;
}

void PrintVerification(const VerificationResult& result, bool quiet) {
  if (!quiet) {
    std::printf("startup: %d calls (%d allowed, %d denied, %d denials intended "
                "by the policy)\n",
                result.startup.calls, result.startup.allowed, result.startup.denied,
                result.startup.intended_denials);
    std::printf("runtime: %d calls (%d allowed, %d denied, %d denials intended "
                "by the policy)\n",
                result.runtime.calls, result.runtime.allowed, result.runtime.denied,
                result.runtime.intended_denials);
  }
  for (const std::string& warning : result.warnings) {
    std::printf("warning: %s\n", warning.c_str());
  }
  if (result.ok) {
    std::printf("verified: the generated filter matches the policy on all %d "
                "recorded calls\n", result.total_calls);
  } else {
    std::printf("FAILED: %zu problem(s) in the generated filter\n",
                result.errors.size());
    for (const std::string& error : result.errors) {
      std::printf("  - %s\n", error.c_str());
    }
  }
}

void PrintTrace(const Trace& trace) {
  for (const Process& proc : trace.processes) {
    std::printf("process %d%s%s: %zu startup, %zu runtime syscalls%s\n", proc.pid,
                proc.is_thread ? " (thread)" : "",
                proc.is_forked_child ? " (forked child)" : "",
                proc.startup.size(), proc.runtime.size(),
                proc.created_by_syscall.empty() ? "" :
                (" (created by " + proc.created_by_syscall + ")").c_str());
    for (const Syscall& call : proc.syscalls) {
      std::printf("  %s(%s)\n", call.name.c_str(), call.args.empty() ? "" :
                  [&] {
                    std::string out;
                    for (size_t i = 0; i < call.args.size(); ++i) {
                      if (i) out += ", ";
                      out += call.args[i].text;
                    }
                    return out;
                  }().c_str());
    }
  }
  for (const TraceDiagnostic& d : trace.diagnostics) {
    std::printf("diagnostic line %d: %s\n", d.line, d.message.c_str());
  }
}

}  // namespace

int RunCli(const std::vector<std::string>& args) {
  if (args.empty() || args[0] == "help" || args[0] == "--help" || args[0] == "-h") {
    std::printf("%s", kUsage);
    return 0;
  }

  ParsedArgs parsed = ParseArgs(args);
  if (!parsed.errors.empty()) {
    for (const std::string& error : parsed.errors) {
      std::cerr << "error: " << error << "\n";
    }
    std::cerr << kUsage;
    return 2;
  }
  const CliOptions& options = parsed.options;

  try {
    const std::string& command = options.command;

    if (command == "tables") {
      Arch arch = ResolveArchOrDie(options.arch_name);
      for (const std::string& name : AllSyscallNames()) {
        int nr = SyscallNumber(arch, name);
        if (nr >= 0) std::printf("%d %s\n", nr, name.c_str());
      }
      return 0;
    }

    if (command == "explain") {
      if (options.policy_in.empty()) {
        std::cerr << "error: --policy is required\n";
        return 2;
      }
      Arch arch = ResolveArchOrDie(options.arch_name);
      Policy policy = LoadPolicyOrDie(options.policy_in, arch, nullptr);
      CompileOptions copts;
      copts.arch = arch;
      CompiledFilter startup = CompileFilter(policy, Phase::kStartup, copts);
      CompiledFilter runtime = CompileFilter(policy, Phase::kRuntime, copts);
      std::printf("startup: %s\n", SummarizeFilter(startup, arch).c_str());
      std::printf("  allows: %s\n", Join(startup.allowed, ", ").c_str());
      std::printf("runtime: %s\n", SummarizeFilter(runtime, arch).c_str());
      std::printf("  allows: %s\n", Join(runtime.allowed, ", ").c_str());
      for (const auto& restriction : runtime.restricted) {
        for (const auto& clause : restriction.clauses) {
          std::printf("  %s: if %s -> %s\n", restriction.syscall.c_str(),
                      clause.condition.c_str(), clause.verdict.c_str());
        }
      }
      return 0;
    }

    if (command == "dump") {
      if (options.trace_path.empty()) {
        std::cerr << "error: --trace is required\n";
        return 2;
      }
      Arch arch = ResolveArchOrDie(options.arch_name);
      std::vector<std::string> errors;
      PhaseOptions phase = MakePhaseOptions(options, &errors);
      if (!errors.empty()) {
        for (auto& e : errors) std::cerr << "error: " << e << "\n";
        return 2;
      }
      Trace trace = ParseTraceFile(options.trace_path, arch);
      AssignPhases(trace, phase);
      PrintTrace(trace);
      return 0;
    }

    if (command == "emit") {
      if (options.policy_in.empty()) {
        std::cerr << "error: --policy is required\n";
        return 2;
      }
      Arch arch = ResolveArchOrDie(options.arch_name);
      Policy policy = LoadPolicyOrDie(options.policy_in, arch, nullptr);
      CompileOptions copts;
      copts.arch = arch;
      CompiledFilter startup = CompileFilter(policy, Phase::kStartup, copts);
      CompiledFilter runtime = CompileFilter(policy, Phase::kRuntime, copts);
      ValidationResult sv = Validate(startup.program);
      ValidationResult rv = Validate(runtime.program);
      if (!sv.ok || !rv.ok) {
        std::cerr << "error: generated filter is invalid: "
                  << (sv.ok ? rv.message : sv.message) << "\n";
        return 1;
      }
      ReportOptions ropts;
      ropts.arch = arch;
      ropts.include_disassembly = options.dump_program;
      std::string c_source = BuildCSource(policy, startup, runtime, ropts);
      if (!options.c_out.empty()) {
        WriteFile(options.c_out, c_source);
        std::printf("wrote %s\n", options.c_out.c_str());
      } else {
        std::printf("%s", c_source.c_str());
      }
      if (!options.report_out.empty()) {
        VerificationResult empty;
        empty.ok = true;
        std::string guide = BuildPolicyGuide(policy, startup, runtime, empty, nullptr, ropts);
        WriteFile(options.report_out, guide);
        std::printf("wrote %s\n", options.report_out.c_str());
      }
      return 0;
    }

    if (command != "generate" && command != "verify") {
      std::cerr << "error: unknown command '" << command << "'\n";
      std::cerr << kUsage;
      return 2;
    }

    if (options.trace_path.empty()) {
      std::cerr << "error: --trace is required\n";
      return 2;
    }
    Arch arch = ResolveArchOrDie(options.arch_name);
    std::vector<std::string> phase_errors;
    PhaseOptions phase = MakePhaseOptions(options, &phase_errors);
    if (!phase_errors.empty()) {
      for (auto& e : phase_errors) std::cerr << "error: " << e << "\n";
      return 2;
    }

    Trace trace = ParseTraceFile(options.trace_path, arch);
    AssignPhases(trace, phase);
    for (const TraceDiagnostic& d : trace.diagnostics) {
      std::cerr << "trace: line " << d.line << ": " << d.message << "\n";
    }

    Policy policy;
    GenerationResult generation;
    bool generated = command == "generate" && options.policy_in.empty();
    if (command == "verify") {
      if (options.policy_in.empty()) {
        std::cerr << "error: verify needs --policy\n";
        return 2;
      }
      policy = LoadPolicyOrDie(options.policy_in, arch, nullptr);
    } else if (!options.policy_in.empty()) {
      // generate --policy FILE: verify an existing policy against the trace.
      policy = LoadPolicyOrDie(options.policy_in, arch, nullptr);
    } else {
      GeneratorOptions gopts;
      gopts.arch = arch;
      gopts.max_in_list = options.max_in_list;
      generation = GeneratePolicy(trace, gopts);
      policy = generation.policy;
      for (const std::string& warning : generation.stats.warnings) {
        std::cerr << "warning: " << warning << "\n";
      }
    }

    VerifyOptions vopts;
    vopts.arch = arch;
    VerificationResult verification = VerifyTrace(trace, policy, vopts);

    if (generated) {
      // Emit the DSL text and re-parse it: the policy we verify against must be
      // the policy the file contains, not just the in-memory structure.
      std::string dsl = FormatPolicyDsl(policy, arch);
      if (!options.policy_out.empty()) {
        WriteFile(options.policy_out, dsl);
        std::printf("wrote policy %s\n", options.policy_out.c_str());
      }
      DslParseResult reparsed = ParsePolicyDsl(dsl, "<generated>", arch);
      if (!reparsed.errors.empty()) {
        for (const std::string& error : reparsed.errors) {
          std::cerr << "error: generated policy does not re-parse: " << error << "\n";
        }
        return 1;
      }
      VerificationResult roundtrip = VerifyTrace(trace, reparsed.policy, vopts);
      if (!roundtrip.ok) {
        std::cerr << "error: policy text and generated policy disagree after a "
                     "round trip\n";
        for (const std::string& e : roundtrip.errors) std::cerr << "  " << e << "\n";
        return 1;
      }
    }

    CompileOptions copts;
    copts.arch = arch;
    CompiledFilter startup = CompileFilter(policy, Phase::kStartup, copts);
    CompiledFilter runtime = CompileFilter(policy, Phase::kRuntime, copts);

    ValidationResult sv = Validate(startup.program);
    ValidationResult rv = Validate(runtime.program);
    if (!sv.ok || !rv.ok) {
      std::cerr << "error: generated filter failed validation: "
                << (sv.ok ? rv.message : sv.message) << "\n";
      return 1;
    }

    PrintVerification(verification, options.quiet);

    ReportOptions ropts;
    ropts.arch = arch;
    ropts.trace_path = options.trace_path;
    ropts.binary_name = options.binary_name;
    ropts.phase_options = phase;
    ropts.include_disassembly = options.dump_program;
    if (!options.report_out.empty()) {
      std::string guide = BuildPolicyGuide(policy, startup, runtime, verification,
                                           generated ? &generation : nullptr, ropts);
      WriteFile(options.report_out, guide);
      std::printf("wrote report %s\n", options.report_out.c_str());
    }
    if (!options.c_out.empty()) {
      WriteFile(options.c_out, BuildCSource(policy, startup, runtime, ropts));
      std::printf("wrote C source %s\n", options.c_out.c_str());
    }
    if (options.print_trace) PrintTrace(trace);

    if (!verification.ok) return 1;
    if (options.fail_on_warning && !verification.warnings.empty()) return 1;
    return 0;
  } catch (const Error& error) {
    std::cerr << "error: " << error.what() << "\n";
    return 2;
  } catch (const std::exception& error) {
    std::cerr << "internal error: " << error.what() << "\n";
    return 2;
  }
}

}  // namespace scgen

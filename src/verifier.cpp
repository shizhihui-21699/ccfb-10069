#include "verifier.h"

#include <algorithm>
#include <cstring>
#include <set>
#include <sstream>

#include "common.h"

namespace scgen {
namespace {

// ---------------------------------------------------------------------------
// Argument comparison against a trace argument
//
// Trace arguments are not always numeric: strace prints AF_INET rather than 2,
// and a truncated string shows up as 0x7ffe... with a "...".  For comparison we
// need a number.  When the trace gave a symbolic value we resolved it already;
// when it gave nothing usable the call cannot be verified and is reported.
// ---------------------------------------------------------------------------

struct ArgValue {
  bool known = false;
  uint64_t value = 0;
  bool from_symbol = false;
};

ArgValue GetArgValue(const Argument& arg) {
  ArgValue out;
  if (arg.value) {
    out.known = true;
    out.value = *arg.value;
    out.from_symbol = arg.shape == Argument::Shape::kSymbolic;
  }
  return out;
}

bool CompareHolds(const Compare& cmp, uint64_t value) {
  switch (cmp.op) {
    case CompareOp::kEq: return value == cmp.a;
    case CompareOp::kNe: return value != cmp.a;
    case CompareOp::kLt: return value < cmp.a;
    case CompareOp::kLe: return value <= cmp.a;
    case CompareOp::kGt: return value > cmp.a;
    case CompareOp::kGe: return value >= cmp.a;
    case CompareOp::kMask: return (value & cmp.a) == cmp.a;
    case CompareOp::kNotMask: return (value & cmp.a) != cmp.a;
    case CompareOp::kIn:
      for (uint64_t item : cmp.set) {
        if (value == item) return true;
      }
      return false;
    case CompareOp::kNotIn:
      for (uint64_t item : cmp.set) {
        if (value == item) return false;
      }
      return true;
    case CompareOp::kRange: return value >= cmp.a && value <= cmp.b;
  }
  return false;
}

std::string RenderArgument(const Argument& arg) {
  return arg.text;
}

}  // namespace

Verdict EvaluatePolicy(const Policy& policy, Phase phase,
                       const std::string& syscall_name,
                       const std::vector<Argument>& args, Arch arch) {
  Verdict verdict;
  verdict.allowed = false;
  verdict.action = policy.default_action.ToReturnValue();
  verdict.explanation = "no rule matches; default " +
                        policy.default_action.ToString();

  // Rules are consulted in source order, but a rule with argument conditions
  // that fails must not mask a later unconditional rule.  The generator emits
  // restricted rules first; here we follow the same precedence: the first rule
  // for this syscall whose conditions hold decides.  Rules for other syscalls
  // are skipped.
  const Rule* best = nullptr;
  int best_index = -1;
  for (size_t i = 0; i < policy.rules.size(); ++i) {
    const Rule& rule = policy.rules[i];
    if (!RuleAppliesInPhaseForVerification(rule, phase)) continue;
    if (!RuleMentions(rule, syscall_name, arch)) continue;
    // Evaluate conditions.
    bool holds = true;
    for (const Condition& cond : rule.conditions) {
      if (cond.arg >= static_cast<int>(args.size())) {
        holds = false;
        break;
      }
      ArgValue value = GetArgValue(args[cond.arg]);
      if (!value.known) {
        // An argument we could not resolve (a pointer, a truncated string).
        // The kernel compares the raw number; we cannot.  Treat the condition
        // as failing so that the reference is conservative and the mismatch
        // shows up as a "filter allowed, reference unsure" note rather than a
        // silent pass.
        holds = false;
        break;
      }
      uint64_t compared = cond.mask ? (value.value & cond.mask) : value.value;
      if (!CompareHolds(cond.cmp, compared)) {
        holds = false;
        break;
      }
    }
    if (!holds) continue;
    // Prefer the more specific rule: rules with conditions outrank those
    // without, matching the compiler's ordering.
    if (best == nullptr ||
        rule.conditions.size() > best->conditions.size() ||
        (rule.conditions.size() == best->conditions.size() && best_index < 0)) {
      best = &rule;
      best_index = static_cast<int>(i);
    }
  }

  if (best != nullptr) {
    verdict.allowed = best->action.is_allow();
    verdict.action = best->action.ToReturnValue();
    verdict.matched_rule = best;
    std::ostringstream why;
    why << (best->action.is_allow() ? "allowed by " : "denied by ")
        << (best->wildcard ? "*" : best->syscall.empty() ? "group rule" : best->syscall);
    if (!best->conditions.empty()) why << " (conditions hold)";
    verdict.explanation = why.str();
  }
  return verdict;
}

SeccompData BuildSeccompData(const Syscall& call, Arch arch) {
  SeccompData data;
  data.nr = SyscallNumber(arch, call.name);
  if (data.nr < 0) {
    // Unknown name: use the number the trace's own architecture would assign.
    // We cannot know it, so use 0 and let the verifier report the name.
    data.nr = 0;
  }
  data.arch = AuditArch(arch);
  for (int i = 0; i < 6; ++i) {
    if (i < static_cast<int>(call.args.size())) {
      ArgValue value = GetArgValue(call.args[i]);
      // A kernel sees the raw register value.  When strace gave us a symbolic
      // name we resolved it; when it gave us a pointer we use the address.
      data.args[i] = value.known ? value.value : 0;
    } else {
      data.args[i] = 0;
    }
  }
  return data;
}

namespace {

bool ActionMatchesReference(const Verdict& reference, uint32_t filter_action) {
  if (reference.allowed) return (filter_action & kRetActionFullMask) == kRetAllow;
  return reference.action == filter_action;
}

void CountVerdict(PhaseReport& report, const CallResult& call) {
  (void)report;
  (void)call;
}

}  // namespace

VerificationResult VerifyTrace(const Trace& trace, const Policy& policy,
                               const std::vector<Instruction>& startup_filter,
                               const std::vector<Instruction>& runtime_filter,
                               const VerifyOptions& options) {
  VerificationResult result;
  result.startup.phase = Phase::kStartup;
  result.runtime.phase = Phase::kRuntime;

  for (const Process& proc : trace.processes) {
    VerificationResult::ProcessSummary summary;
    summary.pid = proc.pid;
    summary.comm = proc.comm;
    summary.is_thread = proc.is_thread;
    summary.is_forked_child = proc.is_forked_child;
    summary.created_by_pid = proc.created_by_pid;
    summary.created_by_syscall = proc.created_by_syscall;

    // A forked child inherits the parent's installed filter.  A thread shares
    // the filter of its group.  The startup filter applies until the process
    // reaches readiness; after that, the runtime filter is in force.
    for (const Syscall& call : proc.startup) {
      ++summary.calls;
      CallResult cr;
      cr.pid = proc.pid;
      cr.line = call.line;
      cr.syscall = call.name;
      cr.phase = Phase::kStartup;
      for (const auto& arg : call.args) cr.args.push_back(RenderArgument(arg));

      if (SyscallNumber(options.arch, call.name) < 0) {
        result.unknown_syscalls.push_back(call.name);
        continue;
      }
      cr.reference = EvaluatePolicy(policy, Phase::kStartup, call.name, call.args,
                                    options.arch);
      SeccompData data = BuildSeccompData(call, options.arch);
      uint32_t action = 0;
      try {
        action = RunFilter(startup_filter, data);
      } catch (const Error& e) {
        result.errors.push_back("filter execution failed for " + call.name +
                                " at line " + std::to_string(call.line) + ": " +
                                e.what());
        continue;
      }
      cr.filter.allowed = (action & kRetActionFullMask) == kRetAllow;
      cr.filter.action = action;
      cr.filter.explanation = ActionDescription(action);
      cr.matches = ActionMatchesReference(cr.reference, action);

      ++result.total_calls;
      ++result.startup.calls;
      if (cr.filter.allowed) {
        ++result.startup.allowed;
      } else {
        ++result.startup.denied;
        ++summary.denials;
      }
      if (cr.matches) {
        if (!cr.filter.allowed) {
          ++result.startup.intended_denials;
          result.startup.blocked_recorded.push_back(cr);
        }
      } else if (cr.filter.allowed && !cr.reference.allowed) {
        cr.mismatch_is_error = true;
        result.startup.mismatches.push_back(cr);
        result.errors.push_back("line " + std::to_string(call.line) + ": filter "
                                "allows " + call.name +
                                " but the policy denies it");
      } else {
        // Filter stricter than the reference.  When the reference itself
        // denied the call this is only a difference in the deny mechanism;
        // when the reference allowed it, the service would break.
        if (cr.reference.allowed) {
          result.startup.blocked_recorded.push_back(cr);
          result.errors.push_back(
              "line " + std::to_string(call.line) + ": filter denies " +
              call.name + " (" + ActionDescription(action).substr(0, 64) +
              ") but the policy allows it; the service would fail here");
        } else {
          result.startup.mismatches.push_back(cr);
          result.warnings.push_back("line " + std::to_string(call.line) + ": " +
                                    call.name + " is denied both ways but with "
                                    "different verdicts (" + cr.reference.explanation +
                                    " vs " + ActionDescription(action) + ")");
        }
      }
      if (cr.reference.matched_rule && cr.reference.allowed) {
        std::string key = call.name;
        std::vector<std::string>& why = result.allow_explanations[key];
        std::string text = cr.reference.explanation;
        if (std::find(why.begin(), why.end(), text) == why.end()) why.push_back(text);
      }
    }

    for (const Syscall& call : proc.runtime) {
      ++summary.calls;
      CallResult cr;
      cr.pid = proc.pid;
      cr.line = call.line;
      cr.syscall = call.name;
      cr.phase = Phase::kRuntime;
      for (const auto& arg : call.args) cr.args.push_back(RenderArgument(arg));

      if (SyscallNumber(options.arch, call.name) < 0) {
        result.unknown_syscalls.push_back(call.name);
        continue;
      }
      cr.reference = EvaluatePolicy(policy, Phase::kRuntime, call.name, call.args,
                                    options.arch);
      SeccompData data = BuildSeccompData(call, options.arch);
      uint32_t action = 0;
      try {
        action = RunFilter(runtime_filter, data);
      } catch (const Error& e) {
        result.errors.push_back("filter execution failed for " + call.name +
                                " at line " + std::to_string(call.line) + ": " +
                                e.what());
        continue;
      }
      cr.filter.allowed = (action & kRetActionFullMask) == kRetAllow;
      cr.filter.action = action;
      cr.filter.explanation = ActionDescription(action);
      cr.matches = ActionMatchesReference(cr.reference, action);

      ++result.total_calls;
      ++result.runtime.calls;
      if (cr.filter.allowed) {
        ++result.runtime.allowed;
      } else {
        ++result.runtime.denied;
        ++summary.denials;
      }
      if (cr.matches) {
        if (!cr.filter.allowed) {
          ++result.runtime.intended_denials;
          result.runtime.blocked_recorded.push_back(cr);
        }
      } else if (cr.filter.allowed && !cr.reference.allowed) {
        cr.mismatch_is_error = true;
        result.runtime.mismatches.push_back(cr);
        result.errors.push_back("line " + std::to_string(call.line) + ": filter "
                                "allows " + call.name +
                                " but the policy denies it");
      } else {
        if (cr.reference.allowed) {
          result.runtime.blocked_recorded.push_back(cr);
          result.errors.push_back(
              "line " + std::to_string(call.line) + ": filter denies " +
              call.name + " but the policy allows it; the service would fail here");
        } else {
          result.runtime.mismatches.push_back(cr);
          result.warnings.push_back("line " + std::to_string(call.line) + ": " +
                                    call.name + " is denied both ways but with "
                                    "different verdicts");
        }
      }
      if (cr.reference.matched_rule && cr.reference.allowed) {
        std::vector<std::string>& why = result.allow_explanations[call.name];
        std::string text = cr.reference.explanation;
        if (std::find(why.begin(), why.end(), text) == why.end()) why.push_back(text);
      }
    }

    result.processes.push_back(summary);
  }

  // A policy that blocks calls the trace shows is the finding this tool exists
  // to produce: report one line per (phase, syscall) and fail.  Listing every
  // occurrence would bury the signal in a long trace.
  auto report_blocks = [&](PhaseReport& report, const char* phase_name) {
    std::set<std::string> seen;
    for (const CallResult& call : report.blocked_recorded) {
      if (!seen.insert(call.syscall).second) continue;
      result.errors.push_back(
          std::string(phase_name) + ": the policy denies " + call.syscall +
          " (seen at line " + std::to_string(call.line) +
          "), which the trace shows the service calling; it would fail there "
          "unless blocking that path is intended");
    }
  };
  report_blocks(result.startup, "startup");
  report_blocks(result.runtime, "runtime");

  std::sort(result.unknown_syscalls.begin(), result.unknown_syscalls.end());
  result.unknown_syscalls.erase(
      std::unique(result.unknown_syscalls.begin(), result.unknown_syscalls.end()),
      result.unknown_syscalls.end());

  result.ok = result.errors.empty();
  (void)CountVerdict;
  return result;
}

VerificationResult VerifyTrace(const Trace& trace, const Policy& policy,
                               const VerifyOptions& options) {
  CompileOptions copts;
  copts.arch = options.arch;
  CompiledFilter startup = CompileFilter(policy, Phase::kStartup, copts);
  CompiledFilter runtime = CompileFilter(policy, Phase::kRuntime, copts);
  return VerifyTrace(trace, policy, startup.program, runtime.program, options);
}

}  // namespace scgen

#include "generator.h"

#include <algorithm>
#include <map>
#include <set>
#include <sstream>

#include "common.h"

namespace scgen {
namespace {

// Observed argument values for one syscall in one phase.
struct ArgStats {
  bool seen_symbolic = false;
  bool seen_unresolved = false;
  bool seen_truncated = false;
  std::vector<uint64_t> values;        // distinct, in first-seen order
  std::map<uint64_t, int> counts;
  std::vector<std::string> rendered;   // symbolic names strace printed

  void Observe(const Argument& arg) {
    if (arg.truncated) seen_truncated = true;
    if (!arg.value) {
      seen_unresolved = true;
      return;
    }
    if (arg.shape == Argument::Shape::kSymbolic) seen_symbolic = true;
    if (!counts.count(*arg.value)) {
      values.push_back(*arg.value);
      for (const auto& sym : arg.symbols) rendered.push_back(sym);
    }
    counts[*arg.value]++;
  }
};

struct SyscallStats {
  std::string name;
  int calls = 0;
  std::map<int, ArgStats> args;
  std::vector<const Syscall*> samples;
};

// The set of syscalls observed in one phase.
struct PhaseStats {
  std::map<std::string, SyscallStats> syscalls;
  int calls = 0;
};

void ObserveCall(PhaseStats* stats, const Syscall& call) {
  ++stats->calls;
  SyscallStats& entry = stats->syscalls[call.name];
  entry.name = call.name;
  ++entry.calls;
  for (size_t i = 0; i < call.args.size() && i < 6; ++i) {
    entry.args[static_cast<int>(i)].Observe(call.args[i]);
  }
}

std::string ValueName(uint64_t value, std::string_view prefix) {
  std::string best;
  for (const std::string& name : AllConstantNames()) {
    if (!prefix.empty() && !StartsWith(name, prefix)) continue;
    const NamedConstant* c = FindConstant(name);
    if (c && static_cast<uint64_t>(c->value) == value) {
      if (best.empty() || name.size() < best.size()) best = name;
    }
  }
  return best.empty() ? Decimal(value) : best;
}



// Builds a condition for one argument of one syscall, or nothing when the
// observations do not justify a restriction.
std::optional<Condition> InferCondition(const SyscallStats& stats, int arg,
                                        const GeneratorOptions& options,
                                        std::vector<std::string>* notes) {
  auto it = stats.args.find(arg);
  if (it == stats.args.end()) return std::nullopt;
  const ArgStats& observed = it->second;
  if (observed.seen_truncated) {
    notes->push_back(stats.name + " arg" + std::to_string(arg) +
                     " was truncated in the trace, left unrestricted");
    return std::nullopt;
  }
  if (observed.values.empty()) {
    if (observed.seen_unresolved) {
      notes->push_back(stats.name + " arg" + std::to_string(arg) +
                       " never had a resolvable value, left unrestricted");
    }
    return std::nullopt;
  }

  const ArgKind kind = SyscallArgKind(stats.name, arg);
  const std::string_view prefix = SyscallArgConstantPrefix(stats.name, arg);

  Condition cond;
  cond.arg = arg;

  // Socket domain: the headline restriction.  AF_INET only if that is all we
  // ever saw.
  if (kind == ArgKind::kAddressFamily) {
    if (observed.values.size() == 1) {
      cond.cmp.op = CompareOp::kEq;
      cond.cmp.a = observed.values.front();
    } else if (static_cast<int>(observed.values.size()) <= options.max_in_list) {
      cond.cmp.op = CompareOp::kIn;
      cond.cmp.set = observed.values;
    } else {
      notes->push_back(stats.name + " used " +
                       std::to_string(observed.values.size()) +
                       " address families, left unrestricted");
      return std::nullopt;
    }
    cond.comment = "address family";
    return cond;
  }

  // Socket type: the low nibble is the type, the upper bits are flags.  Pin
  // the type, leave SOCK_CLOEXEC/SOCK_NONBLOCK free.
  if (kind == ArgKind::kSocketType) {
    std::set<uint64_t> types;
    bool saw_flags = false;
    for (uint64_t v : observed.values) {
      types.insert(v & 0xf);
      if ((v & ~static_cast<uint64_t>(0xf)) != 0) saw_flags = true;
    }
    if (types.size() == 1) {
      cond.cmp.op = CompareOp::kEq;
      cond.cmp.a = *types.begin();
      if (saw_flags) {
        // SOCK_CLOEXEC / SOCK_NONBLOCK share the word with the type; compare
        // only the type nibble so the flags stay free.
        cond.mask = 0xf;
        cond.comment = "socket type, ignoring flag bits";
      }
      return cond;
    }
    notes->push_back(stats.name + " used " + std::to_string(types.size()) +
                     " socket types, left unrestricted");
    return std::nullopt;
  }

  // Flag words: keep only the bits every call shared, as a `has` test.
  if (options.constrain_flags &&
      (kind == ArgKind::kOpenFlags || kind == ArgKind::kAtFlags ||
       kind == ArgKind::kFlags || kind == ArgKind::kProtFlags ||
       kind == ArgKind::kMapFlags)) {
    uint64_t common = observed.values.front();
    for (uint64_t v : observed.values) common &= v;
    // Only pin a bit if the flag is meaningful on its own; the access mode of
    // open(2) is two bits, so O_RDONLY (0) is indistinguishable from "no
    // flags".  Skip zero and multi-bit-only masks that would be vacuous.
    if (common != 0) {
      cond.cmp.op = CompareOp::kMask;
      cond.cmp.a = common;
      cond.is_flags = true;
      cond.comment = "flags common to every observed call";
      return cond;
    }
    return std::nullopt;
  }

  // IPPROTO_*: 0 and TCP are the same request for a TCP socket, and a service
  // that passes 0 today may pass IPPROTO_TCP tomorrow.  The protocol number is
  // already implied by the socket type and family, so pinning it adds no
  // security and real breakage risk.
  if (kind == ArgKind::kProtocol) {
    return std::nullopt;
  }

  // A single observed value: pin it ("socket only AF_INET" generalises here).
  // Only for arguments whose value is a property of the call rather than an
  // accident of this run: pinning a file descriptor or a pointer address
  // would block the service on its next run.
  if (!ArgKindIsPinnable(kind)) {
    if (kind == ArgKind::kPointer || kind == ArgKind::kBuffer) {
      notes->push_back(stats.name + " arg" + std::to_string(arg) +
                       " is a pointer; the filter cannot inspect the memory it "
                       "points at");
    } else if (observed.values.size() <= 1) {
      notes->push_back(stats.name + " arg" + std::to_string(arg) +
                       " is a " + std::string(ArgKindName(kind)) +
                       ", left unrestricted (its value belongs to this run, not "
                       "to the policy)");
    }
    return std::nullopt;
  }
  if (observed.values.size() == 1 && options.pin_single_values) {
    cond.cmp.op = CompareOp::kEq;
    cond.cmp.a = observed.values.front();
    cond.comment = "only value observed";
    return cond;
  }

  // A small set of values: emit an `in` list.
  if (static_cast<int>(observed.values.size()) <= options.max_in_list) {
    cond.cmp.op = CompareOp::kIn;
    cond.cmp.set = observed.values;
    cond.comment = std::to_string(observed.values.size()) + " values observed";
    return cond;
  }

  notes->push_back(stats.name + " arg" + std::to_string(arg) + " took " +
                   std::to_string(observed.values.size()) +
                   " distinct values, left unrestricted");
  (void)prefix;
  return std::nullopt;
}

// Renders an observed value set for the report.  Flag words are shown as the
// union of their known bits ("SOCK_STREAM|SOCK_CLOEXEC") because a bare
// 524289 tells a reviewer nothing.
std::string DescribeValues(const SyscallStats& stats, int arg) {
  auto it = stats.args.find(arg);
  if (it == stats.args.end()) return "";
  const std::string prefix(SyscallArgConstantPrefix(stats.name, arg));
  const ArgKind kind = SyscallArgKind(stats.name, arg);
  const bool flag_like = kind == ArgKind::kFlags || kind == ArgKind::kSocketType ||
                         kind == ArgKind::kOpenFlags || kind == ArgKind::kAtFlags ||
                         kind == ArgKind::kProtFlags || kind == ArgKind::kMapFlags;
  std::vector<std::string> pieces;
  for (uint64_t v : it->second.values) {
    if (flag_like) {
      std::string rendered = RenderFlagWord(v, prefix);
      pieces.push_back(rendered.empty() ? ValueName(v, prefix) : rendered);
    } else {
      pieces.push_back(ValueName(v, prefix));
    }
    if (pieces.size() >= 6) break;
  }
  std::string out = Join(pieces, ", ");
  if (it->second.values.size() > 6) {
    out += ", ... (" + std::to_string(it->second.values.size()) + " total)";
  }
  return out;
}

// Adds one rule per syscall, with all inferred conditions ANDed.
void EmitRules(const PhaseStats& stats, Phase phase, const GeneratorOptions& options,
               GenerationResult* result) {
  for (const auto& [name, syscall_stats] : stats.syscalls) {
    int nr = SyscallNumber(options.arch, name);
    if (nr < 0) {
      result->stats.warnings.push_back("syscall '" + name +
                                       "' is not in the " +
                                       std::string(ArchName(options.arch)) +
                                       " table; emitting a rule by number is not "
                                       "possible, so it will be denied");
      continue;
    }
    Rule rule;
    rule.syscall = name;
    rule.phase = phase;
    rule.action = Action::Allow();
    rule.generated = true;
    rule.note = "observed " + std::to_string(syscall_stats.calls) + " time(s)";

    int argc = SyscallArgCount(name);
    for (int arg = 0; arg < std::min(argc, 6); ++arg) {
      if (auto cond = InferCondition(syscall_stats, arg, options, &result->stats.notes)) {
        rule.conditions.push_back(*cond);
        ++result->stats.argument_restrictions;
      }
    }

    // Record what we saw for the report.
    for (int arg = 0; arg < std::min(argc, 6); ++arg) {
      std::string values = DescribeValues(syscall_stats, arg);
      if (values.empty()) continue;
      std::string arg_name(SyscallArgName(name, arg));
      if (arg_name.empty()) arg_name = "arg" + std::to_string(arg);
      result->observed_arguments[name].push_back(arg_name + ": " + values);
    }

    result->policy.rules.push_back(std::move(rule));
  }
}

}  // namespace

GenerationResult GeneratePolicy(const Trace& trace, const GeneratorOptions& options) {
  GenerationResult result;
  result.policy.name = "generated";

  PhaseStats startup;
  PhaseStats runtime;
  for (const Process& proc : trace.processes) {
    ProcessObservation observed;
    observed.pid = proc.pid;
    observed.created_by_pid = proc.created_by_pid;
    observed.created_by_syscall = proc.created_by_syscall;
    observed.is_thread = proc.is_thread;
    observed.is_forked_child = proc.is_forked_child;
    observed.startup_calls = static_cast<int>(proc.startup.size());
    observed.runtime_calls = static_cast<int>(proc.runtime.size());
    result.processes.push_back(std::move(observed));
    for (const Syscall& call : proc.startup) {
      // A thread's startup syscalls are the same calls the process makes; all
      // processes contribute to the same policy.
      ObserveCall(&startup, call);
    }
    for (const Syscall& call : proc.runtime) {
      ObserveCall(&runtime, call);
    }
  }

  // Classify syscalls by where they appear.
  std::set<std::string> startup_names;
  std::set<std::string> runtime_names;
  for (const auto& [name, _] : startup.syscalls) startup_names.insert(name);
  for (const auto& [name, _] : runtime.syscalls) runtime_names.insert(name);

  // A syscall that appears in both phases is allowed in both: the startup
  // rules cover the early calls, and the same call may also happen later.
  // Emiting it only in startup would make the runtime filter deny it.
  for (const auto& name : startup_names) {
    if (runtime_names.count(name)) {
      result.in_both.push_back(name);
    } else {
      result.startup_only.push_back(name);
    }
  }
  for (const auto& name : runtime_names) {
    if (!startup_names.count(name)) result.runtime_only.push_back(name);
  }
  result.stats.only_startup = static_cast<int>(result.startup_only.size());
  result.stats.only_runtime = static_cast<int>(result.runtime_only.size());
  result.stats.both = static_cast<int>(result.in_both.size());
  result.stats.startup_syscalls = static_cast<int>(startup_names.size());
  result.stats.runtime_syscalls = static_cast<int>(runtime_names.size());

  // For calls seen in both phases, merge their observations so one rule with
  // one condition covers both.
  PhaseStats merged_both;
  for (const auto& name : result.in_both) {
    SyscallStats combined = startup.syscalls.at(name);
    const SyscallStats& late = runtime.syscalls.at(name);
    combined.calls += late.calls;
    for (const auto& [arg, stats] : late.args) {
      for (uint64_t value : stats.values) {
        if (!combined.args[arg].counts.count(value)) {
          combined.args[arg].values.push_back(value);
        }
        combined.args[arg].counts[value] += stats.counts.at(value);
      }
      combined.args[arg].seen_symbolic |= stats.seen_symbolic;
      combined.args[arg].seen_unresolved |= stats.seen_unresolved;
      combined.args[arg].seen_truncated |= stats.seen_truncated;
    }
    merged_both.syscalls[name] = combined;
    // Remove from both phase sets; the merged rule goes into the startup block
    // with phase "both".
    startup.syscalls.erase(name);
    runtime.syscalls.erase(name);
  }

  // A call used in both phases becomes a "both" rule so it appears in the
  // startup block and stays allowed at runtime.
  for (auto& [name, stats] : merged_both.syscalls) {
    (void)name;
    (void)stats;
  }
  {
    GeneratorOptions both_options = options;
    // Emit merged rules with phase kBoth by temporarily passing a phase and
    // patching it afterwards.  Kept explicit rather than special-casing in
    // EmitRules so the report's phase counts stay honest.
    size_t before = result.policy.rules.size();
    EmitRules(merged_both, Phase::kStartup, both_options, &result);
    for (size_t i = before; i < result.policy.rules.size(); ++i) {
      result.policy.rules[i].phase = Phase::kBoth;
    }
  }
  EmitRules(startup, Phase::kStartup, options, &result);
  EmitRules(runtime, Phase::kRuntime, options, &result);

  // Stable output: sort by phase, then syscall name.
  std::stable_sort(result.policy.rules.begin(), result.policy.rules.end(),
                   [](const Rule& a, const Rule& b) {
                     auto rank = [](Phase p) {
                       return p == Phase::kStartup ? 0 : p == Phase::kBoth ? 1 : 2;
                     };
                     if (rank(a.phase) != rank(b.phase)) return rank(a.phase) < rank(b.phase);
                     return a.syscall < b.syscall;
                   });

  // The default is kill: a syscall nobody saw is never legitimate.
  result.policy.default_action = Action::Kill();
  result.policy.notes.push_back(
      "Generated from a trace of " +
      std::to_string(trace.processes.size()) + " process(es), " +
      std::to_string(result.stats.startup_syscalls + result.stats.runtime_syscalls) +
      " distinct syscalls.");
  result.policy.notes.push_back(
      "Argument restrictions come only from values the trace actually showed; "
      "arguments the trace could not resolve were left unconstrained on "
      "purpose.");

  if (result.policy.rules.empty()) {
    result.stats.warnings.push_back(
        "the trace contained no syscalls; the generated policy denies "
        "everything, which is almost certainly not what you want");
  }
  return result;
}

}  // namespace scgen

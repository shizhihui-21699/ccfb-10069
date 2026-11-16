#include "compiler.h"

#include <algorithm>
#include <map>
#include <set>
#include <sstream>

#include "common.h"

namespace scgen {
namespace {

// A syscall's entry in the dispatch: the rules that could apply to it.
// First matching rule wins.
struct DispatchEntry {
  std::string name;
  int number = -1;
  // Restricted rules first (more specific), then the unconditional one.
  std::vector<const Rule*> rules;
};

// A conditional jump maps `has any of these bits` onto JSET; everything else
// is done with JEQ/JGT/JGE, since cBPF has no JLT.
bool RuleAppliesInPhase(const Rule& rule, Phase phase) {
  if (phase == Phase::kStartup) {
    // The startup filter must also permit everything the runtime filter will
    // permit: another thread may reach the ready point (and start issuing
    // runtime calls) before the second filter is installed on it.  Runtime
    // *denials* are irrelevant before the switch, and folding them in would
    // turn "allow during startup, deny afterwards" into a conflict.
    return rule.phase == Phase::kStartup || rule.phase == Phase::kBoth ||
           rule.phase == Phase::kAny ||
           (rule.phase == Phase::kRuntime && rule.action.is_allow());
  }
  return rule.phase == Phase::kRuntime || rule.phase == Phase::kBoth ||
         rule.phase == Phase::kAny;
}

bool ConditionsEqual(const std::vector<Condition>& a,
                     const std::vector<Condition>& b) {
  if (a.size() != b.size()) return false;
  for (size_t i = 0; i < a.size(); ++i) {
    if (a[i].arg != b[i].arg) return false;
    if (a[i].cmp.op != b[i].cmp.op) return false;
    if (a[i].cmp.a != b[i].cmp.a || a[i].cmp.b != b[i].cmp.b) return false;
    if (a[i].mask != b[i].mask) return false;
    if (a[i].cmp.set != b[i].cmp.set) return false;
  }
  return true;
}

constexpr uint32_t LowHalf(uint64_t value) { return static_cast<uint32_t>(value); }
constexpr uint32_t HighHalf(uint64_t value) { return static_cast<uint32_t>(value >> 32); }
constexpr uint32_t ArgOffset(int arg) {
  return kSeccompDataArgOffset + 8u * static_cast<uint32_t>(arg);
}

// ---------------------------------------------------------------------------
// Condition emission
//
// Emits straight-line code jumping to `t` when the condition holds and `f`
// when it does not.  Arguments are 64-bit and cBPF registers are 32-bit, so
// each comparison looks at the high half first and only compares the low half
// when the high halves are equal.
// ---------------------------------------------------------------------------

class ConditionEmitter {
 public:
  ConditionEmitter(Assembler& as, int unique) : as_(as), unique_(unique) {}

  void Emit(const Condition& cond, const std::string& t, const std::string& f) {
    const uint32_t off = ArgOffset(cond.arg);
    if (cond.mask != 0) {
      // Apply the mask to both halves once, then compare normally.  Loading the
      // masked halves into scratch slots keeps the comparison code below
      // unchanged.
      EmitMaskedCondition(cond, off, t, f);
      return;
    }
    switch (cond.cmp.op) {
      case CompareOp::kEq:
        EmitEq(off, cond.cmp.a, t, f, /*equal_goes_true=*/true);
        break;
      case CompareOp::kNe:
        EmitEq(off, cond.cmp.a, t, f, /*equal_goes_true=*/false);
        break;
      case CompareOp::kLt: EmitLt(off, cond.cmp.a, t, f); break;
      case CompareOp::kLe: EmitLe(off, cond.cmp.a, t, f); break;
      case CompareOp::kGt: EmitGt(off, cond.cmp.a, t, f); break;
      case CompareOp::kGe: EmitGe(off, cond.cmp.a, t, f); break;
      case CompareOp::kMask: EmitMask(off, cond.cmp.a, t, f, true); break;
      case CompareOp::kNotMask: EmitMask(off, cond.cmp.a, t, f, false); break;
      case CompareOp::kIn: EmitIn(off, cond.cmp.set, t, f, /*negate=*/false); break;
      case CompareOp::kNotIn: EmitIn(off, cond.cmp.set, t, f, /*negate=*/true); break;
      case CompareOp::kRange: EmitRange(off, cond.cmp.a, cond.cmp.b, t, f); break;
    }
  }

 private:
  // arg & mask, compared against the value.  The masked halves end up in the
  // scratch slots 0 and 1; the comparison helpers read both halves through
  // `EmitEq`-style code, so the cleanest approach is to compute the halves into
  // two temporaries and inline the comparison here.
  void EmitMaskedCondition(const Condition& cond, uint32_t off,
                           const std::string& t, const std::string& f) {
    const uint64_t mask = cond.mask;
    const Compare& cmp = cond.cmp;
    // Only equality/inequality/membership on a masked value are meaningful;
    // ordering on a bit-masked word is not something the generator emits.
    switch (cmp.op) {
      case CompareOp::kEq:
        EmitMaskedEq(off, mask, cmp.a, t, f, true);
        return;
      case CompareOp::kNe:
        EmitMaskedEq(off, mask, cmp.a, t, f, false);
        return;
      case CompareOp::kIn:
      case CompareOp::kNotIn: {
        const bool negate = cmp.op == CompareOp::kNotIn;
        for (size_t i = 0; i < cmp.set.size(); ++i) {
          bool last = i + 1 == cmp.set.size();
          std::string next = Label("min");
          EmitMaskedEq(off, mask, cmp.set[i], negate ? f : t,
                       last ? (negate ? t : f) : next, true);
          if (!last) as_.Bind(next);
        }
        return;
      }
      default:
        throw Error("a masked argument can only be tested for equality or "
                    "membership (socket type masks)");
    }
  }

  // (arg & mask) == value (or != when equal_goes_true is false).
  void EmitMaskedEq(uint32_t off, uint64_t mask, uint64_t value,
                    const std::string& t, const std::string& f,
                    bool equal_goes_true) {
    const std::string& on_equal = equal_goes_true ? t : f;
    const std::string& on_differ = equal_goes_true ? f : t;
    const uint32_t lo_mask = LowHalf(mask);
    const uint32_t hi_mask = HighHalf(mask);
    const uint32_t lo_value = LowHalf(value) & lo_mask;
    const uint32_t hi_value = HighHalf(value) & hi_mask;
    if ((LowHalf(value) & ~lo_mask) != 0 || (HighHalf(value) & ~hi_mask) != 0) {
      // The comparison value has bits the mask clears; it can never match.
      as_.Ja(on_differ);
      return;
    }
    std::string lo = Label("meq_lo");
    if (hi_mask != 0) {
      as_.LdAbs(off + 4);
      as_.AluK(kAnd, hi_mask);
      as_.JmpK(kJeq, hi_value, lo, on_differ);
    } else if (hi_value != 0) {
      as_.Ja(on_differ);
      return;
    }
    as_.Bind(lo);
    if (lo_mask != 0) {
      as_.LdAbs(off);
      as_.AluK(kAnd, lo_mask);
      as_.JmpK(kJeq, lo_value, on_equal, on_differ);
    } else {
      as_.Ja(on_equal);
    }
  }

  std::string Label(std::string_view kind) {
    return "c" + std::to_string(unique_) + "_" + std::string(kind) + "_" +
           std::to_string(counter_++);
  }

  // arg == value.  When equal_goes_true, equality jumps to t and inequality to
  // f; otherwise the two are swapped.
  void EmitEq(uint32_t off, uint64_t value, const std::string& t,
              const std::string& f, bool equal_goes_true) {
    const std::string& on_equal = equal_goes_true ? t : f;
    const std::string& on_differ = equal_goes_true ? f : t;
    std::string low = Label("eq_lo");
    as_.LdAbs(off + 4);
    as_.JmpK(kJeq, HighHalf(value), low, on_differ);
    as_.Bind(low);
    as_.LdAbs(off);
    as_.JmpK(kJeq, LowHalf(value), on_equal, on_differ);
  }

  // Three-way compare of the high halves; `lo_label` is reached only when they
  // are equal.  When the high half is strictly greater, control goes to
  // `on_greater`, otherwise to `on_less`.
  void EmitHighSplit(uint32_t off, uint64_t value, const std::string& on_greater,
                     const std::string& on_less, const std::string& lo_label) {
    if (HighHalf(value) == 0) {
      // Any nonzero high half means arg > value.
      as_.LdAbs(off + 4);
      as_.JmpK(kJeq, 0, lo_label, on_greater);
      return;
    }
    as_.LdAbs(off + 4);
    as_.JmpK(kJgt, HighHalf(value), on_greater, lo_label);
    // Reaching lo_label means hi <= value_hi; fall through only for equality,
    // so check it explicitly.
    as_.Bind(lo_label);
    // The `on_less` case is handled by the equality check that follows.
    (void)on_less;
  }

  // arg < value
  void EmitLt(uint32_t off, uint64_t value, const std::string& t,
              const std::string& f) {
    if (HighHalf(value) == 0) {
      // hi must be 0, then compare lo.
      std::string lo = Label("lt_lo");
      as_.LdAbs(off + 4);
      as_.JmpK(kJeq, 0, lo, f);
      as_.Bind(lo);
      as_.LdAbs(off);
      // lo < value_lo  <=>  !(lo >= value_lo)
      as_.JmpK(kJge, LowHalf(value), f, t);
      return;
    }
    std::string hi_less = Label("lt_hiless");
    std::string lo = Label("lt_lo");
    as_.LdAbs(off + 4);
    as_.JmpK(kJgt, HighHalf(value), f, hi_less);
    as_.Bind(hi_less);
    as_.JmpK(kJeq, HighHalf(value), lo, t);   // hi < value_hi -> true
    as_.Bind(lo);
    as_.LdAbs(off);
    as_.JmpK(kJge, LowHalf(value), f, t);     // hi == value_hi: compare lo
  }

  // arg <= value
  void EmitLe(uint32_t off, uint64_t value, const std::string& t,
              const std::string& f) {
    if (HighHalf(value) == 0) {
      std::string lo = Label("le_lo");
      as_.LdAbs(off + 4);
      as_.JmpK(kJeq, 0, lo, f);
      as_.Bind(lo);
      as_.LdAbs(off);
      as_.JmpK(kJgt, LowHalf(value), f, t);
      return;
    }
    std::string hi_less = Label("le_hiless");
    std::string lo = Label("le_lo");
    as_.LdAbs(off + 4);
    as_.JmpK(kJgt, HighHalf(value), f, hi_less);
    as_.Bind(hi_less);
    as_.JmpK(kJeq, HighHalf(value), lo, t);
    as_.Bind(lo);
    as_.LdAbs(off);
    as_.JmpK(kJgt, LowHalf(value), f, t);
  }

  // arg > value
  void EmitGt(uint32_t off, uint64_t value, const std::string& t,
              const std::string& f) {
    if (HighHalf(value) == 0) {
      std::string lo = Label("gt_lo");
      as_.LdAbs(off + 4);
      as_.JmpK(kJeq, 0, lo, t);
      as_.Bind(lo);
      as_.LdAbs(off);
      as_.JmpK(kJgt, LowHalf(value), t, f);
      return;
    }
    std::string hi_less = Label("gt_hiless");
    std::string lo = Label("gt_lo");
    as_.LdAbs(off + 4);
    as_.JmpK(kJgt, HighHalf(value), t, hi_less);
    as_.Bind(hi_less);
    as_.JmpK(kJeq, HighHalf(value), lo, f);
    as_.Bind(lo);
    as_.LdAbs(off);
    as_.JmpK(kJgt, LowHalf(value), t, f);
  }

  // arg >= value
  void EmitGe(uint32_t off, uint64_t value, const std::string& t,
              const std::string& f) {
    if (HighHalf(value) == 0) {
      std::string lo = Label("ge_lo");
      as_.LdAbs(off + 4);
      as_.JmpK(kJeq, 0, lo, t);
      as_.Bind(lo);
      as_.LdAbs(off);
      as_.JmpK(kJge, LowHalf(value), t, f);
      return;
    }
    std::string hi_less = Label("ge_hiless");
    std::string lo = Label("ge_lo");
    as_.LdAbs(off + 4);
    as_.JmpK(kJgt, HighHalf(value), t, hi_less);
    as_.Bind(hi_less);
    as_.JmpK(kJeq, HighHalf(value), lo, f);
    as_.Bind(lo);
    as_.LdAbs(off);
    as_.JmpK(kJge, LowHalf(value), t, f);
  }

  // want_all: (arg & mask) == mask.  !want_all: (arg & mask) != mask.
  void EmitMask(uint32_t off, uint64_t mask, const std::string& t,
                const std::string& f, bool want_all) {
    const uint32_t lo = LowHalf(mask);
    const uint32_t hi = HighHalf(mask);
    if (lo == 0 && hi == 0) {
      as_.Ja(want_all ? t : f);
      return;
    }
    const std::string& on_hi_ok = (lo != 0) ? "" : (want_all ? t : f);
    if (hi != 0) {
      std::string next = Label("mask_hi");
      as_.LdAbs(off + 4);
      as_.AluK(kAnd, hi);
      if (lo != 0) {
        as_.JmpK(kJeq, hi, next, want_all ? f : t);
        as_.Bind(next);
      } else {
        as_.JmpK(kJeq, hi, want_all ? t : f, want_all ? f : t);
      }
    }
    if (lo != 0) {
      as_.LdAbs(off);
      as_.AluK(kAnd, lo);
      as_.JmpK(kJeq, lo, want_all ? t : f, want_all ? f : t);
    }
    (void)on_hi_ok;
  }

  // arg is one of `set` (negate == false) or none of them.
  void EmitIn(uint32_t off, const std::vector<uint64_t>& set, const std::string& t,
              const std::string& f, bool negate) {
    for (size_t i = 0; i < set.size(); ++i) {
      bool last = i + 1 == set.size();
      std::string next = Label("in");
      // Equality with a member takes `negate ? f : t`; the final mismatch
      // takes the other.
      EmitEq(off, set[i], negate ? f : t, last ? (negate ? t : f) : next,
             /*equal_goes_true=*/true);
      if (!last) as_.Bind(next);
    }
  }

  // low <= arg <= high, unsigned.
  void EmitRange(uint32_t off, uint64_t low, uint64_t high, const std::string& t,
                 const std::string& f) {
    std::string in_low = Label("range");
    EmitGe(off, low, in_low, f);
    as_.Bind(in_low);
    EmitLe(off, high, t, f);
  }

  Assembler& as_;
  int unique_;
  int counter_ = 0;
};

void EmitConditions(Assembler& as, const Rule& rule, int unique,
                    const std::string& hit, const std::string& miss) {
  ConditionEmitter emitter(as, unique);
  for (size_t i = 0; i < rule.conditions.size(); ++i) {
    bool last = i + 1 == rule.conditions.size();
    if (last) {
      emitter.Emit(rule.conditions[i], hit, miss);
    } else {
      std::string next = "cond_" + std::to_string(unique) + "_" +
                         std::to_string(i);
      emitter.Emit(rule.conditions[i], next, miss);
      as.Bind(next);
    }
  }
}

}  // namespace

CompiledFilter CompileFilter(const Policy& policy, Phase phase,
                             const CompileOptions& options) {
  CompiledFilter result;
  const Arch arch = options.arch;

  std::map<int, DispatchEntry> dispatch;  // keyed by syscall number
  const Rule* wildcard_allow = nullptr;

  auto ensure_entry = [&](const std::string& name, int number) -> DispatchEntry& {
    auto it = dispatch.find(number);
    if (it != dispatch.end()) return it->second;
    DispatchEntry entry;
    entry.name = name;
    entry.number = number;
    auto [inserted, _] = dispatch.emplace(number, std::move(entry));
    return inserted->second;
  };

  for (const Rule& rule : policy.rules) {
    if (!RuleAppliesInPhase(rule, phase)) continue;
    if (rule.wildcard) {
      if (!rule.action.is_allow()) {
        throw Error("wildcard deny rules are not supported; state the rule per "
                    "syscall or change the policy's 'default' action");
      }
      if (!rule.conditions.empty()) {
        throw Error("a wildcard allow with argument conditions is not "
                    "meaningful; constrain specific syscalls instead");
      }
      wildcard_allow = &rule;
      continue;
    }
    if (rule.syscall_number) {
      std::string_view name = SyscallName(arch, *rule.syscall_number);
      ensure_entry(std::string(name), *rule.syscall_number).rules.push_back(&rule);
      continue;
    }
    if (!rule.syscall.empty()) {
      int nr = SyscallNumber(arch, rule.syscall);
      if (nr < 0) continue;  // ResolvePolicy reports unknown names
      ensure_entry(rule.syscall, nr).rules.push_back(&rule);
      continue;
    }
    for (const std::string& group : rule.group) {
      const SyscallGroup* g = FindGroup(group);
      if (!g) continue;
      for (const std::string& member : g->members) {
        int nr = SyscallNumber(arch, member);
        if (nr < 0) continue;
        ensure_entry(member, nr).rules.push_back(&rule);
      }
    }
  }

  // A wildcard allow applies to every syscall the policy does not mention.
  // Mentioned syscalls keep their own rules: a specific deny still wins.
  if (wildcard_allow != nullptr) {
    for (const std::string& name : AllSyscallNames()) {
      int nr = SyscallNumber(arch, name);
      if (nr < 0 || dispatch.count(nr)) continue;
      DispatchEntry entry;
      entry.name = name;
      entry.number = nr;
      entry.rules.push_back(wildcard_allow);
      dispatch.emplace(nr, std::move(entry));
    }
  }

  // Restricted rules first: a narrow rule outranks a blanket one.
  //
  // Duplicates are collapsed.  Writing "allow execve" in both the startup and
  // the runtime block is the natural way to say "this call is fine throughout",
  // and since the startup filter also admits runtime rules both copies land in
  // it.  Identical rules are idempotent, so drop the repeat.  Two rules for one
  // syscall with *different* verdicts and no conditions are genuinely
  // ambiguous (which wins?) and are rejected with both line numbers.
  for (auto& [nr, entry] : dispatch) {
    (void)nr;
    std::stable_sort(entry.rules.begin(), entry.rules.end(),
                     [](const Rule* a, const Rule* b) {
                       return a->conditions.size() > b->conditions.size();
                     });
    std::vector<const Rule*> unique_rules;
    for (const Rule* rule : entry.rules) {
      bool merged = false;
      for (const Rule* seen : unique_rules) {
        if (seen->action.ToReturnValue() != rule->action.ToReturnValue()) continue;
        if (ConditionsEqual(seen->conditions, rule->conditions)) {
          merged = true;
          break;
        }
      }
      if (merged) continue;
      unique_rules.push_back(rule);
    }
    entry.rules = std::move(unique_rules);

    const Rule* unconditional = nullptr;
    for (const Rule* rule : entry.rules) {
      if (!rule->conditions.empty()) continue;
      if (unconditional == nullptr) {
        unconditional = rule;
        continue;
      }
      throw Error("conflicting unconditional rules for " + entry.name + ": " +
                  unconditional->action.ToString() + " (line " +
                  std::to_string(unconditional->source_line) + ") and " +
                  rule->action.ToString() + " (line " +
                  std::to_string(rule->source_line) +
                  "); only the first would ever apply");
    }
  }

  // Order syscalls by number: the dispatch reads naturally and is stable.
  std::vector<std::pair<std::string, int>> order;
  for (const auto& [nr, entry] : dispatch) order.emplace_back(entry.name, nr);
  std::sort(order.begin(), order.end(),
            [](const auto& a, const auto& b) { return a.second < b.second; });

  // ---------------------------------------------------------------------
  // Assemble.
  // ---------------------------------------------------------------------
  Assembler as;
  const uint32_t default_ret = policy.default_action.ToReturnValue();

  as.Bind("entry");
  as.LdAbs(kSeccompDataArchOffset);
  as.JmpK(kJeq, AuditArch(arch), "arch_ok", "arch_bad");
  as.Bind("arch_bad");
  // A syscall from a different ABI (x86_64's 32-bit compat entry, say) uses a
  // different numbering, so there is no safe interpretation: kill it.
  as.RetK(kRetKillThread);

  as.Bind("arch_ok");
  as.LdAbs(kSeccompDataNrOffset);

  for (size_t i = 0; i < order.size(); ++i) {
    const std::string& name = order[i].first;
    int nr = order[i].second;
    std::string next = "dispatch_" + std::to_string(i + 1);
    as.JmpK(kJeq, static_cast<uint32_t>(nr), "sc_" + name, next);
    as.Bind(next);
  }
  as.Ja("default");

  int unique = 0;
  for (const auto& [name, nr] : order) {
    (void)nr;
    const DispatchEntry& entry = dispatch.at(nr);
    as.Bind("sc_" + name);
    for (size_t i = 0; i < entry.rules.size(); ++i) {
      const Rule* rule = entry.rules[i];
      const std::string hit = "sc_" + name + "_hit" + std::to_string(i);
      const bool last = i + 1 == entry.rules.size();
      const std::string miss = last ? "sc_" + name + "_miss"
                                    : "sc_" + name + "_next" + std::to_string(i + 1);
      // Every rule body starts at its "next" label: a restricted rule above
      // falls through to it, and the unconditional rule below jumps here.
      as.Bind("sc_" + name + "_next" + std::to_string(i));
      if (!rule->conditions.empty()) {
        EmitConditions(as, *rule, unique++, hit, miss);
      }
      as.Bind(hit);
      as.RetK(rule->action.ToReturnValue());
    }
    // Only a trailing restricted rule can reach the miss block: an
    // unrestricted rule always returns, and any restricted rule that declines
    // flows into the next body.  Emitting the block otherwise would leave
    // unreachable instructions, which the verifier rejects.
    bool last_is_restricted =
        !entry.rules.empty() && !entry.rules.back()->conditions.empty();
    if (last_is_restricted) {
      as.Bind("sc_" + name + "_miss");
      // Every restricted rule declined.  Fall back to the policy default; when
      // the default is ALLOW this is what makes a restrictive rule useless,
      // and the policy check reports that combination.
      as.Ja("default");
    }
  }

  as.Bind("default");
  as.RetK(default_ret);

  result.program = as.Finalize();
  result.instruction_count = static_cast<int>(result.program.size());

  // ---------------------------------------------------------------------
  // Report data.
  // ---------------------------------------------------------------------
  for (const auto& [name, nr] : order) {
    const DispatchEntry& entry = dispatch.at(nr);
    bool allows = false;
    for (const Rule* rule : entry.rules) {
      if (rule->action.is_allow()) allows = true;
    }
    if (allows) {
      result.allowed.push_back(entry.name);
    } else if (!entry.rules.empty()) {
      result.denied.emplace_back(entry.name, entry.rules.front()->action);
    }
    CompiledFilter::ArgRestriction restriction;
    restriction.syscall = entry.name;
    for (const Rule* rule : entry.rules) {
      if (rule->conditions.empty()) continue;
      std::vector<std::string> parts;
      for (const Condition& cond : rule->conditions) {
        parts.push_back(DescribeCondition(*rule, cond));
      }
      CompiledFilter::ArgRestriction::Clause clause;
      clause.verdict = rule->action.ToString();
      clause.condition = Join(parts, " and ");
      restriction.clauses.push_back(std::move(clause));
    }
    if (!restriction.clauses.empty()) {
      result.restricted.push_back(std::move(restriction));
    }
  }
  std::sort(result.allowed.begin(), result.allowed.end());
  std::sort(result.denied.begin(), result.denied.end(),
            [](const auto& a, const auto& b) { return a.first < b.first; });
  std::sort(result.restricted.begin(), result.restricted.end(),
            [](const auto& a, const auto& b) { return a.syscall < b.syscall; });
  return result;
}

std::string SummarizeFilter(const CompiledFilter& filter, Arch arch) {
  (void)arch;
  std::ostringstream out;
  out << filter.allowed.size() << " allowed syscalls, "
      << filter.restricted.size() << " argument-restricted, "
      << filter.instruction_count << " BPF instructions";
  return out.str();
}

}  // namespace scgen

#include "policy.h"

#include <algorithm>
#include <set>
#include <sstream>

#include "bpf.h"
#include "common.h"

namespace scgen {

std::string_view PhaseName(Phase phase) {
  switch (phase) {
    case Phase::kStartup: return "startup";
    case Phase::kRuntime: return "runtime";
    case Phase::kAny: return "any";
    case Phase::kBoth: return "both";
  }
  return "any";
}

Action Action::Errno(uint32_t errno_value) {
  Action a;
  a.kind = Kind::kErrno;
  a.errno_value = errno_value;
  return a;
}

Action Action::Kill() {
  Action a;
  a.kind = Kind::kKill;
  return a;
}

Action Action::KillProcess() {
  Action a;
  a.kind = Kind::kKillProcess;
  return a;
}

Action Action::Trap() {
  Action a;
  a.kind = Kind::kTrap;
  return a;
}

Action Action::Trace(uint32_t data) {
  Action a;
  a.kind = Kind::kTrace;
  a.trace_data = data;
  return a;
}

Action Action::Log() {
  Action a;
  a.kind = Kind::kLog;
  return a;
}

Action Action::Notify(uint32_t data) {
  Action a;
  a.kind = Kind::kNotify;
  a.trace_data = data;
  return a;
}

std::string Action::ToString() const {
  switch (kind) {
    case Kind::kAllow: return "allow";
    case Kind::kErrno: {
      // Prefer the symbolic name when the errno is one we know.
      static const char* kNames[] = {
          nullptr, "EPERM", "ENOENT", "ESRCH", "EINTR", "EIO", "ENXIO", "E2BIG",
          "ENOEXEC", "EBADF", "ECHILD", "EAGAIN", "ENOMEM", "EACCES", "EFAULT",
          "ENOTBLK", "EBUSY", "EEXIST", "EXDEV", "ENODEV", "ENOTDIR", "EISDIR",
          "EINVAL", "ENFILE", "EMFILE", "ENOTTY", "ETXTBSY", "EFBIG", "ENOSPC",
          "ESPIPE", "EROFS", "EMLINK", "EPIPE", "EDOM", "ERANGE", "EDEADLK",
          "ENAMETOOLONG", "ENOLCK", "ENOSYS", "ENOTEMPTY", "ELOOP", nullptr,
          "ENOMSG", "EIDRM", "ECHRNG", "EL2NSYNC", "EL3HLT", "EL3RST",
          "ELNRNG", "EUNATCH", "ENOCSI", "EL2HLT", "EBADE", "EBADR", "EXFULL",
          "ENOANO", "EBADRQC", "EBADSLT", nullptr, "EBFONT", "ENOSTR", "ENODATA",
          "ETIME", "ENOSR", "ENONET", "ENOPKG", "EREMOTE", "ENOLINK", "EADV",
          "ESRMNT", "ECOMM", "EPROTO", "EMULTIHOP", "EDOTDOT", "EBADMSG",
          "EOVERFLOW", "ENOTUNIQ", "EBADFD", "EREMCHG", "ELIBACC", "ELIBBAD",
          "ELIBSCN", "ELIBMAX", "ELIBEXEC", "EILSEQ", "ERESTART", "ESTRPIPE",
          "EUSERS", "ENOTSOCK", "EDESTADDRREQ", "EMSGSIZE", "EPROTOTYPE",
          "ENOPROTOOPT", "EPROTONOSUPPORT", "ESOCKTNOSUPPORT", "EOPNOTSUPP",
          "EPFNOSUPPORT", "EAFNOSUPPORT", "EADDRINUSE", "EADDRNOTAVAIL",
          "ENETDOWN", "ENETUNREACH", "ENETRESET", "ECONNABORTED", "ECONNRESET",
          "ENOBUFS", "EISCONN", "ENOTCONN", "ESHUTDOWN", "ETOOMANYREFS",
          "ETIMEDOUT", "ECONNREFUSED", "EHOSTDOWN", "EHOSTUNREACH", "EALREADY",
          "EINPROGRESS", "ESTALE", "EUCLEAN", "ENOTNAM", "ENAVAIL", "EISNAM",
          "EREMOTEIO", "EDQUOT", "ENOMEDIUM", "EMEDIUMTYPE", "ECANCELED",
          "ENOKEY", "EKEYEXPIRED", "EKEYREVOKED", "EKEYREJECTED",
          "EOWNERDEAD", "ENOTRECOVERABLE", "ERFKILL", "EHWPOISON",
      };
      if (errno_value > 0 && errno_value < std::size(kNames) && kNames[errno_value]) {
        return std::string("errno(") + kNames[errno_value] + ")";
      }
      return "errno(" + Decimal(errno_value) + ")";
    }
    case Kind::kKill: return "kill";
    case Kind::kKillProcess: return "kill_process";
    case Kind::kTrap: return "trap";
    case Kind::kTrace: return "trace(" + Decimal(trace_data) + ")";
    case Kind::kLog: return "log";
    case Kind::kNotify: return "notify(" + Decimal(trace_data) + ")";
  }
  return "allow";
}

uint32_t Action::ToReturnValue() const {
  switch (kind) {
    case Kind::kAllow: return kRetAllow;
    case Kind::kErrno: return kRetErrno | (errno_value & kRetDataMask);
    case Kind::kKill: return kRetKillThread;
    case Kind::kKillProcess: return kRetKillProcess;
    case Kind::kTrap: return kRetTrap;
    case Kind::kTrace: return kRetTrace | (trace_data & kRetDataMask);
    case Kind::kLog: return kRetLog;
    case Kind::kNotify: return kRetUserNotif | (trace_data & kRetDataMask);
  }
  return kRetKillThread;
}

std::string_view CompareOpName(CompareOp op) {
  switch (op) {
    case CompareOp::kEq: return "==";
    case CompareOp::kNe: return "!=";
    case CompareOp::kLt: return "<";
    case CompareOp::kLe: return "<=";
    case CompareOp::kGt: return ">";
    case CompareOp::kGe: return ">=";
    case CompareOp::kMask: return "has";
    case CompareOp::kNotMask: return "lacks";
    case CompareOp::kIn: return "in";
    case CompareOp::kNotIn: return "not in";
    case CompareOp::kRange: return "in_range";
  }
  return "?";
}

std::string Compare::ToString() const {
  std::ostringstream out;
  switch (op) {
    case CompareOp::kIn:
    case CompareOp::kNotIn: {
      out << CompareOpName(op) << " [";
      for (size_t i = 0; i < set.size(); ++i) {
        if (i) out << ", ";
        out << Decimal(set[i]);
      }
      out << "]";
      break;
    }
    case CompareOp::kRange:
      out << "in [" << Decimal(a) << ", " << Decimal(b) << "]";
      break;
    default:
      out << CompareOpName(op) << " " << Decimal(a);
      break;
  }
  return out.str();
}

std::string RenderFlagWord(uint64_t value, std::string_view prefix) {
  if (value == 0) return FormatConstantValue(0, prefix);
  std::vector<std::pair<uint64_t, std::string>> candidates;
  for (const std::string& name : AllConstantNames()) {
    if (!prefix.empty() && !StartsWith(name, prefix)) continue;
    const NamedConstant* c = FindConstant(name);
    if (!c || c->value <= 0) continue;
    uint64_t bits = static_cast<uint64_t>(c->value);
    if ((bits & (bits - 1)) != 0) continue;  // not a single bit
    candidates.emplace_back(bits, name);
  }
  std::sort(candidates.begin(), candidates.end(),
            [](const auto& a, const auto& b) {
              if (a.first != b.first) return a.first > b.first;
              return a.second.size() < b.second.size();
            });
  uint64_t remaining = value;
  std::vector<std::string> names;
  for (const auto& [bits, name] : candidates) {
    if ((remaining & bits) != bits) continue;
    names.push_back(name);
    remaining &= ~bits;
  }
  if (remaining != 0 || names.empty()) return FormatConstantValue(value, prefix);
  return Join(names, "|");
}

std::string FormatConstantValue(uint64_t value, std::string_view prefix) {
  std::string best;
  for (const std::string& name : AllConstantNames()) {
    if (!prefix.empty() && !StartsWith(name, prefix)) continue;
    const NamedConstant* constant = FindConstant(name);
    if (!constant || static_cast<uint64_t>(constant->value) != value) continue;
    if (best.empty() || name.size() < best.size()) best = name;
  }
  return best.empty() ? Decimal(value) : best;
}

std::string DescribeCondition(const Rule& rule, const Condition& cond) {
  std::string arg;
  if (!rule.syscall.empty()) {
    std::string_view name = SyscallArgName(rule.syscall, cond.arg);
    if (!name.empty()) arg = std::string(name);
  }
  if (arg.empty()) arg = "arg" + std::to_string(cond.arg);
  std::string prefix;
  if (!rule.syscall.empty()) {
    prefix = std::string(SyscallArgConstantPrefix(rule.syscall, cond.arg));
  }
  if (cond.mask != 0) {
    arg += " & " + FormatConstantValue(cond.mask, prefix);
  }
  std::ostringstream out;
  switch (cond.cmp.op) {
    case CompareOp::kIn:
    case CompareOp::kNotIn: {
      out << arg << " " << CompareOpName(cond.cmp.op) << " [";
      for (size_t i = 0; i < cond.cmp.set.size(); ++i) {
        if (i) out << ", ";
        out << FormatConstantValue(cond.cmp.set[i], prefix);
      }
      out << "]";
      break;
    }
    case CompareOp::kRange:
      out << arg << " in [" << FormatConstantValue(cond.cmp.a, prefix) << ", "
          << FormatConstantValue(cond.cmp.b, prefix) << "]";
      break;
    default:
      out << arg << " " << CompareOpName(cond.cmp.op) << " "
          << FormatConstantValue(cond.cmp.a, prefix);
      break;
  }
  return out.str();
}

bool RuleAppliesInPhaseForVerification(const Rule& rule, Phase phase) {
  if (phase == Phase::kStartup) {
    return rule.phase == Phase::kStartup || rule.phase == Phase::kBoth ||
           rule.phase == Phase::kRuntime || rule.phase == Phase::kAny;
  }
  return rule.phase == Phase::kRuntime || rule.phase == Phase::kBoth ||
         rule.phase == Phase::kAny;
}

bool RuleMentions(const Rule& rule, std::string_view syscall_name, Arch arch) {
  if (rule.wildcard) return true;
  if (!rule.syscall.empty() && rule.syscall == syscall_name) return true;
  if (rule.syscall_number) {
    int nr = SyscallNumber(arch, syscall_name);
    if (nr == *rule.syscall_number) return true;
  }
  for (const auto& group_name : rule.group) {
    if (const SyscallGroup* g = FindGroup(group_name)) {
      if (std::find(g->members.begin(), g->members.end(), syscall_name) !=
          g->members.end()) {
        return true;
      }
    }
  }
  return false;
}

}  // namespace scgen

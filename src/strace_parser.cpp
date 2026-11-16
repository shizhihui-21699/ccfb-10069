#include "strace_parser.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <set>
#include <sstream>
#include <unordered_map>

#include "common.h"

namespace scgen {
namespace {

bool IsDigit(char c) { return c >= '0' && c <= '9'; }


std::vector<std::string_view> SplitArguments(std::string_view text) {
  std::vector<std::string_view> out;
  int depth = 0;
  bool in_string = false;
  size_t start = 0;
  for (size_t i = 0; i < text.size(); ++i) {
    char c = text[i];
    if (in_string) {
      if (c == '\\') {
        ++i;
      } else if (c == '"') {
        in_string = false;
      }
      continue;
    }
    switch (c) {
      case '"': in_string = true; break;
      case '(': case '[': case '{': case '<': ++depth; break;
      case ')': case ']': case '}': case '>': --depth; break;
      case ',':
        if (depth <= 0) {
          out.push_back(text.substr(start, i - start));
          start = i + 1;
        }
        break;
      default: break;
    }
  }
  if (start < text.size() || !out.empty()) out.push_back(text.substr(start));
  return out;
}

// Parses "12:34:56.123456", "0.000123" and "1700000000.123456" into seconds.
bool ParseTimestamp(std::string_view text, double* out) {
  text = Trim(text);
  if (text.empty()) return false;
  size_t first_colon = text.find(':');
  if (first_colon != std::string_view::npos) {
    auto parts = Split(text, ':');
    if (parts.size() != 3) return false;
    double seconds = 0;
    for (size_t i = 0; i < parts.size(); ++i) {
      std::string part(Trim(parts[i]));
      double value = 0;
      try {
        size_t consumed = 0;
        value = std::stod(part, &consumed);
        if (consumed != part.size()) return false;
      } catch (...) {
        return false;
      }
      seconds = seconds * 60 + value;
    }
    *out = seconds;
    return true;
  }
  try {
    std::string copy(text);
    size_t consumed = 0;
    double value = std::stod(copy, &consumed);
    if (consumed != copy.size()) return false;
    *out = value;
    return true;
  } catch (...) {
    return false;
  }
}

// Strips a trailing "<0.000123>" (strace -T) from the return part.
std::string_view StripDuration(std::string_view ret) {
  ret = Trim(ret);
  if (!ret.empty() && ret.back() == '>') {
    size_t open = ret.rfind('<');
    if (open != std::string_view::npos && open > 0) {
      return Trim(ret.substr(0, open));
    }
  }
  return ret;
}

// Extracts the fd path strace prints with -y: "3</etc/passwd>" -> "/etc/passwd"
std::string ExtractFdPath(std::string_view text) {
  size_t lt = text.find('<');
  size_t gt = text.rfind('>');
  if (lt == std::string_view::npos || gt == std::string_view::npos || gt < lt) return "";
  return std::string(text.substr(lt + 1, gt - lt - 1));
}

// Removes any "/* name */" annotation strace adds in -X raw/verbose mode.
std::string_view StripAnnotation(std::string_view text) {
  size_t open = text.find("/*");
  if (open == std::string_view::npos) return text;
  return Trim(text.substr(0, open));
}

std::string ExtractAnnotation(std::string_view text) {
  size_t open = text.find("/*");
  size_t close = text.find("*/", open == std::string_view::npos ? 0 : open);
  if (open == std::string_view::npos || close == std::string_view::npos) return "";
  return std::string(Trim(text.substr(open + 2, close - open - 2)));
}

Argument ParseArgument(std::string_view raw) {
  Argument arg;
  std::string_view text = Trim(raw);
  if (text.empty()) {
    arg.shape = Argument::Shape::kUnknown;
    return arg;
  }
  arg.text = std::string(text);
  std::string annotation = ExtractAnnotation(text);
  std::string_view bare = Trim(StripAnnotation(text));

  if (bare.find("...") != std::string_view::npos) arg.truncated = true;

  // fd path annotation, e.g. 3</dev/null>
  if (bare.find('<') != std::string_view::npos &&
      bare.find('<') != 0) {
    arg.fd_path = ExtractFdPath(bare);
  }

  if (!bare.empty() && bare.front() == '"') {
    arg.shape = Argument::Shape::kString;
    return arg;
  }
  if (bare == "NULL") {
    arg.shape = Argument::Shape::kPointer;
    arg.value = 0;
    return arg;
  }
  if (bare == "..." || bare == "???") {
    arg.shape = Argument::Shape::kUnknown;
    return arg;
  }

  // Strip a trailing fd path: "3</etc/passwd>" -> "3"
  std::string cleaned(bare);
  size_t lt = cleaned.find('<');
  if (lt != std::string::npos) cleaned = std::string(Trim(cleaned.substr(0, lt)));

  if (!cleaned.empty() && (cleaned.front() == '{' || cleaned.front() == '[')) {
    arg.shape = Argument::Shape::kStruct;
    return arg;
  }

  // Symbolic value: identifiers optionally OR-ed together, possibly wrapped in
  // parentheses, e.g. AF_INET, O_RDWR|O_CLOEXEC, SIGCHLD, (flags.
  std::string_view sym = Trim(cleaned);
  bool looks_symbolic = !sym.empty() && (std::isalpha(static_cast<unsigned char>(sym[0])) ||
                                         sym[0] == '_');
  if (looks_symbolic) {
    auto pieces = Split(sym, '|');
    bool all_named = true;
    std::vector<std::string> names;
    for (auto piece : pieces) {
      std::string_view p = Trim(piece);
      if (p.empty()) continue;
      bool named = true;
      for (char c : p) {
        if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '+')) {
          named = false;
          break;
        }
      }
      if (!named) {
        all_named = false;
        break;
      }
      names.emplace_back(p);
    }
    if (all_named && !names.empty()) {
      arg.shape = Argument::Shape::kSymbolic;
      arg.symbols = names;
      uint64_t combined = 0;
      bool all_resolved = true;
      for (const auto& n : names) {
        auto v = LookupConstant(n);
        if (!v) {
          all_resolved = false;
          break;
        }
        combined |= static_cast<uint64_t>(*v);
      }
      if (all_resolved) arg.value = combined;
      return arg;
    }
  }

  if (!annotation.empty()) {
    // e.g. "2 /* AF_INET */"
    auto v = ParseInteger(cleaned);
    if (v) {
      arg.shape = Argument::Shape::kInteger;
      arg.value = *v;
      arg.symbols.push_back(annotation);
    }
    return arg;
  }

  if (auto v = ParseInteger(cleaned)) {
    arg.shape = cleaned.find("0x") != std::string::npos ||
                        cleaned.find("0X") != std::string::npos
                    ? Argument::Shape::kPointer
                    : Argument::Shape::kInteger;
    arg.value = *v;
    return arg;
  }

  arg.shape = Argument::Shape::kUnknown;
  return arg;
}

struct PendingCall {
  std::string name;
  std::string prefix_args;  // text before <unfinished ...>
  int line = 0;
};

// The parser itself.
class TraceParser {
 public:
  TraceParser(Arch arch, std::string source) : arch_(arch), source_(std::move(source)) {}

  Trace Parse(std::string_view text) {
    std::istringstream stream{std::string(text)};
    std::string line;
    int line_no = 0;
    double first_stamp = -1;
    while (std::getline(stream, line)) {
      ++line_no;
      if (!line.empty() && line.back() == '\r') line.pop_back();
      if (Trim(line).empty()) continue;
      ParseLine(line, line_no, &first_stamp);
    }
    // Any still-unfinished call: record it without a return value.
    for (auto& [pid, pending] : pending_) {
      Process& proc = GetProcess(pid, 0);
      Syscall call;
      call.pid = pid;
      call.name = pending.name;
      call.args = ParseArgs(pending.prefix_args);
      call.unfinished = true;
      call.line = pending.line;
      proc.syscalls.push_back(std::move(call));
    }
    Finish();
    return std::move(trace_);
  }

 private:
  Process& GetProcess(int pid, int line) {
    if (pid == 0) {
      if (trace_.root_pid == 0 && !processes_.empty()) {
        pid = processes_.begin()->first;
      } else if (trace_.root_pid != 0) {
        pid = trace_.root_pid;
      } else {
        pid = kUnprefixedPid;
        trace_.root_pid = pid;
      }
    }
    auto it = processes_.find(pid);
    if (it != processes_.end()) return it->second;
    Process proc;
    proc.pid = pid;
    if (trace_.root_pid == 0) trace_.root_pid = pid;
    auto [inserted, _] = processes_.emplace(pid, std::move(proc));
    (void)line;
    return inserted->second;
  }

  std::vector<Argument> ParseArgs(std::string_view text) {
    std::vector<Argument> args;
    std::string_view trimmed = Trim(text);
    if (trimmed.empty()) return args;
    for (auto piece : SplitArguments(trimmed)) {
      args.push_back(ParseArgument(piece));
    }
    return args;
  }

  void ParseLine(const std::string& line, int line_no, double* first_stamp) {
    std::string_view rest = Trim(line);
    if (rest.empty()) return;

    int pid = 0;
    bool have_pid = false;

    // "[pid  1234] ..." (strace -f with --prefix)
    if (StartsWith(rest, "[pid")) {
      size_t close = rest.find(']');
      if (close != std::string_view::npos) {
        auto digits = rest.substr(5, close - 5);
        if (auto v = ParseInteger(digits)) {
          pid = static_cast<int>(*v);
          have_pid = true;
        }
        rest = Trim(rest.substr(close + 1));
      }
    } else if (IsDigit(rest[0])) {
      // plain -f prefix: "1234  syscall(...)"
      size_t i = 0;
      while (i < rest.size() && IsDigit(rest[i])) ++i;
      // A timestamp can also start with digits (e.g. "0.000123"); only treat
      // the number as a pid when it is followed by whitespace and then a
      // non-digit, and when it is followed by another token.
      if (i < rest.size() && (rest[i] == ' ' || rest[i] == '\t')) {
        auto maybe_pid = ParseInteger(rest.substr(0, i));
        std::string_view after = Trim(rest.substr(i));
        if (maybe_pid && !after.empty()) {
          // Heuristic: pid prefixes are <= 7 digits and are not followed by
          // a timestamp-like '.'.
          bool looks_like_pid = rest.substr(0, i).size() <= 8 &&
                                (after.empty() || !IsDigit(after[0]) ||
                                 after.find('(') != std::string_view::npos ||
                                 after.find(':') != std::string_view::npos ||
                                 StartsWith(after, "---") || StartsWith(after, "+++") ||
                                 StartsWith(after, "<...")) ;
          if (looks_like_pid) {
            pid = static_cast<int>(*maybe_pid);
            have_pid = true;
            rest = after;
          }
        }
      }
    }

    // Optional timestamp: "12:34:56.123456 ", "0.000123 " or "1700000000.123"
    double stamp = 0;
    bool have_stamp = false;
    {
      size_t i = 0;
      while (i < rest.size() && rest[i] != ' ' && rest[i] != '\t') ++i;
      std::string_view token = rest.substr(0, i);
      if (!token.empty() && ParseTimestamp(token, &stamp)) {
        // Do not mistake a bare syscall name for a timestamp; ParseTimestamp
        // only accepts digits/colons/dots, so this is safe.
        rest = Trim(rest.substr(std::min(i, rest.size())));
        have_stamp = true;
      }
    }

    if (rest.empty()) return;

    if (!have_pid) {
      // Without -f every line belongs to the single traced process.  pid 0
      // means "unassigned"; GetProcess resolves it to the root pid.
      pid = 0;
    }

    if (have_stamp) {
      if (*first_stamp < 0) *first_stamp = stamp;
      stamp -= (*first_stamp < 0 ? stamp : *first_stamp);
      trace_.has_timestamps = true;
    }

    // "+++ exited with 0 +++", "+++ killed by SIGKILL +++"
    if (StartsWith(rest, "+++")) {
      Process& proc = GetProcess(pid, line_no);
      if (StartsWith(rest, "+++ exited")) {
        proc.exited = true;
      } else if (StartsWith(rest, "+++ killed")) {
        proc.signaled = true;
      }
      return;
    }
    // "--- SIGCHLD {si_signo=...} ---"
    if (StartsWith(rest, "---")) {
      return;
    }
    // "strace: Process 1234 attached"
    if (StartsWith(rest, "strace:") || StartsWith(rest, "<...")) {
      if (StartsWith(rest, "<...")) {
        HandleResumed(pid, std::string(rest), line_no, have_stamp, stamp);
      }
      return;
    }

    size_t open = rest.find('(');
    if (open == std::string_view::npos) {
      diagnostics_.push_back({line_no, "unrecognised line: " + std::string(rest)});
      return;
    }
    std::string name(Trim(rest.substr(0, open)));
    // A syscall name is an identifier; anything else is a line we do not know.
    if (name.empty() ||
        !std::all_of(name.begin(), name.end(), [](char c) {
          return std::isalnum(static_cast<unsigned char>(c)) || c == '_';
        })) {
      // These are typically signal-delivery lines such as "--- SIGCHLD ... ---".
      return;
    }
    if (FindSyscall(name) == nullptr) {
      // Not a name we know from either table.  Keep the call (the policy
      // compiler decides what to do with it) but say so once, because a trace
      // from an older strace may print a name we have not seen.
      unknown_names_.insert(name);
    }
    std::string_view body = rest.substr(open + 1);

    // Unfinished: "read(3, <unfinished ...>"
    size_t unfinished = body.find("<unfinished ...>");
    if (unfinished != std::string_view::npos) {
      PendingCall pending;
      pending.name = name;
      pending.prefix_args = std::string(Trim(body.substr(0, unfinished)));
      pending.line = line_no;
      pending_[pid] = pending;
      return;
    }

    // Completed call: find the matching closing paren.
    int depth = 1;
    bool in_string = false;
    size_t close = std::string_view::npos;
    for (size_t i = 0; i < body.size(); ++i) {
      char c = body[i];
      if (in_string) {
        if (c == '\\') {
          ++i;
        } else if (c == '"') {
          in_string = false;
        }
        continue;
      }
      if (c == '"') {
        in_string = true;
      } else if (c == '(') {
        ++depth;
      } else if (c == ')') {
        if (--depth == 0) {
          close = i;
          break;
        }
      }
    }
    std::string arg_text;
    std::string ret_text;
    if (close == std::string_view::npos) {
      arg_text = std::string(Trim(body));
    } else {
      arg_text = std::string(body.substr(0, close));
      std::string_view tail = Trim(body.substr(close + 1));
      if (StartsWith(tail, "=")) ret_text = std::string(Trim(tail.substr(1)));
    }

    // A resumed call stored its argument prefix earlier; glue it back on.
    // Only when the completing call is the one that was left unfinished: a
    // thread cannot be inside two syscalls, but malformed or interleaved input
    // should produce a diagnostic rather than silently mixing arguments.
    auto it = pending_.find(pid);
    if (it != pending_.end()) {
      if (it->second.name != name) {
        // A thread is never inside two syscalls, so one of the two lines is
        // not what it seems: typically a log that was cut off, or a pid that
        // was reused.  Keep the pending call pending (it may still resume),
        // record this one on its own, and say so: silently mixing the two
        // argument lists would produce a policy built on invented arguments.
        diagnostics_.push_back(
            {line_no, "pid " + std::to_string(pid) + ": '" + name +
                          "' completed while '" + it->second.name +
                          "' was still unfinished; recorded separately, "
                          "arguments not merged"});
        // fall through with the fresh call's own arguments
      } else {
        if (!arg_text.empty()) {
          it->second.prefix_args = it->second.prefix_args.empty()
                                       ? arg_text
                                       : it->second.prefix_args + arg_text;
        }
        arg_text = it->second.prefix_args;
        pending_.erase(it);
      }
    }

    Syscall call;
    call.pid = pid;
    call.name = name;
    call.args = ParseArgs(arg_text);
    call.line = line_no;
    call.time = stamp;
    call.has_time = have_stamp;
    ParseReturn(ret_text, &call);

    // Process bookkeeping before storing the call.
    Process& proc = GetProcess(pid, line_no);
    if (proc.first_time == 0.0 && have_stamp) proc.first_time = stamp;
    if (have_stamp) proc.last_time = stamp;

    RecordCreation(pid, call, line_no);

    proc.syscalls.push_back(std::move(call));
  }

  void HandleResumed(int pid, std::string text, int line_no, bool have_stamp,
                     double stamp) {
    // "<... read resumed>\"abc\", 3) = 3"
    size_t open = text.find("<...");
    size_t resumed = text.find("resumed>");
    if (open == std::string_view::npos || resumed == std::string::npos) return;
    std::string tail(text.substr(resumed + strlen("resumed>")));
    auto it = pending_.find(pid);
    std::string name;
    std::string prefix;
    int pending_line = line_no;
    if (it != pending_.end()) {
      name = it->second.name;
      prefix = it->second.prefix_args;
      pending_line = it->second.line;
      pending_.erase(it);
    } else {
      name = std::string(Trim(text.substr(open + 4, resumed - open - 4)));
    }
    // tail is "rest_of_args) = ret"
    std::string arg_text = prefix;
    std::string ret_text;
    if (!tail.empty()) {
      if (tail[0] == ')') {
        std::string_view rest = Trim(tail.substr(1));
        if (StartsWith(rest, "=")) ret_text = std::string(Trim(rest.substr(1)));
      } else {
        // The resumed text begins with the rest of the arguments.
        int depth = 1;
        bool in_string = false;
        size_t close = std::string::npos;
        for (size_t i = 0; i < tail.size(); ++i) {
          char c = tail[i];
          if (in_string) {
            if (c == '\\') ++i;
            else if (c == '"') in_string = false;
            continue;
          }
          if (c == '"') in_string = true;
          else if (c == '(') ++depth;
          else if (c == ')') {
            if (--depth == 0) { close = i; break; }
          }
        }
        if (close != std::string::npos) {
          arg_text += " " + tail.substr(0, close);
          std::string_view rest = Trim(std::string_view(tail).substr(close + 1));
          if (StartsWith(rest, "=")) ret_text = std::string(Trim(rest.substr(1)));
        } else {
          arg_text += " " + tail;
        }
      }
    }
    Syscall call;
    call.pid = pid;
    call.name = name;
    call.args = ParseArgs(arg_text);
    call.line = pending_line;
    call.resumed = true;
    call.time = stamp;
    call.has_time = have_stamp;
    ParseReturn(ret_text, &call);
    Process& proc = GetProcess(pid, line_no);
    RecordCreation(pid, call, line_no);
    proc.syscalls.push_back(std::move(call));
  }

  static void ParseReturn(std::string_view text, Syscall* call) {
    text = StripDuration(text);
    if (text.empty() || text == "?") return;
    if (StartsWith(text, "-1")) {
      call->ret = -1;
      // "-1 ENOENT (No such file or directory)"
      auto parts = Split(text, ' ');
      for (auto part : parts) {
        if (StartsWith(part, "E") && part.size() > 1 &&
            std::isupper(static_cast<unsigned char>(part[1]))) {
          if (auto v = FindConstant(std::string(part))) {
            call->errno_value = static_cast<int>(v->value);
          }
          break;
        }
      }
      return;
    }
    if (auto v = ParseInteger(text)) {
      call->ret = static_cast<int64_t>(*v);
    }
  }

  void RecordCreation(int pid, const Syscall& call, int line_no) {
    (void)line_no;
    if (call.name != "clone" && call.name != "clone3" && call.name != "fork" &&
        call.name != "vfork") {
      return;
    }
    if (!call.ret || *call.ret <= 0) return;
    int child = static_cast<int>(*call.ret);
    if (child == pid) return;
    ChildInfo info;
    info.parent = pid;
    info.syscall = call.name;
    // clone()'s first argument is the flag word, but strace prints its fields
    // by name ("child_stack=NULL, flags=CLONE_VM|..."), so the flag word is
    // whatever argument carries the CLONE_* names.  CLONE_THREAD (0x10000) is
    // what distinguishes a thread from a forked child.
    auto mentions_clone_thread = [](const Argument& arg) {
      if (arg.text.find("CLONE_THREAD") != std::string::npos) return true;
      return arg.value.has_value() &&
             ((*arg.value & 0x00010000ULL) != 0);
    };
    if (call.name == "clone" || call.name == "clone3") {
      for (const auto& arg : call.args) {
        if (mentions_clone_thread(arg)) {
          info.is_thread = true;
          break;
        }
      }
    }
    children_[child] = info;
  }

  void Finish() {
    for (auto& [pid, proc] : processes_) {
      auto it = children_.find(pid);
      if (it != children_.end()) {
        proc.created_by_pid = it->second.parent;
        proc.created_by_syscall = it->second.syscall;
        proc.is_thread = it->second.is_thread;
        proc.is_forked_child = !it->second.is_thread;
        auto parent = processes_.find(it->second.parent);
        proc.ppid = it->second.parent;
        proc.tgid = it->second.is_thread && parent != processes_.end()
                        ? (parent->second.tgid ? parent->second.tgid
                                               : parent->second.pid)
                        : pid;
      } else {
        proc.tgid = pid;
      }
      // A thread that calls exit_group or is created without CLONE_THREAD is
      // still tracked as its own pid; that is what strace reports.
      std::sort(proc.syscalls.begin(), proc.syscalls.end(),
                [](const Syscall& a, const Syscall& b) {
                  if (a.has_time && b.has_time) return a.time < b.time;
                  return a.line < b.line;
                });
    }
    trace_.processes.clear();
    for (auto& [pid, proc] : processes_) trace_.processes.push_back(proc);
    std::sort(trace_.processes.begin(), trace_.processes.end(),
              [](const Process& a, const Process& b) { return a.pid < b.pid; });
    trace_.source = source_;
    for (const std::string& name : unknown_names_) {
      // A name the tables do not know may still be a real syscall on a newer
      // kernel; the verifier reports it as unverifiable rather than guessing.
      if (SyscallNumber(arch_, 0) >= 0 && FindSyscall(name) == nullptr) {
        diagnostics_.push_back(
            {0, "syscall name '" + name +
                    "' is not in the generated tables; its calls cannot be "
                    "verified and will be denied unless the policy names it"});
      }
    }
    for (auto& d : diagnostics_) trace_.diagnostics.push_back(std::move(d));
    if (trace_.root_pid == 0 && !trace_.processes.empty()) {
      trace_.root_pid = trace_.processes.front().pid;
    }
  }

  static constexpr int kUnprefixedPid = 1;

  struct ChildInfo {
    int parent = 0;
    bool is_thread = false;
    std::string syscall;
  };

  Arch arch_;
  std::set<std::string> unknown_names_;
  std::string source_;
  Trace trace_;
  std::unordered_map<int, Process> processes_;
  std::unordered_map<int, PendingCall> pending_;
  std::unordered_map<int, ChildInfo> children_;
  std::vector<TraceDiagnostic> diagnostics_;
};

// Names that indicate a server has finished starting up.
const char* const kReadySyscalls[] = {
    "listen", "accept", "accept4", "epoll_wait", "epoll_pwait", "epoll_pwait2",
    "select", "pselect6", "poll", "ppoll",
};

bool IsReadySyscall(const std::string& name) {
  for (const char* n : kReadySyscalls) {
    if (name == n) return true;
  }
  return false;
}

}  // namespace

Trace ParseTraceFile(const std::string& path, Arch arch) {
  std::ifstream in(path, std::ios::binary);
  if (!in) throw Error("cannot open trace file: " + path);
  std::ostringstream buffer;
  buffer << in.rdbuf();
  return ParseTrace(buffer.str(), arch, path);
}

Trace ParseTrace(std::string_view text, Arch arch, std::string source_name) {
  TraceParser parser(arch, std::move(source_name));
  Trace trace = parser.Parse(text);
  if (trace.processes.size() == 1) {
    trace.root_pid = trace.processes.front().pid;
  }
  return trace;
}

void AssignPhases(Trace& trace, const PhaseOptions& options) {
  // Find the global "ready" moment.
  double ready_time = -1;
  int ready_pid = 0;
  int ready_line_ = 0;
  bool have_ready = false;

  if (!options.ready_syscall.empty()) {
    for (const auto& proc : trace.processes) {
      for (const auto& call : proc.syscalls) {
        if (call.name != options.ready_syscall) continue;
        if (call.ret && *call.ret < 0) continue;
        ready_pid = proc.pid;
        if (call.has_time) {
          ready_time = call.time;
        } else {
          ready_line_ = call.line;
        }
        have_ready = true;
        break;
      }
      if (have_ready) break;
    }
  } else if (options.ready_after_seconds) {
    ready_time = *options.ready_after_seconds;
    have_ready = true;
  } else if (options.ready_after_syscalls) {
    // Count per process; the process that reaches the threshold first wins.
    for (const auto& proc : trace.processes) {
      if (static_cast<int>(proc.syscalls.size()) <= *options.ready_after_syscalls) {
        continue;
      }
      const Syscall& at = proc.syscalls[*options.ready_after_syscalls];
      ready_pid = proc.pid;
      if (at.has_time) {
        ready_time = at.time;
      } else {
        ready_line_ = at.line;
      }
      have_ready = true;
      break;
    }
  } else {
    // Heuristic: the first successful listen/accept, or the first wait-family
    // call (a server entering its loop), whichever comes first.  A trace
    // without timestamps has no comparable clock, so fall back to the first
    // readiness syscall in file order (see AssignPhases for the split).
    for (const auto& proc : trace.processes) {
      for (const auto& call : proc.syscalls) {
        if (!IsReadySyscall(call.name)) continue;
        if ((call.name == "listen" || call.name == "accept" ||
             call.name == "accept4") &&
            call.ret && *call.ret < 0) {
          continue;
        }
        if (call.has_time) {
          if (ready_time < 0 || call.time < ready_time) {
            ready_time = call.time;
            ready_pid = proc.pid;
          }
        } else {
          ready_line_ = call.line;
          ready_pid = proc.pid;
        }
        have_ready = true;
        break;
      }
    }
  }

  if (!have_ready) {
    trace.diagnostics.push_back(
        {0, "no ready marker found (no listen/accept/epoll_wait/poll call); "
            "every syscall is classified as runtime.  Pass --ready-syscall or "
            "--ready-after to split explicitly."});
  }

  for (auto& proc : trace.processes) {
    proc.startup.clear();
    proc.runtime.clear();
    bool proc_ready = !have_ready;  // with no marker, everything is runtime
    for (auto& call : proc.syscalls) {
      if (!proc_ready) {
        bool after = false;
        if (options.ready_after_seconds) {
          after = call.has_time && call.time > ready_time;
        } else if (call.has_time && ready_time >= 0) {
          after = call.time > ready_time ||
                  (call.time == ready_time && proc.pid == ready_pid &&
                   call.name == options.ready_syscall);
        } else if (ready_line_ > 0) {
          // No timestamps: the ready marker is a line in the trace file, and
          // lines before it are start-up.
          after = call.line > ready_line_;
        } else {
          after = ready_time < 0 ? false : true;
        }
        if (after) proc_ready = true;
      }
      if (proc_ready) {
        proc.runtime.push_back(call);
      } else {
        proc.startup.push_back(call);
      }
    }
  }
}

}  // namespace scgen

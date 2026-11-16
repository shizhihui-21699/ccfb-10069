// Parsing of `strace -f` output into per-process syscall traces.
//
// What we consume
// ---------------
//   strace -f -tt -yy -xx -s 4096 -o trace.log ./service
//
// The parser is deliberately tolerant: it accepts plain `strace -f` output
// too (no -tt, no -yy, truncated strings, "..." suffixes).  Everything it
// cannot understand is reported as a diagnostic rather than silently dropped,
// because an incomplete trace produces an over-permissive policy.
#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "syscalls.h"

namespace scgen {

// One argument as it appeared in the trace.
struct Argument {
  enum class Shape {
    kInteger,   // 3, 0x7f00, -1
    kSymbolic,  // AF_INET, O_RDONLY|O_CLOEXEC, SIGCHLD
    kString,    // "..."
    kPointer,   // 0x7ffe..., NULL
    kStruct,    // {...} or [ ... ]
    kUnknown,   // ???
  };

  Shape shape = Shape::kUnknown;
  std::string text;            // original text, trimmed
  std::optional<uint64_t> value;   // numeric value when determinable
  std::vector<std::string> symbols;  // OR-ed symbolic names, e.g. O_CREAT
  std::string fd_path;         // "/etc/passwd" from strace -y, else empty
  bool truncated = false;      // strace printed "..." inside the argument

  bool IsNumeric() const { return value.has_value(); }
  std::string ToString() const { return text; }
};

struct Syscall {
  int pid = 0;                 // strace's pid (thread id for threads)
  std::string name;
  std::vector<Argument> args;
  std::optional<int64_t> ret;  // exit value; -1 for errors
  std::optional<int> errno_value;
  bool unfinished = false;     // -f output: call not yet resumed
  bool resumed = false;        // "<... name resumed>"
  bool exited = false;         // "+++ exited with 0 +++"
  bool signaled = false;
  bool signaled_by_signal = false;
  double time = 0.0;           // seconds since trace start, from -tt/-r
  bool has_time = false;
  int line = 0;                // line in the trace file
  int duration_serial = 0;     // orders resumed calls correctly
};

// A process (or thread) seen in the trace.
struct Process {
  int pid = 0;
  int ppid = 0;                 // 0 when the trace did not record it
  int tgid = 0;                 // thread group id == pid for the leader
  std::string comm;
  bool is_thread = false;
  bool is_forked_child = false; // created by clone/fork inside the trace
  int created_by_pid = 0;       // parent strace pid, 0 for the traced root
  std::string created_by_syscall;
  std::vector<Syscall> syscalls;
  bool exited = false;
  bool signaled = false;
  std::vector<Syscall> startup;   // calls before the "ready" marker
  std::vector<Syscall> runtime;   // calls after it
  double first_time = 0.0;
  double last_time = 0.0;
};

struct TraceDiagnostic {
  int line = 0;
  std::string message;
};

struct Trace {
  std::vector<Process> processes;   // sorted by pid
  std::vector<TraceDiagnostic> diagnostics;
  int root_pid = 0;
  bool has_timestamps = false;
  bool has_fd_paths = false;        // -yy was used
  std::string source;               // file name, for reports
};

// Parses a trace file.  `arch` is used to resolve "@@" entries and to warn
// about syscall names that do not exist on that architecture.
Trace ParseTraceFile(const std::string& path, Arch arch);

// Parses trace text already in memory (used by tests).
Trace ParseTrace(std::string_view text, Arch arch, std::string source_name);

// Splits a trace into startup and runtime at the point where the program
// becomes ready.  A "ready" marker can be supplied explicitly (the name of a
// syscall such as `listen`, or a wall time in seconds); otherwise the split
// is made with a heuristic documented in the implementation.
struct PhaseOptions {
  // Ready when this syscall has been seen (on any process).  Empty means use
  // the heuristic.
  std::string ready_syscall;
  // Ready after this many seconds of trace time.
  std::optional<double> ready_after_seconds;
  // Ready when this many syscalls have been observed, per process.
  std::optional<int> ready_after_syscalls;
};

void AssignPhases(Trace& trace, const PhaseOptions& options);

}  // namespace scgen

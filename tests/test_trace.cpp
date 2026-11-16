// The trace parser: real strace shapes, thread and fork tracking, phases.
#include "strace_parser.h"

#include "common.h"
#include "test_harness.h"

using namespace scgen;

namespace {

Trace Parse(const char* text) {
  return ParseTrace(text, Arch::kX86_64, "test.log");
}

const Process* Find(const Trace& trace, int pid) {
  for (const auto& proc : trace.processes) {
    if (proc.pid == pid) return &proc;
  }
  return nullptr;
}

}  // namespace

TEST(parses_plain_without_pid_prefix) {
  Trace trace = Parse(
      "execve(\"/bin/true\", [\"true\"], 0x7ffd) = 0\n"
      "exit_group(0) = ?\n");
  CHECK_EQ(trace.processes.size(), static_cast<size_t>(1));
  CHECK_EQ(trace.processes[0].syscalls.size(), static_cast<size_t>(2));
  CHECK_EQ(trace.processes[0].syscalls[0].name, std::string("execve"));
  CHECK_EQ(trace.processes[0].syscalls[0].args.size(), static_cast<size_t>(3));
}

TEST(parses_pid_prefix_and_timestamps) {
  Trace trace = Parse(
      "1234  12:00:00.000100 read(0, \"x\", 1) = 1\n"
      "1234  12:00:00.000200 write(1, \"y\", 1) = 1\n");
  CHECK_EQ(trace.processes.size(), static_cast<size_t>(1));
  CHECK_EQ(trace.processes[0].pid, 1234);
  CHECK(trace.has_timestamps);
  CHECK_EQ(trace.processes[0].syscalls.size(), static_cast<size_t>(2));
  CHECK(trace.processes[0].syscalls[1].has_time);
}

TEST(parses_unfinished_and_resumed_calls) {
  Trace trace = Parse(
      "100 read(0, <unfinished ...>\n"
      "101 write(1, \"a\", 1) = 1\n"
      "100 <... read resumed>\"z\", 1) = 1\n");
  const Process* p100 = Find(trace, 100);
  CHECK(p100 != nullptr);
  CHECK_EQ(p100->syscalls.size(), static_cast<size_t>(1));
  CHECK_EQ(p100->syscalls[0].name, std::string("read"));
  CHECK_EQ(p100->syscalls[0].args.size(), static_cast<size_t>(3));
  CHECK_EQ(p100->syscalls[0].ret.value(), 1);
  CHECK_EQ(p100->syscalls[0].args[0].text, std::string("0"));
}

TEST(unfinished_call_does_not_steal_another_calls_arguments) {
  // A thread cannot be in two syscalls, but a malformed log can claim it.
  Trace trace = Parse(
      "100 read(0, <unfinished ...>\n"
      "100 socket(AF_UNIX, SOCK_DGRAM, 0) = 8\n"
      "100 <... read resumed>\"z\", 1) = 1\n");
  const Process* p = Find(trace, 100);
  CHECK(p != nullptr);
  CHECK_EQ(p->syscalls.size(), static_cast<size_t>(2));
  // The socket call must keep its own arguments and not inherit "0".
  bool found_socket = false;
  for (const auto& call : p->syscalls) {
    if (call.name != "socket") continue;
    found_socket = true;
    CHECK_EQ(call.args.size(), static_cast<size_t>(3));
    CHECK_EQ(call.args[0].text, std::string("AF_UNIX"));
  }
  CHECK(found_socket);
  CHECK(!trace.diagnostics.empty());
}

TEST(tracks_threads_and_forked_children) {
  Trace trace = Parse(
      "200 clone(child_stack=NULL, flags=CLONE_VM|CLONE_THREAD|CLONE_SIGHAND) = 201\n"
      "200 clone(child_stack=0x7f, flags=CLONE_VM|CLONE_VFORK|SIGCHLD) = 202\n"
      "201 futex(0x7f, FUTEX_WAIT, 0, NULL) = 0\n"
      "202 execve(\"/bin/true\", [\"true\"], 0x7f) = 0\n");
  const Process* parent = Find(trace, 200);
  const Process* thread = Find(trace, 201);
  const Process* child = Find(trace, 202);
  CHECK(parent != nullptr && thread != nullptr && child != nullptr);
  CHECK(thread->is_thread);
  CHECK(!thread->is_forked_child);
  CHECK(child->is_forked_child);
  CHECK(!child->is_thread);
  CHECK_EQ(thread->created_by_pid, 200);
  CHECK_EQ(child->created_by_pid, 200);
  CHECK_EQ(child->tgid, 202);
  CHECK_EQ(thread->tgid, 200);
}

TEST(parses_symbolic_arguments_to_numbers) {
  Trace trace = Parse(
      "1 socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 3\n"
      "1 openat(AT_FDCWD, \"/etc/passwd\", O_RDONLY|O_CLOEXEC) = 3\n");
  const Syscall& socket = trace.processes[0].syscalls[0];
  CHECK_EQ(socket.args[0].text, std::string("AF_INET"));
  CHECK(socket.args[0].value.has_value());
  CHECK_EQ(*socket.args[0].value, 2u);
  CHECK_EQ(*socket.args[1].value, 1u | 0x80000u);
  CHECK_EQ(*socket.args[2].value, 6u);
  const Syscall& openat = trace.processes[0].syscalls[1];
  CHECK_EQ(*openat.args[2].value, 0x80000u);  // O_RDONLY is 0, O_CLOEXEC is set
}

TEST(captures_fd_paths_from_yy_output) {
  Trace trace = Parse("1 read(3</etc/passwd>, \"x\", 1) = 1\n");
  const Syscall& call = trace.processes[0].syscalls[0];
  CHECK_EQ(call.args[0].fd_path, std::string("/etc/passwd"));
  CHECK_EQ(*call.args[0].value, 3u);
}

TEST(records_errors_and_ignores_signal_lines) {
  Trace trace = Parse(
      "1 openat(AT_FDCWD, \"/nope\", O_RDONLY) = -1 ENOENT (No such file or directory)\n"
      "1 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED} ---\n"
      "1 close(3) = 0\n");
  CHECK_EQ(trace.processes[0].syscalls.size(), static_cast<size_t>(2));
  CHECK_EQ(trace.processes[0].syscalls[0].ret.value(), -1);
  CHECK(trace.processes[0].syscalls[0].errno_value.has_value());
  CHECK_EQ(*trace.processes[0].syscalls[0].errno_value, 2);  // ENOENT
}

TEST(assigns_phases_at_first_readiness_syscall) {
  Trace trace = Parse(
      "1 execve(\"/s\", [\"s\"], 0x1) = 0\n"
      "1 socket(AF_INET, SOCK_STREAM, 0) = 3\n"
      "1 listen(3, 5) = 0\n"
      "1 accept4(3, NULL, NULL, 0) = 4\n"
      "1 read(4, \"x\", 1) = 1\n");
  PhaseOptions options;
  AssignPhases(trace, options);
  const Process& proc = trace.processes[0];
  // listen is the readiness marker; it and everything before it is startup.
  CHECK_EQ(proc.startup.size(), static_cast<size_t>(3));
  CHECK_EQ(proc.runtime.size(), static_cast<size_t>(2));
  CHECK_EQ(proc.runtime[0].name, std::string("accept4"));
}

TEST(explicit_ready_syscall_overrides_heuristic) {
  Trace trace = Parse(
      "1 execve(\"/s\", [\"s\"], 0x1) = 0\n"
      "1 listen(3, 5) = 0\n"
      "1 read(3, \"x\", 1) = 1\n");
  PhaseOptions options;
  options.ready_syscall = "execve";
  AssignPhases(trace, options);
  CHECK_EQ(trace.processes[0].startup.size(), static_cast<size_t>(1));
  CHECK_EQ(trace.processes[0].runtime.size(), static_cast<size_t>(2));
}

TEST(trace_without_timestamps_still_splits) {
  Trace trace = Parse(
      "1 socket(AF_INET, SOCK_STREAM, 0) = 3\n"
      "1 listen(3, 5) = 0\n"
      "1 read(3, \"x\", 1) = 1\n");
  PhaseOptions options;
  AssignPhases(trace, options);
  CHECK(!trace.has_timestamps);
  CHECK_EQ(trace.processes[0].startup.size(), static_cast<size_t>(2));
  CHECK_EQ(trace.processes[0].runtime.size(), static_cast<size_t>(1));
}

TEST(reports_when_no_ready_marker_exists) {
  Trace trace = Parse("1 write(1, \"x\", 1) = 1\n");
  PhaseOptions options;
  AssignPhases(trace, options);
  CHECK(!trace.diagnostics.empty());
  CHECK_EQ(trace.processes[0].runtime.size(), static_cast<size_t>(1));
}

TEST(parses_bracket_pid_prefix) {
  Trace trace = Parse(
      "[pid  4242] execve(\"/bin/x\", [\"x\"], 0x1) = 0\n"
      "[pid  4242] exit_group(0) = ?\n");
  CHECK_EQ(trace.processes.size(), static_cast<size_t>(1));
  CHECK_EQ(trace.processes[0].pid, 4242);
  CHECK_EQ(trace.processes[0].syscalls.size(), static_cast<size_t>(2));
}

TEST(handles_strings_with_commas_and_escapes) {
  Trace trace = Parse("1 write(1, \"a, b\\\"c\", 6) = 6\n");
  const Syscall& call = trace.processes[0].syscalls[0];
  CHECK_EQ(call.args.size(), static_cast<size_t>(3));
  CHECK_EQ(call.args[1].shape, Argument::Shape::kString);
  CHECK_EQ(*call.args[2].value, 6u);
}

TEST(handles_long_lines_with_structs) {
  Trace trace = Parse(
      "1 bind(3, {sa_family=AF_INET, sin_port=htons(80), "
      "sin_addr=inet_addr(\"0.0.0.0\")}, 16) = 0\n");
  const Syscall& call = trace.processes[0].syscalls[0];
  CHECK_EQ(call.args.size(), static_cast<size_t>(3));
  CHECK_EQ(call.args[1].shape, Argument::Shape::kStruct);
  CHECK_EQ(*call.args[2].value, 16u);
}

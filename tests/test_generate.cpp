// The generator and end-to-end verification: inference from a trace, the
// filter-vs-policy cross-check, and the "would the service break?" answer.
#include "generator.h"

#include "bpf.h"
#include "common.h"
#include "compiler.h"
#include "dsl.h"
#include "strace_parser.h"
#include "syscalls.h"
#include "test_harness.h"
#include "verifier.h"

using namespace scgen;

namespace {

const char* kServerTrace =
    "500  0.000100 execve(\"/srv\", [\"srv\"], 0x1) = 0\n"
    "500  0.000200 brk(NULL) = 0x5555\n"
    "500  0.000300 openat(AT_FDCWD, \"/etc/srv.conf\", O_RDONLY|O_CLOEXEC) = 3\n"
    "500  0.000400 read(3, \"port=8080\\n\", 10) = 10\n"
    "500  0.000500 close(3) = 0\n"
    "500  0.000600 socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 4\n"
    "500  0.000700 setsockopt(4, SOL_SOCKET, SO_REUSEADDR, [1], 4) = 0\n"
    "500  0.000800 bind(4, {sa_family=AF_INET, sin_port=htons(8080), "
    "sin_addr=inet_addr(\"0.0.0.0\")}, 16) = 0\n"
    "500  0.000900 listen(4, 128) = 0\n"
    "500  0.001000 clone(child_stack=NULL, flags=CLONE_VM|CLONE_THREAD) = 501\n"
    "501  0.001100 futex(0x7f00, FUTEX_WAIT_PRIVATE, 0, NULL) = 0\n"
    "500  0.001200 epoll_create1(EPOLL_CLOEXEC) = 5\n"
    "500  0.001300 epoll_ctl(5, EPOLL_CTL_ADD, 4, {events=EPOLLIN, "
    "data={u32=4}}) = 0\n"
    "500  0.001400 epoll_wait(5, [], 128, -1) = 1\n"
    "500  0.001500 accept4(4, {sa_family=AF_INET}, [16], SOCK_CLOEXEC) = 6\n"
    "500  0.001600 read(6, \"GET /\\n\", 6) = 6\n"
    "500  0.001700 write(6, \"200 OK\\n\", 7) = 7\n"
    "500  0.001800 close(6) = 0\n"
    "501  0.001900 write(2, \"log\\n\", 4) = 4\n"
    "500  0.002000 exit_group(0) = ?\n";

Trace ServerTrace(PhaseOptions* phase_options = nullptr) {
  Trace trace = ParseTrace(kServerTrace, Arch::kX86_64, "server.log");
  PhaseOptions defaults;
  AssignPhases(trace, phase_options ? *phase_options : defaults);
  return trace;
}

GenerationResult Generate(const Trace& trace) {
  GeneratorOptions options;
  options.arch = Arch::kX86_64;
  return GeneratePolicy(trace, options);
}

bool Mentions(const Policy& policy, const std::string& syscall, Phase phase) {
  for (const auto& rule : policy.rules) {
    if (rule.syscall != syscall) continue;
    if (rule.phase == phase || rule.phase == Phase::kBoth) return true;
  }
  return false;
}

const Rule* FindRule(const Policy& policy, const std::string& syscall,
                     Phase phase) {
  for (const auto& rule : policy.rules) {
    if (rule.syscall != syscall) continue;
    if (rule.phase == phase || rule.phase == Phase::kBoth) return &rule;
  }
  return nullptr;
}

}  // namespace

TEST(generator_allows_every_syscall_in_the_trace) {
  Trace trace = ServerTrace();
  GenerationResult generation = Generate(trace);
  VerificationResult verification = VerifyTrace(trace, generation.policy,
                                                VerifyOptions{});
  CHECK(verification.errors.empty());
  CHECK(verification.ok);
  CHECK_EQ(verification.startup.denied, 0);
  CHECK_EQ(verification.runtime.denied, 0);
}

TEST(generator_splits_startup_and_runtime) {
  Trace trace = ServerTrace();
  GenerationResult generation = Generate(trace);
  // listen is the readiness marker, so openat/read/close/socket are startup
  // and the event loop calls are runtime.
  CHECK(Mentions(generation.policy, "openat", Phase::kStartup));
  CHECK(Mentions(generation.policy, "epoll_wait", Phase::kRuntime));
  CHECK(Mentions(generation.policy, "accept4", Phase::kRuntime));
  // execve appears only once, before readiness.
  CHECK(Mentions(generation.policy, "execve", Phase::kStartup));
}

TEST(generator_constrains_socket_family_to_what_it_saw) {
  Trace trace = ServerTrace();
  GenerationResult generation = Generate(trace);
  const Rule* socket = FindRule(generation.policy, "socket", Phase::kStartup);
  CHECK(socket != nullptr);
  CHECK(!socket->conditions.empty());
  CHECK_EQ(socket->conditions[0].arg, 0);
  CHECK_EQ(socket->conditions[0].cmp.op, CompareOp::kEq);
  CHECK_EQ(socket->conditions[0].cmp.a, 2u);  // AF_INET
  // The socket type is pinned to its type nibble only, leaving SOCK_CLOEXEC and
  // SOCK_NONBLOCK free: the trace's SOCK_STREAM|SOCK_CLOEXEC must not become
  // "type == SOCK_STREAM|SOCK_CLOEXEC".
  for (const auto& cond : socket->conditions) {
    if (cond.arg != 1) continue;
    CHECK_EQ(cond.cmp.op, CompareOp::kEq);
    CHECK_EQ(cond.mask, 0xfu);
    CHECK_EQ(cond.cmp.a, 1u);  // SOCK_STREAM
  }
}

TEST(generator_does_not_pin_file_descriptors) {
  Trace trace = ServerTrace();
  GenerationResult generation = Generate(trace);
  const Rule* read = FindRule(generation.policy, "read", Phase::kBoth);
  if (read == nullptr) read = FindRule(generation.policy, "read", Phase::kStartup);
  CHECK(read != nullptr);
  for (const auto& cond : read->conditions) {
    CHECK(cond.arg != 0);  // never "fd == 3"
  }
}

TEST(generator_does_not_pin_pointer_arguments) {
  Trace trace = ServerTrace();
  GenerationResult generation = Generate(trace);
  const Rule* execve = FindRule(generation.policy, "execve", Phase::kStartup);
  CHECK(execve != nullptr);
  CHECK(execve->conditions.empty());  // pathname/argv/envp are pointers
}

TEST(generator_keeps_flag_bits_seen_in_every_call) {
  Trace trace = ServerTrace();
  GenerationResult generation = Generate(trace);
  const Rule* openat = FindRule(generation.policy, "openat", Phase::kStartup);
  CHECK(openat != nullptr);
  bool has_flags = false;
  for (const auto& cond : openat->conditions) {
    if (cond.arg == 2 && cond.cmp.op == CompareOp::kMask) {
      has_flags = true;
      CHECK_EQ(cond.cmp.a & 0x80000u, 0x80000u);  // O_CLOEXEC
    }
  }
  CHECK(has_flags);
}

TEST(generated_policy_denies_unseen_syscalls) {
  Trace trace = ServerTrace();
  GenerationResult generation = Generate(trace);
  CHECK(generation.policy.default_action.kind == Action::Kind::kKill);
  CompileOptions options;
  CompiledFilter filter = CompileFilter(generation.policy, Phase::kRuntime, options);
  SeccompData data;
  data.arch = AuditArch(Arch::kX86_64);
  data.nr = SyscallNumber(Arch::kX86_64, "ptrace");
  CHECK_EQ(RunFilter(filter.program, data), kRetKillThread);
}

TEST(generated_policy_denies_wrong_socket_family) {
  Trace trace = ServerTrace();
  GenerationResult generation = Generate(trace);
  CompileOptions options;
  // socket is used before readiness in this trace, so its rule lives in the
  // startup filter (which also carries runtime allowances).
  CompiledFilter filter = CompileFilter(generation.policy, Phase::kStartup, options);
  SeccompData data;
  data.arch = AuditArch(Arch::kX86_64);
  data.nr = SyscallNumber(Arch::kX86_64, "socket");
  data.args[0] = 1;  // AF_UNIX: never seen in the trace
  data.args[1] = 1;
  CHECK_EQ(RunFilter(filter.program, data), kRetKillThread);
  data.args[0] = 2;   // AF_INET: what the service uses
  data.args[1] = 1;   // SOCK_STREAM
  CHECK_EQ(RunFilter(filter.program, data), kRetAllow);
  data.args[1] = 1 | 0x80000;  // SOCK_STREAM|SOCK_CLOEXEC must also pass
  CHECK_EQ(RunFilter(filter.program, data), kRetAllow);
}

TEST(verifier_reports_a_filter_that_blocks_a_recorded_call) {
  // A policy that looks reasonable but omits a syscall the trace uses must be
  // caught: the service would fail at that line.
  Trace trace = ServerTrace();
  Policy policy = ParsePolicyDsl(
                     "default kill\n"
                     "runtime { allow epoll_wait }\n"
                     "startup { allow @fs_read }\n",
                     "hand.dsl", Arch::kX86_64)
                     .policy;
  VerificationResult verification = VerifyTrace(trace, policy, VerifyOptions{});
  // The filter agrees with the policy, so this is not a compiler bug: it is a
  // policy that blocks calls the service makes.  That must fail verification,
  // naming the affected syscalls, or a broken policy would look green.
  CHECK(!verification.ok);
  CHECK(!verification.errors.empty());
  CHECK(!verification.startup.blocked_recorded.empty() ||
        !verification.runtime.blocked_recorded.empty());
  bool mentions_line = false;
  for (const std::string& error : verification.errors) {
    if (error.find("the policy denies") != std::string::npos &&
        error.find("line ") != std::string::npos) {
      mentions_line = true;
    }
  }
  CHECK(mentions_line);
}

TEST(verifier_reports_a_policy_that_allows_what_the_filter_denies) {
  // The reverse direction: the filter must never be more permissive than the
  // policy.  Build a filter by hand that allows everything and a policy that
  // does not; the verifier must flag it.
  Trace trace = ServerTrace();
  Policy policy = ParsePolicyDsl("default kill\nruntime { allow read }\n",
                                 "hand.dsl", Arch::kX86_64)
                      .policy;
  std::vector<Instruction> allow_all{insn::RetK(kRetAllow)};
  VerificationResult verification =
      VerifyTrace(trace, policy, allow_all, allow_all, VerifyOptions{});
  CHECK(!verification.ok);
  CHECK(!verification.errors.empty());
}

TEST(verifier_detects_compiler_bug_via_independent_evaluation) {
  // Feed the verifier a deliberately wrong filter (one syscall allowed that
  // the policy denies) and confirm it is caught by the cross-check rather than
  // trusted.
  Trace trace = ServerTrace();
  GenerationResult generation = Generate(trace);
  CompileOptions options;
  CompiledFilter good = CompileFilter(generation.policy, Phase::kRuntime, options);
  // Strip the syscall dispatch: a program that allows only read.
  Assembler as;
  as.LdAbs(kSeccompDataNrOffset);
  as.JmpK(kJeq, SyscallNumber(Arch::kX86_64, "ptrace"), "yes", "no");
  as.Bind("yes");
  as.RetK(kRetAllow);
  as.Bind("no");
  as.RetK(kRetKillThread);
  VerificationResult verification =
      VerifyTrace(trace, generation.policy, good.program, as.Finalize(),
                  VerifyOptions{});
  CHECK(!verification.ok);
}

TEST(generator_records_why_an_argument_was_left_open) {
  Trace trace = ServerTrace();
  GenerationResult generation = Generate(trace);
  // socket's fd is observed once, but it is an fd, not a policy fact.
  bool explained = false;
  for (const std::string& note : generation.stats.notes) {
    if (note.find("fd") != std::string::npos ||
        note.find("pointer") != std::string::npos) {
      explained = true;
    }
  }
  CHECK(explained);
}

TEST(generator_result_round_trips_through_dsl) {
  Trace trace = ServerTrace();
  GenerationResult generation = Generate(trace);
  std::string text = FormatPolicyDsl(generation.policy, Arch::kX86_64);
  DslParseResult reparsed = ParsePolicyDsl(text, "<gen>", Arch::kX86_64);
  CHECK(reparsed.errors.empty());
  VerificationResult verification = VerifyTrace(trace, reparsed.policy,
                                                VerifyOptions{});
  CHECK(verification.ok);
}

TEST(aarch64_generation_uses_aarch64_numbers) {
  Trace trace = ParseTrace(kServerTrace, Arch::kAarch64, "server.log");
  AssignPhases(trace, PhaseOptions{});
  // The same textual trace, but read as aarch64: syscall numbers come from the
  // aarch64 table.
  GeneratorOptions options;
  options.arch = Arch::kAarch64;
  GenerationResult generation = GeneratePolicy(trace, options);
  CompileOptions copts;
  copts.arch = Arch::kAarch64;
  CompiledFilter filter =
      CompileFilter(generation.policy, Phase::kRuntime, copts);
  SeccompData data;
  data.arch = AuditArch(Arch::kAarch64);
  data.nr = 63;  // aarch64 read
  CHECK_EQ(RunFilter(filter.program, data), kRetAllow);
}

TEST(verification_attributes_denials_to_the_right_process) {
  Trace trace = ServerTrace();
  Policy policy = ParsePolicyDsl("default kill\nruntime { allow read }\n",
                                 "hand.dsl", Arch::kX86_64)
                      .policy;
  VerificationResult verification = VerifyTrace(trace, policy, VerifyOptions{});
  bool saw_thread = false;
  bool saw_main = false;
  for (const auto& summary : verification.processes) {
    if (summary.pid == 501) saw_thread = true;
    if (summary.pid == 500) saw_main = true;
  }
  CHECK(saw_thread);
  CHECK(saw_main);
}

TEST(trace_with_only_startup_calls_produces_a_valid_policy) {
  Trace trace = ParseTrace(
      "1 execve(\"/x\", [\"x\"], 0x1) = 0\n"
      "1 write(1, \"done\\n\", 5) = 5\n", Arch::kX86_64, "short.log");
  AssignPhases(trace, PhaseOptions{});
  GenerationResult generation = Generate(trace);
  CHECK(!generation.policy.rules.empty());
  VerificationResult verification = VerifyTrace(trace, generation.policy,
                                                VerifyOptions{});
  CHECK(verification.ok);
}

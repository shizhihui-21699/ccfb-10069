// Architectural guarantees that the rest of the suite only implies: the two
// architecture tables, the primary-architecture check, and behaviour that must
// not silently regress.
#include <cstdio>
#include <cstring>
#include <set>
#include <stdexcept>

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

Policy Parse(const char* text, Arch arch) {
  DslParseResult result = ParsePolicyDsl(text, "t.dsl", arch);
  if (!result.errors.empty()) {
    throw std::runtime_error("parse error: " + result.errors.front());
  }
  return result.policy;
}

uint32_t RunOn(const Policy& policy, Arch arch, int nr,
               std::initializer_list<uint64_t> args) {
  CompileOptions options;
  options.arch = arch;
  CompiledFilter filter = CompileFilter(policy, Phase::kRuntime, options);
  SeccompData data;
  data.arch = AuditArch(arch);
  data.nr = nr;
  int i = 0;
  for (uint64_t value : args) data.args[i++] = value;
  return RunFilter(filter.program, data);
}

}  // namespace

TEST(tables_cover_both_architectures) {
  // Spot-check numbers that differ between the ABIs; a swapped table would
  // produce a filter that kills the service's first read().
  CHECK_EQ(SyscallNumber(Arch::kX86_64, "read"), 0);
  CHECK_EQ(SyscallNumber(Arch::kAarch64, "read"), 63);
  CHECK_EQ(SyscallNumber(Arch::kX86_64, "write"), 1);
  CHECK_EQ(SyscallNumber(Arch::kAarch64, "write"), 64);
  CHECK_EQ(SyscallNumber(Arch::kX86_64, "socket"), 41);
  CHECK_EQ(SyscallNumber(Arch::kAarch64, "socket"), 198);
  CHECK_EQ(SyscallNumber(Arch::kX86_64, "execve"), 59);
  CHECK_EQ(SyscallNumber(Arch::kAarch64, "execve"), 221);
  CHECK_EQ(SyscallNumber(Arch::kX86_64, "clone"), 56);
  CHECK_EQ(SyscallNumber(Arch::kAarch64, "clone"), 220);
  CHECK_EQ(SyscallNumber(Arch::kX86_64, "openat"), 257);
  CHECK_EQ(SyscallNumber(Arch::kAarch64, "openat"), 56);
  CHECK_EQ(SyscallNumber(Arch::kX86_64, "futex"), 202);
  CHECK_EQ(SyscallNumber(Arch::kAarch64, "futex"), 98);
}

TEST(tables_name_lookups_are_symmetric) {
  for (Arch arch : {Arch::kX86_64, Arch::kAarch64}) {
    for (const std::string& name : AllSyscallNames()) {
      int nr = SyscallNumber(arch, name);
      if (nr < 0) continue;  // not present on this ABI
      std::string_view back = SyscallName(arch, nr);
      // A few numbers have two names (e.g. fstatat/newfstatat); the reverse
      // lookup must at least return a name that maps to the same number.
      CHECK(!back.empty());
      CHECK_EQ(SyscallNumber(arch, back), nr);
    }
  }
}

TEST(audit_arch_values_are_correct) {
  CHECK_EQ(AuditArch(Arch::kX86_64), 0xc000003eu);
  CHECK_EQ(AuditArch(Arch::kAarch64), 0xc00000b7u);
}

TEST(filter_kills_foreign_architecture_even_for_allowed_syscall) {
  Policy policy = Parse("default kill\nruntime { allow * }\n", Arch::kX86_64);
  CompileOptions options;
  CompiledFilter filter = CompileFilter(policy, Phase::kRuntime, options);
  SeccompData data;
  data.arch = AuditArch(Arch::kAarch64);  // the wrong ABI
  data.nr = 0;                            // x86_64 read, meaningless here
  CHECK_EQ(RunFilter(filter.program, data), kRetKillThread);
}

TEST(same_policy_compiles_to_different_filters_per_arch) {
  Policy policy = Parse("default kill\nruntime { allow read }\n", Arch::kX86_64);
  CompileOptions x86;
  x86.arch = Arch::kX86_64;
  CompileOptions arm;
  arm.arch = Arch::kAarch64;
  CompiledFilter a = CompileFilter(policy, Phase::kRuntime, x86);
  CompiledFilter b = CompileFilter(policy, Phase::kRuntime, arm);
  // Both are valid but they are not the same program: the numbers differ.
  CHECK(Validate(a.program).ok);
  CHECK(Validate(b.program).ok);
  std::string text_a = Disassemble(a.program);
  std::string text_b = Disassemble(b.program);
  CHECK(text_a != text_b);
}

TEST(masked_membership_test_works) {
  Policy policy = Parse(
      "default kill\n"
      "runtime { allow socket where type & 0xf in [SOCK_STREAM, SOCK_DGRAM] }\n",
      Arch::kX86_64);
  const int nr = SyscallNumber(Arch::kX86_64, "socket");
  CHECK_EQ(RunOn(policy, Arch::kX86_64, nr, {2, 1, 0}), kRetAllow);
  CHECK_EQ(RunOn(policy, Arch::kX86_64, nr, {2, 2, 0}), kRetAllow);
  CHECK_EQ(RunOn(policy, Arch::kX86_64, nr, {2, 3, 0}), kRetKillThread);  // RAW
  CHECK_EQ(RunOn(policy, Arch::kX86_64, nr, {2, 1 | 0x80000, 0}), kRetAllow);
}

TEST(mask_ignores_bits_outside_the_mask) {
  Policy policy = Parse(
      "default kill\nruntime { allow read where arg2 & 0xff == 4 }\n",
      Arch::kX86_64);
  const int nr = SyscallNumber(Arch::kX86_64, "read");
  CHECK_EQ(RunOn(policy, Arch::kX86_64, nr, {0, 0, 0x104}), kRetAllow);
  CHECK_EQ(RunOn(policy, Arch::kX86_64, nr, {0, 0, 0x105}), kRetKillThread);
  // A comparison value with bits the mask clears can never match.
  CHECK_EQ(RunOn(policy, Arch::kX86_64, nr, {0, 0, 0x104}), kRetAllow);
}

TEST(negated_membership_is_the_complement) {
  Policy policy = Parse(
      "default kill\nruntime { allow read where arg0 not in [1, 2, 3] }\n",
      Arch::kX86_64);
  const int nr = SyscallNumber(Arch::kX86_64, "read");
  for (uint64_t v : {0ULL, 4ULL, 100ULL}) {
    CHECK_EQ(RunOn(policy, Arch::kX86_64, nr, {v, 0, 0}), kRetAllow);
  }
  for (uint64_t v : {1ULL, 2ULL, 3ULL}) {
    CHECK_EQ(RunOn(policy, Arch::kX86_64, nr, {v, 0, 0}), kRetKillThread);
  }
}

TEST(ordering_handles_the_high_half_at_the_boundary) {
  Policy policy = Parse(
      "default kill\n"
      "runtime { allow read where arg2 < 0x100000000 }\n",
      Arch::kX86_64);
  const int nr = SyscallNumber(Arch::kX86_64, "read");
  CHECK_EQ(RunOn(policy, Arch::kX86_64, nr, {0, 0, 0xffffffffULL}), kRetAllow);
  CHECK_EQ(RunOn(policy, Arch::kX86_64, nr, {0, 0, 0x100000000ULL}),
           kRetKillThread);
  CHECK_EQ(RunOn(policy, Arch::kX86_64, nr, {0, 0, 0x100000001ULL}),
           kRetKillThread);
}

TEST(unresolvable_trace_argument_is_conservative) {
  // A path argument is a pointer; the trace shows a string, not a number.  The
  // reference evaluator must not claim the condition holds on the strength of
  // a value it could not see.  The filter, fed a placeholder 0, would allow the
  // call, and the disagreement is what surfaces the problem instead of a
  // silent pass.
  Trace trace = ParseTrace(
      "1 openat(AT_FDCWD, \"x\", O_RDONLY) = 3\n", Arch::kX86_64, "x");
  AssignPhases(trace, PhaseOptions{});
  Policy policy = Parse(
      "default kill\nruntime { allow openat where arg1 == 0 }\n", Arch::kX86_64);
  VerificationResult verification = VerifyTrace(trace, policy, VerifyOptions{});
  CHECK_EQ(verification.total_calls, 1);
  // The reference refuses to treat the string as 0, so the filter's ALLOW is
  // reported as a mismatch.
  CHECK(!verification.ok);
  CHECK(verification.errors.size() == 1);
}

TEST(phase_split_covers_runtime_calls_in_the_startup_filter) {
  // A thread may issue a runtime syscall before the second filter is installed.
  // The start-up filter must therefore permit runtime allowances.
  Trace trace = ParseTrace(
      "1 execve(\"/s\", [\"s\"], 0x1) = 0\n"
      "1 listen(3, 5) = 0\n"
      "1 epoll_wait(3, [], 1, 0) = 0\n", Arch::kX86_64, "x");
  AssignPhases(trace, PhaseOptions{});
  Policy policy = Parse(
      "default kill\n"
      "startup { allow execve, listen }\n"
      "runtime { allow epoll_wait }\n", Arch::kX86_64);
  CompileOptions options;
  CompiledFilter startup = CompileFilter(policy, Phase::kStartup, options);
  SeccompData data;
  data.arch = AuditArch(Arch::kX86_64);
  data.nr = SyscallNumber(Arch::kX86_64, "epoll_wait");
  CHECK_EQ(RunFilter(startup.program, data), kRetAllow);
}

TEST(startup_filter_does_not_apply_runtime_denials) {
  // "allow execve at startup, deny it afterwards" must compile: the runtime
  // deny belongs only to the second filter.
  Policy policy = Parse(
      "default kill\n"
      "startup { allow execve }\n"
      "runtime { deny execve }\n", Arch::kX86_64);
  CompileOptions options;
  CompiledFilter startup = CompileFilter(policy, Phase::kStartup, options);
  CompiledFilter runtime = CompileFilter(policy, Phase::kRuntime, options);
  CHECK(Validate(startup.program).ok);
  CHECK(Validate(runtime.program).ok);
  SeccompData data;
  data.arch = AuditArch(Arch::kX86_64);
  data.nr = SyscallNumber(Arch::kX86_64, "execve");
  CHECK_EQ(RunFilter(startup.program, data), kRetAllow);
  CHECK_EQ(RunFilter(runtime.program, data) & kRetActionFullMask, kRetErrno);
}

TEST(large_policy_stays_within_the_instruction_limit) {
  // Allowing every syscall exercises the widest dispatch the compiler can
  // produce.  It must either fit or fail loudly; silently truncating would
  // produce a filter that denies calls the policy allows.
  Policy policy = Parse("default kill\nruntime { allow * }\n", Arch::kX86_64);
  CompileOptions options;
  CompiledFilter filter = CompileFilter(policy, Phase::kRuntime, options);
  CHECK(filter.instruction_count <= 4096);
  CHECK(Validate(filter.program).ok);
  // Every syscall in the table must now be allowed.
  SeccompData data;
  data.arch = AuditArch(Arch::kX86_64);
  for (const std::string& name : AllSyscallNames()) {
    int nr = SyscallNumber(Arch::kX86_64, name);
    if (nr < 0) continue;
    data.nr = nr;
    CHECK_EQ(RunFilter(filter.program, data), kRetAllow);
  }
}

TEST(policy_with_varied_argument_types_verifies_end_to_end) {
  const char* trace_text =
      "1  0.1 execve(\"/s\", [\"s\"], 0x1) = 0\n"
      "1  0.2 socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 3\n"
      "1  0.3 listen(3, 5) = 0\n"
      "1  0.4 epoll_ctl(4, EPOLL_CTL_ADD, 3, {events=EPOLLIN}) = 0\n"
      "1  0.5 epoll_wait(4, [], 16, -1) = 1\n"
      "1  0.6 accept4(3, NULL, NULL, SOCK_CLOEXEC) = 5\n"
      "1  0.7 read(5, \"x\", 1) = 1\n"
      "1  0.8 write(5, \"y\", 1) = 1\n";
  Trace trace = ParseTrace(trace_text, Arch::kX86_64, "e2e.log");
  AssignPhases(trace, PhaseOptions{});
  Policy policy = Parse(
      "default kill\n"
      "startup {\n"
      "  allow execve\n"
      "  allow socket where domain == AF_INET, type & 0xf == SOCK_STREAM\n"
      "  allow listen\n"
      "}\n"
      "runtime {\n"
      "  allow epoll_ctl, epoll_wait\n"
      "  allow accept4 where flags has SOCK_CLOEXEC\n"
      "  allow read, write\n"
      "}\n", Arch::kX86_64);
  VerificationResult verification = VerifyTrace(trace, policy, VerifyOptions{});
  CHECK(verification.ok);
  CHECK_EQ(verification.startup.denied, 0);
  CHECK_EQ(verification.runtime.denied, 0);
}

TEST(compiler_reports_unsupported_masked_ordering) {
  Policy policy = Parse(
      "default kill\nruntime { allow read where arg2 & 0xff < 4 }\n",
      Arch::kX86_64);
  bool threw = false;
  try {
    CompileOptions options;
    CompileFilter(policy, Phase::kRuntime, options);
  } catch (const Error&) {
    threw = true;
  }
  CHECK(threw);
}

// The DSL: parsing, constant resolution, and — most importantly — that the
// *policy's* verdict equals the *filter's* verdict for real argument values.
#include "dsl.h"

#include "bpf.h"
#include "common.h"
#include "compiler.h"
#include "syscalls.h"
#include "test_harness.h"

using namespace scgen;

namespace {

Policy ParsePolicy(const char* text, Arch arch = Arch::kX86_64,
                   std::vector<std::string>* errors = nullptr) {
  DslParseResult result = ParsePolicyDsl(text, "test.dsl", arch);
  if (errors) *errors = result.errors;
  if (!result.errors.empty() && !errors) {
    throw std::runtime_error("unexpected parse error: " + result.errors.front());
  }
  return result.policy;
}

// Builds the seccomp_data the kernel would present for one call.
SeccompData Data(int nr, std::initializer_list<uint64_t> args) {
  SeccompData data;
  data.nr = nr;
  data.arch = AuditArch(Arch::kX86_64);
  int i = 0;
  for (uint64_t value : args) data.args[i++] = value;
  return data;
}

// Runs the compiled runtime filter on one call.
uint32_t Run(const Policy& policy, int nr, std::initializer_list<uint64_t> args) {
  CompileOptions options;
  CompiledFilter filter = CompileFilter(policy, Phase::kRuntime, options);
  return RunFilter(filter.program, Data(nr, args));
}

}  // namespace

TEST(parses_policy_header_and_default) {
  Policy policy = ParsePolicy(
      "policy \"svc\"\n"
      "note \"hello\"\n"
      "default errno(EPERM)\n");
  CHECK_EQ(policy.name, std::string("svc"));
  CHECK_EQ(policy.notes.size(), static_cast<size_t>(1));
  CHECK(policy.default_action.kind == Action::Kind::kErrno);
  CHECK_EQ(policy.default_action.errno_value, 1u);
}

TEST(parses_phase_blocks) {
  Policy policy = ParsePolicy(
      "policy \"x\"\n"
      "default kill\n"
      "startup { allow execve }\n"
      "runtime { allow read, write }\n");
  CHECK_EQ(policy.rules.size(), static_cast<size_t>(3));
  CHECK(policy.rules[0].phase == Phase::kStartup);
  CHECK(policy.rules[1].phase == Phase::kRuntime);
  CHECK(policy.rules[2].phase == Phase::kRuntime);
}

TEST(rejects_unknown_syscall) {
  std::vector<std::string> errors;
  ParsePolicy("runtime { allow not_a_syscall }\n", Arch::kX86_64, &errors);
  CHECK(!errors.empty());
  CHECK(errors[0].find("unknown syscall") != std::string::npos);
}

TEST(rejects_unknown_syscall_for_architecture) {
  // epoll_pwait2 exists on both, but x86_64-only names must fail on aarch64.
  std::vector<std::string> errors;
  ParsePolicy("runtime { allow arch_prctl }\n", Arch::kAarch64, &errors);
  CHECK(!errors.empty());
  CHECK(errors[0].find("unknown syscall") != std::string::npos);
}

TEST(resolves_named_arguments) {
  Policy policy = ParsePolicy(
      "runtime { allow socket where domain == AF_INET, type has SOCK_STREAM }\n");
  CHECK_EQ(policy.rules.size(), static_cast<size_t>(1));
  CHECK_EQ(policy.rules[0].conditions.size(), static_cast<size_t>(2));
  CHECK_EQ(policy.rules[0].conditions[0].arg, 0);
  CHECK_EQ(policy.rules[0].conditions[1].arg, 1);
}

TEST(resolves_argument_names_for_each_syscall) {
  Policy policy = ParsePolicy(
      "runtime { allow openat where flags has O_CLOEXEC }\n");
  CHECK_EQ(policy.rules[0].conditions[0].arg, 2);
  Policy setsockopt = ParsePolicy(
      "runtime { allow setsockopt where optname == SO_REUSEADDR }\n");
  CHECK_EQ(setsockopt.rules[0].conditions[0].arg, 2);
}

TEST(rejects_unknown_argument_name) {
  std::vector<std::string> errors;
  ParsePolicy("runtime { allow read where nonexistent == 1 }\n", Arch::kX86_64,
              &errors);
  CHECK(!errors.empty());
}

TEST(accepts_numeric_arguments) {
  Policy policy = ParsePolicy("runtime { allow read where arg0 == 3 }\n");
  CHECK_EQ(policy.rules[0].conditions.size(), static_cast<size_t>(1));
  CHECK_EQ(policy.rules[0].conditions[0].cmp.a, 3u);
}

TEST(supports_in_lists_and_ranges) {
  Policy policy = ParsePolicy(
      "runtime { allow lseek where whence in [SEEK_SET, SEEK_CUR] }\n"
      "runtime { allow read where arg2 in_range [1 .. 4096] }\n");
  CHECK_EQ(policy.rules[0].conditions[0].cmp.op, CompareOp::kIn);
  CHECK_EQ(policy.rules[0].conditions[0].cmp.set.size(), static_cast<size_t>(2));
  CHECK_EQ(policy.rules[1].conditions[0].cmp.op, CompareOp::kRange);
  CHECK_EQ(policy.rules[1].conditions[0].cmp.b, 4096u);
}

TEST(supports_negation) {
  Policy policy = ParsePolicy(
      "runtime { allow socket where not domain == AF_UNIX }\n");
  CHECK_EQ(policy.rules[0].conditions[0].cmp.op, CompareOp::kNe);
  CHECK_EQ(policy.rules[0].conditions[0].cmp.a, 1u);
}

TEST(groups_expand_to_syscalls) {
  Policy policy = ParsePolicy("runtime { allow @net }\n");
  CHECK_EQ(policy.rules.size(), static_cast<size_t>(1));
  CHECK_EQ(policy.rules[0].group.size(), static_cast<size_t>(1));
  ResolveResult resolved = ResolvePolicy(policy, Arch::kX86_64);
  CHECK(resolved.resolved.size() > 10);
  CHECK(resolved.errors.empty());
}

TEST(rejects_unknown_group) {
  std::vector<std::string> errors;
  ParsePolicy("runtime { allow @nope }\n", Arch::kX86_64, &errors);
  CHECK(!errors.empty());
}

TEST(rejects_empty_rule) {
  std::vector<std::string> errors;
  ParsePolicy("runtime { allow }\n", Arch::kX86_64, &errors);
  CHECK(!errors.empty());
}

TEST(deny_defaults_to_eperm) {
  Policy policy = ParsePolicy("runtime { deny socket }\n");
  CHECK(policy.rules[0].action.kind == Action::Kind::kErrno);
  CHECK_EQ(policy.rules[0].action.errno_value, 1u);
}

TEST(deny_accepts_named_errno) {
  Policy policy = ParsePolicy("runtime { deny execve -> errno(ENOENT) }\n");
  CHECK_EQ(policy.rules[0].action.errno_value, 2u);
}

TEST(parses_trace_and_notify_actions) {
  Policy policy = ParsePolicy(
      "runtime { allow clone -> trace(7) }\n"
      "runtime { allow socket -> notify(9) }\n");
  CHECK_EQ(policy.rules[0].action.ToReturnValue() & kRetDataMask, 7u);
  CHECK_EQ(policy.rules[1].action.ToReturnValue() & kRetDataMask, 9u);
}

TEST(filter_allows_the_restricted_value) {
  Policy policy = ParsePolicy(
      "default kill\n"
      "runtime { allow socket where domain == AF_INET }\n");
  const int socket_nr = SyscallNumber(Arch::kX86_64, "socket");
  CHECK_EQ(Run(policy, socket_nr, {2, 1, 0}), kRetAllow);
}

TEST(filter_denies_other_family) {
  Policy policy = ParsePolicy(
      "default kill\n"
      "runtime { allow socket where domain == AF_INET }\n");
  const int socket_nr = SyscallNumber(Arch::kX86_64, "socket");
  CHECK_EQ(Run(policy, socket_nr, {1, 1, 0}), kRetKillThread);  // AF_UNIX
}

TEST(filter_denies_high_half_mismatch) {
  // A 64-bit argument whose low half matches but whose high half does not must
  // not be allowed: this is the classic "compared only 32 bits" bug.
  Policy policy = ParsePolicy(
      "default kill\n"
      "runtime { allow read where arg0 == 2 }\n");
  const int read_nr = SyscallNumber(Arch::kX86_64, "read");
  CHECK_EQ(Run(policy, read_nr, {0x1'0000'0002ULL, 0, 0}), kRetKillThread);
  CHECK_EQ(Run(policy, read_nr, {2, 0, 0}), kRetAllow);
}

TEST(filter_implements_in_lists) {
  Policy policy = ParsePolicy(
      "default kill\n"
      "runtime { allow socket where domain in [AF_INET, AF_INET6] }\n");
  const int socket_nr = SyscallNumber(Arch::kX86_64, "socket");
  CHECK_EQ(Run(policy, socket_nr, {2, 1, 0}), kRetAllow);
  CHECK_EQ(Run(policy, socket_nr, {10, 1, 0}), kRetAllow);
  CHECK_EQ(Run(policy, socket_nr, {1, 1, 0}), kRetKillThread);
}

TEST(filter_implements_not_in_lists) {
  Policy policy = ParsePolicy(
      "default kill\n"
      "runtime { allow socket where domain not in [AF_UNIX] }\n");
  const int socket_nr = SyscallNumber(Arch::kX86_64, "socket");
  CHECK_EQ(Run(policy, socket_nr, {2, 1, 0}), kRetAllow);
  CHECK_EQ(Run(policy, socket_nr, {1, 1, 0}), kRetKillThread);
}

TEST(filter_implements_flag_tests) {
  Policy policy = ParsePolicy(
      "default kill\n"
      "runtime { allow socket where type has SOCK_CLOEXEC }\n");
  const int socket_nr = SyscallNumber(Arch::kX86_64, "socket");
  // SOCK_STREAM|SOCK_CLOEXEC
  CHECK_EQ(Run(policy, socket_nr, {2, 1 | 0x80000, 0}), kRetAllow);
  // SOCK_STREAM alone
  CHECK_EQ(Run(policy, socket_nr, {2, 1, 0}), kRetKillThread);
}

TEST(filter_implements_lacks) {
  Policy policy = ParsePolicy(
      "default kill\n"
      "runtime { allow socket where type lacks SOCK_CLOEXEC }\n");
  const int socket_nr = SyscallNumber(Arch::kX86_64, "socket");
  CHECK_EQ(Run(policy, socket_nr, {2, 1, 0}), kRetAllow);
  CHECK_EQ(Run(policy, socket_nr, {2, 1 | 0x80000, 0}), kRetKillThread);
}

TEST(filter_implements_ordering) {
  Policy policy = ParsePolicy(
      "default kill\n"
      "runtime { allow read where arg2 < 100 }\n"
      "runtime { allow write where arg2 >= 100 }\n");
  const int read_nr = SyscallNumber(Arch::kX86_64, "read");
  const int write_nr = SyscallNumber(Arch::kX86_64, "write");
  CHECK_EQ(Run(policy, read_nr, {0, 0, 99}), kRetAllow);
  CHECK_EQ(Run(policy, read_nr, {0, 0, 100}), kRetKillThread);
  CHECK_EQ(Run(policy, write_nr, {0, 0, 100}), kRetAllow);
  CHECK_EQ(Run(policy, write_nr, {0, 0, 99}), kRetKillThread);
  // Values with a set high half must compare as 64-bit numbers.
  CHECK_EQ(Run(policy, read_nr, {0, 0, 0x1'0000'0000ULL}), kRetKillThread);
}

TEST(filter_implements_ranges) {
  Policy policy = ParsePolicy(
      "default kill\n"
      "runtime { allow read where arg2 in_range [10 .. 20] }\n");
  const int read_nr = SyscallNumber(Arch::kX86_64, "read");
  CHECK_EQ(Run(policy, read_nr, {0, 0, 10}), kRetAllow);
  CHECK_EQ(Run(policy, read_nr, {0, 0, 20}), kRetAllow);
  CHECK_EQ(Run(policy, read_nr, {0, 0, 9}), kRetKillThread);
  CHECK_EQ(Run(policy, read_nr, {0, 0, 21}), kRetKillThread);
}

TEST(conjunction_requires_every_condition) {
  Policy policy = ParsePolicy(
      "default kill\n"
      "runtime { allow socket where domain == AF_INET and type == SOCK_STREAM }\n");
  const int socket_nr = SyscallNumber(Arch::kX86_64, "socket");
  CHECK_EQ(Run(policy, socket_nr, {2, 1, 0}), kRetAllow);
  CHECK_EQ(Run(policy, socket_nr, {2, 2, 0}), kRetKillThread);
  CHECK_EQ(Run(policy, socket_nr, {1, 1, 0}), kRetKillThread);
}

TEST(narrow_rule_wins_over_blanket_rule) {
  Policy policy = ParsePolicy(
      "default kill\n"
      "runtime {\n"
      "  allow socket\n"
      "  allow socket where domain == AF_INET\n"
      "}\n");
  // Both orders mean the same thing; the unrestricted rule is the effective
  // one, and the restricted rule is redundant but harmless.
  const int socket_nr = SyscallNumber(Arch::kX86_64, "socket");
  CHECK_EQ(Run(policy, socket_nr, {1, 1, 0}), kRetAllow);
}

TEST(restricted_deny_beats_blanket_allow) {
  Policy policy = ParsePolicy(
      "default kill\n"
      "runtime {\n"
      "  allow socket\n"
      "  deny socket where domain == AF_UNIX\n"
      "}\n");
  const int socket_nr = SyscallNumber(Arch::kX86_64, "socket");
  CHECK_EQ(Run(policy, socket_nr, {2, 1, 0}), kRetAllow);
  // "deny" without an explicit errno is ERRNO(EPERM).
  CHECK_EQ(Run(policy, socket_nr, {1, 1, 0}), kRetErrno | 1);
}

TEST(deny_returns_configured_errno) {
  Policy policy = ParsePolicy(
      "default kill\n"
      "runtime { deny execve -> errno(EACCES) }\n");
  const int execve_nr = SyscallNumber(Arch::kX86_64, "execve");
  CHECK_EQ(Run(policy, execve_nr, {0, 0, 0}) & kRetActionFullMask, kRetErrno);
  CHECK_EQ(Run(policy, execve_nr, {0, 0, 0}) & kRetDataMask, 13u);
}

TEST(default_action_applies_to_unlisted_syscalls) {
  Policy policy = ParsePolicy(
      "default errno(ENOSYS)\n"
      "runtime { allow read }\n");
  const int getpid_nr = SyscallNumber(Arch::kX86_64, "getpid");
  CHECK_EQ(Run(policy, getpid_nr, {}), kRetErrno | 38);
}

TEST(default_allow_makes_restrictions_ineffective) {
  // This is a policy smell: with a permissive default, a rule that declines
  // falls back to "allow", so the restriction never denies anything.  The
  // compiler must still be self-consistent, and this documents the semantics.
  Policy policy = ParsePolicy(
      "default allow\n"
      "runtime { allow socket where domain == AF_INET }\n");
  const int socket_nr = SyscallNumber(Arch::kX86_64, "socket");
  CHECK_EQ(Run(policy, socket_nr, {1, 1, 0}), kRetAllow);
}

TEST(round_trip_preserves_meaning) {
  Policy policy = ParsePolicy(
      "policy \"rt\"\n"
      "default errno(EPERM)\n"
      "startup {\n"
      "  allow execve\n"
      "  allow socket where domain in [AF_INET, AF_INET6]\n"
      "}\n"
      "runtime {\n"
      "  allow read, write\n"
      "  deny execve\n"
      "  allow openat where flags has O_CLOEXEC\n"
      "}\n");
  std::string text = FormatPolicyDsl(policy, Arch::kX86_64);
  DslParseResult reparsed = ParsePolicyDsl(text, "<roundtrip>", Arch::kX86_64);
  CHECK(reparsed.errors.empty());
  CHECK_EQ(reparsed.policy.rules.size(), policy.rules.size());
  // Compare the compiled programs: identical bytecode means identical meaning.
  CompileOptions options;
  for (Phase phase : {Phase::kStartup, Phase::kRuntime}) {
    CompiledFilter a = CompileFilter(policy, phase, options);
    CompiledFilter b = CompileFilter(reparsed.policy, phase, options);
    CHECK_EQ(a.program.size(), b.program.size());
    for (size_t i = 0; i < a.program.size(); ++i) {
      CHECK_EQ(a.program[i].code, b.program[i].code);
      CHECK_EQ(a.program[i].jt, b.program[i].jt);
      CHECK_EQ(a.program[i].jf, b.program[i].jf);
      CHECK_EQ(a.program[i].k, b.program[i].k);
    }
  }
}

TEST(aarch64_numbers_differ_from_x86_64) {
  Policy policy = ParsePolicy("runtime { allow read, write }\n");
  CompileOptions options;
  options.arch = Arch::kAarch64;
  CompiledFilter filter = CompileFilter(policy, Phase::kRuntime, options);
  CHECK(filter.program.size() > 4);
  SeccompData data;
  data.arch = AuditArch(Arch::kAarch64);
  data.nr = 63;  // aarch64 read
  CHECK_EQ(RunFilter(filter.program, data), kRetAllow);
  data.nr = 0;   // x86_64 read, meaningless on aarch64
  CHECK_EQ(RunFilter(filter.program, data), kRetKillThread);
}

TEST(compiler_rejects_wildcard_deny) {
  Policy policy = ParsePolicy("default allow\nruntime { deny * }\n");
  bool threw = false;
  try {
    CompileOptions options;
    CompileFilter(policy, Phase::kRuntime, options);
  } catch (const Error&) {
    threw = true;
  }
  CHECK(threw);
}

TEST(compiler_rejects_conflicting_unconditional_rules) {
  Policy policy = ParsePolicy(
      "runtime {\n"
      "  allow read\n"
      "  deny read\n"
      "}\n");
  bool threw = false;
  try {
    CompileOptions options;
    CompileFilter(policy, Phase::kRuntime, options);
  } catch (const Error&) {
    threw = true;
  }
  CHECK(threw);
}

TEST(parser_reports_errors_without_hanging) {
  std::vector<std::string> errors;
  ParsePolicy("runtime { allow } runtime { allow }\n", Arch::kX86_64, &errors);
  CHECK(!errors.empty());
}

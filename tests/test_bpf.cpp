// BPF: encoding round-trips, label resolution, validation rules and the
// interpreter.  Each filter here is small enough to reason about by hand.
#include <cstring>

#include "bpf.h"
#include "common.h"
#include "syscalls.h"
#include "test_harness.h"

using namespace scgen;

namespace {

SeccompData MakeData(int nr, uint64_t a0 = 0, uint64_t a1 = 0, uint64_t a2 = 0,
                     uint64_t a3 = 0) {
  SeccompData data;
  data.nr = nr;
  data.arch = AuditArch(Arch::kX86_64);
  data.args[0] = a0;
  data.args[1] = a1;
  data.args[2] = a2;
  data.args[3] = a3;
  return data;
}

// Builds: if arch != x86_64 kill; if nr == 1 allow; else kill.
std::vector<Instruction> SimpleAllowNr1() {
  Assembler as;
  as.LdAbs(kSeccompDataArchOffset);
  as.JmpK(kJeq, AuditArch(Arch::kX86_64), "ok", "bad");
  as.Bind("bad");
  as.RetK(kRetKillThread);
  as.Bind("ok");
  as.LdAbs(kSeccompDataNrOffset);
  as.JmpK(kJeq, 1, "allow", "deny");
  as.Bind("allow");
  as.RetK(kRetAllow);
  as.Bind("deny");
  as.RetK(kRetErrno | 13);
  return as.Finalize();
}

}  // namespace

TEST(interpreter_allows_matching_syscall) {
  auto program = SimpleAllowNr1();
  CHECK_EQ(RunFilter(program, MakeData(1)), kRetAllow);
}

TEST(interpreter_applies_errno_for_other_syscall) {
  auto program = SimpleAllowNr1();
  CHECK_EQ(RunFilter(program, MakeData(2)), kRetErrno | 13);
}

TEST(interpreter_kills_foreign_architecture) {
  auto program = SimpleAllowNr1();
  SeccompData data = MakeData(1);
  data.arch = 0x40000003;  // EM_386 as seccomp sees it
  CHECK_EQ(RunFilter(program, data), kRetKillThread);
}

TEST(interpreter_compares_64_bit_arguments) {
  // allow if arg0 == 0x1'0000'0001, else kill.  Exercises the split into two
  // 32-bit halves: the value's high half is 1, so a filter that only looked at
  // the low half would match 0x1 as well.
  Assembler as;
  as.LdAbs(kSeccompDataArgOffset + 4);
  as.JmpK(kJeq, 1, "lo", "deny");
  as.Bind("lo");
  as.LdAbs(kSeccompDataArgOffset);
  as.JmpK(kJeq, 1, "allow", "deny");
  as.Bind("allow");
  as.RetK(kRetAllow);
  as.Bind("deny");
  as.RetK(kRetKillThread);
  auto program = as.Finalize();

  CHECK_EQ(RunFilter(program, MakeData(0, 0x100000001ULL)), kRetAllow);
  CHECK_EQ(RunFilter(program, MakeData(0, 1ULL)), kRetKillThread);
  CHECK_EQ(RunFilter(program, MakeData(0, 0x200000001ULL)), kRetKillThread);
}

TEST(interpreter_handles_bit_mask_tests) {
  // allow if (arg0 & (SOCK_CLOEXEC)) != 0: JSET semantics via AND+JEQ.
  constexpr uint64_t kFlag = 0x80000;
  Assembler as;
  as.LdAbs(kSeccompDataArgOffset);
  as.AluK(kAnd, static_cast<uint32_t>(kFlag));
  as.JmpK(kJeq, static_cast<uint32_t>(kFlag), "allow", "deny");
  as.Bind("allow");
  as.RetK(kRetAllow);
  as.Bind("deny");
  as.RetK(kRetKillThread);
  auto program = as.Finalize();
  CHECK_EQ(RunFilter(program, MakeData(0, kFlag | 1)), kRetAllow);
  CHECK_EQ(RunFilter(program, MakeData(0, kFlag)), kRetAllow);
  CHECK_EQ(RunFilter(program, MakeData(0, 1)), kRetKillThread);
}

TEST(assembler_inserts_trampolines_for_long_jumps) {
  // A conditional jump over more than 255 instructions must still target the
  // right place.  Build allow-if-nr==1 where the "allow" block is far away.
  Assembler as;
  as.LdAbs(kSeccompDataNrOffset);
  as.JmpK(kJeq, 1, "allow", "far");
  as.Bind("far");
  // 300 filler instructions, each provably harmless.
  for (int i = 0; i < 300; ++i) as.LdAbs(kSeccompDataNrOffset);
  as.Ja("deny");
  as.Bind("allow");
  as.RetK(kRetAllow);
  as.Bind("deny");
  as.RetK(kRetKillThread);
  auto program = as.Finalize();
  CHECK(static_cast<int>(program.size()) > 300);
  CHECK_EQ(RunFilter(program, MakeData(1)), kRetAllow);
  CHECK_EQ(RunFilter(program, MakeData(2)), kRetKillThread);
  // The trampoline must not shift the target: an off-by-one here is exactly
  // the bug this test exists to catch.
  CHECK_EQ(RunFilter(program, MakeData(1)), kRetAllow);
}

TEST(assembler_rejects_undefined_label) {
  Assembler as;
  as.LdAbs(0);
  as.JmpK(kJeq, 1, "nowhere", "somewhere");
  as.Bind("somewhere");
  as.RetK(kRetAllow);
  bool threw = false;
  try {
    as.Finalize();
  } catch (const Error&) {
    threw = true;
  }
  CHECK(threw);
}

TEST(assembler_rejects_backward_label) {
  Assembler as;
  as.Bind("loop");
  as.LdAbs(0);
  as.Ja("loop");
  bool threw = false;
  try {
    as.Finalize();
  } catch (const Error&) {
    threw = true;
  }
  CHECK(threw);
}

TEST(validator_rejects_program_without_return) {
  std::vector<Instruction> program{insn::LdAbs(0)};
  ValidationResult result = Validate(program);
  CHECK(!result.ok);
  CHECK(result.message.find("falls off the end") != std::string::npos);
}

TEST(validator_rejects_load_outside_seccomp_data) {
  std::vector<Instruction> program{insn::LdAbs(64), insn::RetK(kRetAllow)};
  ValidationResult result = Validate(program);
  CHECK(!result.ok);
  CHECK(result.message.find("outside struct seccomp_data") != std::string::npos);
}

TEST(validator_rejects_errno_above_limit) {
  std::vector<Instruction> program{insn::RetK(kRetErrno | 5000)};
  ValidationResult result = Validate(program);
  CHECK(!result.ok);
}

TEST(validator_rejects_unknown_action) {
  std::vector<Instruction> program{insn::RetK(0x12340000)};
  ValidationResult result = Validate(program);
  CHECK(!result.ok);
}

TEST(validator_rejects_unreachable_code) {
  std::vector<Instruction> program{insn::RetK(kRetAllow), insn::RetK(kRetKillThread)};
  ValidationResult result = Validate(program);
  CHECK(!result.ok);
  CHECK(result.message.find("unreachable") != std::string::npos);
}

TEST(validator_accepts_generated_programs) {
  auto program = SimpleAllowNr1();
  ValidationResult result = Validate(program);
  CHECK(result.ok);
  CHECK_EQ(result.max_stack_slot, -1);
}

TEST(disassembly_is_stable_and_descriptive) {
  auto program = SimpleAllowNr1();
  std::string text = Disassemble(program);
  CHECK(text.find("ld [arch]") != std::string::npos);
  CHECK(text.find("ret ALLOW") != std::string::npos);
  CHECK(text.find("ret ERRNO(13)") != std::string::npos);
}

TEST(c_initializer_matches_program) {
  auto program = SimpleAllowNr1();
  std::string text = ToCInitializer(program);
  // One line per instruction, each an initializer with the encoded fields.
  size_t lines = 0;
  for (char c : text) lines += (c == '\n');
  CHECK_EQ(static_cast<int>(lines), static_cast<int>(program.size()));
  CHECK(text.find("0x0006") != std::string::npos);  // a RET encoding
}

TEST(interpreter_rejects_invalid_program) {
  std::vector<Instruction> program{insn::LdAbs(0)};
  bool threw = false;
  try {
    RunFilter(program, MakeData(1));
  } catch (const Error&) {
    threw = true;
  }
  CHECK(threw);
}

// The encoding constants are copied by hand from include/uapi/linux/filter.h
// and seccomp.h; if one drifts the generated filter would be silently wrong,
// so pin them against the kernel's values.
TEST(encoding_constants_match_the_kernel_headers) {
  CHECK_EQ(static_cast<uint16_t>(kLd | kW | kAbs), 0x20);
  CHECK_EQ(static_cast<uint16_t>(kLd | kW | kImm), 0x00);
  CHECK_EQ(static_cast<uint16_t>(kSt), 0x02);
  CHECK_EQ(static_cast<uint16_t>(kAlu | kAdd | kK), 0x04);
  CHECK_EQ(static_cast<uint16_t>(kAlu | kAnd | kK), 0x54);
  CHECK_EQ(static_cast<uint16_t>(kJmp | kJeq | kK), 0x15);
  CHECK_EQ(static_cast<uint16_t>(kJmp | kJgt | kK), 0x25);
  CHECK_EQ(static_cast<uint16_t>(kJmp | kJge | kK), 0x35);
  CHECK_EQ(static_cast<uint16_t>(kJmp | kJset | kK), 0x45);
  CHECK_EQ(static_cast<uint16_t>(kJmp | kJa), 0x05);
  CHECK_EQ(static_cast<uint16_t>(kRet | kRetK), 0x06);
  CHECK_EQ(static_cast<uint16_t>(kMisc | kTax), 0x07);
  CHECK_EQ(static_cast<uint16_t>(kMisc | kTxa), 0x87);

  CHECK_EQ(kRetAllow, 0x7fff0000u);
  CHECK_EQ(kRetKillThread, 0x00000000u);
  CHECK_EQ(kRetKillProcess, 0x80000000u);
  CHECK_EQ(kRetTrap, 0x00030000u);
  CHECK_EQ(kRetErrno, 0x00050000u);
  CHECK_EQ(kRetTrace, 0x7ff00000u);
  CHECK_EQ(kRetLog, 0x7ffc0000u);
  CHECK_EQ(kRetUserNotif, 0x7fc00000u);

  // struct seccomp_data: int nr; __u32 arch; __u64 ip; __u64 args[6];
  CHECK_EQ(kSeccompDataNrOffset, 0u);
  CHECK_EQ(kSeccompDataArchOffset, 4u);
  CHECK_EQ(kSeccompDataIpOffset, 8u);
  CHECK_EQ(kSeccompDataArgOffset, 16u);
  CHECK_EQ(kSeccompDataSize, 64u);
}

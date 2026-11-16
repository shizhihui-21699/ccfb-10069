// A self-contained model of classic BPF as used by seccomp.
//
// This header provides:
//   * the instruction encoding Linux expects (struct sock_filter semantics),
//   * an assembler with symbolic labels that relaxes out-of-range conditional
//     jumps by inserting JA trampolines,
//   * a validator that rejects programs the kernel's verifier would reject
//     (backward jumps, out-of-range targets, missing return, ...),
//   * an interpreter over struct seccomp_data, used by the policy verifier.
//
// The interpreter is intentionally independent of the compiler: the compiler
// emits instructions, the interpreter executes them, and the verifier compares
// the result against the DSL's own semantics.  A bug in either side shows up
// as a mismatch rather than passing silently.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace scgen {

// ---------------------------------------------------------------------------
// seccomp_data layout (include/uapi/linux/seccomp.h)
// ---------------------------------------------------------------------------

struct SeccompData {
  int32_t nr = 0;
  uint32_t arch = 0;
  uint64_t instruction_pointer = 0;
  uint64_t args[6] = {0, 0, 0, 0, 0, 0};
};

constexpr uint32_t kSeccompDataNrOffset = 0;
constexpr uint32_t kSeccompDataArchOffset = 4;
constexpr uint32_t kSeccompDataIpOffset = 8;
constexpr uint32_t kSeccompDataArgOffset = 16;
constexpr uint32_t kSeccompDataSize = 64;

// ---------------------------------------------------------------------------
// Return values
// ---------------------------------------------------------------------------

constexpr uint32_t kRetKillThread = 0x00000000u;
constexpr uint32_t kRetTrap = 0x00030000u;
constexpr uint32_t kRetErrno = 0x00050000u;
constexpr uint32_t kRetUserNotif = 0x7fc00000u;
constexpr uint32_t kRetTrace = 0x7ff00000u;
constexpr uint32_t kRetLog = 0x7ffc0000u;
constexpr uint32_t kRetAllow = 0x7fff0000u;
constexpr uint32_t kRetKillProcess = 0x80000000u;
constexpr uint32_t kRetActionFullMask = 0xffff0000u;
constexpr uint32_t kRetDataMask = 0x0000ffffu;
constexpr uint32_t kMaxErrno = 4095;
constexpr uint32_t kMaxTraceData = 0xffff;

std::string_view ActionName(uint32_t action);  // "ALLOW", "ERRNO(1)", ...
std::string ActionDescription(uint32_t action);

// ---------------------------------------------------------------------------
// Instructions
// ---------------------------------------------------------------------------

enum BpfClass : uint16_t {
  kLd = 0x00,
  kLdx = 0x01,
  kSt = 0x02,
  kStx = 0x03,
  kAlu = 0x04,
  kJmp = 0x05,
  kRet = 0x06,
  kMisc = 0x07,
};

enum BpfSize : uint16_t { kW = 0x00, kH = 0x08, kB = 0x10 };
enum BpfMode : uint16_t {
  kImm = 0x00,
  kAbs = 0x20,
  kInd = 0x40,
  kMem = 0x60,
  kLen = 0x80,
  kMsh = 0xa0,
};
enum BpfAluOp : uint16_t {
  kAdd = 0x00,
  kSub = 0x10,
  kMul = 0x20,
  kDiv = 0x30,
  kOr = 0x40,
  kAnd = 0x50,
  kLsh = 0x60,
  kRsh = 0x70,
  kNeg = 0x80,
  kMod = 0x90,
  kXor = 0xa0,
};
enum BpfJmpOp : uint16_t { kJa = 0x00, kJeq = 0x10, kJgt = 0x20, kJge = 0x30, kJset = 0x40 };
enum BpfSrc : uint16_t { kK = 0x00, kX = 0x08 };
enum BpfRetOp : uint16_t { kRetK = 0x00, kRetA = 0x10 };
enum BpfMiscOp : uint16_t { kTax = 0x00, kTxa = 0x80 };

struct Instruction {
  uint16_t code = 0;
  uint8_t jt = 0;
  uint8_t jf = 0;
  uint32_t k = 0;

  // Filled in only while assembling; cleared on finalize().
  std::string jt_label;
  std::string jf_label;

  bool has_labels() const { return !jt_label.empty() || !jf_label.empty(); }
};

// Convenience constructors for the instructions the compiler emits.
namespace insn {
Instruction LdAbs(uint32_t offset);                 // BPF_LD|BPF_W|BPF_ABS
Instruction LdImm(uint32_t value);                  // BPF_LD|BPF_IMM
Instruction LdMem(uint32_t slot);                   // BPF_LD|BPF_MEM
Instruction LdLen();                                // BPF_LD|BPF_LEN
Instruction StMem(uint32_t slot);                   // BPF_ST
Instruction AluK(BpfAluOp op, uint32_t value);      // BPF_ALU|op|BPF_K
Instruction AluX(BpfAluOp op);                      // BPF_ALU|op|BPF_X
Instruction JmpK(BpfJmpOp op, uint32_t value);      // BPF_JMP|op|BPF_K
Instruction JmpA(uint32_t offset);                  // BPF_JMP|BPF_JA
Instruction JmpLabel(BpfJmpOp op, uint32_t value, std::string true_label,
                     std::string false_label);
Instruction JaLabel(std::string target);
Instruction JmpX(BpfJmpOp op);                      // BPF_JMP|op|BPF_X
Instruction RetK(uint32_t value);                   // BPF_RET|BPF_K
Instruction RetA();                                 // BPF_RET|BPF_A
Instruction Tax();                                  // BPF_MISC|BPF_TAX
Instruction Txa();                                  // BPF_MISC|BPF_TXA
}  // namespace insn

// ---------------------------------------------------------------------------
// Assembler
// ---------------------------------------------------------------------------

class Assembler {
 public:
  void Bind(std::string label);            // attach label to the next insn
  void Emit(const Instruction& insn);

  void LdAbs(uint32_t offset) { Emit(insn::LdAbs(offset)); }
  void LdImm(uint32_t value) { Emit(insn::LdImm(value)); }
  void LdMem(uint32_t slot) { Emit(insn::LdMem(slot)); }
  void StMem(uint32_t slot) { Emit(insn::StMem(slot)); }
  void AluK(BpfAluOp op, uint32_t value) { Emit(insn::AluK(op, value)); }
  void AluX(BpfAluOp op) { Emit(insn::AluX(op)); }
  void JmpK(BpfJmpOp op, uint32_t value, std::string true_label,
            std::string false_label);
  void Ja(std::string label);
  void RetK(uint32_t value) { Emit(insn::RetK(value)); }
  void RetA() { Emit(insn::RetA()); }
  void Tax() { Emit(insn::Tax()); }
  void Txa() { Emit(insn::Txa()); }

  int InstructionCount() const { return static_cast<int>(program_.size()); }

  // Resolves all labels, inserts jump trampolines where a conditional target
  // is farther than 255 instructions, and returns the final program.
  // Throws Error on undefined labels or empty programs.
  std::vector<Instruction> Finalize();

 private:
  std::vector<Instruction> program_;
  std::vector<std::pair<std::string, int>> labels_;
};

// ---------------------------------------------------------------------------
// Validation and execution
// ---------------------------------------------------------------------------

struct ValidationResult {
  bool ok = true;
  std::string message;      // first problem found
  int instruction = -1;     // index of the offending instruction
  int max_jump_distance = 0;
  int max_stack_slot = -1;
};

// Checks the structural rules the kernel's cBPF verifier applies for seccomp:
// forward-only jumps, targets in range, every path ends in RET, memory access
// only inside the 16-slot scratch space, and a valid action in every RET.
ValidationResult Validate(const std::vector<Instruction>& program);

// Executes a validated program over `data`.  Throws Error if the program is
// invalid or if execution runs off the end (which Validate already rejects).
uint32_t Execute(const std::vector<Instruction>& program, const SeccompData& data);

// Convenience: validate then execute.
uint32_t RunFilter(const std::vector<Instruction>& program, const SeccompData& data);

// ---------------------------------------------------------------------------
// Serialisation
// ---------------------------------------------------------------------------

// C initializer list body, one instruction per line:
//   { 0x20, 0, 0, 0x00000004 },  /* ld arch */
std::string ToCInitializer(const std::vector<Instruction>& program,
                           std::string_view indent = "    ");

// A compact textual listing used in reports and by the CLI's --dump-program.
std::string Disassemble(const std::vector<Instruction>& program);

std::string InstructionName(const Instruction& insn);

}  // namespace scgen

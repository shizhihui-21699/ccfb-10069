#include "bpf.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <map>
#include <set>
#include <sstream>

#include "common.h"

namespace scgen {

std::string_view ActionName(uint32_t action) {
  uint32_t base = action & kRetActionFullMask;
  switch (base) {
    case kRetKillThread: return "KILL_THREAD";
    case kRetKillProcess: return "KILL_PROCESS";
    case kRetTrap: return "TRAP";
    case kRetErrno: return "ERRNO";
    case kRetUserNotif: return "USER_NOTIF";
    case kRetTrace: return "TRACE";
    case kRetLog: return "LOG";
    case kRetAllow: return "ALLOW";
    default: return "UNKNOWN";
  }
}

std::string ActionDescription(uint32_t action) {
  uint32_t base = action & kRetActionFullMask;
  uint32_t data = action & kRetDataMask;
  std::string name(ActionName(action));
  if (base == kRetErrno || base == kRetTrace) {
    return name + "(" + Decimal(data) + ")";
  }
  if (base == kRetUserNotif) {
    return name + "(" + Decimal(data) + ")";
  }
  return name;
}

namespace {

constexpr uint16_t Code(std::initializer_list<uint16_t> parts) {
  uint16_t out = 0;
  for (uint16_t p : parts) out = static_cast<uint16_t>(out | p);
  return out;
}

constexpr Instruction Make(uint16_t code, uint8_t jt, uint8_t jf, uint32_t k) {
  Instruction insn;
  insn.code = code;
  insn.jt = jt;
  insn.jf = jf;
  insn.k = k;
  return insn;
}

}  // namespace

namespace insn {

Instruction LdAbs(uint32_t offset) {
  return Make(Code({kLd, kW, kAbs}), 0, 0, offset);
}
Instruction LdImm(uint32_t value) {
  return Make(Code({kLd, kW, kImm}), 0, 0, value);
}
Instruction LdMem(uint32_t slot) {
  return Make(Code({kLd, kW, kMem}), 0, 0, slot);
}
Instruction LdLen() {
  return Make(Code({kLd, kW, kLen}), 0, 0, 0);
}
Instruction StMem(uint32_t slot) {
  return Make(Code({kSt}), 0, 0, slot);
}
Instruction AluK(BpfAluOp op, uint32_t value) {
  return Make(Code({kAlu, op, kK}), 0, 0, value);
}
Instruction AluX(BpfAluOp op) {
  return Make(Code({kAlu, op, kX}), 0, 0, 0);
}
Instruction JmpK(BpfJmpOp op, uint32_t value) {
  return Make(Code({kJmp, op, kK}), 0, 0, value);
}
Instruction JmpA(uint32_t offset) {
  return Make(Code({kJmp, kJa}), 0, 0, offset);
}
Instruction JmpLabel(BpfJmpOp op, uint32_t value, std::string true_label,
                     std::string false_label) {
  Instruction i = Make(Code({kJmp, op, kK}), 0, 0, value);
  i.jt_label = std::move(true_label);
  i.jf_label = std::move(false_label);
  return i;
}
Instruction JaLabel(std::string target) {
  Instruction i = Make(Code({kJmp, kJa}), 0, 0, 0);
  i.jt_label = std::move(target);
  return i;
}
Instruction JmpX(BpfJmpOp op) {
  return Make(Code({kJmp, op, kX}), 0, 0, 0);
}
Instruction RetK(uint32_t value) {
  return Make(Code({kRet, kRetK}), 0, 0, value);
}
Instruction RetA() {
  return Make(Code({kRet, kRetA}), 0, 0, 0);
}
Instruction Tax() { return Make(Code({kMisc, kTax}), 0, 0, 0); }
Instruction Txa() { return Make(Code({kMisc, kTxa}), 0, 0, 0); }

}  // namespace insn

// ---------------------------------------------------------------------------
// Assembler
// ---------------------------------------------------------------------------

void Assembler::Bind(std::string label) {
  if (label.empty()) throw Error("empty label");
  for (const auto& [name, addr] : labels_) {
    if (name == label) throw Error("duplicate label: " + label);
  }
  labels_.emplace_back(std::move(label), static_cast<int>(program_.size()));
}

void Assembler::Emit(const Instruction& insn) {
  program_.push_back(insn);
  if (program_.size() > 4096) {
    // The kernel refuses seccomp filters longer than BPF_MAXINSNS (4096).
    throw Error("program exceeds the kernel's 4096-instruction limit");
  }
}

void Assembler::JmpK(BpfJmpOp op, uint32_t value, std::string true_label,
                     std::string false_label) {
  Emit(insn::JmpLabel(op, value, std::move(true_label), std::move(false_label)));
}

void Assembler::Ja(std::string label) { Emit(insn::JaLabel(std::move(label))); }


std::vector<Instruction> Assembler::Finalize() {
  if (program_.empty()) throw Error("empty BPF program");

  const int n = static_cast<int>(program_.size());
  std::map<std::string, int> label_to_index;
  for (const auto& [name, addr] : labels_) {
    if (addr < 0 || addr > n) {
      throw Error("label '" + name + "' bound out of range");
    }
    label_to_index[name] = addr;
  }
  // A label bound at the end of the program is only usable as a jump target if
  // some instruction follows it; catch that during target resolution below.

  auto resolve = [&](const std::string& label, int from_index) {
    auto it = label_to_index.find(label);
    if (it == label_to_index.end()) throw Error("undefined label: " + label);
    if (it->second <= from_index) {
      throw Error("seccomp filters cannot jump backwards (label '" + label +
                  "' is at instruction " + std::to_string(it->second) +
                  ", jump at " + std::to_string(from_index) + ")");
    }
    if (it->second >= n) {
      throw Error("label '" + label +
                  "' points past the end of the program; a jump target must be "
                  "an instruction");
    }
    return it->second;
  };

  // Which conditional jumps need trampolines?  A conditional jump's jt/jf are
  // 8-bit, so any target more than 255 instructions ahead needs a JA (32-bit
  // displacement) in between.  When one branch needs this, we emit a pair of
  // JAs and route both branches through them.
  std::set<int> long_jumps;
  auto compute_long_jumps = [&](const std::vector<int>& addr) {
    std::set<int> out;
    for (int i = 0; i < n; ++i) {
      const Instruction& ins = program_[i];
      bool conditional = (ins.code & 0x07) == kJmp && (ins.code & 0xf0) != kJa;
      if (!conditional) continue;
      if (ins.jt_label.empty() || ins.jf_label.empty()) {
        throw Error("internal: conditional jump at " + std::to_string(i) +
                    " lacks a target label");
      }
      auto true_it = label_to_index.find(ins.jt_label);
      auto false_it = label_to_index.find(ins.jf_label);
      if (true_it == label_to_index.end()) {
        throw Error("undefined label '" + ins.jt_label + "' at instruction " +
                    std::to_string(i));
      }
      if (false_it == label_to_index.end()) {
        throw Error("undefined label '" + ins.jf_label + "' at instruction " +
                    std::to_string(i));
      }
      int target_true = addr[true_it->second];
      int target_false = addr[false_it->second];
      if (target_true - (i + 1) > 255 || target_false - (i + 1) > 255) {
        out.insert(i);
      }
    }
    return out;
  };

  std::vector<int> addr(n);
  long_jumps.clear();
  for (int iteration = 0; iteration < 64; ++iteration) {
    // address of original instruction i = i + 2 * (number of long jumps before i)
    int shift = 0;
    int index = 0;
    for (int i = 0; i < n; ++i) {
      addr[i] = i + shift;
      if (long_jumps.count(i)) {
        shift += 2;
      }
      ++index;
    }
    (void)index;
    std::set<int> next = compute_long_jumps(addr);
    if (next == long_jumps) break;
    long_jumps = next;
    if (iteration == 63) {
      throw Error("internal: jump trampoline layout did not converge");
    }
  }

  // Emit the final program.
  std::vector<Instruction> out;
  out.reserve(n + 2 * long_jumps.size());
  for (int i = 0; i < n; ++i) {
    Instruction ins = program_[i];
    bool conditional = (ins.code & 0x07) == kJmp && (ins.code & 0xf0) != kJa;
    if (conditional && long_jumps.count(i)) {
      // jt -> next instruction (a JA to the true target), jf -> skip it.
      int target_true = resolve(ins.jt_label, i);
      int target_false = resolve(ins.jf_label, i);
      int ja_true_index = static_cast<int>(out.size()) + 1;
      int ja_false_index = static_cast<int>(out.size()) + 2;
      ins.jt = 0;
      ins.jf = 1;
      ins.jt_label.clear();
      ins.jf_label.clear();
      out.push_back(ins);
      out.push_back(insn::JmpA(
          static_cast<uint32_t>(addr[target_true] - (ja_true_index + 1))));
      out.push_back(insn::JmpA(
          static_cast<uint32_t>(addr[target_false] - (ja_false_index + 1))));
      continue;
    }
    if (conditional) {
      int here = static_cast<int>(out.size());
      int target_true = resolve(ins.jt_label, i);
      int target_false = resolve(ins.jf_label, i);
      int jt = addr[target_true] - (here + 1);
      int jf = addr[target_false] - (here + 1);
      if (jt < 0 || jt > 255 || jf < 0 || jf > 255) {
        throw Error("internal: jump offset out of range");
      }
      ins.jt = static_cast<uint8_t>(jt);
      ins.jf = static_cast<uint8_t>(jf);
      ins.jt_label.clear();
      ins.jf_label.clear();
      out.push_back(ins);
      continue;
    }
    if ((ins.code & 0x07) == kJmp && (ins.code & 0xf0) == kJa) {
      int here = static_cast<int>(out.size());
      if (ins.jt_label.empty()) {
        throw Error("internal: JA without a target label");
      }
      int target = resolve(ins.jt_label, i);
      int offset = addr[target] - (here + 1);
      if (offset < 0) throw Error("internal: negative JA offset");
      ins.k = static_cast<uint32_t>(offset);
      ins.jt_label.clear();
      ins.jf_label.clear();
      out.push_back(ins);
      continue;
    }
    ins.jt_label.clear();
    ins.jf_label.clear();
    out.push_back(ins);
  }

  if (out.size() > 4096) {
    throw Error("program exceeds the kernel's 4096-instruction limit (" +
                std::to_string(out.size()) + " instructions)");
  }
  return out;
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

ValidationResult Validate(const std::vector<Instruction>& program) {
  ValidationResult result;
  const int n = static_cast<int>(program.size());
  if (n == 0) {
    result.ok = false;
    result.message = "empty program";
    return result;
  }
  if (n > 4096) {
    result.ok = false;
    result.message = "program has " + std::to_string(n) +
                     " instructions, the kernel limit is 4096";
    return result;
  }

  // Every instruction must be reachable from the entry point, and every path
  // must terminate in a RET.  cBPF is a DAG because jumps are forward-only.
  std::vector<bool> reachable(n, false);
  std::vector<bool> visited(n, false);
  std::vector<int> worklist{0};
  std::vector<std::string> pending_errors;

  while (!worklist.empty()) {
    int pc = worklist.back();
    worklist.pop_back();
    if (visited[pc]) continue;
    visited[pc] = true;
    reachable[pc] = true;
    const Instruction& ins = program[pc];
    uint16_t cls = ins.code & 0x07;

    auto jump_to = [&](int target, const char* which) -> bool {
      // A zero displacement jumps to the following instruction, which is the
      // common encoding for "this branch falls through"; only targets at or
      // before the jump itself are backward.
      if (target < pc + 1) {
        pending_errors.push_back("instruction " + std::to_string(pc) +
                                 ": backward jump (" + which + ") to " +
                                 std::to_string(target) + " is not allowed");
        return false;
      }
      if (target >= n) {
        pending_errors.push_back("instruction " + std::to_string(pc) +
                                 ": jump (" + which + ") past end of program (" +
                                 std::to_string(target) + " >= " +
                                 std::to_string(n) + ")");
        return false;
      }
      result.max_jump_distance = std::max(result.max_jump_distance, target - pc);
      worklist.push_back(target);
      return true;
    };

    switch (cls) {
      case kLd: {
        uint16_t mode = ins.code & 0xe0;
        if (mode == kAbs) {
          if (ins.k + 4 > kSeccompDataSize) {
            pending_errors.push_back(
                "instruction " + std::to_string(pc) +
                ": absolute load at offset " + Hex(ins.k) +
                " is outside struct seccomp_data (64 bytes)");
          }
        } else if (mode == kMem) {
          if (ins.k >= 16) {
            pending_errors.push_back("instruction " + std::to_string(pc) +
                                     ": scratch slot " + std::to_string(ins.k) +
                                     " is out of range (0..15)");
          }
          result.max_stack_slot = std::max(result.max_stack_slot,
                                           static_cast<int>(ins.k));
        } else if (mode != kImm && mode != kLen) {
          pending_errors.push_back("instruction " + std::to_string(pc) +
                                   ": invalid load mode");
        }
        if (pc + 1 >= n) {
          pending_errors.push_back("instruction " + std::to_string(pc) +
                                   ": falls off the end of the program");
        } else {
          worklist.push_back(pc + 1);
        }
        break;
      }
      case kAlu:
      case kMisc: {
        if (pc + 1 >= n) {
          pending_errors.push_back("instruction " + std::to_string(pc) +
                                   ": falls off the end of the program");
        } else {
          worklist.push_back(pc + 1);
        }
        break;
      }
      case kSt:
      case kStx: {
        if (ins.k >= 16) {
          pending_errors.push_back("instruction " + std::to_string(pc) +
                                   ": scratch slot " + std::to_string(ins.k) +
                                   " is out of range (0..15)");
        } else {
          result.max_stack_slot = std::max(result.max_stack_slot,
                                           static_cast<int>(ins.k));
        }
        if (pc + 1 >= n) {
          pending_errors.push_back("instruction " + std::to_string(pc) +
                                   ": falls off the end of the program");
        } else {
          worklist.push_back(pc + 1);
        }
        break;
      }
      case kJmp: {
        uint16_t op = ins.code & 0xf0;
        if (op == kJa) {
          jump_to(pc + 1 + static_cast<int>(ins.k), "ja");
        } else {
          jump_to(pc + 1 + static_cast<int>(ins.jt), "jt");
          jump_to(pc + 1 + static_cast<int>(ins.jf), "jf");
        }
        break;
      }
      case kRet: {
        uint16_t rv = ins.code & 0x18;
        if (rv == kRetK) {
          uint32_t action = ins.k;
          uint32_t base = action & kRetActionFullMask;
          bool known = base == kRetKillThread || base == kRetKillProcess ||
                       base == kRetTrap || base == kRetErrno ||
                       base == kRetUserNotif || base == kRetTrace ||
                       base == kRetLog || base == kRetAllow;
          if (!known) {
            pending_errors.push_back("instruction " + std::to_string(pc) +
                                     ": unknown seccomp action " + Hex(base));
          }
          if (base == kRetErrno && (action & kRetDataMask) > kMaxErrno) {
            pending_errors.push_back("instruction " + std::to_string(pc) +
                                     ": errno value " +
                                     std::to_string(action & kRetDataMask) +
                                     " exceeds the kernel's limit of 4095");
          }
        } else if (rv == kRetA) {
          // Valid, but the value must have been loaded from a constant; we
          // cannot check that statically here, and the compiler never emits it.
        } else {
          pending_errors.push_back("instruction " + std::to_string(pc) +
                                   ": invalid return encoding");
        }
        break;
      }
      default:
        pending_errors.push_back("instruction " + std::to_string(pc) +
                                 ": unknown instruction class " + Hex(cls));
        break;
    }
    if (!pending_errors.empty()) {
      result.ok = false;
      result.message = pending_errors.front();
      result.instruction = pc;
      return result;
    }
  }

  // Unreachable instructions are legal for the kernel but are almost always a
  // compiler bug; report them so the generator can be fixed.
  for (int i = 0; i < n; ++i) {
    if (!reachable[i]) {
      result.ok = false;
      result.message = "instruction " + std::to_string(i) +
                       " is unreachable (dead code in the generated filter)";
      result.instruction = i;
      return result;
    }
  }
  return result;
}

// ---------------------------------------------------------------------------
// Interpreter
// ---------------------------------------------------------------------------

uint32_t Execute(const std::vector<Instruction>& program, const SeccompData& data) {
  if (program.empty()) throw Error("cannot execute an empty filter");

  const uint8_t* bytes = reinterpret_cast<const uint8_t*>(&data);
  uint32_t A = 0;
  uint32_t X = 0;
  uint32_t mem[16] = {0};

  auto load_word = [&](uint32_t offset) -> uint32_t {
    if (offset + 4 > kSeccompDataSize) {
      throw Error("filter reads outside struct seccomp_data at offset " + Hex(offset));
    }
    uint32_t value;
    std::memcpy(&value, bytes + offset, sizeof(value));
    return value;
  };

  int pc = 0;
  // A valid filter terminates in at most n steps since jumps are forward-only.
  const int limit = static_cast<int>(program.size()) + 1;
  for (int steps = 0; steps < limit; ++steps) {
    if (pc < 0 || pc >= static_cast<int>(program.size())) {
      throw Error("filter ran off the end of the program at pc=" + std::to_string(pc));
    }
    const Instruction& ins = program[pc];
    uint16_t cls = ins.code & 0x07;
    switch (cls) {
      case kLd: {
        uint16_t mode = ins.code & 0xe0;
        if (mode == kAbs) {
          A = load_word(ins.k);
          ++pc;
        } else if (mode == kImm) {
          A = ins.k;
          ++pc;
        } else if (mode == kMem) {
          if (ins.k >= 16) throw Error("scratch slot out of range");
          A = mem[ins.k];
          ++pc;
        } else if (mode == kLen) {
          // Packet length is the payload handed to the filter; seccomp does not
          // expose it meaningfully, and the compiler never emits BPF_LEN.
          A = 0;
          ++pc;
        } else {
          throw Error("unsupported load mode " + Hex(mode));
        }
        break;
      }
      case kSt: {
        if (ins.k >= 16) throw Error("scratch slot out of range");
        mem[ins.k] = A;
        ++pc;
        break;
      }
      case kStx: {
        if (ins.k >= 16) throw Error("scratch slot out of range");
        mem[ins.k] = X;
        ++pc;
        break;
      }
      case kAlu: {
        uint16_t op = ins.code & 0xf0;
        bool from_x = (ins.code & 0x08) == kX;
        uint32_t operand = from_x ? X : ins.k;
        switch (op) {
          case kAdd: A += operand; break;
          case kSub: A -= operand; break;
          case kMul: A *= operand; break;
          case kDiv:
            if (operand == 0) throw Error("division by zero in filter");
            A /= operand;
            break;
          case kOr: A |= operand; break;
          case kAnd: A &= operand; break;
          case kLsh: A <<= (operand & 31); break;
          case kRsh: A >>= (operand & 31); break;
          case kNeg: A = static_cast<uint32_t>(-static_cast<int32_t>(A)); break;
          case kMod:
            if (operand == 0) throw Error("modulo by zero in filter");
            A %= operand;
            break;
          case kXor: A ^= operand; break;
          default: throw Error("unsupported ALU op " + Hex(op));
        }
        ++pc;
        break;
      }
      case kMisc: {
        uint16_t op = ins.code & 0xf8;
        if (op == kTax) {
          X = A;
        } else if (op == kTxa) {
          A = X;
        } else {
          throw Error("unsupported misc op " + Hex(op));
        }
        ++pc;
        break;
      }
      case kJmp: {
        uint16_t op = ins.code & 0xf0;
        if (op == kJa) {
          pc += 1 + static_cast<int>(ins.k);
          break;
        }
        bool from_x = (ins.code & 0x08) == kX;
        uint32_t operand = from_x ? X : ins.k;
        bool taken = false;
        switch (op) {
          case kJeq: taken = (A == operand); break;
          case kJgt: taken = (A > operand); break;
          case kJge: taken = (A >= operand); break;
          case kJset: taken = (A & operand) != 0; break;
          default: throw Error("unsupported jump op " + Hex(op));
        }
        pc += 1 + static_cast<int>(taken ? ins.jt : ins.jf);
        break;
      }
      case kRet: {
        uint16_t rv = ins.code & 0x18;
        if (rv == kRetK) return ins.k;
        if (rv == kRetA) return A;
        throw Error("invalid return encoding");
      }
      default:
        throw Error("unknown instruction class " + Hex(cls));
    }
  }
  throw Error("filter did not terminate (possible loop)");
}

uint32_t RunFilter(const std::vector<Instruction>& program, const SeccompData& data) {
  ValidationResult check = Validate(program);
  if (!check.ok) {
    throw Error("invalid filter: " + check.message);
  }
  return Execute(program, data);
}

// ---------------------------------------------------------------------------
// Serialisation
// ---------------------------------------------------------------------------

namespace {

std::string LoadModeName(uint16_t code) {
  switch (code & 0xe0) {
    case kAbs: return "ABS";
    case kImm: return "IMM";
    case kMem: return "MEM";
    case kLen: return "LEN";
    default: return "?";
  }
}

std::string AluName(uint16_t op) {
  switch (op) {
    case kAdd: return "ADD";
    case kSub: return "SUB";
    case kMul: return "MUL";
    case kDiv: return "DIV";
    case kOr: return "OR";
    case kAnd: return "AND";
    case kLsh: return "LSH";
    case kRsh: return "RSH";
    case kNeg: return "NEG";
    case kMod: return "MOD";
    case kXor: return "XOR";
    default: return "?";
  }
}

std::string JmpName(uint16_t op) {
  switch (op) {
    case kJa: return "JA";
    case kJeq: return "JEQ";
    case kJgt: return "JGT";
    case kJge: return "JGE";
    case kJset: return "JSET";
    default: return "?";
  }
}

const char* SeccompDataFieldName(uint32_t offset) {
  switch (offset) {
    case 0: return "nr";
    case 4: return "arch";
    case 8: return "ip.lo";
    case 12: return "ip.hi";
    case 16: return "arg0.lo";
    case 20: return "arg0.hi";
    case 24: return "arg1.lo";
    case 28: return "arg1.hi";
    case 32: return "arg2.lo";
    case 36: return "arg2.hi";
    case 40: return "arg3.lo";
    case 44: return "arg3.hi";
    case 48: return "arg4.lo";
    case 52: return "arg4.hi";
    case 56: return "arg5.lo";
    case 60: return "arg5.hi";
    default: return nullptr;
  }
}

}  // namespace

std::string InstructionName(const Instruction& insn) {
  uint16_t cls = insn.code & 0x07;
  switch (cls) {
    case kLd: {
      std::string mode = LoadModeName(insn.code);
      if (mode == "ABS") {
        const char* field = SeccompDataFieldName(insn.k);
        if (field) return std::string("ld [") + field + "]";
        return "ld [" + Hex(insn.k) + "]";
      }
      if (mode == "IMM") return "ld #" + Hex(insn.k);
      if (mode == "MEM") return "ld M[" + std::to_string(insn.k) + "]";
      if (mode == "LEN") return "ld len";
      return "ld ?" + Hex(insn.code);
    }
    case kSt: return "st M[" + std::to_string(insn.k) + "]";
    case kStx: return "stx M[" + std::to_string(insn.k) + "]";
    case kAlu: {
      std::string name = AluName(insn.code & 0xf0);
      if ((insn.code & 0x08) == kX) return name + " x";
      if (name == "NEG") return "neg";
      return name + " #" + Hex(insn.k);
    }
    case kMisc: {
      uint16_t op = insn.code & 0xf8;
      if (op == kTax) return "tax";
      if (op == kTxa) return "txa";
      return "misc ?" + Hex(insn.code);
    }
    case kJmp: {
      std::string name = JmpName(insn.code & 0xf0);
      if ((insn.code & 0xf0) == kJa) {
        return "ja +" + std::to_string(insn.k);
      }
      std::string operand = (insn.code & 0x08) == kX ? "x" : "#" + Hex(insn.k);
      return name + " " + operand + ", +" + std::to_string(insn.jt) + ", +" +
             std::to_string(insn.jf);
    }
    case kRet: {
      if ((insn.code & 0x18) == kRetA) return "ret a";
      return "ret " + ActionDescription(insn.k);
    }
    default: return "unknown " + Hex(insn.code);
  }
}

std::string Disassemble(const std::vector<Instruction>& program) {
  std::ostringstream out;
  int width = static_cast<int>(std::to_string(program.size()).size());
  for (int i = 0; i < static_cast<int>(program.size()); ++i) {
    char index[16];
    std::snprintf(index, sizeof(index), "%0*d", width, i);
    out << index << ": " << InstructionName(program[i]) << "\n";
  }
  return out.str();
}

std::string ToCInitializer(const std::vector<Instruction>& program,
                           std::string_view indent) {
  std::ostringstream out;
  for (const Instruction& insn : program) {
    char buf[128];
    std::snprintf(buf, sizeof(buf), "{ 0x%04x, %3u, %3u, 0x%08x },", insn.code,
                  static_cast<unsigned>(insn.jt), static_cast<unsigned>(insn.jf),
                  insn.k);
    out << indent << buf << "  /* " << InstructionName(insn) << " */\n";
  }
  return out.str();
}

}  // namespace scgen

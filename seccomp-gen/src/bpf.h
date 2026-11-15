// SPDX-License-Identifier: MIT
// Classic BPF (cBPF) for seccomp: instruction model, emitter with label
// resolution and 8-bit jump-distance patching (trampolines), a from-scratch
// interpreter, and a static verifier.
//
// Reference: linux/filter.h, linux/seccomp.h,
// Documentation/bpf/classic_bpf.rst
#pragma once

#include "common.h"
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace scg {

// ---- instruction model --------------------------------------------------

// BPF class values
enum : uint8_t {
    BPF_LD    = 0x00,
    BPF_LDX   = 0x01,
    BPF_ST    = 0x02,
    BPF_STX   = 0x03,
    BPF_ALU   = 0x04,
    BPF_JMP   = 0x05,
    BPF_RET   = 0x06,
    BPF_MISC  = 0x07,
};
// sizes
enum : uint8_t { BPF_W = 0x00, BPF_H = 0x08, BPF_B = 0x10, BPF_DW = 0x18 };
// modes
enum : uint8_t {
    BPF_IMM = 0x00, BPF_ABS = 0x20, BPF_IND = 0x40, BPF_MEM = 0x60,
    BPF_LEN = 0x80, BPF_MSH = 0xa0,
};
// alu / jmp opcodes
enum : uint8_t {
    BPF_ADD = 0x00, BPF_SUB = 0x10, BPF_MUL = 0x20, BPF_DIV = 0x30,
    BPF_OR  = 0x40, BPF_AND = 0x50, BPF_LSH = 0x60, BPF_RSH = 0x70,
    BPF_NEG = 0x80, BPF_MOD = 0x90, BPF_XOR = 0xa0,
    BPF_JA  = 0x00, BPF_JEQ = 0x10, BPF_JGT = 0x20, BPF_JGE = 0x30,
    BPF_JSET = 0x40,
    BPF_K = 0x00, BPF_X = 0x08,
};

#pragma pack(push, 1)
struct BpfInsn {
    uint16_t code;
    uint8_t jt;
    uint8_t jf;
    uint32_t k;
};
#pragma pack(pop)
static_assert(sizeof(BpfInsn) == 8, "cBPF insn must be 8 bytes");

inline bool operator==(const BpfInsn& a, const BpfInsn& b) {
    return a.code == b.code && a.jt == b.jt && a.jf == b.jf && a.k == b.k;
}
inline bool operator!=(const BpfInsn& a, const BpfInsn& b) {
    return !(a == b);
}

// ---- emitter ------------------------------------------------------------

class BpfEmitter {
public:
    BpfEmitter();

    // labels
    int newLabel(const std::string& name = "");
    void placeLabel(int id);
    void emit(uint16_t code, uint8_t jt, uint8_t jf, uint32_t k);
    // convenience emitters
    void loadDataW(uint32_t off);       // LD W ABS off
    void loadDataH(uint32_t off);
    void loadDataDW(uint32_t off);      // LD DW ABS off (kernel extension)
    void loadImm(uint32_t v);
    void jumpLabel(uint8_t op, uint32_t k, int tLabel, int fLabel);
    void jaLabel(int label);
    void retAction(SeccompAction a, uint16_t errnoData = 0);

    // Resolve labels, fix 8-bit jump limits by inserting JA trampolines,
    // and return the final program. Throws on unresolved labels.
    std::vector<BpfInsn> finalize();

    size_t size() const;

private:
    struct Item {
        enum Kind { INSN, LABEL } kind;
        BpfInsn insn{};
        int labelId = -1;
        // for jump insns: target labels (-1 = fallthrough)
        int jtLabel = -1, jfLabel = -1, jaLabel = -1;
    };
    std::vector<Item> items_;
    int labelSeq_ = 0;
    std::map<int, std::string> labelNames_;
};

// ---- interpreter --------------------------------------------------------

struct VmResult {
    uint32_t ret = 0;
    uint64_t steps = 0;
    std::string error;   // non-empty on VM fault
};

// Run a cBPF program over a seccomp_data buffer (64 bytes).
// data layout: nr(4) arch(4) ip(8) args[6](8 each)
VmResult bpfRun(const std::vector<BpfInsn>& prog, const uint8_t data[64],
                uint64_t maxSteps = 1'000'000);

// Convenience: build seccomp_data from components.
void makeSeccompData(uint8_t out[64], uint32_t nr, uint32_t arch,
                     uint64_t ip, const uint64_t args[6]);

// ---- static verifier ----------------------------------------------------

struct VerifyError {
    size_t pc;
    std::string message;
};
std::vector<VerifyError> bpfVerify(const std::vector<BpfInsn>& prog);

// ---- serialization ------------------------------------------------------

constexpr uint32_t kFilterMagic = 0x53434731; // "SCG1"
constexpr uint32_t kFilterVersion = 1;

struct FilterBlob {
    uint32_t archAudit = 0;
    std::string archName;
    std::string phase;
    SeccompAction defaultAction = SeccompAction::KILL;
    uint16_t defaultErrno = 0;
    std::vector<BpfInsn> prog;
};

std::vector<uint8_t> serializeFilter(const FilterBlob& blob);
FilterBlob deserializeFilter(const std::vector<uint8_t>& bytes);

// C source text embedding the filter (ready for prctl(PR_SET_SECCOMP)).
std::string emitCArray(const FilterBlob& blob);

} // namespace scg

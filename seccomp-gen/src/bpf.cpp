// SPDX-License-Identifier: MIT
#include "bpf.h"

#include <cstring>
#include <iomanip>
#include <limits>
#include <sstream>

namespace scg {

// =====================================================================
// Emitter
// =====================================================================

BpfEmitter::BpfEmitter() = default;

int BpfEmitter::newLabel(const std::string& name) {
    int id = ++labelSeq_;
    labelNames_[id] = name.empty() ? ("L" + std::to_string(id)) : name;
    return id;
}

void BpfEmitter::placeLabel(int id) {
    Item it;
    it.kind = Item::LABEL;
    it.labelId = id;
    items_.push_back(it);
}

void BpfEmitter::emit(uint16_t code, uint8_t jt, uint8_t jf, uint32_t k) {
    Item it;
    it.kind = Item::INSN;
    it.insn = BpfInsn{code, jt, jf, k};
    items_.push_back(it);
}

void BpfEmitter::loadDataW(uint32_t off) {
    emit(BPF_LD | BPF_W | BPF_ABS, 0, 0, off);
}
void BpfEmitter::loadDataH(uint32_t off) {
    emit(BPF_LD | BPF_H | BPF_ABS, 0, 0, off);
}
void BpfEmitter::loadDataDW(uint32_t off) {
    // BPF_LD | BPF_DW | BPF_ABS: Linux seccomp extension, loads 8 bytes
    // into A (low word) and X (high word).
    emit(BPF_LD | BPF_DW | BPF_ABS, 0, 0, off);
}
void BpfEmitter::loadImm(uint32_t v) {
    emit(BPF_LD | BPF_W | BPF_IMM, 0, 0, v);
}

void BpfEmitter::jumpLabel(uint8_t op, uint32_t k, int tLabel, int fLabel) {
    Item it;
    it.kind = Item::INSN;
    it.insn = BpfInsn{(uint16_t)(BPF_JMP | op | BPF_K), 0, 0, k};
    it.jtLabel = tLabel;
    it.jfLabel = fLabel;
    items_.push_back(it);
}

void BpfEmitter::jaLabel(int label) {
    Item it;
    it.kind = Item::INSN;
    it.insn = BpfInsn{(uint16_t)(BPF_JMP | BPF_JA | BPF_K), 0, 0, 0};
    it.jaLabel = label;
    items_.push_back(it);
}

void BpfEmitter::retAction(SeccompAction a, uint16_t errnoData) {
    emit(BPF_RET | BPF_K, 0, 0, seccompRet(a, errnoData));
}

size_t BpfEmitter::size() const {
    size_t n = 0;
    for (const auto& it : items_)
        if (it.kind == Item::INSN) ++n;
    return n;
}

std::vector<BpfInsn> BpfEmitter::finalize() {
    // The compiler emits a strictly-linear program in which every jump is a
    // short, local, forward branch (see compiler.cpp for why a binary-search
    // / long-jump design cannot be repaired with trampolines). Finalization
    // therefore only resolves labels to relative offsets and asserts the
    // 8-bit limit holds; no trampoline insertion is required or performed.
    std::map<int, size_t> addr;
    size_t pc = 0;
    for (const auto& it : items_) {
        if (it.kind == Item::LABEL) addr[it.labelId] = pc;
        else ++pc;
    }

    std::vector<BpfInsn> out;
    out.reserve(pc);
    for (const auto& it : items_) {
        if (it.kind == Item::LABEL) continue;
        BpfInsn insn = it.insn;
        if ((insn.code & 0x07) == BPF_JMP) {
            size_t src = out.size();
            bool isJa = (insn.code & 0xF0) == BPF_JA;
            if (isJa) {
                auto found = addr.find(it.jaLabel);
                if (found == addr.end())
                    throw Error("unresolved BPF jump label");
                size_t dst = found->second;
                if (dst <= src)
                    throw Error("backward JA in seccomp filter");
                if (dst - src - 1 > 255)
                    throw Error("jump exceeds 8-bit range (JA); the linear "
                                "compiler should prevent this");
                insn.k = (uint32_t)(dst - src - 1);
            } else {
                auto boff = [&](int lbl) -> uint8_t {
                    if (lbl < 0) return 0; // fall-through branch
                    auto found = addr.find(lbl);
                    if (found == addr.end())
                        throw Error("unresolved BPF branch label");
                    size_t dst = found->second;
                    if (dst <= src)
                        throw Error("backward conditional branch in filter");
                    if (dst - src - 1 > 255)
                        throw Error("jump exceeds 8-bit range (branch); the "
                                    "linear compiler should prevent this");
                    return (uint8_t)(dst - src - 1);
                };
                insn.jt = boff(it.jtLabel);
                insn.jf = boff(it.jfLabel);
            }
        }
        out.push_back(insn);
    }
    return out;
}

// =====================================================================
// Interpreter
// =====================================================================

void makeSeccompData(uint8_t out[64], uint32_t nr, uint32_t arch,
                     uint64_t ip, const uint64_t args[6]) {
    std::memset(out, 0, 64);
    std::memcpy(out + 0, &nr, 4);
    std::memcpy(out + 4, &arch, 4);
    std::memcpy(out + 8, &ip, 8);
    for (int i = 0; i < 6; ++i)
        std::memcpy(out + 16 + 8 * i, &args[i], 8);
}

VmResult bpfRun(const std::vector<BpfInsn>& prog, const uint8_t data[64],
                uint64_t maxSteps) {
    VmResult res;
    uint32_t A = 0, X = 0;
    uint32_t M[16] = {0};
    size_t pc = 0;

    auto loadAt = [&](uint32_t off, uint8_t size) -> uint32_t {
        if (size == BPF_W) {
            if (off + 4 > 64) throw Error("OOB LD_W");
            uint32_t v;
            std::memcpy(&v, data + off, 4);
            return v;
        }
        if (size == BPF_H) {
            if (off + 2 > 64) throw Error("OOB LD_H");
            return (uint32_t)data[off] | ((uint32_t)data[off + 1] << 8);
        }
        if (size == BPF_B) {
            if (off + 1 > 64) throw Error("OOB LD_B");
            return data[off];
        }
        throw Error("bad LD size");
    };

    while (pc < prog.size()) {
        if (++res.steps > maxSteps) {
            res.error = "step limit exceeded";
            return res;
        }
        const BpfInsn& in = prog[pc++];
        uint8_t cls = in.code & 0x07;

        if (cls == BPF_LD) {
            uint8_t mode = in.code & 0xE0;
            uint8_t size = in.code & 0x18;
            if (mode == BPF_ABS) {
                if (size == BPF_DW) {
                    if (in.k + 8 > 64) { res.error = "OOB LD_DW"; return res; }
                    uint64_t v;
                    std::memcpy(&v, data + in.k, 8);
                    A = (uint32_t)v;
                    X = (uint32_t)(v >> 32);
                } else {
                    A = loadAt(in.k, size);
                }
            } else if (mode == BPF_IMM) {
                A = in.k;
            } else if (mode == BPF_LEN) {
                A = 64;
            } else if (mode == BPF_IND) {
                A = loadAt(X + in.k, size);
            } else {
                res.error = "unsupported LD mode";
                return res;
            }
            continue;
        }
        if (cls == BPF_LDX) {
            uint8_t mode = in.code & 0xE0;
            uint8_t size = in.code & 0x18;
            if (mode == BPF_IMM) X = in.k;
            else if (mode == BPF_MEM) X = M[in.k & 15];
            else if (mode == BPF_LEN) X = 64;
            else if (mode == BPF_ABS) X = loadAt(in.k, size);
            else if (mode == BPF_IND) X = loadAt(X + in.k, size);
            else { res.error = "unsupported LDX mode"; return res; }
            continue;
        }
        if (cls == BPF_ST)  { M[in.k & 15] = A; continue; }
        if (cls == BPF_STX) { M[in.k & 15] = X; continue; }

        if (cls == BPF_ALU) {
            uint8_t op = in.code & 0xF0;
            uint8_t src = in.code & 0x08;
            if (op == BPF_NEG) {
                A = (uint32_t)(-(int32_t)A);
                continue;
            }
            uint32_t v = src == BPF_X ? X : in.k;
            switch (op) {
                case BPF_ADD: A += v; break;
                case BPF_SUB: A -= v; break;
                case BPF_MUL: A *= v; break;
                case BPF_DIV:
                    if (v == 0) { res.error = "division by zero"; return res; }
                    A /= v; break;
                case BPF_OR:  A |= v; break;
                case BPF_AND: A &= v; break;
                case BPF_LSH: A <<= (v & 31); break;
                case BPF_RSH: A >>= (v & 31); break;
                case BPF_MOD:
                    if (v == 0) { res.error = "mod by zero"; return res; }
                    A %= v; break;
                case BPF_XOR: A ^= v; break;
                default: res.error = "unknown ALU op"; return res;
            }
            continue;
        }

        if (cls == BPF_JMP) {
            uint8_t op = in.code & 0xF0;
            uint8_t src = in.code & 0x08;
            // The loop's `pc++` above has already advanced to the next
            // instruction. BPF jump offsets are relative to that same next
            // instruction, so the effective target is pc + offset (no extra
            // +1); an offset of zero simply continues at pc.
            if (op == BPF_JA) {
                pc += in.k;
                if (pc > prog.size()) { res.error = "JA out of range"; return res; }
                continue;
            }
            uint32_t v = src == BPF_X ? X : in.k;
            bool take = false;
            switch (op) {
                case BPF_JEQ: take = (A == v); break;
                case BPF_JGT: take = (A > v);  break;
                case BPF_JGE: take = (A >= v); break;
                case BPF_JSET: take = ((A & v) != 0); break;
                default: res.error = "unknown JMP op"; return res;
            }
            pc += take ? in.jt : in.jf;
            if (pc > prog.size()) { res.error = "jump out of range"; return res; }
            continue;
        }

        if (cls == BPF_RET) {
            if ((in.code & 0xF8) != BPF_K) {
                res.error = "only RET K supported by seccomp";
                return res;
            }
            res.ret = in.k;
            return res;
        }
        if (cls == BPF_MISC) {
            if (in.code == (BPF_MISC | 0x00)) X = A;       // TAX
            else if (in.code == (BPF_MISC | 0x08)) A = X;  // TXA
            else { res.error = "unsupported MISC op"; return res; }
            continue;
        }
        res.error = "unknown instruction class";
        return res;
    }
    res.error = "program fell through without RET";
    return res;
}

// =====================================================================
// Static verifier
// =====================================================================

std::vector<VerifyError> bpfVerify(const std::vector<BpfInsn>& prog) {
    std::vector<VerifyError> errs;
    if (prog.empty()) { errs.push_back({0, "empty program"}); return errs; }
    if (prog.size() > 4096)
        errs.push_back({0, "program exceeds 4096-insn seccomp limit"});

    for (size_t i = 0; i < prog.size(); ++i) {
        const BpfInsn& in = prog[i];
        uint8_t cls = in.code & 0x07;
        uint8_t mode = in.code & 0xE0;

        if (cls == BPF_LD || cls == BPF_LDX) {
            uint8_t size = in.code & 0x18;
            uint32_t need = size == BPF_DW ? 8u : size == BPF_W ? 4u
                                           : size == BPF_H ? 2u : 1u;
            if (mode == BPF_ABS && (uint64_t)in.k + need > 64)
                errs.push_back({i, "absolute load outside seccomp_data"});
        }
        if (cls == BPF_ALU) {
            uint8_t op = in.code & 0xF0;
            if ((op == BPF_DIV || op == BPF_MOD) &&
                (in.code & 0x08) == 0 && in.k == 0)
                errs.push_back({i, "division by zero immediate"});
        }
        if (cls == BPF_JMP) {
            uint8_t op = in.code & 0xF0;
            if (op == BPF_JA) {
                if (i + 1 + in.k >= prog.size())
                    errs.push_back({i, "JA target beyond program end"});
            } else {
                if (i + 1 + in.jt >= prog.size())
                    errs.push_back({i, "jt target beyond program end"});
                if (i + 1 + in.jf >= prog.size())
                    errs.push_back({i, "jf target beyond program end"});
            }
        }
        if (cls == BPF_RET && (in.code & 0xF8) != BPF_K)
            errs.push_back({i, "seccomp only supports RET K"});
    }
    if ((prog.back().code & 0x07) != BPF_RET)
        errs.push_back({prog.size() - 1, "last instruction must be RET"});
    return errs;
}

// =====================================================================
// Serialization
// =====================================================================

namespace {

void putU32(std::vector<uint8_t>& b, uint32_t v) {
    for (int i = 0; i < 4; ++i) b.push_back((v >> (8 * i)) & 0xFF);
}
void putU16(std::vector<uint8_t>& b, uint16_t v) {
    b.push_back(v & 0xFF);
    b.push_back(v >> 8);
}
uint32_t getU32(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
uint16_t getU16(const uint8_t* p) {
    return (uint16_t)(p[0] | (p[1] << 8));
}
void putStr(std::vector<uint8_t>& b, const std::string& s) {
    putU16(b, (uint16_t)s.size());
    b.insert(b.end(), s.begin(), s.end());
}
std::string getStr(const uint8_t* p, size_t& off, size_t cap) {
    if (off + 2 > cap) throw Error("corrupt filter blob");
    uint16_t n = getU16(p + off);
    off += 2;
    if (off + n > cap) throw Error("corrupt filter blob");
    std::string s((const char*)(p + off), n);
    off += n;
    return s;
}

} // namespace

std::vector<uint8_t> serializeFilter(const FilterBlob& blob) {
    std::vector<uint8_t> b;
    putU32(b, kFilterMagic);
    putU32(b, kFilterVersion);
    putU32(b, blob.archAudit);
    putStr(b, blob.archName);
    putStr(b, blob.phase);
    b.push_back((uint8_t)blob.defaultAction);
    putU16(b, blob.defaultErrno);
    putU32(b, (uint32_t)blob.prog.size());
    for (const auto& in : blob.prog) {
        putU16(b, in.code);
        b.push_back(in.jt);
        b.push_back(in.jf);
        putU32(b, in.k);
    }
    return b;
}

FilterBlob deserializeFilter(const std::vector<uint8_t>& bytes) {
    const size_t cap = bytes.size();
    size_t off = 0;
    auto need = [&](size_t n) {
        if (off + n > cap) throw Error("corrupt filter blob: truncated");
    };
    need(8);
    if (getU32(bytes.data()) != kFilterMagic)
        throw Error("bad filter magic");
    if (getU32(bytes.data() + 4) != kFilterVersion)
        throw Error("unsupported filter version");
    off = 8;
    FilterBlob blob;
    need(4); blob.archAudit = getU32(bytes.data() + off); off += 4;
    blob.archName = getStr(bytes.data(), off, cap);
    blob.phase = getStr(bytes.data(), off, cap);
    need(1); blob.defaultAction = (SeccompAction)bytes[off++];
    need(2); blob.defaultErrno = getU16(bytes.data() + off); off += 2;
    need(4);
    uint32_t n = getU32(bytes.data() + off); off += 4;
    for (uint32_t i = 0; i < n; ++i) {
        need(8);
        BpfInsn in;
        in.code = getU16(bytes.data() + off); off += 2;
        in.jt = bytes[off++];
        in.jf = bytes[off++];
        in.k = getU32(bytes.data() + off); off += 4;
        blob.prog.push_back(in);
    }
    return blob;
}

std::string emitCArray(const FilterBlob& blob) {
    std::ostringstream os;
    os << "/* seccomp filter: " << blob.archName << " / " << blob.phase
       << ", " << blob.prog.size() << " insns */\n";
    os << "#include <stddef.h>\n#include <linux/filter.h>\n"
          "#include <linux/seccomp.h>\n";
    os << "static const struct sock_filter " << blob.phase
       << "_filter[" << blob.prog.size() << "] = {\n";
    for (const auto& in : blob.prog) {
        os << "    { 0x" << std::hex << std::setw(4) << std::setfill('0')
           << in.code << std::dec << std::setfill(' ')
           << ", 0x" << std::hex << (unsigned)in.jt
           << ", 0x" << (unsigned)in.jf << std::dec
           << ", 0x" << std::hex << in.k << std::dec << " },\n";
    }
    os << "};\n";
    os << "static const struct sock_fprog " << blob.phase
       << "_fprog = { .len = " << blob.prog.size()
       << ", .filter = (struct sock_filter*)" << blob.phase << "_filter };\n";
    return os.str();
}

} // namespace scg

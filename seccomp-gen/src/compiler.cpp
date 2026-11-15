// SPDX-License-Identifier: MIT
#include "compiler.h"

#include <algorithm>
#include <map>
#include <set>
#include <sstream>

namespace scg {

namespace {

// BPF_MISC|0x08 = TXA (X -> A).
constexpr uint16_t TXA = BPF_MISC | 0x08;

// Emit one predicate; on failure jump to failLabel.
void emitCond(BpfEmitter& em, const Cond& c, int failLabel) {
    int pass = em.newLabel("condpass");

    if (c.check64) {
        // LD_DW leaves the low word in A and the high word in X.
        uint32_t low = (uint32_t)c.value;
        uint32_t high = (uint32_t)(c.value >> 32);

        if (c.op == CmpOp::EQ) {
            int hi = em.newLabel("hi");
            em.loadDataDW(argOffset(c.arg));
            em.jumpLabel(BPF_JEQ, low, hi, failLabel);
            em.placeLabel(hi);
            em.emit(TXA, 0, 0, 0); // A := high word
            em.jumpLabel(BPF_JEQ, high, pass, failLabel);
            em.placeLabel(pass);
            return;
        }
        if (c.op == CmpOp::NE) {
            int hi = em.newLabel("hi");
            em.loadDataDW(argOffset(c.arg));
            em.jumpLabel(BPF_JEQ, low, hi, pass);
            em.placeLabel(hi);
            em.emit(TXA, 0, 0, 0);
            em.jumpLabel(BPF_JEQ, high, failLabel, pass);
            em.placeLabel(pass);
            return;
        }
        // MASK_EQ: (v & mask) == value, checked one word at a time.
        uint32_t mLow = (uint32_t)c.mask;
        uint32_t mHigh = (uint32_t)(c.mask >> 32);
        int hi = em.newLabel("hi");
        em.loadDataDW(argOffset(c.arg));
        em.emit(BPF_ALU | BPF_AND | BPF_K, 0, 0, mLow);
        em.jumpLabel(BPF_JEQ, low, hi, failLabel);
        em.placeLabel(hi);
        em.loadDataDW(argOffset(c.arg));
        em.emit(TXA, 0, 0, 0); // A := high word
        em.emit(BPF_ALU | BPF_AND | BPF_K, 0, 0, mHigh);
        em.jumpLabel(BPF_JEQ, high, pass, failLabel);
        em.placeLabel(pass);
        return;
    }

    // 32-bit path: load the argument word.
    em.loadDataW(argOffset(c.arg));
    switch (c.op) {
        case CmpOp::EQ:
            em.jumpLabel(BPF_JEQ, (uint32_t)c.value, pass, failLabel);
            break;
        case CmpOp::NE:
            em.jumpLabel(BPF_JEQ, (uint32_t)c.value, failLabel, pass);
            break;
        case CmpOp::MASK_EQ:
            em.emit(BPF_ALU | BPF_AND | BPF_K, 0, 0, (uint32_t)c.mask);
            em.jumpLabel(BPF_JEQ, (uint32_t)c.value, pass, failLabel);
            break;
    }
    em.placeLabel(pass);
}

} // namespace

CompileResult compilePolicy(const Policy& pol, const SyscallTable& table) {
    CompileResult cr;
    BpfEmitter em;

    // Resolve and validate every rule's syscall number up front.
    std::map<int, std::vector<const Rule*>> byNr;
    std::set<int> nrs;
    for (const auto& r : pol.rules) {
        auto nr = table.number(r.syscall);
        if (!nr)
            throw Error("cannot compile: syscall '" + r.syscall +
                        "' unknown to arch " + archName(pol.arch));
        byNr[*nr].push_back(&r);
        nrs.insert(*nr);
    }
    std::vector<int> sortedNr(nrs.begin(), nrs.end());

    // 1) architecture guard
    int archOk = em.newLabel("archok");
    em.loadDataW(4);
    em.jumpLabel(BPF_JEQ, auditArch(pol.arch), archOk, -1 /*to default*/);
    em.retAction(pol.defaultAction, pol.defaultErrno);
    em.placeLabel(archOk);

    // 2) Linear, adjacent dispatch (no long jumps, see rationale below).
    //
    // A binary-search dispatch forces jumps across hundreds of instructions,
    // overflowing the cBPF 8-bit offset field. Closing that gap with inserted
    // trampolines is unsolvable: any instruction inserted between a jump and
    // its target shifts the target by the same amount, so their distance is
    // invariant and never fits. We therefore lay every syscall block out
    // back-to-back. A non-matching nr falls through straight into the next
    // block; a match runs that block's rule chain. Each block ends with an
    // inline copy of the default-action RET, so EVERY jump in the program is
    // a short local forward branch and the 8-bit limit can never overflow.
    // Worst case is O(#syscalls) compares, the trade-off the kernel's
    // 4096-insn and 8-bit-offset limits impose.
    for (size_t bi = 0; bi < sortedNr.size(); ++bi) {
        int nr = sortedNr[bi];
        int match = em.newLabel("match");
        int after = em.newLabel("afterblock");
        // nr match -> rule chain (jt); nr mismatch -> skip this whole block
        // (jf) and continue scanning at the next syscall's load.
        em.loadDataW(0); // seccomp_data.nr
        em.jumpLabel(BPF_JEQ, (uint32_t)nr, match, after);
        em.placeLabel(match);

        const auto& rules = byNr[nr];
        for (const auto* r : rules) {
            if (r->conds.empty()) {
                em.retAction(r->action, r->errnoData);
                continue;
            }
            int fail = em.newLabel("rulefail");
            for (const auto& c : r->conds) emitCond(em, c, fail);
            em.retAction(r->action, r->errnoData);
            em.placeLabel(fail);
        }
        // nr matched but no rule's conditions did: default action.
        em.retAction(pol.defaultAction, pol.defaultErrno);
        em.placeLabel(after); // next block's LD begins here

        std::ostringstream note;
        note << "nr=" << nr << " (" << table.name(nr).value_or("?")
             << ") rules=" << rules.size();
        cr.notes.push_back(note.str());
    }

    // nr matched no block: default action.
    em.retAction(pol.defaultAction, pol.defaultErrno);

    auto prog = em.finalize();
    auto verr = bpfVerify(prog);
    if (!verr.empty()) {
        std::ostringstream os;
        os << "generated filter failed verification:\n";
        for (const auto& e : verr)
            os << "  pc=" << e.pc << ": " << e.message << "\n";
        throw Error(os.str());
    }

    cr.blob.archAudit = auditArch(pol.arch);
    cr.blob.archName = archName(pol.arch);
    cr.blob.phase = pol.phase;
    cr.blob.defaultAction = pol.defaultAction;
    cr.blob.defaultErrno = pol.defaultErrno;
    cr.blob.prog = std::move(prog);
    return cr;
}

} // namespace scg

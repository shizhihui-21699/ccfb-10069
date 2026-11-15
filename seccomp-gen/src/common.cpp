// SPDX-License-Identifier: MIT
#include "common.h"

#include <sstream>

namespace scg {

const char* archName(Arch a) {
    return a == Arch::X86_64 ? "x86_64" : "aarch64";
}

std::optional<Arch> archFromName(const std::string& s) {
    if (s == "x86_64" || s == "x86-64" || s == "amd64") return Arch::X86_64;
    if (s == "aarch64" || s == "arm64") return Arch::AARCH64;
    return std::nullopt;
}

uint32_t auditArch(Arch a) {
    // linux/audit.h
    // EM_X86_64=62, EM_AARCH64=183; __AUDIT_ARCH_64BIT=0x80000000,
    // __AUDIT_ARCH_LE=0x40000000
    if (a == Arch::X86_64) return 0xC000003E;
    return 0xC00000B7;
}

const char* actionName(SeccompAction a) {
    switch (a) {
        case SeccompAction::ALLOW:       return "ALLOW";
        case SeccompAction::KILL:        return "KILL";
        case SeccompAction::KILL_THREAD: return "KILL_THREAD";
        case SeccompAction::ERRNO:       return "ERRNO";
        case SeccompAction::TRAP:        return "TRAP";
        case SeccompAction::LOG:         return "LOG";
    }
    return "?";
}

uint32_t seccompRet(SeccompAction a, uint16_t errnoData) {
    // linux/seccomp.h SECCOMP_RET_*
    switch (a) {
        case SeccompAction::KILL_THREAD: return 0x00000000u;
        case SeccompAction::TRAP:        return 0x00030000u;
        case SeccompAction::ERRNO:       return 0x00050000u | (errnoData & 0xFFFFu);
        case SeccompAction::ALLOW:       return 0x7FFF0000u;
        case SeccompAction::LOG:         return 0x7FFC0000u;
        case SeccompAction::KILL:        return 0x80000000u;
    }
    return 0x80000000u;
}

std::string Cond::toDsl() const {
    std::ostringstream os;
    os << "arg" << arg;
    switch (op) {
        case CmpOp::EQ:      os << " == "; break;
        case CmpOp::NE:      os << " != "; break;
        case CmpOp::MASK_EQ: os << " &= " << mask << " == "; break;
    }
    os << value;
    if (check64) os << " @64";
    return os.str();
}

std::string Rule::toDsl() const {
    std::ostringstream os;
    os << actionName(action);
    if (action == SeccompAction::ERRNO) os << "(" << errnoData << ")";
    os << " " << syscall;
    for (size_t i = 0; i < conds.size(); ++i)
        os << (i == 0 ? " WHERE " : " AND ") << conds[i].toDsl();
    os << ";";
    return os.str();
}

static bool condMatches(const Cond& c, uint64_t v) {
    switch (c.op) {
        case CmpOp::EQ:      return v == c.value;
        case CmpOp::NE:      return v != c.value;
        case CmpOp::MASK_EQ: return (v & c.mask) == c.value;
    }
    return false;
}

SeccompAction policyEval(const Policy& pol, const std::string& syscall,
                         const uint64_t args[6], uint16_t& errnoOut) {
    // First explicit rule (DSL/trace order) whose syscall and all conditions
    // match wins; otherwise the default action applies.
    for (const auto& r : pol.rules) {
        if (r.syscall != syscall) continue;
        bool ok = true;
        for (const auto& c : r.conds) {
            if (c.arg >= 6) { ok = false; break; }
            if (!condMatches(c, args[c.arg])) { ok = false; break; }
        }
        if (ok) {
            errnoOut = r.errnoData;
            return r.action;
        }
    }
    errnoOut = pol.defaultErrno;
    return pol.defaultAction;
}

} // namespace scg

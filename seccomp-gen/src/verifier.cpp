// SPDX-License-Identifier: MIT
#include "verifier.h"

#include <algorithm>
#include <set>
#include <sstream>

namespace scg {

namespace {

SeccompAction actionFromRet(uint32_t ret, uint16_t& dataOut) {
    uint32_t action = ret & 0xFFFF0000u;
    dataOut = (uint16_t)(ret & 0xFFFFu);
    switch (action) {
        case 0x7FFF0000u: return SeccompAction::ALLOW;
        case 0x00000000u: return SeccompAction::KILL_THREAD;
        case 0x80000000u: return SeccompAction::KILL;
        case 0x00030000u: return SeccompAction::TRAP;
        case 0x7FFC0000u: return SeccompAction::LOG;
        case 0x00050000u: return SeccompAction::ERRNO;
    }
    return SeccompAction::KILL;
}

bool eventInPhase(const SysEvent& e, const std::string& phase) {
    if (phase == "all") return true;
    return e.phase == phase;
}

} // namespace

std::vector<VerifyCase> buildCases(const ParseResult& trace,
                                   const Policy& pol,
                                   const SyscallTable& table) {
    std::vector<VerifyCase> cases;
    std::set<std::string> observedInPhase;

    // ---- positives: every observed event in the selected phase ----
    for (const auto& e : trace.events) {
        if (!eventInPhase(e, pol.phase)) continue;
        auto nr = table.number(e.syscall);
        if (!nr) continue; // unknowns were reported at generation time
        observedInPhase.insert(e.syscall);

        VerifyCase cs;
        cs.lineNo = e.lineNo;
        cs.tid = e.tid;
        cs.syscall = e.syscall;
        cs.phase = e.phase;
        cs.nr = (uint32_t)*nr;
        cs.observed = true;
        for (size_t i = 0; i < e.args.size() && i < 6; ++i)
            cs.args[i] = e.args[i].number.value_or(0);

        // Expected decision computed independently by the software policy
        // evaluator — this is the oracle for the BPF program.
        uint16_t err = 0;
        cs.expected = policyEval(pol, e.syscall, cs.args, err);
        cs.expectedErrno = err;
        cases.push_back(cs);
    }

    // ---- negatives 1: mutate each constrained argument slot ----
    for (const auto& r : pol.rules) {
        if (r.conds.empty()) continue;
        auto nr = table.number(r.syscall);
        if (!nr) continue;
        for (const auto& c : r.conds) {
            VerifyCase cs;
            cs.syscall = r.syscall;
            cs.nr = (uint32_t)*nr;
            cs.observed = false;
            cs.phase = pol.phase;
            // A value the rule cannot match.
            uint64_t bad;
            if (c.op == CmpOp::EQ) {
                bad = c.value == 0 ? 1 : c.value + 1;
                cs.mutation = "arg" + std::to_string(c.arg) +
                              " changed off allowed value";
            } else if (c.op == CmpOp::NE) {
                bad = c.value;
                cs.mutation = "arg" + std::to_string(c.arg) +
                              " set to forbidden value";
            } else {
                bad = c.value ^ (c.mask ? c.mask : 1);
                cs.mutation = "arg" + std::to_string(c.arg) +
                              " mask-equality violated";
            }
            cs.args[c.arg] = bad;
            uint16_t err = 0;
            cs.expected = policyEval(pol, r.syscall, cs.args, err);
            cs.expectedErrno = err;
            cases.push_back(cs);
        }
    }

    // ---- negatives 2: syscalls never observed in this phase ----
    // Sample across the whole architecture table so both arches are covered.
    for (const auto& entry : table.all()) {
        const int nr = entry.first;
        const std::string& name = entry.second;
        if (observedInPhase.count(name)) continue;
        // Skip if an explicit DSL rule still allows it unconditionally.
        bool explicitlyAllowed = std::any_of(
            pol.rules.begin(), pol.rules.end(), [&](const Rule& r) {
                return r.syscall == name && r.conds.empty() &&
                       r.action == SeccompAction::ALLOW;
            });
        if (explicitlyAllowed) continue;

        VerifyCase cs;
        cs.syscall = name;
        cs.nr = (uint32_t)nr;
        cs.observed = false;
        cs.phase = pol.phase;
        cs.mutation = "syscall never observed in phase " + pol.phase;
        uint16_t err = 0;
        cs.expected = policyEval(pol, name, cs.args, err);
        cs.expectedErrno = err;
        cases.push_back(cs);
    }
    return cases;
}

VerifyOutcome runVerification(const std::vector<BpfInsn>& prog,
                              const std::vector<VerifyCase>& cases,
                              Arch progArch) {
    VerifyOutcome out;
    uint32_t goodArch = auditArch(progArch);
    uint32_t otherArch = auditArch(progArch == Arch::X86_64
                                       ? Arch::AARCH64
                                       : Arch::X86_64);

    for (const auto& cs : cases) {
        ++out.total;
        if (cs.observed) ++out.positiveCases;
        else ++out.negativeCases;

        uint8_t data[64];
        makeSeccompData(data, cs.nr, goodArch, 0, cs.args);
        VmResult vm = bpfRun(prog, data);
        if (!vm.error.empty()) {
            ++out.failed;
            out.failures.push_back({cs, 0, SeccompAction::KILL,
                                    "VM fault: " + vm.error});
            continue;
        }
        uint16_t gotData = 0;
        SeccompAction got = actionFromRet(vm.ret, gotData);
        if (got != cs.expected ||
            (got == SeccompAction::ERRNO && gotData != cs.expectedErrno)) {
            ++out.failed;
            std::ostringstream d;
            d << "expected " << actionName(cs.expected);
            if (cs.expected == SeccompAction::ERRNO)
                d << "(" << cs.expectedErrno << ")";
            d << ", got " << actionName(got);
            if (got == SeccompAction::ERRNO) d << "(" << gotData << ")";
            out.failures.push_back({cs, vm.ret, got, d.str()});
            continue;
        }
        ++out.passed;

        // Cross-architecture check: same buffer, foreign AUDIT_ARCH must
        // always hit the architecture guard, which returns the filter's
        // default action regardless of syscall number or arguments.
        ++out.total;
        ++out.crossArchCases;
        makeSeccompData(data, cs.nr, otherArch, 0, cs.args);
        vm = bpfRun(prog, data);
        uint32_t defaultRet = prog.back().k;
        if (!vm.error.empty() || vm.ret != defaultRet) {
            ++out.failed;
            std::ostringstream h;
            h << "foreign-arch guard failed (expected default RET 0x"
              << std::hex << defaultRet << std::dec << ")";
            out.failures.push_back({cs, vm.ret, SeccompAction::KILL, h.str()});
        } else {
            ++out.passed;
        }
    }
    return out;
}

// =====================================================================
// Report
// =====================================================================

std::string renderReport(const Policy& pol, const SyscallTable& table,
                         const ParseResult& trace,
                         const GenReport& gen,
                         const FilterBlob& blob,
                         const VerifyOutcome& verify) {
    std::ostringstream os;
    os << "# Seccomp policy report\n\n";
    os << "- Architecture: **" << archName(pol.arch) << "** (AUDIT_ARCH 0x"
       << std::hex << auditArch(pol.arch) << std::dec << ")\n";
    os << "- Phase: **" << pol.phase << "**\n";
    os << "- Default action: **" << actionName(pol.defaultAction);
    if (pol.defaultAction == SeccompAction::ERRNO)
        os << "(" << pol.defaultErrno << ")";
    os << "**\n";
    os << "- Filter size: **" << blob.prog.size()
       << " instructions** (" << blob.prog.size() * 8 << " bytes)\n";
    os << "- Trace events parsed: " << trace.stats.events
       << " across " << trace.stats.tids.size() << " task(s), "
       << trace.stats.lines << " raw lines\n";
    os << "- Unfinished/resumed pairs merged: " << trace.stats.unfinished
       << "/" << trace.stats.resumed << "\n";
    if (trace.stats.markerSeen)
        os << "- Phase marker hit at line " << trace.stats.markerLine << "\n";
    os << "\n## Allowed syscalls (" << gen.syscallsObserved << ")\n\n";
    os << "| syscall | nr | argument constraints | source |\n";
    os << "|---|---:|---|---|\n";
    for (const auto& r : pol.rules) {
        auto nr = table.number(r.syscall);
        os << "| `" << r.syscall << "` | "
           << (nr ? std::to_string(*nr) : "?") << " | ";
        if (r.conds.empty()) os << "—";
        else {
            for (size_t i = 0; i < r.conds.size(); ++i) {
                if (i) os << " AND ";
                os << r.conds[i].toDsl();
            }
        }
        os << " | " << r.source << " |\n";
    }

    os << "\n## Verification\n\n";
    os << "- Cases executed (own arch): "
       << verify.positiveCases << " positive, "
       << verify.negativeCases << " negative\n";
    os << "- Cross-architecture guard cases: " << verify.crossArchCases
       << "\n";
    os << "- Total VM evaluations: " << verify.total << ", passed: "
       << verify.passed << ", failed: " << verify.failed << "\n";
    if (!verify.failures.empty()) {
        os << "\n### Failures\n\n";
        for (const auto& f : verify.failures)
            os << "- `" << f.cs.syscall << "` (line " << f.cs.lineNo
               << ", " << f.cs.mutation << "): " << f.detail << "\n";
    }

    if (!trace.warnings.empty() || !gen.warnings.empty()) {
        os << "\n## Warnings\n\n";
        for (const auto& w : trace.warnings) os << "- " << w << "\n";
        for (const auto& w : gen.warnings) os << "- " << w << "\n";
    }
    return os.str();
}

} // namespace scg

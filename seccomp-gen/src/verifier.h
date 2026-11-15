// SPDX-License-Identifier: MIT
// Replay verification: feed the raw syscall call sequence through the
// generated BPF program (interpreted by our own VM) and prove every
// allow/deny decision is correct.
#pragma once

#include "bpf.h"
#include "common.h"
#include "policy.h"
#include "strace_parser.h"
#include "syscall_table.h"

namespace scg {

struct VerifyCase {
    uint64_t lineNo = 0;
    int tid = 0;
    std::string syscall;
    std::string phase;
    uint32_t nr = 0;
    uint64_t args[6] = {0,0,0,0,0,0};
    bool observed;        // true = from trace; false = synthesized negative
    std::string mutation; // description for synthesized cases
    SeccompAction expected = SeccompAction::ALLOW;
    uint16_t expectedErrno = 0;
};

struct VerifyFailure {
    VerifyCase cs;
    uint32_t gotRet = 0;
    SeccompAction gotAction = SeccompAction::KILL;
    std::string detail;
};

struct VerifyOutcome {
    uint64_t total = 0;
    uint64_t passed = 0;
    uint64_t failed = 0;
    std::vector<VerifyFailure> failures;
    uint64_t positiveCases = 0;
    uint64_t negativeCases = 0;
    uint64_t crossArchCases = 0;
};

// Build the full case list from the trace:
//   * positive: every observed event in the policy phase must be allowed
//   * negative: arg-mutations of constrained events + never-observed syscalls
//   * cross-arch: the same numbers must be rejected with the other AUDIT_ARCH
std::vector<VerifyCase> buildCases(const ParseResult& trace,
                                   const Policy& pol,
                                   const SyscallTable& table);

VerifyOutcome runVerification(const std::vector<BpfInsn>& prog,
                              const std::vector<VerifyCase>& cases,
                              Arch progArch);

// Human-readable markdown report.
std::string renderReport(const Policy& pol, const SyscallTable& table,
                         const ParseResult& trace,
                         const GenReport& gen,
                         const FilterBlob& blob,
                         const VerifyOutcome& verify);

} // namespace scg

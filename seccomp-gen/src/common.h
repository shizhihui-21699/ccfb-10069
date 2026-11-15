// SPDX-License-Identifier: MIT
// Common data types shared across the seccomp policy generator.
#pragma once

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>
#include <optional>
#include <stdexcept>

namespace scg {

enum class Arch { X86_64, AARCH64 };

const char* archName(Arch a);
std::optional<Arch> archFromName(const std::string& s);
// AUDIT_ARCH_* values used by the seccomp architecture check.
uint32_t auditArch(Arch a);
// Offset of a 64-bit argument within struct seccomp_data (args[] starts at 16).
inline uint32_t argOffset(unsigned index) { return 16u + 8u * index; }

struct Error : std::runtime_error {
    using std::runtime_error::runtime_error;
};

// One resolved-or-raw argument observed on a syscall.
struct ArgValue {
    std::string raw;                 // verbatim token from strace
    std::optional<uint64_t> number;  // numeric meaning, if resolvable
    bool isString = false;           // strace printed it as "..."
    std::string strValue;            // decoded string content, if any

    bool resolvable() const { return number.has_value(); }
};

// One parsed strace syscall event.
struct SysEvent {
    int pid = 0;
    int tid = 0;
    std::string syscall;             // strace name, may be unknown to our tables
    std::vector<ArgValue> args;
    bool hasResult = false;
    int64_t result = 0;
    bool failed = false;             // result looked like -1 / ENOSYS etc.
    int errNo = 0;                   // errno when failed
    bool started = true;             // false for "<unfinished ...>"-only remnants
    bool finished = true;            // false when only a "resumed" trailer exists
    uint64_t lineNo = 0;
    std::string phase;               // "boot" or "runtime"
};

// ---- DSL predicate tree -------------------------------------------------

enum class CmpOp { EQ, NE, MASK_EQ };

struct Cond {
    unsigned arg = 0;
    CmpOp op = CmpOp::EQ;
    uint64_t mask = 0;   // used by MASK_EQ
    uint64_t value = 0;
    bool check64 = false; // emit a true 64-bit comparison (high word tested)

    std::string toDsl() const;
};

enum class SeccompAction {
    ALLOW,           // SECCOMP_RET_ALLOW
    KILL,            // SECCOMP_RET_KILL_PROCESS
    KILL_THREAD,     // SECCOMP_RET_KILL_THREAD
    ERRNO,           // SECCOMP_RET_ERRNO + data
    TRAP,            // SECCOMP_RET_TRAP
    LOG,             // SECCOMP_RET_LOG
};

const char* actionName(SeccompAction a);
uint32_t seccompRet(SeccompAction a, uint16_t errnoData = 0);

struct Rule {
    std::string syscall;
    std::vector<Cond> conds; // conjunction (AND); empty = unconditional
    SeccompAction action = SeccompAction::ALLOW;
    uint16_t errnoData = 1;  // EPERM by default for ERRNO
    std::string source;      // "trace", "dsl:<file>", etc.

    std::string toDsl() const;
};

struct Policy {
    Arch arch = Arch::X86_64;
    std::string phase = "runtime";
    SeccompAction defaultAction = SeccompAction::KILL;
    uint16_t defaultErrno = 1;
    std::vector<Rule> rules;
    // marker that separated boot from runtime (informational)
    std::string phaseMarker;
};

// Evaluate a policy in software (used by report/tests, independent of BPF).
SeccompAction policyEval(const Policy& pol, const std::string& syscall,
                         const uint64_t args[6], uint16_t& errnoOut);

} // namespace scg

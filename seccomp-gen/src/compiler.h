// SPDX-License-Identifier: MIT
// Compile a Policy into a seccomp cBPF program.
//
// Program shape:
//   1. architecture check (wrong arch -> default action)
//   2. binary-search dispatch on seccomp_data.nr over the sorted set of
//      syscall numbers mentioned by rules
//   3. per-syscall block: first matching rule's action, else default
//   4. default action RET at the end
//
// Argument predicates compile to 32-bit loads, or to 64-bit LD_DW loads
// (A=low word, X=high word) when the value exceeds 2^32 or @64 is set.
#pragma once

#include "bpf.h"
#include "common.h"
#include "policy.h"
#include "syscall_table.h"

namespace scg {

struct CompileResult {
    FilterBlob blob;
    // diagnostics: one line per emitted rule block
    std::vector<std::string> notes;
};

CompileResult compilePolicy(const Policy& pol, const SyscallTable& table);

} // namespace scg

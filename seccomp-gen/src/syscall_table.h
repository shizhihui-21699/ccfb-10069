// SPDX-License-Identifier: MIT
// Per-architecture syscall number tables (data verified against musl
// arch/*/bits/syscall.h.in) plus a constant-symbol table used to turn
// strace tokens such as AF_INET into numbers.
#pragma once

#include "common.h"

namespace scg {

class SyscallTable {
public:
    explicit SyscallTable(Arch arch);

    Arch arch() const { return arch_; }

    std::optional<int> number(const std::string& name) const;
    std::optional<std::string> name(int nr) const;

    // Every (name, number) pair, sorted by number.
    const std::vector<std::pair<int, std::string>>& all() const { return byNum_; }

private:
    Arch arch_;
    std::map<std::string, int> nameToNr_;
    std::map<int, std::string> nrToName_;
    std::vector<std::pair<int, std::string>> byNum_;
};

// Resolve a symbolic constant (AF_INET, SOCK_STREAM, O_RDONLY, PROT_READ,
// MAP_SHARED, CLONE_*, FUTEX_WAIT, ...). Returns nullopt when unknown.
std::optional<uint64_t> resolveConstant(const std::string& token);

// Exposed for tests: number of constants known.
size_t constantCount();

} // namespace scg

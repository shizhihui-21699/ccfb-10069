// tables.h — syscall number tables (x86_64 / aarch64) and named constants.
#pragma once
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

struct SysEnt {
    const char* name;
    int32_t x64;    // -1 = does not exist on x86_64
    int32_t arm64;  // -1 = does not exist on aarch64
};

extern const std::vector<SysEnt> kSyscalls;

// Named constants as printed by strace (AF_INET, O_CLOEXEC, TCGETS, ...).
const std::unordered_map<std::string, uint64_t>& constants();

// Errno names for the DSL (EPERM, EACCES, ...).
const std::unordered_map<std::string, uint64_t>& errno_names();

// Look up syscall number by name for "x86_64" or "aarch64". -1 if unknown.
int32_t sys_nr(const std::string& name, const std::string& arch);
// Look up syscall name by number. "" if unknown.
std::string sys_name(int32_t nr, const std::string& arch);

// AUDIT_ARCH_* value for seccomp_data.arch checks.
uint32_t audit_arch(const std::string& arch);

bool valid_arch(const std::string& arch);

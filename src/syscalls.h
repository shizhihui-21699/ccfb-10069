// Architecture-independent description of Linux system calls: numbers,
// argument shapes and, for a handful of calls, what the arguments mean.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace scgen {

enum class Arch { kX86_64, kAarch64 };

std::string_view ArchName(Arch arch);
std::string_view ArchMachine(Arch arch);   // value for seccomp_data.arch
std::optional<Arch> ParseArch(std::string_view name);
uint32_t AuditArch(Arch arch);

struct SyscallEntry {
  const char* name;
  int x86_64;
  int aarch64;
};

// Lookup by name.  Names are the ones strace prints.
const SyscallEntry* FindSyscall(std::string_view name);
const SyscallEntry* FindSyscall(Arch arch, int nr);
int SyscallNumber(Arch arch, std::string_view name);  // -1 if unknown
std::string_view SyscallName(Arch arch, int nr);      // "" if unknown

// All known syscall names, sorted.
std::vector<std::string> AllSyscallNames();

// ---------------------------------------------------------------------------
// Argument semantics
// ---------------------------------------------------------------------------

// What a syscall argument means, which decides how a rule can constrain it.
// This is what makes "socket only with AF_INET" expressible: a rule on
// socket's arg0 compares against an address-family constant, not a raw int.
enum class ArgKind {
  kUnknown,       // opaque value; only exact/range comparisons are sensible
  kFlags,         // bit flags; rules can test "all of" / "any of"
  kAddressFamily, // AF_* / PF_*
  kSocketType,    // SOCK_* (low nibble is the type, high bits are flags)
  kSignal,        // signal number
  kFd,            // file descriptor
  kPointer,       // user pointer (never compared; only faked on output)
  kBuffer,        // user buffer (never compared)
  kSize,          // byte count
  kProtFlags,     // PROT_*
  kMapFlags,      // MAP_*
  kOpenFlags,     // O_*
  kAtFlags,       // AT_*
  kMode,          // file mode bits
  kPid,           // process id
  kProtocol,      // IPPROTO_*
  kUint,
};

std::string_view ArgKindName(ArgKind kind);

// Whether a single observed value for this kind of argument is a meaningful
// thing to pin in a filter.  File descriptors, pointers and sizes are not: the
// service will legitimately use different ones next run, so pinning the
// observed value produces a policy that blocks real traffic.
bool ArgKindIsPinnable(ArgKind kind);

// How many arguments the call takes (min of both architectures' definitions;
// syscalls are defined identically on both for our purposes).
int SyscallArgCount(std::string_view name);

ArgKind SyscallArgKind(std::string_view name, int index);

// Human-readable name of the argument, e.g. "family" for socket(2) arg0.
std::string_view SyscallArgName(std::string_view name, int index);

// Constant namespace a given argument draws from ("AF_", "O_", "SOCK_", ...).
// Empty when the argument has no natural constant family.
std::string_view SyscallArgConstantPrefix(std::string_view name, int index);

// True when the kernel only reads the argument (so a seccomp filter may
// safely pass arbitrary values through into the simulator).
bool SyscallArgIsPointer(std::string_view name, int index);

// Names of syscalls that have flags in `arg index` and the flag family
// (for documentation and validation).
struct NamedConstant {
  const char* name;
  long long value;
};
const NamedConstant* FindConstant(std::string_view name);
std::vector<std::string> AllConstantNames();

// Looks up a constant by name, accepting the bare suffix as well ("O_CLOEXEC"
// and "CLOEXEC" both work when unambiguous within a prefix).
std::optional<long long> LookupConstant(std::string_view name,
                                        std::string_view prefix_hint = {});

}  // namespace scgen

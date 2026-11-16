#include "syscalls.h"

#include <algorithm>
#include <array>
#include <map>
#include <unordered_map>

#include "common.h"

namespace scgen {
// The generated tables are plain arrays of literals.
#include "syscalls_generated.inc"
#include "constants_generated.inc"
}  // namespace scgen

namespace {

const std::unordered_map<std::string_view, const scgen::SyscallEntry*>& SyscallIndex() {
  static const auto* index = [] {
    auto* m =
        new std::unordered_map<std::string_view, const scgen::SyscallEntry*>();
    for (const auto& e : scgen::kSyscallEntries) m->emplace(e.name, &e);
    return m;
  }();
  return *index;
}

const std::unordered_map<std::string_view, const scgen::NamedConstant*>&
ConstantIndex() {
  static const auto* index = [] {
    auto* m =
        new std::unordered_map<std::string_view, const scgen::NamedConstant*>();
    for (const auto& e : scgen::kConstants) m->emplace(e.name, &e);
    return m;
  }();
  return *index;
}

}  // namespace

namespace scgen {

std::string_view ArchName(Arch arch) {
  return arch == Arch::kX86_64 ? "x86_64" : "aarch64";
}

std::string_view ArchMachine(Arch arch) {
  return arch == Arch::kX86_64 ? "x86_64" : "aarch64";
}

std::optional<Arch> ParseArch(std::string_view name) {
  std::string lower = ToLower(Trim(name));
  if (lower == "x86_64" || lower == "x86-64" || lower == "amd64" || lower == "x64") {
    return Arch::kX86_64;
  }
  if (lower == "aarch64" || lower == "arm64") return Arch::kAarch64;
  return std::nullopt;
}

uint32_t AuditArch(Arch arch) {
  return static_cast<uint32_t>(
      arch == Arch::kX86_64 ? kAuditArchX86_64 : kAuditArchAarch64);
}

const SyscallEntry* FindSyscall(std::string_view name) {
  const auto& index = SyscallIndex();
  auto it = index.find(name);
  return it == index.end() ? nullptr : it->second;
}

const SyscallEntry* FindSyscall(Arch arch, int nr) {
  for (const auto& e : kSyscallEntries) {
    if ((arch == Arch::kX86_64 ? e.x86_64 : e.aarch64) == nr) return &e;
  }
  return nullptr;
}

int SyscallNumber(Arch arch, std::string_view name) {
  const SyscallEntry* e = FindSyscall(name);
  if (!e) return -1;
  return arch == Arch::kX86_64 ? e->x86_64 : e->aarch64;
}

std::string_view SyscallName(Arch arch, int nr) {
  const SyscallEntry* e = FindSyscall(arch, nr);
  return e ? std::string_view(e->name) : std::string_view();
}

std::vector<std::string> AllSyscallNames() {
  std::vector<std::string> names;
  names.reserve(std::size(kSyscallEntries));
  for (const auto& e : kSyscallEntries) names.emplace_back(e.name);
  std::sort(names.begin(), names.end());
  return names;
}

bool ArgKindIsPinnable(ArgKind kind) {
  switch (kind) {
    case ArgKind::kFd:
    case ArgKind::kPointer:
    case ArgKind::kBuffer:
    case ArgKind::kSize:
    case ArgKind::kPid:
    case ArgKind::kUint:
    case ArgKind::kUnknown:
      return false;
    default:
      return true;
  }
}

std::string_view ArgKindName(ArgKind kind) {
  switch (kind) {
    case ArgKind::kUnknown: return "value";
    case ArgKind::kFlags: return "flags";
    case ArgKind::kAddressFamily: return "address family";
    case ArgKind::kSocketType: return "socket type";
    case ArgKind::kSignal: return "signal";
    case ArgKind::kFd: return "fd";
    case ArgKind::kPointer: return "pointer";
    case ArgKind::kBuffer: return "buffer";
    case ArgKind::kSize: return "size";
    case ArgKind::kProtFlags: return "prot flags";
    case ArgKind::kMapFlags: return "map flags";
    case ArgKind::kOpenFlags: return "open flags";
    case ArgKind::kAtFlags: return "at flags";
    case ArgKind::kMode: return "mode";
    case ArgKind::kPid: return "pid";
    case ArgKind::kProtocol: return "protocol";
    case ArgKind::kUint: return "uint";
  }
  return "value";
}

// ---------------------------------------------------------------------------
// Per-syscall argument descriptions
//
// Only calls whose arguments we can say something true about are listed.  A
// missing entry means "unknown shape": rules may still constrain arguments as
// raw integers, but the generator will not offer flag validation for them.
// ---------------------------------------------------------------------------

struct ArgInfo {
  const char* name;
  ArgKind kind;
  const char* prefix;  // constant namespace used to render/validate values
};

struct SyscallInfo {
  const char* name;
  int nargs;
  ArgInfo args[6];
};

constexpr ArgInfo A(const char* n, ArgKind k, const char* p = "") {
  return ArgInfo{n, k, p};
}

constexpr SyscallInfo kSyscallInfo[] = {
    {"socket", 3, {A("domain", ArgKind::kAddressFamily, "AF_"),
                   A("type", ArgKind::kSocketType, "SOCK_"),
                   A("protocol", ArgKind::kProtocol, "IPPROTO_")}},
    {"socketpair", 4, {A("domain", ArgKind::kAddressFamily, "AF_"),
                       A("type", ArgKind::kSocketType, "SOCK_"),
                       A("protocol", ArgKind::kProtocol, "IPPROTO_"),
                       A("sv", ArgKind::kPointer)}},
    {"bind", 3, {A("fd", ArgKind::kFd), A("addr", ArgKind::kPointer),
                 A("addrlen", ArgKind::kSize)}},
    {"connect", 3, {A("fd", ArgKind::kFd), A("addr", ArgKind::kPointer),
                    A("addrlen", ArgKind::kSize)}},
    {"listen", 2, {A("fd", ArgKind::kFd), A("backlog", ArgKind::kUint)}},
    {"accept", 3, {A("fd", ArgKind::kFd), A("addr", ArgKind::kPointer),
                   A("addrlen", ArgKind::kPointer)}},
    {"accept4", 4, {A("fd", ArgKind::kFd), A("addr", ArgKind::kPointer),
                    A("addrlen", ArgKind::kPointer),
                    A("flags", ArgKind::kFlags, "SOCK_")}},
    {"getsockname", 3, {A("fd", ArgKind::kFd), A("addr", ArgKind::kPointer),
                        A("addrlen", ArgKind::kPointer)}},
    {"getpeername", 3, {A("fd", ArgKind::kFd), A("addr", ArgKind::kPointer),
                        A("addrlen", ArgKind::kPointer)}},
    {"sendto", 6, {A("fd", ArgKind::kFd), A("buf", ArgKind::kBuffer),
                   A("len", ArgKind::kSize), A("flags", ArgKind::kFlags),
                   A("addr", ArgKind::kPointer), A("addrlen", ArgKind::kSize)}},
    {"recvfrom", 6, {A("fd", ArgKind::kFd), A("buf", ArgKind::kBuffer),
                     A("len", ArgKind::kSize), A("flags", ArgKind::kFlags),
                     A("addr", ArgKind::kPointer), A("addrlen", ArgKind::kPointer)}},
    {"sendmsg", 3, {A("fd", ArgKind::kFd), A("msg", ArgKind::kPointer),
                    A("flags", ArgKind::kFlags)}},
    {"recvmsg", 3, {A("fd", ArgKind::kFd), A("msg", ArgKind::kPointer),
                    A("flags", ArgKind::kFlags)}},
    {"sendmmsg", 4, {A("fd", ArgKind::kFd), A("msgvec", ArgKind::kPointer),
                     A("vlen", ArgKind::kUint), A("flags", ArgKind::kFlags)}},
    {"recvmmsg", 5, {A("fd", ArgKind::kFd), A("msgvec", ArgKind::kPointer),
                     A("vlen", ArgKind::kUint), A("flags", ArgKind::kFlags),
                     A("timeout", ArgKind::kPointer)}},
    {"shutdown", 2, {A("fd", ArgKind::kFd), A("how", ArgKind::kUint)}},
    {"setsockopt", 5, {A("fd", ArgKind::kFd), A("level", ArgKind::kUint, "SOL_"),
                       A("optname", ArgKind::kUint, "SO_"),
                       A("optval", ArgKind::kPointer), A("optlen", ArgKind::kSize)}},
    {"getsockopt", 5, {A("fd", ArgKind::kFd), A("level", ArgKind::kUint, "SOL_"),
                       A("optname", ArgKind::kUint, "SO_"),
                       A("optval", ArgKind::kPointer), A("optlen", ArgKind::kPointer)}},
    {"open", 3, {A("path", ArgKind::kPointer), A("flags", ArgKind::kOpenFlags, "O_"),
                 A("mode", ArgKind::kMode, "S_")}},
    {"openat", 4, {A("dirfd", ArgKind::kFd), A("path", ArgKind::kPointer),
                   A("flags", ArgKind::kOpenFlags, "O_"),
                   A("mode", ArgKind::kMode, "S_")}},
    {"openat2", 4, {A("dirfd", ArgKind::kFd), A("path", ArgKind::kPointer),
                    A("how", ArgKind::kPointer), A("size", ArgKind::kSize)}},
    {"creat", 2, {A("path", ArgKind::kPointer), A("mode", ArgKind::kMode, "S_")}},
    {"close", 1, {A("fd", ArgKind::kFd)}},
    {"read", 3, {A("fd", ArgKind::kFd), A("buf", ArgKind::kBuffer),
                 A("count", ArgKind::kSize)}},
    {"write", 3, {A("fd", ArgKind::kFd), A("buf", ArgKind::kBuffer),
                  A("count", ArgKind::kSize)}},
    {"pread64", 4, {A("fd", ArgKind::kFd), A("buf", ArgKind::kBuffer),
                    A("count", ArgKind::kSize), A("offset", ArgKind::kUint)}},
    {"pwrite64", 4, {A("fd", ArgKind::kFd), A("buf", ArgKind::kBuffer),
                     A("count", ArgKind::kSize), A("offset", ArgKind::kUint)}},
    {"readv", 3, {A("fd", ArgKind::kFd), A("iov", ArgKind::kPointer),
                  A("iovcnt", ArgKind::kUint)}},
    {"writev", 3, {A("fd", ArgKind::kFd), A("iov", ArgKind::kPointer),
                   A("iovcnt", ArgKind::kUint)}},
    {"preadv", 4, {A("fd", ArgKind::kFd), A("iov", ArgKind::kPointer),
                   A("iovcnt", ArgKind::kUint), A("offset", ArgKind::kUint)}},
    {"pwritev", 4, {A("fd", ArgKind::kFd), A("iov", ArgKind::kPointer),
                    A("iovcnt", ArgKind::kUint), A("offset", ArgKind::kUint)}},
    {"lseek", 3, {A("fd", ArgKind::kFd), A("offset", ArgKind::kUint),
                  A("whence", ArgKind::kUint)}},
    {"fcntl", 3, {A("fd", ArgKind::kFd), A("cmd", ArgKind::kUint, "F_"),
                  A("arg", ArgKind::kUint)}},
    {"ioctl", 3, {A("fd", ArgKind::kFd), A("request", ArgKind::kUint),
                  A("arg", ArgKind::kPointer)}},
    {"dup", 1, {A("fd", ArgKind::kFd)}},
    {"dup2", 2, {A("oldfd", ArgKind::kFd), A("newfd", ArgKind::kFd)}},
    {"dup3", 3, {A("oldfd", ArgKind::kFd), A("newfd", ArgKind::kFd),
                 A("flags", ArgKind::kFlags, "O_")}},
    {"pipe", 1, {A("pipefd", ArgKind::kPointer)}},
    {"pipe2", 2, {A("pipefd", ArgKind::kPointer), A("flags", ArgKind::kOpenFlags, "O_")}},
    {"stat", 2, {A("path", ArgKind::kPointer), A("buf", ArgKind::kPointer)}},
    {"lstat", 2, {A("path", ArgKind::kPointer), A("buf", ArgKind::kPointer)}},
    {"fstat", 2, {A("fd", ArgKind::kFd), A("buf", ArgKind::kPointer)}},
    {"newfstatat", 4, {A("dirfd", ArgKind::kFd), A("path", ArgKind::kPointer),
                       A("buf", ArgKind::kPointer), A("flags", ArgKind::kAtFlags, "AT_")}},
    {"fstatfs", 2, {A("fd", ArgKind::kFd), A("buf", ArgKind::kPointer)}},
    {"statfs", 2, {A("path", ArgKind::kPointer), A("buf", ArgKind::kPointer)}},
    {"statx", 5, {A("dirfd", ArgKind::kFd), A("path", ArgKind::kPointer),
                  A("flags", ArgKind::kAtFlags, "AT_"),
                  A("mask", ArgKind::kFlags, "STATX_"), A("buf", ArgKind::kPointer)}},
    {"access", 2, {A("path", ArgKind::kPointer), A("mode", ArgKind::kUint)}},
    {"faccessat", 3, {A("dirfd", ArgKind::kFd), A("path", ArgKind::kPointer),
                      A("mode", ArgKind::kUint)}},
    {"faccessat2", 4, {A("dirfd", ArgKind::kFd), A("path", ArgKind::kPointer),
                       A("mode", ArgKind::kUint), A("flags", ArgKind::kAtFlags, "AT_")}},
    {"unlink", 1, {A("path", ArgKind::kPointer)}},
    {"unlinkat", 3, {A("dirfd", ArgKind::kFd), A("path", ArgKind::kPointer),
                     A("flags", ArgKind::kAtFlags, "AT_")}},
    {"rename", 2, {A("oldpath", ArgKind::kPointer), A("newpath", ArgKind::kPointer)}},
    {"renameat", 4, {A("olddirfd", ArgKind::kFd), A("oldpath", ArgKind::kPointer),
                     A("newdirfd", ArgKind::kFd), A("newpath", ArgKind::kPointer)}},
    {"renameat2", 5, {A("olddirfd", ArgKind::kFd), A("oldpath", ArgKind::kPointer),
                      A("newdirfd", ArgKind::kFd), A("newpath", ArgKind::kPointer),
                      A("flags", ArgKind::kFlags, "RENAME_")}},
    {"mkdir", 2, {A("path", ArgKind::kPointer), A("mode", ArgKind::kMode, "S_")}},
    {"mkdirat", 3, {A("dirfd", ArgKind::kFd), A("path", ArgKind::kPointer),
                    A("mode", ArgKind::kMode, "S_")}},
    {"chmod", 2, {A("path", ArgKind::kPointer), A("mode", ArgKind::kMode, "S_")}},
    {"fchmod", 2, {A("fd", ArgKind::kFd), A("mode", ArgKind::kMode, "S_")}},
    {"fchmodat", 4, {A("dirfd", ArgKind::kFd), A("path", ArgKind::kPointer),
                     A("mode", ArgKind::kMode, "S_"),
                     A("flags", ArgKind::kAtFlags, "AT_")}},
    {"chown", 3, {A("path", ArgKind::kPointer), A("uid", ArgKind::kUint),
                  A("gid", ArgKind::kUint)}},
    {"fchown", 3, {A("fd", ArgKind::kFd), A("uid", ArgKind::kUint),
                   A("gid", ArgKind::kUint)}},
    {"mmap", 6, {A("addr", ArgKind::kPointer), A("length", ArgKind::kSize),
                 A("prot", ArgKind::kProtFlags, "PROT_"),
                 A("flags", ArgKind::kMapFlags, "MAP_"), A("fd", ArgKind::kFd),
                 A("offset", ArgKind::kUint)}},
    {"mprotect", 3, {A("addr", ArgKind::kPointer), A("len", ArgKind::kSize),
                     A("prot", ArgKind::kProtFlags, "PROT_")}},
    {"munmap", 2, {A("addr", ArgKind::kPointer), A("len", ArgKind::kSize)}},
    {"mremap", 5, {A("old_address", ArgKind::kPointer),
                   A("old_size", ArgKind::kSize), A("new_size", ArgKind::kSize),
                   A("flags", ArgKind::kFlags, "MREMAP_"),
                   A("new_address", ArgKind::kPointer)}},
    {"madvise", 3, {A("addr", ArgKind::kPointer), A("length", ArgKind::kSize),
                    A("advice", ArgKind::kUint, "MADV_")}},
    {"membarrier", 3, {A("cmd", ArgKind::kUint, "MEMBARRIER_"),
                       A("flags", ArgKind::kFlags), A("cpu_id", ArgKind::kUint)}},
    {"brk", 1, {A("addr", ArgKind::kPointer)}},
    {"mlock", 2, {A("addr", ArgKind::kPointer), A("len", ArgKind::kSize)}},
    {"munlock", 2, {A("addr", ArgKind::kPointer), A("len", ArgKind::kSize)}},
    {"mlockall", 1, {A("flags", ArgKind::kFlags)}},
    {"prctl", 5, {A("option", ArgKind::kUint, "PR_"), A("arg2", ArgKind::kUint),
                  A("arg3", ArgKind::kUint), A("arg4", ArgKind::kUint),
                  A("arg5", ArgKind::kUint)}},
    {"clone", 5, {A("flags", ArgKind::kFlags, "CLONE_"),
                  A("stack", ArgKind::kPointer), A("parent_tid", ArgKind::kPointer),
                  A("child_tid", ArgKind::kPointer), A("tls", ArgKind::kPointer)}},
    {"clone3", 2, {A("cl_args", ArgKind::kPointer), A("size", ArgKind::kSize)}},
    {"fork", 0, {}},
    {"vfork", 0, {}},
    {"execve", 3, {A("pathname", ArgKind::kPointer), A("argv", ArgKind::kPointer),
                   A("envp", ArgKind::kPointer)}},
    {"execveat", 5, {A("dirfd", ArgKind::kFd), A("pathname", ArgKind::kPointer),
                     A("argv", ArgKind::kPointer), A("envp", ArgKind::kPointer),
                     A("flags", ArgKind::kAtFlags, "AT_")}},
    {"exit", 1, {A("status", ArgKind::kUint)}},
    {"exit_group", 1, {A("status", ArgKind::kUint)}},
    {"wait4", 4, {A("pid", ArgKind::kPid), A("wstatus", ArgKind::kPointer),
                  A("options", ArgKind::kFlags, "W"), A("rusage", ArgKind::kPointer)}},
    {"waitid", 5, {A("idtype", ArgKind::kUint), A("id", ArgKind::kPid),
                   A("infop", ArgKind::kPointer), A("options", ArgKind::kFlags, "W"),
                   A("rusage", ArgKind::kPointer)}},
    {"kill", 2, {A("pid", ArgKind::kPid), A("sig", ArgKind::kSignal, "SIG")}},
    {"tkill", 2, {A("tid", ArgKind::kPid), A("sig", ArgKind::kSignal, "SIG")}},
    {"tgkill", 3, {A("tgid", ArgKind::kPid), A("tid", ArgKind::kPid),
                   A("sig", ArgKind::kSignal, "SIG")}},
    {"pidfd_send_signal", 4, {A("pidfd", ArgKind::kFd),
                              A("sig", ArgKind::kSignal, "SIG"),
                              A("info", ArgKind::kPointer),
                              A("flags", ArgKind::kFlags)}},
    {"rt_sigaction", 4, {A("signum", ArgKind::kSignal, "SIG"),
                         A("act", ArgKind::kPointer),
                         A("oldact", ArgKind::kPointer), A("sigsetsize", ArgKind::kSize)}},
    {"rt_sigprocmask", 4, {A("how", ArgKind::kUint, "SIG"),
                           A("set", ArgKind::kPointer), A("oldset", ArgKind::kPointer),
                           A("sigsetsize", ArgKind::kSize)}},
    {"rt_sigreturn", 0, {}},
    {"sigaltstack", 2, {A("ss", ArgKind::kPointer), A("old_ss", ArgKind::kPointer)}},
    {"nanosleep", 2, {A("req", ArgKind::kPointer), A("rem", ArgKind::kPointer)}},
    {"clock_nanosleep", 4, {A("clockid", ArgKind::kUint),
                            A("flags", ArgKind::kFlags),
                            A("req", ArgKind::kPointer),
                            A("rem", ArgKind::kPointer)}},
    {"epoll_create1", 1, {A("flags", ArgKind::kFlags, "EPOLL_")}},
    {"epoll_ctl", 4, {A("epfd", ArgKind::kFd), A("op", ArgKind::kUint, "EPOLL_CTL_"),
                      A("fd", ArgKind::kFd), A("event", ArgKind::kPointer)}},
    {"epoll_wait", 4, {A("epfd", ArgKind::kFd), A("events", ArgKind::kPointer),
                       A("maxevents", ArgKind::kUint),
                       A("timeout", ArgKind::kUint)}},
    {"epoll_pwait", 6, {A("epfd", ArgKind::kFd), A("events", ArgKind::kPointer),
                        A("maxevents", ArgKind::kUint), A("timeout", ArgKind::kUint),
                        A("sigmask", ArgKind::kPointer),
                        A("sigsetsize", ArgKind::kSize)}},
    {"eventfd2", 2, {A("initval", ArgKind::kUint), A("flags", ArgKind::kFlags, "EFD_")}},
    {"signalfd4", 4, {A("fd", ArgKind::kFd), A("mask", ArgKind::kPointer),
                      A("sizemask", ArgKind::kSize), A("flags", ArgKind::kFlags, "SFD_")}},
    {"timerfd_create", 2, {A("clockid", ArgKind::kUint),
                           A("flags", ArgKind::kFlags, "TFD_")}},
    {"timerfd_settime", 4, {A("fd", ArgKind::kFd), A("flags", ArgKind::kFlags, "TFD_"),
                            A("new", ArgKind::kPointer), A("old", ArgKind::kPointer)}},
    {"inotify_init1", 1, {A("flags", ArgKind::kFlags, "IN_")}},
    {"inotify_add_watch", 3, {A("fd", ArgKind::kFd), A("path", ArgKind::kPointer),
                              A("mask", ArgKind::kFlags, "IN_")}},
    {"inotify_rm_watch", 2, {A("fd", ArgKind::kFd), A("wd", ArgKind::kUint)}},
    {"futex", 6, {A("uaddr", ArgKind::kPointer), A("op", ArgKind::kUint, "FUTEX_"),
                  A("val", ArgKind::kUint), A("timeout", ArgKind::kPointer),
                  A("uaddr2", ArgKind::kPointer), A("val3", ArgKind::kUint)}},
    {"futex_waitv", 5, {A("waiters", ArgKind::kPointer), A("nr_futexes", ArgKind::kUint),
                        A("flags", ArgKind::kFlags), A("timeout", ArgKind::kPointer),
                        A("clockid", ArgKind::kUint)}},
    {"getrandom", 3, {A("buf", ArgKind::kBuffer), A("buflen", ArgKind::kSize),
                      A("flags", ArgKind::kFlags, "GRND_")}},
    {"memfd_create", 2, {A("name", ArgKind::kPointer),
                         A("flags", ArgKind::kFlags, "MFD_")}},
    {"memfd_secret", 1, {A("flags", ArgKind::kFlags)}},
    {"splice", 6, {A("fd_in", ArgKind::kFd), A("off_in", ArgKind::kPointer),
                   A("fd_out", ArgKind::kFd), A("off_out", ArgKind::kPointer),
                   A("len", ArgKind::kSize), A("flags", ArgKind::kFlags, "SPLICE_F_")}},
    {"tee", 4, {A("fd_in", ArgKind::kFd), A("fd_out", ArgKind::kFd),
                A("len", ArgKind::kSize), A("flags", ArgKind::kFlags, "SPLICE_F_")}},
    {"vmsplice", 4, {A("fd", ArgKind::kFd), A("iov", ArgKind::kPointer),
                     A("nr_segs", ArgKind::kUint),
                     A("flags", ArgKind::kFlags, "SPLICE_F_")}},
    {"sendfile", 4, {A("out_fd", ArgKind::kFd), A("in_fd", ArgKind::kFd),
                     A("offset", ArgKind::kPointer), A("count", ArgKind::kSize)}},
    {"copy_file_range", 6, {A("fd_in", ArgKind::kFd), A("off_in", ArgKind::kPointer),
                            A("fd_out", ArgKind::kFd), A("off_out", ArgKind::kPointer),
                            A("len", ArgKind::kSize), A("flags", ArgKind::kFlags)}},
    {"sched_yield", 0, {}},
    {"sched_setscheduler", 3, {A("pid", ArgKind::kPid), A("policy", ArgKind::kUint),
                               A("param", ArgKind::kPointer)}},
    {"sched_setaffinity", 3, {A("pid", ArgKind::kPid), A("cpusetsize", ArgKind::kSize),
                              A("mask", ArgKind::kPointer)}},
    {"sched_getaffinity", 3, {A("pid", ArgKind::kPid), A("cpusetsize", ArgKind::kSize),
                              A("mask", ArgKind::kPointer)}},
    {"setpriority", 3, {A("which", ArgKind::kUint), A("who", ArgKind::kPid),
                        A("prio", ArgKind::kUint)}},
    {"setuid", 1, {A("uid", ArgKind::kUint)}},
    {"setgid", 1, {A("gid", ArgKind::kUint)}},
    {"setgroups", 2, {A("size", ArgKind::kSize), A("list", ArgKind::kPointer)}},
    {"setresuid", 3, {A("ruid", ArgKind::kUint), A("euid", ArgKind::kUint),
                      A("suid", ArgKind::kUint)}},
    {"setresgid", 3, {A("rgid", ArgKind::kUint), A("egid", ArgKind::kUint),
                      A("sgid", ArgKind::kUint)}},
    {"setrlimit", 2, {A("resource", ArgKind::kUint), A("rlim", ArgKind::kPointer)}},
    {"getrlimit", 2, {A("resource", ArgKind::kUint), A("rlim", ArgKind::kPointer)}},
    {"prlimit64", 4, {A("pid", ArgKind::kPid), A("resource", ArgKind::kUint),
                      A("new_limit", ArgKind::kPointer),
                      A("old_limit", ArgKind::kPointer)}},
    {"getrusage", 2, {A("who", ArgKind::kUint, "RUSAGE_"),
                      A("usage", ArgKind::kPointer)}},
    {"setitimer", 3, {A("which", ArgKind::kUint, "ITIMER_"),
                      A("new", ArgKind::kPointer), A("old", ArgKind::kPointer)}},
    {"umask", 1, {A("mask", ArgKind::kMode, "S_")}},
    {"uname", 1, {A("buf", ArgKind::kPointer)}},
    {"sysinfo", 1, {A("info", ArgKind::kPointer)}},
    {"getcwd", 2, {A("buf", ArgKind::kBuffer), A("size", ArgKind::kSize)}},
    {"chdir", 1, {A("path", ArgKind::kPointer)}},
    {"fchdir", 1, {A("fd", ArgKind::kFd)}},
    {"readlink", 3, {A("path", ArgKind::kPointer), A("buf", ArgKind::kBuffer),
                     A("bufsiz", ArgKind::kSize)}},
    {"readlinkat", 4, {A("dirfd", ArgKind::kFd), A("path", ArgKind::kPointer),
                       A("buf", ArgKind::kBuffer), A("bufsiz", ArgKind::kSize)}},
    {"getdents64", 3, {A("fd", ArgKind::kFd), A("dirent", ArgKind::kBuffer),
                       A("count", ArgKind::kSize)}},
    {"getpid", 0, {}},
    {"getppid", 0, {}},
    {"gettid", 0, {}},
    {"getuid", 0, {}},
    {"geteuid", 0, {}},
    {"getgid", 0, {}},
    {"getegid", 0, {}},
    {"set_tid_address", 1, {A("tidptr", ArgKind::kPointer)}},
    {"set_robust_list", 2, {A("head", ArgKind::kPointer), A("len", ArgKind::kSize)}},
    {"rseq", 4, {A("rseq", ArgKind::kPointer), A("rseq_len", ArgKind::kSize),
                 A("flags", ArgKind::kFlags), A("sig", ArgKind::kSignal, "SIG")}},
    {"unshare", 1, {A("flags", ArgKind::kFlags, "CLONE_")}},
    {"setns", 2, {A("fd", ArgKind::kFd), A("nstype", ArgKind::kFlags, "CLONE_")}},
    {"mount", 5, {A("source", ArgKind::kPointer), A("target", ArgKind::kPointer),
                  A("filesystemtype", ArgKind::kPointer),
                  A("mountflags", ArgKind::kFlags), A("data", ArgKind::kPointer)}},
    {"umount2", 2, {A("target", ArgKind::kPointer), A("flags", ArgKind::kFlags)}},
    {"ptrace", 4, {A("request", ArgKind::kUint, "PTRACE_"),
                   A("pid", ArgKind::kPid), A("addr", ArgKind::kPointer),
                   A("data", ArgKind::kPointer)}},
    {"seccomp", 3, {A("operation", ArgKind::kUint), A("flags", ArgKind::kFlags),
                    A("args", ArgKind::kPointer)}},
    {"bpf", 3, {A("cmd", ArgKind::kUint), A("attr", ArgKind::kPointer),
                A("size", ArgKind::kSize)}},
    {"perf_event_open", 5, {A("attr", ArgKind::kPointer), A("pid", ArgKind::kPid),
                            A("cpu", ArgKind::kUint), A("group_fd", ArgKind::kFd),
                            A("flags", ArgKind::kFlags)}},
    {"userfaultfd", 1, {A("flags", ArgKind::kFlags, "UFFD_")}},
    {"fadvise64", 4, {A("fd", ArgKind::kFd), A("offset", ArgKind::kUint),
                      A("len", ArgKind::kSize), A("advice", ArgKind::kUint, "MADV_")}},
    {"io_setup", 2, {A("nr_events", ArgKind::kUint), A("ctxp", ArgKind::kPointer)}},
    {"io_destroy", 1, {A("ctx", ArgKind::kUint)}},
    {"io_uring_setup", 2, {A("entries", ArgKind::kUint), A("params", ArgKind::kPointer)}},
    {"mq_open", 4, {A("name", ArgKind::kPointer),
                    A("oflag", ArgKind::kOpenFlags, "O_"),
                    A("mode", ArgKind::kMode, "S_"), A("attr", ArgKind::kPointer)}},
    {"acct", 1, {A("filename", ArgKind::kPointer)}},
    {"reboot", 4, {A("magic1", ArgKind::kUint), A("magic2", ArgKind::kUint),
                   A("cmd", ArgKind::kUint), A("arg", ArgKind::kPointer)}},
    {"kexec_load", 4, {A("entry", ArgKind::kUint), A("nr_segments", ArgKind::kUint),
                       A("segments", ArgKind::kPointer), A("flags", ArgKind::kFlags)}},
    {"init_module", 3, {A("module_image", ArgKind::kPointer),
                        A("len", ArgKind::kSize), A("param_values", ArgKind::kPointer)}},
    {"delete_module", 2, {A("name", ArgKind::kPointer), A("flags", ArgKind::kFlags)}},
    {"finit_module", 3, {A("fd", ArgKind::kFd), A("param_values", ArgKind::kPointer),
                         A("flags", ArgKind::kFlags)}},
    {"keyctl", 5, {A("operation", ArgKind::kUint), A("arg2", ArgKind::kUint),
                   A("arg3", ArgKind::kUint), A("arg4", ArgKind::kUint),
                   A("arg5", ArgKind::kUint)}},
    {"add_key", 5, {A("type", ArgKind::kPointer), A("description", ArgKind::kPointer),
                    A("payload", ArgKind::kPointer),
                    A("plen", ArgKind::kSize), A("keyring", ArgKind::kUint)}},
    {"request_key", 4, {A("type", ArgKind::kPointer),
                        A("description", ArgKind::kPointer),
                        A("callout_info", ArgKind::kPointer),
                        A("dest_keyring", ArgKind::kUint)}},
    {"landlock_create_ruleset", 3,
     {A("attr", ArgKind::kPointer), A("size", ArgKind::kSize),
      A("flags", ArgKind::kFlags, "LANDLOCK_CREATE_")}},
    {"landlock_add_rule", 4, {A("ruleset_fd", ArgKind::kFd), A("rule_type", ArgKind::kUint),
                              A("rule_attr", ArgKind::kPointer),
                              A("flags", ArgKind::kFlags)}},
    {"landlock_restrict_self", 2, {A("ruleset_fd", ArgKind::kFd),
                                   A("flags", ArgKind::kFlags)}},
};

const SyscallInfo* FindInfo(std::string_view name) {
  for (const auto& info : kSyscallInfo) {
    if (name == info.name) return &info;
  }
  return nullptr;
}

int SyscallArgCount(std::string_view name) {
  const SyscallInfo* info = FindInfo(name);
  return info ? info->nargs : 6;
}

ArgKind SyscallArgKind(std::string_view name, int index) {
  const SyscallInfo* info = FindInfo(name);
  if (!info || index < 0 || index >= 6) return ArgKind::kUnknown;
  if (index >= info->nargs) return ArgKind::kUnknown;
  return info->args[index].kind;
}

std::string_view SyscallArgName(std::string_view name, int index) {
  const SyscallInfo* info = FindInfo(name);
  if (!info || index < 0 || index >= info->nargs) return "";
  return info->args[index].name;
}

std::string_view SyscallArgConstantPrefix(std::string_view name, int index) {
  const SyscallInfo* info = FindInfo(name);
  if (!info || index < 0 || index >= info->nargs) return "";
  return info->args[index].prefix;
}

bool SyscallArgIsPointer(std::string_view name, int index) {
  ArgKind kind = SyscallArgKind(name, index);
  return kind == ArgKind::kPointer || kind == ArgKind::kBuffer;
}

const NamedConstant* FindConstant(std::string_view name) {
  const auto& index = ConstantIndex();
  auto it = index.find(name);
  return it == index.end() ? nullptr : it->second;
}

std::vector<std::string> AllConstantNames() {
  std::vector<std::string> names;
  names.reserve(std::size(kConstants));
  for (const auto& e : kConstants) names.emplace_back(e.name);
  std::sort(names.begin(), names.end());
  return names;
}

std::optional<long long> LookupConstant(std::string_view name,
                                        std::string_view prefix_hint) {
  std::string_view n = Trim(name);
  if (const NamedConstant* exact = FindConstant(n)) return exact->value;
  std::string upper = ToUpper(n);
  if (const NamedConstant* exact = FindConstant(upper)) return exact->value;
  if (!prefix_hint.empty()) {
    std::string candidate = ToUpper(prefix_hint) + upper;
    if (const NamedConstant* c = FindConstant(candidate)) return c->value;
  }
  // Bare suffixes: "CLOEXEC" -> O_CLOEXEC, "INET" -> AF_INET, etc.
  std::string suffix = upper;
  std::optional<long long> found;
  int matches = 0;
  for (const auto& e : kConstants) {
    std::string_view ename(e.name);
    if (EndsWith(ename, "_" + suffix) || ename == suffix) {
      found = e.value;
      ++matches;
    }
  }
  if (matches == 1) return found;
  return std::nullopt;
}

}  // namespace scgen

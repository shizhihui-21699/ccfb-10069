// Built-in syscall groups and policy resolution.
//
// Groups are deliberately coarse: the generator expands them to concrete
// syscalls and then narrows the result down to what the trace actually used.
// They exist so hand-written policies stay readable ("allow group fs_write").
#include <algorithm>
#include <map>
#include <set>

#include "common.h"
#include "policy.h"

namespace scgen {
namespace {

const std::vector<SyscallGroup> kGroups = {
    {"fs_read",
     {"read", "pread64", "readv", "preadv", "preadv2", "readlink", "readlinkat",
      "getdents64", "stat", "lstat", "fstat", "newfstatat", "statx", "statfs",
      "fstatfs", "access", "faccessat", "faccessat2", "getcwd", "listxattr",
      "llistxattr", "flistxattr", "getxattr", "lgetxattr", "fgetxattr",
      "open", "openat", "openat2", "opendir", "readahead", "sendfile"},
     "read-only filesystem access"},
    {"fs_write",
     {"write", "pwrite64", "writev", "pwritev", "pwritev2", "creat", "truncate",
      "ftruncate", "unlink", "unlinkat", "rename", "renameat", "renameat2",
      "mkdir", "mkdirat", "rmdir", "link", "linkat", "symlink", "symlinkat",
      "chmod", "fchmod", "fchmodat", "fchmodat2", "chown", "fchown",
      "fchownat", "lchown", "utime", "utimes", "utimensat", "fallocate",
      "setxattr", "lsetxattr", "fsetxattr", "removexattr", "lremovexattr",
      "fremovexattr", "sync", "fsync", "fdatasync", "syncfs", "sync_file_range",
      "copy_file_range"},
     "mutating filesystem access"},
    {"fs_meta",
     {"fchdir", "chdir", "chroot", "umask", "umount2", "mount", "statvfs",
      "flock", "fcntl", "ioctl", "lseek", "dup", "dup2", "dup3", "close",
      "close_range", "pipe", "pipe2", "eventfd2", "memfd_create"},
     "file descriptor and metadata operations"},
    {"memory",
     {"brk", "mmap", "munmap", "mremap", "mprotect", "madvise", "mlock",
      "munlock", "mlockall", "munlockall", "msync", "mincore", "membarrier",
      "mlock2", "pkey_mprotect", "pkey_alloc", "pkey_free", "remap_file_pages",
      "process_madvise", "process_mrelease"},
     "address space management"},
    {"net",
     {"socket", "socketpair", "bind", "listen", "accept", "accept4", "connect",
      "getsockname", "getpeername", "sendto", "recvfrom", "sendmsg", "recvmsg",
      "sendmmsg", "recvmmsg", "shutdown", "setsockopt", "getsockopt"},
     "socket operations"},
    {"thread",
     {"clone", "clone3", "futex", "futex_waitv", "set_robust_list",
      "get_robust_list", "set_tid_address", "rseq", "sched_yield",
      "sched_getaffinity", "sched_setaffinity", "sched_getparam",
      "sched_getscheduler", "sched_rr_get_interval", "getcpu", "gettid",
      "exit", "exit_group", "membarrier"},
     "thread creation and synchronisation"},
    {"process",
     {"fork", "vfork", "execve", "execveat", "wait4", "waitid", "kill", "tkill",
      "tgkill", "pidfd_send_signal", "pidfd_open", "pidfd_getfd", "getpid",
      "getppid", "setpgid", "getpgid", "getsid", "setsid", "prctl",
      "prlimit64", "getrlimit", "setrlimit", "getrusage", "times",
      "sched_setscheduler", "sched_setparam", "personality", "unshare", "setns",
      "ptrace", "process_vm_readv", "process_vm_writev"},
     "process lifecycle and control"},
    {"signal",
     {"rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "rt_sigpending",
      "rt_sigtimedwait", "rt_sigqueueinfo", "rt_tgsigqueueinfo", "sigaltstack",
      "signalfd4", "kill", "tkill", "tgkill", "pidfd_send_signal", "alarm",
      "pause", "sigsuspend"},
     "signal handling"},
    {"time",
     {"nanosleep", "clock_nanosleep", "clock_gettime", "clock_getres",
      "clock_settime", "clock_adjtime", "gettimeofday", "settimeofday",
      "time", "adjtimex", "timer_create", "timer_settime", "timer_gettime",
      "timer_delete", "timer_getoverrun", "timerfd_create", "timerfd_settime",
      "timerfd_gettime", "getitimer", "setitimer", "times"},
     "clocks and timers"},
    {"poll",
     {"poll", "ppoll", "select", "pselect6", "epoll_create1", "epoll_ctl",
      "epoll_wait", "epoll_pwait", "epoll_pwait2", "eventfd2", "signalfd4",
      "inotify_init1", "inotify_add_watch", "inotify_rm_watch"},
     "event multiplexing"},
    {"info",
     {"uname", "sysinfo", "getuid", "geteuid", "getgid", "getegid",
      "getgroups", "getrlimit", "getrusage", "gettimeofday", "getpid",
      "getppid", "gettid", "getrandom", "capget", "getcpu", "sched_getaffinity",
      "prlimit64", "readlink", "readlinkat"},
     "read-only process and system information"},
    {"random",
     {"getrandom"},
     "entropy"},
    {"io_uring",
     {"io_uring_setup", "io_uring_enter", "io_uring_register"},
     "io_uring"},
    {"keyring",
     {"add_key", "request_key", "keyctl"},
     "kernel keyring"},
    {"seccomp",
     {"seccomp", "prctl"},
     "sandboxing calls"},
};

}  // namespace

const std::vector<SyscallGroup>& BuiltinGroups() { return kGroups; }

const SyscallGroup* FindGroup(std::string_view name) {
  for (const auto& g : kGroups) {
    if (g.name == name) return &g;
  }
  return nullptr;
}

ResolveResult ResolvePolicy(const Policy& policy, Arch arch) {
  ResolveResult result;
  std::set<std::pair<const Rule*, std::string>> emitted;

  auto add = [&](const Rule* rule, const std::string& name) {
    if (emitted.count({rule, name})) return;
    emitted.insert({rule, name});
    result.resolved.emplace_back(rule, name);
  };

  for (const Rule& rule : policy.rules) {
    if (rule.wildcard) {
      // Wildcards are expanded by the compiler over all known syscalls.
      continue;
    }
    if (rule.syscall_number) {
      std::string_view name = SyscallName(arch, *rule.syscall_number);
      if (name.empty()) {
        // Calls missing from the generated table are still allowed by number;
        // the compiler emits an immediate comparison for them.
        continue;
      }
      add(&rule, std::string(name));
      continue;
    }
    if (!rule.syscall.empty()) {
      int nr = SyscallNumber(arch, rule.syscall);
      if (nr < 0) {
        result.errors.push_back("unknown syscall '" + rule.syscall + "' for " +
                                std::string(ArchName(arch)) +
                                (rule.source_line
                                     ? " (rule at line " +
                                           std::to_string(rule.source_line) + ")"
                                     : ""));
        continue;
      }
      add(&rule, rule.syscall);
      continue;
    }
    for (const std::string& group_name : rule.group) {
      const SyscallGroup* g = FindGroup(group_name);
      if (!g) {
        result.errors.push_back("unknown syscall group '" + group_name + "'" +
                                (rule.source_line
                                     ? " (rule at line " +
                                           std::to_string(rule.source_line) + ")"
                                     : ""));
        continue;
      }
      for (const std::string& member : g->members) {
        if (SyscallNumber(arch, member) < 0) continue;  // not on this arch
        add(&rule, member);
      }
    }
  }
  return result;
}

}  // namespace scgen

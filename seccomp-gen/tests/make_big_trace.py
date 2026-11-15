#!/usr/bin/env python3
"""Generate a synthetic strace log with many distinct syscalls so the
resulting cBPF filter exceeds 255 instructions and exercises jump
trampolines. Output path is taken from argv[1]."""
import sys

# (name, args text) — all benign, resolvable numbers where relevant.
CALLS = [
    ("read", '3, "a", 1'), ("write", '1, "b", 1'), ("open", '"/etc/x", 0'),
    ("close", '3'), ("stat", '"/tmp", 0x7000'), ("fstat", '3, 0x7008'),
    ("lstat", '"/tmp/y", 0x7010'), ("poll", '0x7020, 1, 0'),
    ("lseek", '3, 0, 0'), ("mmap", '0, 4096, 3, 34, -1, 0'),
    ("mprotect", '0x7100, 4096, 1'), ("munmap", '0x7100, 4096'),
    ("brk", '0'), ("rt_sigaction", '15, 0, 0, 8'),
    ("rt_sigprocmask", '0, 0, 0, 8'), ("ioctl", '3, 21531, 0'),
    ("pread64", '3, 0x7200, 64, 0'), ("pwrite64", '3, 0x7200, 64, 0'),
    ("readv", '3, 0x7210, 2'), ("writev", '1, 0x7210, 2'),
    ("access", '"/etc/x", 0'), ("pipe", '0x7220'), ("select", '8, 0, 0, 0, 0'),
    ("sched_yield", ''), ("mremap", '0x7300, 4096, 8192, 1, 0, 0'),
    ("msync", '0x7300, 4096, 4'), ("mincore", '0x7300, 4096, 0x7310'),
    ("madvise", '0x7300, 4096, 3'), ("dup", '3'), ("dup2", '3, 4'),
    ("nanosleep", '0x7400, 0'), ("getpid", ''), ("sendfile", '5, 3, 0, 100'),
    ("socket", '2, 1, 0'), ("connect", '3, 0x7500, 16'),
    ("accept", '3, 0, 0'), ("sendto", '3, "d", 1, 0, 0, 0'),
    ("recvfrom", '3, 0x7600, 64, 0, 0, 0'), ("sendmsg", '3, 0x7610, 0'),
    ("recvmsg", '3, 0x7620, 0'), ("shutdown", '3, 2'), ("bind", '3, 0x7630, 16'),
    ("listen", '3, 16'), ("getsockname", '3, 0x7640, 0x7650'),
    ("getpeername", '3, 0x7660, 0x7670'), ("socketpair", '1, 1, 0, 0x7680'),
    ("setsockopt", '3, 1, 2, 0x7690, 4'), ("getsockopt", '3, 1, 2, 0x76a0, 0x76b0'),
    ("clone", '17, 0, 0, 0, 0'), ("execve", '"/bin/x", 0, 0'),
    ("exit", '0'), ("wait4", '-1, 0, 0, 0'), ("kill", '100, 15'),
    ("uname", '0x7700'), ("fcntl", '3, 1, 0'), ("flock", '3, 8'),
    ("fsync", '3'), ("fdatasync", '3'), ("truncate", '"/tmp/f", 0'),
    ("ftruncate", '3, 0'), ("getdents", '3, 0x7800, 256'),
    ("getcwd", '0x7810, 256'), ("chdir", '"/tmp"'), ("fchdir", '3'),
    ("rename", '"/a", "/b"'), ("mkdir", '"/tmp/d", 493'), ("rmdir", '"/tmp/d"'),
    ("creat", '"/tmp/c", 420'), ("link", '"/a", "/b"'), ("unlink", '"/b"'),
    ("symlink", '"/a", "/b"'), ("readlink", '"/b", 0x7900, 256'),
    ("chmod", '"/a", 420'), ("fchmod", '3, 420'), ("chown", '"/a", 0, 0'),
    ("fchown", '3, 0, 0'), ("lchown", '"/a", 0, 0'), ("umask", '18'),
    ("gettimeofday", '0x7a00, 0'), ("getrlimit", '7, 0x7a10'),
    ("getrusage", '0, 0x7a20'), ("sysinfo", '0x7a30'), ("times", '0x7a40'),
    ("getuid", ''), ("getgid", ''), ("geteuid", ''), ("getegid", ''),
    ("setpgid", '0, 0'), ("getppid", ''), ("getpgrp", ''), ("setsid", ''),
    ("getgroups", '64, 0x7b00'), ("getsid", '100'), ("prctl", '38, 0, 0, 0, 0'),
    ("arch_prctl", '4098, 0x7c00'), ("gettid", ''), ("set_tid_address", '0x7c10'),
    ("restart_syscall", ''), ("fadvise64", '3, 0, 100, 2'),
    ("exit_group", '0'), ("epoll_wait", '5, 0x7d00, 64, -1'),
    ("epoll_ctl", '5, 1, 3, 0x7d10'), ("tgkill", '100, 101, 15'),
    ("utimes", '"/a", 0x7d20'), ("getdents64", '3, 0x7e00, 256'),
    ("openat", '-100, "/etc/x", 0, 0'), ("mkdirat", '-100, "d", 493'),
    ("unlinkat", '-100, "f", 0'), ("renameat", '-100, "a", -100, "b"'),
    ("linkat", '-100, "a", -100, "b", 0'), ("fchmodat", '-100, "f", 420, 0'),
    ("faccessat", '-100, "f", 0, 0'), ("ppoll", '0x7f00, 4, 0, 0, 8'),
    ("unshare", '0x10000000'), ("splice", '3, 0, 4, 0, 0x7f10, 64, 0'),
    ("tee", '3, 4, 64, 0'), ("utimensat", '-100, "f", 0, 0'),
    ("epoll_pwait", '5, 0x7f20, 64, -1, 0, 8'), ("eventfd2", '0, 524288'),
    ("epoll_create1", '524288'), ("dup3", '3, 6, 524288'),
    ("pipe2", '0x7f30, 524288'), ("accept4", '3, 0, 0, 524288'),
    ("recvmmsg", '3, 0x7f40, 1, 0, 0'), ("prlimit64", '0, 7, 0, 0x7f50'),
    ("getrandom", '0x7f60, 32, 1'), ("memfd_create", '"m", 0'),
    ("statx", '-100, "/x", 0, 0, 0x7f70'), ("rseq", '0x7f80, 32, 0, 0'),
    ("clock_gettime", '1, 0x7f90'), ("clock_nanosleep", '1, 0, 0, 0x7fa0, 0'),
    ("futex", '0x7fb0, 0, 0, 0, 0, 0'), ("getcpu", '0x7fc00, 0, 0'),
    ("epoll_create", '64'), ("inotify_init1", '524288'),
    ("timerfd_create", '1, 524288'), ("signalfd4", '-1, 0, 8, 524288'),
]

out = sys.argv[1]
with open(out, "w") as f:
    f.write('1000 0.0 execve("/bin/svc", ["svc"], 0) = 0\n')
    f.write("1000 0.1 SECCMP_READY() = 0\n")
    t = 2000
    for i, (name, args) in enumerate(CALLS):
        tid = 1000 + (i % 4)
        # interleave an unfinished/resumed pair every 20 calls
        if i % 20 == 19:
            f.write(f'{tid} 1.{i} {name}({args}) = 0 <unfinished ...>\n')
            f.write(f'{tid} 1.{i} <... {name} resumed> ) = 0\n')
        else:
            f.write(f'{tid} 1.{i} {name}({args}) = 0\n')
    f.write("1000 9.9 +++ exited with 0 +++\n")
print(f"wrote {out} with {len(CALLS)} distinct syscalls", file=sys.stderr)

// tables.cpp — syscall number tables for x86_64 and aarch64 (asm-generic),
// plus named constants used when resolving strace arguments.
#include "tables.h"

const std::vector<SysEnt> kSyscalls = {
    // name, x86_64, aarch64
    {"read", 0, 63}, {"write", 1, 64}, {"open", 2, -1}, {"close", 3, 57},
    {"stat", 4, -1}, {"fstat", 5, 80}, {"lstat", 6, -1}, {"poll", 7, -1},
    {"lseek", 8, 62}, {"mmap", 9, 222}, {"mprotect", 10, 226}, {"munmap", 11, 215},
    {"brk", 12, 214}, {"rt_sigaction", 13, 134}, {"rt_sigprocmask", 14, 135},
    {"rt_sigreturn", 15, 139}, {"ioctl", 16, 29}, {"pread64", 17, 67},
    {"pwrite64", 18, 68}, {"readv", 19, 65}, {"writev", 20, 66},
    {"access", 21, -1}, {"pipe", 22, -1}, {"select", 23, -1},
    {"sched_yield", 24, 124}, {"mremap", 25, 216}, {"msync", 26, 227},
    {"mincore", 27, 232}, {"madvise", 28, 233}, {"shmget", 29, 194},
    {"shmat", 30, 196}, {"shmctl", 31, 195}, {"dup", 32, 23}, {"dup2", 33, -1},
    {"pause", 34, -1}, {"nanosleep", 35, 101}, {"getitimer", 36, 102},
    {"alarm", 37, -1}, {"setitimer", 38, 103}, {"getpid", 39, 172},
    {"sendfile", 40, 71}, {"socket", 41, 198}, {"connect", 42, 203},
    {"accept", 43, 202}, {"sendto", 44, 206}, {"recvfrom", 45, 207},
    {"sendmsg", 46, 211}, {"recvmsg", 47, 212}, {"shutdown", 48, 210},
    {"bind", 49, 200}, {"listen", 50, 201}, {"getsockname", 51, 204},
    {"getpeername", 52, 205}, {"socketpair", 53, 199}, {"setsockopt", 54, 208},
    {"getsockopt", 55, 209}, {"clone", 56, 220}, {"fork", 57, -1},
    {"vfork", 58, -1}, {"execve", 59, 221}, {"exit", 60, 93},
    {"wait4", 61, 260}, {"kill", 62, 129}, {"uname", 63, 160},
    {"semget", 64, 190}, {"semop", 65, 193}, {"semctl", 66, 191},
    {"shmdt", 67, 197}, {"msgget", 68, 186}, {"msgsnd", 69, 189},
    {"msgrcv", 70, 188}, {"msgctl", 71, 187}, {"fcntl", 72, 25},
    {"flock", 73, 32}, {"fsync", 74, 82}, {"fdatasync", 75, 83},
    {"truncate", 76, 45}, {"ftruncate", 77, 46}, {"getdents", 78, -1},
    {"getcwd", 79, 17}, {"chdir", 80, 49}, {"fchdir", 81, 50},
    {"rename", 82, -1}, {"mkdir", 83, -1}, {"rmdir", 84, -1},
    {"creat", 85, -1}, {"link", 86, -1}, {"unlink", 87, -1},
    {"symlink", 88, -1}, {"readlink", 89, -1}, {"chmod", 90, -1},
    {"fchmod", 91, 52}, {"chown", 92, -1}, {"fchown", 93, 55},
    {"lchown", 94, -1}, {"umask", 95, 166}, {"gettimeofday", 96, 169},
    {"getrlimit", 97, 163}, {"getrusage", 98, 165}, {"sysinfo", 99, 179},
    {"times", 100, 153}, {"ptrace", 101, 117}, {"getuid", 102, 174},
    {"syslog", 103, 116}, {"getgid", 104, 176}, {"setuid", 105, 146},
    {"setgid", 106, 144}, {"geteuid", 107, 175}, {"getegid", 108, 177},
    {"setpgid", 109, 154}, {"getppid", 110, 173}, {"getpgrp", 111, -1},
    {"setsid", 112, 157}, {"setreuid", 113, 145}, {"setregid", 114, 143},
    {"getgroups", 115, 158}, {"setgroups", 116, 159}, {"setresuid", 117, 147},
    {"getresuid", 118, 148}, {"setresgid", 119, 149}, {"getresgid", 120, 150},
    {"getpgid", 121, 155}, {"setfsuid", 122, 151}, {"setfsgid", 123, 152},
    {"getsid", 124, 156}, {"capget", 125, 90}, {"capset", 126, 91},
    {"rt_sigpending", 127, 136}, {"rt_sigtimedwait", 128, 137},
    {"rt_sigqueueinfo", 129, 138}, {"rt_sigsuspend", 130, 133},
    {"sigaltstack", 131, 132}, {"utime", 132, -1}, {"mknod", 133, -1},
    {"uselib", 134, -1}, {"personality", 135, 92}, {"ustat", 136, -1},
    {"statfs", 137, 43}, {"fstatfs", 138, 44}, {"sysfs", 139, -1},
    {"getpriority", 140, 141}, {"setpriority", 141, 140},
    {"sched_setparam", 142, 118}, {"sched_getparam", 143, 121},
    {"sched_setscheduler", 144, 119}, {"sched_getscheduler", 145, 120},
    {"sched_get_priority_max", 146, 125}, {"sched_get_priority_min", 147, 126},
    {"sched_rr_get_interval", 148, 127}, {"mlock", 149, 228},
    {"munlock", 150, 229}, {"mlockall", 151, 230}, {"munlockall", 152, 231},
    {"vhangup", 153, 58}, {"modify_ldt", 154, -1}, {"pivot_root", 155, 41},
    {"_sysctl", 156, -1}, {"prctl", 157, 167}, {"arch_prctl", 158, -1},
    {"adjtimex", 159, 171}, {"setrlimit", 160, 164}, {"chroot", 161, 51},
    {"sync", 162, 81}, {"acct", 163, 89}, {"settimeofday", 164, 170},
    {"mount", 165, 40}, {"umount2", 166, 39}, {"swapon", 167, 224},
    {"swapoff", 168, 225}, {"reboot", 169, 142}, {"sethostname", 170, 161},
    {"setdomainname", 171, 162}, {"iopl", 172, -1}, {"ioperm", 173, -1},
    {"create_module", 174, -1}, {"init_module", 175, 105},
    {"delete_module", 176, 106}, {"get_kernel_syms", 177, -1},
    {"query_module", 178, -1}, {"quotactl", 179, 60}, {"nfsservctl", 180, 42},
    {"getpmsg", 181, -1}, {"putpmsg", 182, -1}, {"afs_syscall", 183, -1},
    {"tuxcall", 184, -1}, {"security", 185, -1}, {"gettid", 186, 178},
    {"readahead", 187, 213}, {"setxattr", 188, 5}, {"lsetxattr", 189, 6},
    {"fsetxattr", 190, 7}, {"getxattr", 191, 8}, {"lgetxattr", 192, 9},
    {"fgetxattr", 193, 10}, {"listxattr", 194, 11}, {"llistxattr", 195, 12},
    {"flistxattr", 196, 13}, {"removexattr", 197, 14}, {"lremovexattr", 198, 15},
    {"fremovexattr", 199, 16}, {"tkill", 200, 130}, {"time", 201, -1},
    {"futex", 202, 98}, {"sched_setaffinity", 203, 122},
    {"sched_getaffinity", 204, 123}, {"set_thread_area", 205, -1},
    {"io_setup", 206, 0}, {"io_destroy", 207, 1}, {"io_getevents", 208, 4},
    {"io_submit", 209, 2}, {"io_cancel", 210, 3}, {"get_thread_area", 211, -1},
    {"lookup_dcookie", 212, 18}, {"epoll_create", 213, -1},
    {"epoll_ctl_old", 214, -1}, {"epoll_wait_old", 215, -1},
    {"remap_file_pages", 216, 234}, {"getdents64", 217, 61},
    {"set_tid_address", 218, 96}, {"restart_syscall", 219, 128},
    {"semtimedop", 220, 192}, {"fadvise64", 221, 223}, {"timer_create", 222, 107},
    {"timer_settime", 223, 110}, {"timer_gettime", 224, 108},
    {"timer_getoverrun", 225, 109}, {"timer_delete", 226, 111},
    {"clock_settime", 227, 112}, {"clock_gettime", 228, 113},
    {"clock_getres", 229, 114}, {"clock_nanosleep", 230, 115},
    {"exit_group", 231, 94}, {"epoll_wait", 232, -1}, {"epoll_ctl", 233, 21},
    {"tgkill", 234, 131}, {"utimes", 235, -1}, {"vserver", 236, -1},
    {"mbind", 237, 235}, {"set_mempolicy", 238, 237},
    {"get_mempolicy", 239, 236}, {"mq_open", 240, 180}, {"mq_unlink", 241, 181},
    {"mq_timedsend", 242, 182}, {"mq_timedreceive", 243, 183},
    {"mq_notify", 244, 184}, {"mq_getsetattr", 245, 185},
    {"kexec_load", 246, 104}, {"waitid", 247, 95}, {"add_key", 248, 217},
    {"request_key", 249, 218}, {"keyctl", 250, 219}, {"ioprio_set", 251, 30},
    {"ioprio_get", 252, 31}, {"inotify_init", 253, -1},
    {"inotify_add_watch", 254, 27}, {"inotify_rm_watch", 255, 28},
    {"migrate_pages", 256, 238}, {"openat", 257, 56}, {"mkdirat", 258, 34},
    {"mknodat", 259, 33}, {"fchownat", 260, 54}, {"futimesat", 261, -1},
    {"newfstatat", 262, 79}, {"unlinkat", 263, 35}, {"renameat", 264, 38},
    {"linkat", 265, 37}, {"symlinkat", 266, 36}, {"readlinkat", 267, 78},
    {"fchmodat", 268, 53}, {"faccessat", 269, 48}, {"pselect6", 270, 72},
    {"ppoll", 271, 73}, {"unshare", 272, 97}, {"set_robust_list", 273, 99},
    {"get_robust_list", 274, 100}, {"splice", 275, 76}, {"tee", 276, 77},
    {"sync_file_range", 277, 84}, {"vmsplice", 278, 75},
    {"move_pages", 279, 239}, {"utimensat", 280, 88}, {"epoll_pwait", 281, 22},
    {"signalfd", 282, -1}, {"timerfd_create", 283, 85}, {"eventfd", 284, -1},
    {"fallocate", 285, 47}, {"timerfd_settime", 286, 86},
    {"timerfd_gettime", 287, 87}, {"accept4", 288, 242}, {"signalfd4", 289, 74},
    {"eventfd2", 290, 19}, {"epoll_create1", 291, 20}, {"dup3", 292, 24},
    {"pipe2", 293, 59}, {"inotify_init1", 294, 26}, {"preadv", 295, 69},
    {"pwritev", 296, 70}, {"rt_tgsigqueueinfo", 297, 240},
    {"perf_event_open", 298, 241}, {"recvmmsg", 299, 243},
    {"fanotify_init", 300, 262}, {"fanotify_mark", 301, 263},
    {"prlimit64", 302, 261}, {"name_to_handle_at", 303, 264},
    {"open_by_handle_at", 304, 265}, {"clock_adjtime", 305, 266},
    {"syncfs", 306, 267}, {"sendmmsg", 307, 269}, {"setns", 308, 268},
    {"getcpu", 309, 168}, {"process_vm_readv", 310, 270},
    {"process_vm_writev", 311, 271}, {"kcmp", 312, 272},
    {"finit_module", 313, 273}, {"sched_setattr", 314, 274},
    {"sched_getattr", 315, 275}, {"renameat2", 316, 276}, {"seccomp", 317, 277},
    {"getrandom", 318, 278}, {"memfd_create", 319, 279},
    {"kexec_file_load", 320, 294}, {"bpf", 321, 280}, {"execveat", 322, 281},
    {"userfaultfd", 323, 282}, {"membarrier", 324, 283}, {"mlock2", 325, 284},
    {"copy_file_range", 326, 285}, {"preadv2", 327, 286},
    {"pwritev2", 328, 287}, {"pkey_mprotect", 329, 288},
    {"pkey_alloc", 330, 289}, {"pkey_free", 331, 290}, {"statx", 332, 291},
    {"io_pgetevents", 333, 292}, {"rseq", 334, 293},
    {"pidfd_send_signal", 424, 424}, {"io_uring_setup", 425, 425},
    {"io_uring_enter", 426, 426}, {"io_uring_register", 427, 427},
    {"open_tree", 428, 428}, {"move_mount", 429, 429}, {"fsopen", 430, 430},
    {"fsconfig", 431, 431}, {"fsmount", 432, 432}, {"fspick", 433, 433},
    {"pidfd_open", 434, 434}, {"clone3", 435, 435}, {"close_range", 436, 436},
    {"openat2", 437, 437}, {"pidfd_getfd", 438, 438}, {"faccessat2", 439, 439},
    {"process_madvise", 440, 440}, {"epoll_pwait2", 441, 441},
    {"mount_setattr", 442, 442}, {"quotactl_fd", 443, 443},
    {"landlock_create_ruleset", 444, 444}, {"landlock_add_rule", 445, 445},
    {"landlock_restrict_self", 446, 446}, {"memfd_secret", 447, -1},
    {"process_mrelease", 448, 448}, {"futex_waitv", 449, 449},
    {"set_mempolicy_home_node", 450, 450},
};

static const std::vector<std::pair<const char*, uint64_t>> kConstants = {
    // socket domains
    {"AF_UNIX", 1}, {"AF_LOCAL", 1}, {"AF_INET", 2}, {"AF_AX25", 3},
    {"AF_IPX", 4}, {"AF_APPLETALK", 5}, {"AF_NETROM", 6}, {"AF_BRIDGE", 7},
    {"AF_ATMPVC", 8}, {"AF_X25", 9}, {"AF_INET6", 10}, {"AF_ROSE", 11},
    {"AF_DECnet", 12}, {"AF_NETBEUI", 13}, {"AF_SECURITY", 14}, {"AF_KEY", 15},
    {"AF_NETLINK", 16}, {"AF_PACKET", 17}, {"AF_ASH", 18}, {"AF_ECONET", 19},
    {"AF_ATMSVC", 20}, {"AF_RDS", 21}, {"AF_SNA", 22}, {"AF_IRDA", 23},
    {"AF_PPPOX", 24}, {"AF_WANPIPE", 25}, {"AF_LLC", 26}, {"AF_IB", 27},
    {"AF_MPLS", 28}, {"AF_CAN", 29}, {"AF_TIPC", 30}, {"AF_BLUETOOTH", 31},
    {"AF_IUCV", 32}, {"AF_RXRPC", 33}, {"AF_ISDN", 34}, {"AF_PHONET", 35},
    {"AF_IEEE802154", 36}, {"AF_CAIF", 37}, {"AF_ALG", 38}, {"AF_NFC", 39},
    {"AF_VSOCK", 40}, {"AF_KCM", 41}, {"AF_QIPCRTR", 42}, {"AF_SMC", 43},
    {"AF_XDP", 44},
    // socket types
    {"SOCK_STREAM", 1}, {"SOCK_DGRAM", 2}, {"SOCK_RAW", 3}, {"SOCK_RDM", 4},
    {"SOCK_SEQPACKET", 5}, {"SOCK_DCCP", 6}, {"SOCK_PACKET", 10},
    {"SOCK_CLOEXEC", 0520000}, {"SOCK_NONBLOCK", 0004000},
    // ip protocols
    {"IPPROTO_IP", 0}, {"IPPROTO_ICMP", 1}, {"IPPROTO_TCP", 6},
    {"IPPROTO_UDP", 17}, {"IPPROTO_IPV6", 41}, {"IPPROTO_RAW", 255},
    // open flags
    {"O_RDONLY", 0}, {"O_WRONLY", 1}, {"O_RDWR", 2}, {"O_CREAT", 0100},
    {"O_EXCL", 0200}, {"O_NOCTTY", 0400}, {"O_TRUNC", 01000},
    {"O_APPEND", 02000}, {"O_NONBLOCK", 04000}, {"O_DSYNC", 010000},
    {"O_DIRECT", 040000}, {"O_LARGEFILE", 0100000}, {"O_DIRECTORY", 0200000},
    {"O_NOFOLLOW", 0400000}, {"O_NOATIME", 01000000}, {"O_CLOEXEC", 02000000},
    {"O_SYNC", 04010000}, {"O_PATH", 010000000}, {"O_TMPFILE", 020000000 | 0200000},
    // at flags
    {"AT_FDCWD", (uint64_t)-100}, {"AT_SYMLINK_NOFOLLOW", 0x100},
    {"AT_REMOVEDIR", 0x200}, {"AT_SYMLINK_FOLLOW", 0x400},
    {"AT_EMPTY_PATH", 0x1000},
    // fcntl
    {"F_DUPFD", 0}, {"F_GETFD", 1}, {"F_SETFD", 2}, {"F_GETFL", 3},
    {"F_SETFL", 4}, {"F_GETLK", 5}, {"F_SETLK", 6}, {"F_SETLKW", 7},
    {"F_SETOWN", 8}, {"F_GETOWN", 9}, {"F_SETSIG", 10}, {"F_GETSIG", 11},
    {"F_DUPFD_CLOEXEC", 1030}, {"F_SETPIPE_SZ", 1031}, {"F_GETPIPE_SZ", 1032},
    {"F_ADD_SEALS", 1033}, {"F_GET_SEALS", 1034},
    // prctl
    {"PR_SET_PDEATHSIG", 1}, {"PR_GET_PDEATHSIG", 2}, {"PR_GET_DUMPABLE", 3},
    {"PR_SET_DUMPABLE", 4}, {"PR_GET_KEEPCAPS", 7}, {"PR_SET_KEEPCAPS", 8},
    {"PR_SET_NAME", 15}, {"PR_GET_NAME", 16}, {"PR_GET_SECCOMP", 21},
    {"PR_SET_SECCOMP", 22}, {"PR_CAPBSET_READ", 23}, {"PR_CAPBSET_DROP", 24},
    {"PR_SET_TIMERSLACK", 29}, {"PR_GET_TIMERSLACK", 30},
    {"PR_SET_CHILD_SUBREAPER", 36}, {"PR_GET_CHILD_SUBREAPER", 37},
    {"PR_SET_NO_NEW_PRIVS", 38}, {"PR_GET_NO_NEW_PRIVS", 39},
    {"PR_SET_PTRACER", 0x59616d61},
    {"SECCOMP_MODE_STRICT", 1}, {"SECCOMP_MODE_FILTER", 2},
    // ptrace
    {"PTRACE_TRACEME", 0}, {"PTRACE_PEEKTEXT", 1}, {"PTRACE_PEEKDATA", 2},
    {"PTRACE_CONT", 7}, {"PTRACE_ATTACH", 16}, {"PTRACE_DETACH", 17},
    {"PTRACE_SYSCALL", 24}, {"PTRACE_SETOPTIONS", 0x4200},
    {"PTRACE_GETEVENTMSG", 0x4201}, {"PTRACE_GETSIGINFO", 0x4202},
    // socket options
    {"SOL_SOCKET", 1}, {"SO_REUSEADDR", 2}, {"SO_TYPE", 3}, {"SO_ERROR", 4},
    {"SO_BROADCAST", 6}, {"SO_SNDBUF", 7}, {"SO_RCVBUF", 8},
    {"SO_KEEPALIVE", 9}, {"SO_OOBINLINE", 10}, {"SO_LINGER", 13},
    {"SO_PASSCRED", 16}, {"SO_PEERCRED", 17}, {"SO_RCVTIMEO", 20},
    {"SO_SNDTIMEO", 21}, {"SO_TIMESTAMP", 29}, {"SO_BUSY_POLL", 46},
    {"SOL_TCP", 6}, {"SOL_UDP", 17}, {"SOL_IPV6", 41},
    {"TCP_NODELAY", 1}, {"TCP_KEEPIDLE", 4}, {"TCP_KEEPINTVL", 5},
    {"TCP_KEEPCNT", 6}, {"TCP_INFO", 11}, {"TCP_QUICKACK", 12},
    {"TCP_CONGESTION", 13}, {"TCP_USER_TIMEOUT", 18}, {"TCP_FASTOPEN", 23},
    // ioctls
    {"TCGETS", 0x5401}, {"TCSETS", 0x5402}, {"TCSETSW", 0x5403},
    {"TCSETSF", 0x5404}, {"TCGETA", 0x5405}, {"TIOCSCTTY", 0x540E},
    {"TIOCGPGRP", 0x540F}, {"TIOCSPGRP", 0x5410}, {"TIOCOUTQ", 0x5411},
    {"TIOCGWINSZ", 0x5413}, {"TIOCSWINSZ", 0x5414}, {"TIOCMGET", 0x5415},
    {"FIONREAD", 0x541B}, {"TIOCINQ", 0x541B}, {"TIOCNOTTY", 0x5422},
    {"FIONBIO", 0x5421}, {"FIONCLEX", 0x5450}, {"FIOCLEX", 0x5451},
    {"FIOASYNC", 0x5452}, {"SIOCADDRT", 0x890B}, {"SIOCDELRT", 0x890C},
    {"SIOCGIFCONF", 0x8912}, {"SIOCGIFFLAGS", 0x8913}, {"SIOCGIFADDR", 0x8915},
    {"SIOCGIFNETMASK", 0x891B}, {"SIOCGIFMTU", 0x8921},
    {"SIOCGIFHWADDR", 0x8927}, {"KDSETMODE", 0x4B3A}, {"KDSKBMODE", 0x4B45},
    {"VT_OPENQRY", 0x5600}, {"VT_GETMODE", 0x5601}, {"VT_SETMODE", 0x5602},
    {"VT_RELDISP", 0x5605}, {"VT_ACTIVATE", 0x5606}, {"VT_WAITACTIVE", 0x5607},
    // futex
    {"FUTEX_WAIT", 0}, {"FUTEX_WAKE", 1}, {"FUTEX_FD", 2}, {"FUTEX_REQUEUE", 3},
    {"FUTEX_CMP_REQUEUE", 4}, {"FUTEX_WAKE_OP", 5}, {"FUTEX_WAIT_BITSET", 9},
    {"FUTEX_PRIVATE_FLAG", 128}, {"FUTEX_CLOCK_REALTIME", 256},
    // clone flags
    {"CLONE_VM", 0x100}, {"CLONE_FS", 0x200}, {"CLONE_FILES", 0x400},
    {"CLONE_SIGHAND", 0x800}, {"CLONE_PIDFD", 0x1000}, {"CLONE_PTRACE", 0x2000},
    {"CLONE_VFORK", 0x4000}, {"CLONE_PARENT", 0x8000}, {"CLONE_THREAD", 0x10000},
    {"CLONE_NEWNS", 0x20000}, {"CLONE_SYSVSEM", 0x40000},
    {"CLONE_SETTLS", 0x80000}, {"CLONE_PARENT_SETTID", 0x100000},
    {"CLONE_CHILD_CLEARTID", 0x200000}, {"CLONE_DETACHED", 0x400000},
    {"CLONE_UNTRACED", 0x800000}, {"CLONE_CHILD_SETTID", 0x1000000},
    {"CLONE_NEWCGROUP", 0x2000000}, {"CLONE_NEWUTS", 0x4000000},
    {"CLONE_NEWIPC", 0x8000000}, {"CLONE_NEWUSER", 0x10000000},
    {"CLONE_NEWPID", 0x20000000}, {"CLONE_NEWNET", 0x40000000},
    {"CLONE_IO", 0x80000000},
    // mmap
    {"PROT_NONE", 0}, {"PROT_READ", 1}, {"PROT_WRITE", 2}, {"PROT_EXEC", 4},
    {"MAP_SHARED", 1}, {"MAP_PRIVATE", 2}, {"MAP_FIXED", 0x10},
    {"MAP_ANONYMOUS", 0x20}, {"MAP_GROWSDOWN", 0x100}, {"MAP_DENYWRITE", 0x800},
    {"MAP_EXECUTABLE", 0x1000}, {"MAP_LOCKED", 0x2000}, {"MAP_NORESERVE", 0x4000},
    {"MAP_POPULATE", 0x8000}, {"MAP_NONBLOCK", 0x10000}, {"MAP_STACK", 0x20000},
    {"MAP_HUGETLB", 0x40000},
    // madvise
    {"MADV_NORMAL", 0}, {"MADV_RANDOM", 1}, {"MADV_SEQUENTIAL", 2},
    {"MADV_WILLNEED", 3}, {"MADV_DONTNEED", 4}, {"MADV_FREE", 8},
    {"MADV_MERGEABLE", 12}, {"MADV_UNMERGEABLE", 13}, {"MADV_HUGEPAGE", 14},
    {"MADV_NOHUGEPAGE", 15}, {"MADV_DONTDUMP", 16}, {"MADV_DODUMP", 17},
    // epoll
    {"EPOLL_CTL_ADD", 1}, {"EPOLL_CTL_DEL", 2}, {"EPOLL_CTL_MOD", 3},
    {"EPOLLIN", 1}, {"EPOLLPRI", 2}, {"EPOLLOUT", 4}, {"EPOLLERR", 8},
    {"EPOLLHUP", 0x10}, {"EPOLLRDHUP", 0x2000}, {"EPOLLET", 0x80000000},
    {"EPOLLONESHOT", 0x40000000}, {"EPOLL_CLOEXEC", 02000000},
    // clocks
    {"CLOCK_REALTIME", 0}, {"CLOCK_MONOTONIC", 1},
    {"CLOCK_PROCESS_CPUTIME_ID", 2}, {"CLOCK_THREAD_CPUTIME_ID", 3},
    {"CLOCK_MONOTONIC_RAW", 4}, {"CLOCK_REALTIME_COARSE", 5},
    {"CLOCK_MONOTONIC_COARSE", 6}, {"CLOCK_BOOTTIME", 7},
    // eventfd/timerfd/signalfd/inotify init flags
    {"EFD_SEMAPHORE", 1}, {"EFD_CLOEXEC", 02000000}, {"EFD_NONBLOCK", 04000},
    {"TFD_CLOEXEC", 02000000}, {"TFD_NONBLOCK", 04000},
    {"SFD_CLOEXEC", 02000000}, {"SFD_NONBLOCK", 04000},
    {"IN_CLOEXEC", 02000000}, {"IN_NONBLOCK", 04000},
    // rusage / rlimit
    {"RUSAGE_SELF", 0}, {"RUSAGE_CHILDREN", (uint64_t)-1},
    {"RLIMIT_CPU", 0}, {"RLIMIT_FSIZE", 1}, {"RLIMIT_DATA", 2},
    {"RLIMIT_STACK", 3}, {"RLIMIT_CORE", 4}, {"RLIMIT_RSS", 5},
    {"RLIMIT_NPROC", 6}, {"RLIMIT_NOFILE", 7}, {"RLIMIT_MEMLOCK", 8},
    {"RLIMIT_AS", 9}, {"RLIMIT_LOCKS", 10}, {"RLIMIT_SIGPENDING", 11},
    {"RLIMIT_MSGQUEUE", 12}, {"RLIMIT_NICE", 13}, {"RLIMIT_RTPRIO", 14},
    {"RLIMIT_RTTIME", 15},
    // shutdown / msg
    {"SHUT_RD", 0}, {"SHUT_WR", 1}, {"SHUT_RDWR", 2},
    {"MSG_OOB", 1}, {"MSG_PEEK", 2}, {"MSG_DONTROUTE", 4}, {"MSG_CTRUNC", 8},
    {"MSG_TRUNC", 0x20}, {"MSG_DONTWAIT", 0x40}, {"MSG_EOR", 0x80},
    {"MSG_WAITALL", 0x100}, {"MSG_NOSIGNAL", 0x4000}, {"MSG_MORE", 0x8000},
    // seek / getrandom / wait
    {"SEEK_SET", 0}, {"SEEK_CUR", 1}, {"SEEK_END", 2},
    {"GRND_NONBLOCK", 1}, {"GRND_RANDOM", 2},
    {"WNOHANG", 1}, {"WUNTRACED", 2}, {"WEXITED", 4}, {"WCONTINUED", 8},
    {"WNOWAIT", 0x1000000}, {"__WALL", 0x40000000}, {"__WCLONE", 0x80000000},
    // signals (a few, for rt_sigaction args etc.)
    {"SIGHUP", 1}, {"SIGINT", 2}, {"SIGQUIT", 3}, {"SIGILL", 4},
    {"SIGTRAP", 5}, {"SIGABRT", 6}, {"SIGBUS", 7}, {"SIGFPE", 8},
    {"SIGKILL", 9}, {"SIGUSR1", 10}, {"SIGSEGV", 11}, {"SIGUSR2", 12},
    {"SIGPIPE", 13}, {"SIGALRM", 14}, {"SIGTERM", 15}, {"SIGSTKFLT", 16},
    {"SIGCHLD", 17}, {"SIGCONT", 18}, {"SIGSTOP", 19}, {"SIGTSTP", 20},
    {"SIGTTIN", 21}, {"SIGTTOU", 22}, {"SIGURG", 23}, {"SIGXCPU", 24},
    {"SIGXFSZ", 25}, {"SIGVTALRM", 26}, {"SIGPROF", 27}, {"SIGWINCH", 28},
    {"SIGIO", 29}, {"SIGPWR", 30}, {"SIGSYS", 31},
};

static const std::vector<std::pair<const char*, uint64_t>> kErrnos = {
    {"EPERM", 1}, {"ENOENT", 2}, {"ESRCH", 3}, {"EINTR", 4}, {"EIO", 5},
    {"ENXIO", 6}, {"E2BIG", 7}, {"ENOEXEC", 8}, {"EBADF", 9}, {"ECHILD", 10},
    {"EAGAIN", 11}, {"ENOMEM", 12}, {"EACCES", 13}, {"EFAULT", 14},
    {"EBUSY", 16}, {"EEXIST", 17}, {"ENODEV", 19}, {"ENOTDIR", 20},
    {"EISDIR", 21}, {"EINVAL", 22}, {"ENFILE", 23}, {"EMFILE", 24},
    {"ENOTTY", 25}, {"EFBIG", 27}, {"ENOSPC", 28}, {"ESPIPE", 29},
    {"EROFS", 30}, {"EMLINK", 31}, {"EPIPE", 32}, {"ERANGE", 34},
    {"ENOSYS", 38}, {"ENOTSUP", 95},
};

static std::unordered_map<std::string, uint64_t> build_map(
    const std::vector<std::pair<const char*, uint64_t>>& v) {
    std::unordered_map<std::string, uint64_t> m;
    for (auto& p : v) m.emplace(p.first, p.second);
    return m;
}

const std::unordered_map<std::string, uint64_t>& constants() {
    static const auto m = build_map(kConstants);
    return m;
}

const std::unordered_map<std::string, uint64_t>& errno_names() {
    static const auto m = build_map(kErrnos);
    return m;
}

int32_t sys_nr(const std::string& name, const std::string& arch) {
    for (const auto& e : kSyscalls) {
        if (name == e.name) return arch == "aarch64" ? e.arm64 : e.x64;
    }
    return -1;
}

std::string sys_name(int32_t nr, const std::string& arch) {
    for (const auto& e : kSyscalls) {
        int32_t n = arch == "aarch64" ? e.arm64 : e.x64;
        if (n == nr) return e.name;
    }
    return "";
}

uint32_t audit_arch(const std::string& arch) {
    if (arch == "aarch64") return 0xC00000B7u;  // AUDIT_ARCH_AARCH64
    return 0xC000003Eu;                          // AUDIT_ARCH_X86_64
}

bool valid_arch(const std::string& arch) {
    return arch == "x86_64" || arch == "aarch64";
}

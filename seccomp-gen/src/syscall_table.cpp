// SPDX-License-Identifier: MIT
#include "syscall_table.h"

namespace scg {

namespace {

// Verified against musl arch/x86_64/bits/syscall.h.in (0..470).
const std::pair<int, const char*> kX86_64[] = {
    {0,"read"},{1,"write"},{2,"open"},{3,"close"},{4,"stat"},{5,"fstat"},
    {6,"lstat"},{7,"poll"},{8,"lseek"},{9,"mmap"},{10,"mprotect"},
    {11,"munmap"},{12,"brk"},{13,"rt_sigaction"},{14,"rt_sigprocmask"},
    {15,"rt_sigreturn"},{16,"ioctl"},{17,"pread64"},{18,"pwrite64"},
    {19,"readv"},{20,"writev"},{21,"access"},{22,"pipe"},{23,"select"},
    {24,"sched_yield"},{25,"mremap"},{26,"msync"},{27,"mincore"},
    {28,"madvise"},{29,"shmget"},{30,"shmat"},{31,"shmctl"},{32,"dup"},
    {33,"dup2"},{34,"pause"},{35,"nanosleep"},{36,"getitimer"},
    {37,"alarm"},{38,"setitimer"},{39,"getpid"},{40,"sendfile"},
    {41,"socket"},{42,"connect"},{43,"accept"},{44,"sendto"},
    {45,"recvfrom"},{46,"sendmsg"},{47,"recvmsg"},{48,"shutdown"},
    {49,"bind"},{50,"listen"},{51,"getsockname"},{52,"getpeername"},
    {53,"socketpair"},{54,"setsockopt"},{55,"getsockopt"},{56,"clone"},
    {57,"fork"},{58,"vfork"},{59,"execve"},{60,"exit"},{61,"wait4"},
    {62,"kill"},{63,"uname"},{64,"semget"},{65,"semop"},{66,"semctl"},
    {67,"shmdt"},{68,"msgget"},{69,"msgsnd"},{70,"msgrcv"},{71,"msgctl"},
    {72,"fcntl"},{73,"flock"},{74,"fsync"},{75,"fdatasync"},
    {76,"truncate"},{77,"ftruncate"},{78,"getdents"},{79,"getcwd"},
    {80,"chdir"},{81,"fchdir"},{82,"rename"},{83,"mkdir"},{84,"rmdir"},
    {85,"creat"},{86,"link"},{87,"unlink"},{88,"symlink"},
    {89,"readlink"},{90,"chmod"},{91,"fchmod"},{92,"chown"},
    {93,"fchown"},{94,"lchown"},{95,"umask"},{96,"gettimeofday"},
    {97,"getrlimit"},{98,"getrusage"},{99,"sysinfo"},{100,"times"},
    {101,"ptrace"},{102,"getuid"},{103,"syslog"},{104,"getgid"},
    {105,"setuid"},{106,"setgid"},{107,"geteuid"},{108,"getegid"},
    {109,"setpgid"},{110,"getppid"},{111,"getpgrp"},{112,"setsid"},
    {113,"setreuid"},{114,"setregid"},{115,"getgroups"},
    {116,"setgroups"},{117,"setresuid"},{118,"getresuid"},
    {119,"setresgid"},{120,"getresgid"},{121,"getpgid"},
    {122,"setfsuid"},{123,"setfsgid"},{124,"getsid"},{125,"capget"},
    {126,"capset"},{127,"rt_sigpending"},{128,"rt_sigtimedwait"},
    {129,"rt_sigqueueinfo"},{130,"rt_sigsuspend"},{131,"sigaltstack"},
    {132,"utime"},{133,"mknod"},{134,"uselib"},{135,"personality"},
    {136,"ustat"},{137,"statfs"},{138,"fstatfs"},{139,"sysfs"},
    {140,"getpriority"},{141,"setpriority"},{142,"sched_setparam"},
    {143,"sched_getparam"},{144,"sched_setscheduler"},
    {145,"sched_getscheduler"},{146,"sched_get_priority_max"},
    {147,"sched_get_priority_min"},{148,"sched_rr_get_interval"},
    {149,"mlock"},{150,"munlock"},{151,"mlockall"},{152,"munlockall"},
    {153,"vhangup"},{154,"modify_ldt"},{155,"pivot_root"},
    {156,"_sysctl"},{157,"prctl"},{158,"arch_prctl"},{159,"adjtimex"},
    {160,"setrlimit"},{161,"chroot"},{162,"sync"},{163,"acct"},
    {164,"settimeofday"},{165,"mount"},{166,"umount2"},{167,"swapon"},
    {168,"swapoff"},{169,"reboot"},{170,"sethostname"},
    {171,"setdomainname"},{172,"iopl"},{173,"ioperm"},
    {174,"create_module"},{175,"init_module"},{176,"delete_module"},
    {177,"get_kernel_syms"},{178,"query_module"},{179,"quotactl"},
    {180,"nfsservctl"},{181,"getpmsg"},{182,"putpmsg"},
    {183,"afs_syscall"},{184,"tuxcall"},{185,"security"},
    {186,"gettid"},{187,"readahead"},{188,"setxattr"},
    {189,"lsetxattr"},{190,"fsetxattr"},{191,"getxattr"},
    {192,"lgetxattr"},{193,"fgetxattr"},{194,"listxattr"},
    {195,"llistxattr"},{196,"flistxattr"},{197,"removexattr"},
    {198,"lremovexattr"},{199,"fremovexattr"},{200,"tkill"},{201,"time"},
    {202,"futex"},{203,"sched_setaffinity"},{204,"sched_getaffinity"},
    {205,"set_thread_area"},{206,"io_setup"},{207,"io_destroy"},
    {208,"io_getevents"},{209,"io_submit"},{210,"io_cancel"},
    {211,"get_thread_area"},{212,"lookup_dcookie"},
    {213,"epoll_create"},{214,"epoll_ctl_old"},{215,"epoll_wait_old"},
    {216,"remap_file_pages"},{217,"getdents64"},
    {218,"set_tid_address"},{219,"restart_syscall"},{220,"semtimedop"},
    {221,"fadvise64"},{222,"timer_create"},{223,"timer_settime"},
    {224,"timer_gettime"},{225,"timer_getoverrun"},{226,"timer_delete"},
    {227,"clock_settime"},{228,"clock_gettime"},{229,"clock_getres"},
    {230,"clock_nanosleep"},{231,"exit_group"},{232,"epoll_wait"},
    {233,"epoll_ctl"},{234,"tgkill"},{235,"utimes"},{236,"vserver"},
    {237,"mbind"},{238,"set_mempolicy"},{239,"get_mempolicy"},
    {240,"mq_open"},{241,"mq_unlink"},{242,"mq_timedsend"},
    {243,"mq_timedreceive"},{244,"mq_notify"},{245,"mq_getsetattr"},
    {246,"kexec_load"},{247,"waitid"},{248,"add_key"},
    {249,"request_key"},{250,"keyctl"},{251,"ioprio_set"},
    {252,"ioprio_get"},{253,"inotify_init"},{254,"inotify_add_watch"},
    {255,"inotify_rm_watch"},{256,"migrate_pages"},{257,"openat"},
    {258,"mkdirat"},{259,"mknodat"},{260,"fchownat"},{261,"futimesat"},
    {262,"newfstatat"},{263,"unlinkat"},{264,"renameat"},{265,"linkat"},
    {266,"symlinkat"},{267,"readlinkat"},{268,"fchmodat"},
    {269,"faccessat"},{270,"pselect6"},{271,"ppoll"},{272,"unshare"},
    {273,"set_robust_list"},{274,"get_robust_list"},{275,"splice"},
    {276,"tee"},{277,"sync_file_range"},{278,"vmsplice"},
    {279,"move_pages"},{280,"utimensat"},{281,"epoll_pwait"},
    {282,"signalfd"},{283,"timerfd_create"},{284,"eventfd"},
    {285,"fallocate"},{286,"timerfd_settime"},{287,"timerfd_gettime"},
    {288,"accept4"},{289,"signalfd4"},{290,"eventfd2"},
    {291,"epoll_create1"},{292,"dup3"},{293,"pipe2"},
    {294,"inotify_init1"},{295,"preadv"},{296,"pwritev"},
    {297,"rt_tgsigqueueinfo"},{298,"perf_event_open"},
    {299,"recvmmsg"},{300,"fanotify_init"},{301,"fanotify_mark"},
    {302,"prlimit64"},{303,"name_to_handle_at"},{304,"open_by_handle_at"},
    {305,"clock_adjtime"},{306,"syncfs"},{307,"sendmmsg"},{308,"setns"},
    {309,"getcpu"},{310,"process_vm_readv"},{311,"process_vm_writev"},
    {312,"kcmp"},{313,"finit_module"},{314,"sched_setattr"},
    {315,"sched_getattr"},{316,"renameat2"},{317,"seccomp"},
    {318,"getrandom"},{319,"memfd_create"},{320,"kexec_file_load"},
    {321,"bpf"},{322,"execveat"},{323,"userfaultfd"},{324,"membarrier"},
    {325,"mlock2"},{326,"copy_file_range"},{327,"preadv2"},
    {328,"pwritev2"},{329,"pkey_mprotect"},{330,"pkey_alloc"},
    {331,"pkey_free"},{332,"statx"},{333,"io_pgetevents"},{334,"rseq"},
    {335,"uretprobe"},{336,"uprobe"},
    // 337..423: gap (no generic numbers on x86_64)
    {424,"pidfd_send_signal"},{425,"io_uring_setup"},
    {426,"io_uring_enter"},{427,"io_uring_register"},{428,"open_tree"},
    {429,"move_mount"},{430,"fsopen"},{431,"fsconfig"},{432,"fsmount"},
    {433,"fspick"},{434,"pidfd_open"},{435,"clone3"},
    {436,"close_range"},{437,"openat2"},{438,"pidfd_getfd"},
    {439,"faccessat2"},{440,"process_madvise"},{441,"epoll_pwait2"},
    {442,"mount_setattr"},{443,"quotactl_fd"},
    {444,"landlock_create_ruleset"},{445,"landlock_add_rule"},
    {446,"landlock_restrict_self"},{447,"memfd_secret"},
    {448,"process_mrelease"},{449,"futex_waitv"},
    {450,"set_mempolicy_home_node"},{451,"cachestat"},{452,"fchmodat2"},
    {453,"map_shadow_stack"},{454,"futex_wake"},{455,"futex_wait"},
    {456,"futex_requeue"},{457,"statmount"},{458,"listmount"},
    {459,"lsm_get_self_attr"},{460,"lsm_set_self_attr"},
    {461,"lsm_list_modules"},{462,"mseal"},{463,"setxattrat"},
    {464,"getxattrat"},{465,"listxattrat"},{466,"removexattrat"},
    {467,"open_tree_attr"},{468,"file_getattr"},{469,"file_setattr"},
    {470,"listns"},
};

// Verified against musl arch/aarch64/bits/syscall.h.in (0..470).
const std::pair<int, const char*> kAarch64[] = {
    {0,"io_setup"},{1,"io_destroy"},{2,"io_submit"},{3,"io_cancel"},
    {4,"io_getevents"},{5,"setxattr"},{6,"lsetxattr"},{7,"fsetxattr"},
    {8,"getxattr"},{9,"lgetxattr"},{10,"fgetxattr"},{11,"listxattr"},
    {12,"llistxattr"},{13,"flistxattr"},{14,"removexattr"},
    {15,"lremovexattr"},{16,"fremovexattr"},{17,"getcwd"},
    {18,"lookup_dcookie"},{19,"eventfd2"},{20,"epoll_create1"},
    {21,"epoll_ctl"},{22,"epoll_pwait"},{23,"dup"},{24,"dup3"},
    {25,"fcntl"},{26,"inotify_init1"},{27,"inotify_add_watch"},
    {28,"inotify_rm_watch"},{29,"ioctl"},{30,"ioprio_set"},
    {31,"ioprio_get"},{32,"flock"},{33,"mknodat"},{34,"mkdirat"},
    {35,"unlinkat"},{36,"symlinkat"},{37,"linkat"},{38,"renameat"},
    {39,"umount2"},{40,"mount"},{41,"pivot_root"},{42,"nfsservctl"},
    {43,"statfs"},{44,"fstatfs"},{45,"truncate"},{46,"ftruncate"},
    {47,"fallocate"},{48,"faccessat"},{49,"chdir"},{50,"fchdir"},
    {51,"chroot"},{52,"fchmod"},{53,"fchmodat"},{54,"fchownat"},
    {55,"fchown"},{56,"openat"},{57,"close"},{58,"vhangup"},
    {59,"pipe2"},{60,"quotactl"},{61,"getdents64"},{62,"lseek"},
    {63,"read"},{64,"write"},{65,"readv"},{66,"writev"},{67,"pread64"},
    {68,"pwrite64"},{69,"preadv"},{70,"pwritev"},{71,"sendfile"},
    {72,"pselect6"},{73,"ppoll"},{74,"signalfd4"},{75,"vmsplice"},
    {76,"splice"},{77,"tee"},{78,"readlinkat"},{79,"newfstatat"},
    {80,"fstat"},{81,"sync"},{82,"fsync"},{83,"fdatasync"},
    {84,"sync_file_range"},{85,"timerfd_create"},{86,"timerfd_settime"},
    {87,"timerfd_gettime"},{88,"utimensat"},{89,"acct"},{90,"capget"},
    {91,"capset"},{92,"personality"},{93,"exit"},{94,"exit_group"},
    {95,"waitid"},{96,"set_tid_address"},{97,"unshare"},{98,"futex"},
    {99,"set_robust_list"},{100,"get_robust_list"},{101,"nanosleep"},
    {102,"getitimer"},{103,"setitimer"},{104,"kexec_load"},
    {105,"init_module"},{106,"delete_module"},{107,"timer_create"},
    {108,"timer_gettime"},{109,"timer_getoverrun"},
    {110,"timer_settime"},{111,"timer_delete"},{112,"clock_settime"},
    {113,"clock_gettime"},{114,"clock_getres"},{115,"clock_nanosleep"},
    {116,"syslog"},{117,"ptrace"},{118,"sched_setparam"},
    {119,"sched_setscheduler"},{120,"sched_getscheduler"},
    {121,"sched_getparam"},{122,"sched_setaffinity"},
    {123,"sched_getaffinity"},{124,"sched_yield"},
    {125,"sched_get_priority_max"},{126,"sched_get_priority_min"},
    {127,"sched_rr_get_interval"},{128,"restart_syscall"},
    {129,"kill"},{130,"tkill"},{131,"tgkill"},{132,"sigaltstack"},
    {133,"rt_sigsuspend"},{134,"rt_sigaction"},
    {135,"rt_sigprocmask"},{136,"rt_sigpending"},
    {137,"rt_sigtimedwait"},{138,"rt_sigqueueinfo"},
    {139,"rt_sigreturn"},{140,"setpriority"},{141,"getpriority"},
    {142,"reboot"},{143,"setregid"},{144,"setgid"},{145,"setreuid"},
    {146,"setuid"},{147,"setresuid"},{148,"getresuid"},
    {149,"setresgid"},{150,"getresgid"},{151,"setfsuid"},
    {152,"setfsgid"},{153,"times"},{154,"setpgid"},{155,"getpgid"},
    {156,"getsid"},{157,"setsid"},{158,"getgroups"},{159,"setgroups"},
    {160,"uname"},{161,"sethostname"},{162,"setdomainname"},
    {163,"getrlimit"},{164,"setrlimit"},{165,"getrusage"},{166,"umask"},
    {167,"prctl"},{168,"getcpu"},{169,"gettimeofday"},
    {170,"settimeofday"},{171,"adjtimex"},{172,"getpid"},
    {173,"getppid"},{174,"getuid"},{175,"geteuid"},{176,"getgid"},
    {177,"getegid"},{178,"gettid"},{179,"sysinfo"},{180,"mq_open"},
    {181,"mq_unlink"},{182,"mq_timedsend"},{183,"mq_timedreceive"},
    {184,"mq_notify"},{185,"mq_getsetattr"},{186,"msgget"},
    {187,"msgctl"},{188,"msgrcv"},{189,"msgsnd"},{190,"semget"},
    {191,"semctl"},{192,"semtimedop"},{193,"semop"},{194,"shmget"},
    {195,"shmctl"},{196,"shmat"},{197,"shmdt"},{198,"socket"},
    {199,"socketpair"},{200,"bind"},{201,"listen"},{202,"accept"},
    {203,"connect"},{204,"getsockname"},{205,"getpeername"},
    {206,"sendto"},{207,"recvfrom"},{208,"setsockopt"},
    {209,"getsockopt"},{210,"shutdown"},{211,"sendmsg"},{212,"recvmsg"},
    {213,"readahead"},{214,"brk"},{215,"munmap"},{216,"mremap"},
    {217,"add_key"},{218,"request_key"},{219,"keyctl"},{220,"clone"},
    {221,"execve"},{222,"mmap"},{223,"fadvise64"},{224,"swapon"},
    {225,"swapoff"},{226,"mprotect"},{227,"msync"},{228,"mlock"},
    {229,"munlock"},{230,"mlockall"},{231,"munlockall"},
    {232,"mincore"},{233,"madvise"},{234,"remap_file_pages"},
    {235,"mbind"},{236,"get_mempolicy"},{237,"set_mempolicy"},
    {238,"migrate_pages"},{239,"move_pages"},
    {240,"rt_tgsigqueueinfo"},{241,"perf_event_open"},{242,"accept4"},
    {243,"recvmmsg"},
    // 244..259: gap on aarch64
    {260,"wait4"},{261,"prlimit64"},{262,"fanotify_init"},
    {263,"fanotify_mark"},{264,"name_to_handle_at"},
    {265,"open_by_handle_at"},{266,"clock_adjtime"},{267,"syncfs"},
    {268,"setns"},{269,"sendmmsg"},{270,"process_vm_readv"},
    {271,"process_vm_writev"},{272,"kcmp"},{273,"finit_module"},
    {274,"sched_setattr"},{275,"sched_getattr"},{276,"renameat2"},
    {277,"seccomp"},{278,"getrandom"},{279,"memfd_create"},{280,"bpf"},
    {281,"execveat"},{282,"userfaultfd"},{283,"membarrier"},
    {284,"mlock2"},{285,"copy_file_range"},{286,"preadv2"},
    {287,"pwritev2"},{288,"pkey_mprotect"},{289,"pkey_alloc"},
    {290,"pkey_free"},{291,"statx"},{292,"io_pgetevents"},{293,"rseq"},
    {294,"kexec_file_load"},
    // 295..423: gap on aarch64
    {424,"pidfd_send_signal"},{425,"io_uring_setup"},
    {426,"io_uring_enter"},{427,"io_uring_register"},{428,"open_tree"},
    {429,"move_mount"},{430,"fsopen"},{431,"fsconfig"},{432,"fsmount"},
    {433,"fspick"},{434,"pidfd_open"},{435,"clone3"},
    {436,"close_range"},{437,"openat2"},{438,"pidfd_getfd"},
    {439,"faccessat2"},{440,"process_madvise"},{441,"epoll_pwait2"},
    {442,"mount_setattr"},{443,"quotactl_fd"},
    {444,"landlock_create_ruleset"},{445,"landlock_add_rule"},
    {446,"landlock_restrict_self"},{447,"memfd_secret"},
    {448,"process_mrelease"},{449,"futex_waitv"},
    {450,"set_mempolicy_home_node"},{451,"cachestat"},{452,"fchmodat2"},
    {453,"map_shadow_stack"},{454,"futex_wake"},{455,"futex_wait"},
    {456,"futex_requeue"},{457,"statmount"},{458,"listmount"},
    {459,"lsm_get_self_attr"},{460,"lsm_set_self_attr"},
    {461,"lsm_list_modules"},{462,"mseal"},{463,"setxattrat"},
    {464,"getxattrat"},{465,"listxattrat"},{466,"removexattrat"},
    {467,"open_tree_attr"},{468,"file_getattr"},{469,"file_setattr"},
    {470,"listns"},
};

// Symbolic constants strace prints in arguments. Values are the Linux
// userspace ABI values, identical on x86_64 and aarch64.
const std::pair<const char*, uint64_t> kConstants[] = {
    // socket(2) address families (also protocol families, same values)
    {"AF_UNSPEC",0},{"AF_UNIX",1},{"AF_LOCAL",1},{"AF_INET",2},{"AF_AX25",3},
    {"AF_IPX",4},{"AF_APPLETALK",5},{"AF_NETROM",6},{"AF_BRIDGE",7},
    {"AF_ATMPVC",8},{"AF_X25",9},{"AF_INET6",10},{"AF_ROSE",11},
    {"AF_NETBEUI",13},{"AF_SECURITY",14},{"AF_KEY",15},{"AF_NETLINK",16},
    {"AF_ROUTE",16},{"AF_PACKET",17},{"AF_ASH",18},{"AF_ECONET",19},
    {"AF_ATMSVC",20},{"AF_RDS",21},{"AF_SNA",22},{"AF_IRDA",23},
    {"AF_PPPOX",24},{"AF_WANPIPE",25},{"AF_LLC",26},{"AF_CAN",29},
    {"AF_TIPC",30},{"AF_BLUETOOTH",31},{"AF_IUCV",32},{"AF_RXRPC",33},
    {"AF_ISDN",34},{"AF_PHONET",35},{"AF_IEEE802154",36},{"AF_CAIF",37},
    {"AF_ALG",38},{"AF_NFC",39},{"AF_VSOCK",40},{"AF_KCM",41},
    {"AF_QIPCRTR",42},{"AF_SMC",43},{"AF_XDP",44},{"AF_MCTP",45},
    {"PF_UNIX",1},{"PF_INET",2},{"PF_INET6",10},{"PF_NETLINK",16},
    {"PF_PACKET",17},{"PF_BLUETOOTH",31},{"PF_VSOCK",40},
    // socket types (accept SOCK_CLOEXEC/SOCK_NONBLOCK OR-masks)
    {"SOCK_STREAM",1},{"SOCK_DGRAM",2},{"SOCK_RAW",3},{"SOCK_RDM",4},
    {"SOCK_SEQPACKET",5},{"SOCK_DCCP",6},{"SOCK_PACKET",10},
    {"SOCK_CLOEXEC",02000000},{"SOCK_NONBLOCK",04000},
    // errno values 1..34 (asm-generic, shared by both arches)
    {"EPERM",1},{"ENOENT",2},{"ESRCH",3},{"EINTR",4},{"EIO",5},
    {"ENXIO",6},{"E2BIG",7},{"ENOEXEC",8},{"EBADF",9},{"ECHILD",10},
    {"EAGAIN",11},{"EWOULDBLOCK",11},{"ENOMEM",12},{"EACCES",13},
    {"EFAULT",14},{"ENOTBLK",15},{"EBUSY",16},{"EEXIST",17},
    {"EXDEV",18},{"ENODEV",19},{"ENOTDIR",20},{"EISDIR",21},{"EINVAL",22},
    {"ENFILE",23},{"EMFILE",24},{"ENOTTY",25},{"ETXTBSY",26},
    {"EFBIG",27},{"ENOSPC",28},{"ESPIPE",29},{"EROFS",30},{"EMLINK",31},
    {"EPIPE",32},{"EDOM",33},{"ERANGE",34},
    // open/openat flags
    {"O_RDONLY",0},{"O_WRONLY",1},{"O_RDWR",2},{"O_CREAT",0100},
    {"O_EXCL",0200},{"O_NOCTTY",0400},{"O_TRUNC",01000},
    {"O_APPEND",02000},{"O_NONBLOCK",04000},{"O_DSYNC",010000},
    {"O_ASYNC",020000},{"O_DIRECT",040000},{"O_LARGEFILE",0100000},
    {"O_DIRECTORY",0200000},{"O_NOFOLLOW",0400000},{"O_NOATIME",01000000},
    {"O_CLOEXEC",02000000},{"O_SYNC",04010000},{"O_PATH",010000000},
    {"O_TMPFILE",020000000},
    // mmap protection and flags
    {"PROT_NONE",0},{"PROT_READ",1},{"PROT_WRITE",2},{"PROT_EXEC",4},
    {"PROT_GROWSDOWN",0x01000000},{"PROT_GROWSUP",0x02000000},
    {"MAP_SHARED",1},{"MAP_PRIVATE",2},{"MAP_FIXED",0x10},
    {"MAP_ANONYMOUS",0x20},{"MAP_ANON",0x20},{"MAP_32BIT",0x40},
    {"MAP_GROWSDOWN",0x0100},{"MAP_DENYWRITE",0x0800},
    {"MAP_EXECUTABLE",0x1000},{"MAP_LOCKED",0x2000},{"MAP_NORESERVE",0x4000},
    {"MAP_POPULATE",0x8000},{"MAP_NONBLOCK",0x10000},{"MAP_STACK",0x20000},
    {"MAP_HUGETLB",0x40000},{"MAP_UNINITIALIZED",0x4000000},
    // mmap advice / madvise
    {"MADV_NORMAL",0},{"MADV_RANDOM",1},{"MADV_SEQUENTIAL",2},
    {"MADV_WILLNEED",3},{"MADV_DONTNEED",4},{"MADV_FREE",8},
    {"MADV_REMOVE",9},{"MADV_DONTFORK",10},{"MADV_DOFORK",11},
    {"MADV_HUGEPAGE",14},{"MADV_NOHUGEPAGE",15},{"MADV_DONTDUMP",16},
    {"MADV_DODUMP",17},{"MADV_WIPEONFORK",18},{"MADV_KEEPONFORK",19},
    // clone(2) flags
    {"CLONE_VM",0x100},{"CLONE_FS",0x200},{"CLONE_FILES",0x400},
    {"CLONE_SIGHAND",0x800},{"CLONE_PIDFD",0x1000},{"CLONE_PTRACE",0x2000},
    {"CLONE_VFORK",0x4000},{"CLONE_PARENT",0x8000},{"CLONE_THREAD",0x10000},
    {"CLONE_NEWNS",0x20000},{"CLONE_SYSVSEM",0x40000},
    {"CLONE_SETTLS",0x80000},{"CLONE_PARENT_SETTID",0x100000},
    {"CLONE_CHILD_CLEARTID",0x200000},{"CLONE_DETACHED",0x400000},
    {"CLONE_UNTRACED",0x800000},{"CLONE_CHILD_SETTID",0x1000000},
    {"CLONE_NEWCGROUP",0x2000000},{"CLONE_NEWUTS",0x4000000},
    {"CLONE_NEWIPC",0x8000000},{"CLONE_NEWUSER",0x10000000},
    {"CLONE_NEWPID",0x20000000},{"CLONE_NEWNET",0x40000000},
    {"CLONE_IO",0x80000000},
    // futex operations (base op + flags)
    {"FUTEX_WAIT",0},{"FUTEX_WAKE",1},{"FUTEX_FD",2},{"FUTEX_REQUEUE",3},
    {"FUTEX_CMP_REQUEUE",4},{"FUTEX_WAKE_OP",5},{"FUTEX_LOCK_PI",6},
    {"FUTEX_TRYLOCK_PI",7},{"FUTEX_UNLOCK_PI",8},{"FUTEX_WAIT_BITSET",9},
    {"FUTEX_WAKE_BITSET",10},{"FUTEX_WAIT_REQUEUE_PI",11},
    {"FUTEX_CMP_REQUEUE_PI",12},{"FUTEX_LOCK_PI2",13},
    {"FUTEX_PRIVATE_FLAG",128},{"FUTEX_CLOCK_REALTIME",256},
    // fcntl commands
    {"F_DUPFD",0},{"F_GETFD",1},{"F_SETFD",2},{"F_GETFL",3},{"F_SETFL",4},
    {"F_GETLK",5},{"F_SETLK",6},{"F_SETLKW",7},{"F_SETOWN",8},
    {"F_GETOWN",9},{"F_SETSIG",10},{"F_GETSIG",11},{"F_SETOWN_EX",15},
    {"F_GETOWN_EX",16},{"F_DUPFD_CLOEXEC",1030},{"F_ADD_SEALS",1033},
    {"F_GET_SEALS",1034},
    {"FD_CLOEXEC",1},
    // file mode bits (openat mode)
    {"S_ISUID",04000},{"S_ISGID",02000},{"S_ISVTX",01000},
    {"S_IRWXU",0700},{"S_IRUSR",0400},{"S_IWUSR",0200},{"S_IXUSR",0100},
    {"S_IRWXG",0070},{"S_IRGRP",0040},{"S_IWGRP",0020},{"S_IXGRP",0010},
    {"S_IRWXO",0007},{"S_IROTH",0004},{"S_IWOTH",0002},{"S_IXOTH",0001},
    // lseek whence
    {"SEEK_SET",0},{"SEEK_CUR",1},{"SEEK_END",2},{"SEEK_DATA",3},
    {"SEEK_HOLE",4},{"WHENCE_ENUM_NONE",0},
    // shutdown(2) how
    {"SHUT_RD",0},{"SHUT_WR",1},{"SHUT_RDWR",2},
    // socket option levels (setsockopt arg 1)
    {"SOL_SOCKET",1},{"SOL_IP",0},{"SOL_IPV6",41},{"SOL_TCP",6},
    {"SOL_UDP",17},{"SOL_NETLINK",270},
    // common setsockopt names
    {"SO_REUSEADDR",2},{"SO_KEEPALIVE",9},{"SO_BROADCAST",6},
    {"SO_LINGER",13},{"SO_RCVBUF",8},{"SO_SNDBUF",7},{"SO_RCVTIMEO",20},
    {"SO_SNDTIMEO",21},{"SO_ERROR",4},{"SO_TYPE",3},{"SO_ACCEPTCONN",30},
    {"TCP_NODELAY",1},{"IPPROTO_TCP",6},{"IPPROTO_UDP",17},
    {"IPPROTO_ICMP",1},{"IPPROTO_IPV6",41},{"IPPROTO_RAW",255},
    {"IPPROTO_SCTP",132},
    // access/faccessat modes
    {"F_OK",0},{"X_OK",1},{"W_OK",2},{"R_OK",4},
    // AT_* (openat/newfstatat flags and dirfds)
    {"AT_FDCWD",-100},{"AT_SYMLINK_NOFOLLOW",0x100},
    {"AT_REMOVEDIR",0x200},{"AT_SYMLINK_FOLLOW",0x400},
    {"AT_NO_AUTOMOUNT",0x800},{"AT_EMPTY_PATH",0x1000},
    {"AT_STATX_SYNC_AS_STAT",0},{"AT_STATX_FORCE_SYNC",0x2000},
    {"AT_STATX_DONT_SYNC",0x4000},{"AT_RECURSIVE",0x8000},
    // reboot magic/flags
    {"LINUX_REBOOT_MAGIC1",0xfee1dead},
    {"LINUX_REBOOT_MAGIC2",672274793},
    // prctl options (subset)
    {"PR_SET_PDEATHSIG",1},{"PR_GET_PDEATHSIG",2},{"PR_SET_DUMPABLE",4},
    {"PR_GET_DUMPABLE",3},{"PR_SET_NAME",15},{"PR_GET_NAME",16},
    {"PR_SET_NO_NEW_PRIVS",38},{"PR_GET_NO_NEW_PRIVS",39},
    {"PR_SET_SECCOMP",22},{"PR_GET_SECCOMP",21},
    {"PR_CAP_AMBIENT",47},
    // seccomp constants
    {"SECCOMP_MODE_DISABLED",0},{"SECCOMP_MODE_STRICT",1},
    {"SECCOMP_MODE_FILTER",2},
    // rseq / membarrier / limit ids seen occasionally
    {"MEMBARRIER_CMD_QUERY",0},{"MEMBARRIER_CMD_SHARED",1},
    {"MEMBARRIER_CMD_GLOBAL",1},
    // getrandom flags
    {"GRND_NONBLOCK",1},{"GRND_RANDOM",2},
    // epoll event flags
    {"EPOLLIN",0x001},{"EPOLLPRI",0x002},{"EPOLLOUT",0x004},
    {"EPOLLERR",0x008},{"EPOLLHUP",0x010},{"EPOLLRDNORM",0x040},
    {"EPOLLRDBAND",0x080},{"EPOLLWRNORM",0x100},{"EPOLLWRBAND",0x200},
    {"EPOLLMSG",0x400},{"EPOLLET",0x80000000u},
    {"EPOLLONESHOT",0x40000000u},
    // epoll_create1 flags reuse O_CLOEXEC/O_NONBLOCK; add EPOLL_CLOEXEC alias
    {"EPOLL_CLOEXEC",02000000},
    // timerfd / clock ids
    {"CLOCK_REALTIME",0},{"CLOCK_MONOTONIC",1},{"CLOCK_PROCESS_CPUTIME_ID",2},
    {"CLOCK_THREAD_CPUTIME_ID",3},{"CLOCK_MONOTONIC_RAW",4},
    {"CLOCK_REALTIME_COARSE",5},{"CLOCK_MONOTONIC_COARSE",6},
    {"CLOCK_BOOTTIME",7},{"CLOCK_REALTIME_ALARM",8},
    {"CLOCK_BOOTTIME_ALARM",9},{"CLOCK_TAI",11},
    {"TFD_NONBLOCK",04000},{"TFD_CLOEXEC",02000000},
    // xattr flags
    {"XATTR_CREATE",1},{"XATTR_REPLACE",2},
    // sync_file_range
    {"SYNC_FILE_RANGE_WAIT_BEFORE",1},{"SYNC_FILE_RANGE_WRITE",2},
    {"SYNC_FILE_RANGE_WAIT_AFTER",4},
    // splice
    {"SPLICE_F_MOVE",1},{"SPLICE_F_NONBLOCK",2},{"SPLICE_F_MORE",4},
    {"SPLICE_F_GIFT",8},
};

} // namespace

SyscallTable::SyscallTable(Arch arch) : arch_(arch) {
    auto load = [&](const std::pair<int, const char*>* src, size_t n) {
        for (size_t i = 0; i < n; ++i) {
            const auto& [nr, name] = src[i];
            nameToNr_.emplace(name, nr);
            nrToName_.emplace(nr, name);
        }
    };
    if (arch == Arch::X86_64)
        load(kX86_64, sizeof(kX86_64) / sizeof(kX86_64[0]));
    else
        load(kAarch64, sizeof(kAarch64) / sizeof(kAarch64[0]));
    for (const auto& [nr, name] : nrToName_)
        byNum_.emplace_back(nr, name);
}

std::optional<int> SyscallTable::number(const std::string& name) const {
    auto it = nameToNr_.find(name);
    if (it == nameToNr_.end()) return std::nullopt;
    return it->second;
}

std::optional<std::string> SyscallTable::name(int nr) const {
    auto it = nrToName_.find(nr);
    if (it == nrToName_.end()) return std::nullopt;
    return it->second;
}

std::optional<uint64_t> resolveConstant(const std::string& token) {
    // Built via function-local static to avoid static-init order issues.
    static const std::map<std::string, uint64_t> table = [] {
        std::map<std::string, uint64_t> m;
        for (const auto& [k, v] : kConstants) m.emplace(k, v);
        return m;
    }();
    auto it = table.find(token);
    if (it == table.end()) return std::nullopt;
    return it->second;
}

size_t constantCount() {
    size_t n = 0;
    for ([[maybe_unused]] const auto& e : kConstants) ++n;
    return n;
}

} // namespace scg

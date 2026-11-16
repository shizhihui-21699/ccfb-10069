# The policy DSL

A policy file is a sequence of statements. Comments start with `#` and run to
the end of the line. Whitespace is insignificant except that a rule ends at the
next keyword.

## Grammar

```
file        := { statement }
statement   := "policy" STRING
             | "note" STRING
             | "default" action
             | "startup" block
             | "runtime" block
             | rule
block       := "{" { rule } "}"

rule        := action targets [ "->" action ] [ "where" conds ]
targets     := target { "," target }
target      := SYSCALL | "@" GROUP | "*"

conds       := cond { ("and" | "," | "&&") cond }
cond        := [ "(" ] cond-atom [ ")" ]
cond-atom   := argref [ "&" value ] op value
argref      := INT | "arg" INT | ARGNAME
op          := "==" | "!=" | "<" | "<=" | ">" | ">="
             | "has" | "lacks"
             | "in" | "not" "in"
             | "in_range" | "in" "range"
value       := INT | CONST | "[" list "]" | "[" value ".." value "]"
```

`SYSCALL` is a name from the generated tables for the target architecture.
`GROUP` is a built-in group (`@net`, `@fs_read`, `@process`, …). `*` matches
every syscall and is only accepted with `allow` and without conditions.

`INT` accepts decimal, `0x` hex and leading-zero octal, with an optional sign.
`CONST` is any constant the kernel headers define, resolved with the argument's
own family first:

| argument family | constants tried first |
|---|---|
| `socket(domain)` | `AF_*`, then `PF_*` aliases |
| `socket(type)` | `SOCK_*` |
| `socket(protocol)` | `IPPROTO_*` |
| `openat(flags)`, `pipe2(flags)` | `O_*` |
| `newfstatat(flags)`, `faccessat2(flags)` | `AT_*` |
| `setsockopt(level)` | `SOL_*` |
| `setsockopt(optname)` | `SO_*` |
| signal arguments | `SIG*` |
| `prctl(option)` | `PR_*` |
| `futex(op)` | `FUTEX_*` |
| `epoll_ctl(op)` | `EPOLL_CTL_*` |
| `madvise(advice)`, `fadvise64(advice)` | `MADV_*` |
| any | `E*` (errno) and bare suffixes such as `CLOEXEC` when unambiguous |

## Actions

| spelling | seccomp return | meaning |
|---|---|---|
| `allow` | `SECCOMP_RET_ALLOW` | run the syscall |
| `deny` | `SECCOMP_RET_ERRNO\|EPERM` | fail with `EPERM` |
| `deny(EACCES)` / `errno(EACCES)` | `SECCOMP_RET_ERRNO\|13` | fail with that errno |
| `kill` | `SECCOMP_RET_KILL_THREAD` | kill the calling thread |
| `kill_process` | `SECCOMP_RET_KILL_PROCESS` | kill the whole process |
| `trap` | `SECCOMP_RET_TRAP` | deliver `SIGSYS` |
| `trace(N)` | `SECCOMP_RET_TRACE\|N` | hand to a ptracer |
| `log` | `SECCOMP_RET_LOG` | allow and audit |
| `notify(N)` | `SECCOMP_RET_USER_NOTIF\|N` | hand to a supervisor |

`deny` without parentheses is `errno(EPERM)`. The action may be written at the
start of the rule or after `->`; both of these are the same:

```
deny execve -> errno(ENOENT)
execve -> errno(ENOENT)
```

The `default` action applies to syscalls no rule mentions. With `default allow`
an argument-restricted rule cannot tighten anything — when its conditions fail,
the call falls through to the default — so the generated report calls that
combination out.

## Comparisons

| operator | meaning |
|---|---|
| `==`, `!=` | exact 64-bit equality |
| `<`, `<=`, `>`, `>=` | unsigned 64-bit ordering |
| `has MASK` | every bit of `MASK` is set |
| `lacks MASK` | at least one bit of `MASK` is clear |
| `in [A, B, …]` | equal to one member |
| `not in [A, B, …]` | equal to none |
| `in_range [LO .. HI]` | `LO <= arg <= HI` |

Every comparison is on the full 64-bit argument: the compiler compares the high
32 bits before the low ones, so `arg0 == 0x100000001` never matches `1`.

`has` tests single bits or a union of bits (`has O_CLOEXEC|O_DIRECT` means both
must be set). For an argument that mixes a value with flags — `socket`'s type
word — write a mask on the left:

```
allow socket where type & 0xf == SOCK_STREAM
```

That compares the type nibble and leaves `SOCK_CLOEXEC` and `SOCK_NONBLOCK`
free.

## Phases

`startup { … }` rules apply while the service is initialising; `runtime { … }`
rules apply after the ready point. The generated code installs two filters, and
the start-up filter also admits runtime **allowances** (never runtime denials),
because another thread may reach readiness before the second filter is on it.
A rule written outside any block applies in both phases.

The ready point is chosen by:

```
--ready-syscall NAME      the first successful NAME in the trace
--ready-after SECONDS     a point on strace's -tt timeline
--ready-after-calls N     after N syscalls in the first process
                          (default: first listen/accept/epoll_wait/poll)
```

## Precedence

Within one syscall, a narrow rule wins over a blanket one:

```
allow socket
deny  socket where domain == AF_UNIX   # wins for AF_UNIX
```

Two rules for the same syscall with different verdicts and no conditions are
rejected: only the first could ever apply, and that is a mistake worth
reporting rather than silently accepting. Identical rules (the same verdict and
conditions) are merged.

## Round-tripping

`generate` writes the policy through the same formatter the parser reads back,
and the CLI re-parses it before verifying. A policy file and its compiled
filter are therefore guaranteed to agree, including argument masks and
phase assignment.

## Groups

`sctrace explain --policy FILE` shows the compiled result. Groups are listed in
`src/groups.cpp`; a member missing from the target architecture's table is
skipped silently, so one policy can be compiled for both x86_64 and aarch64.

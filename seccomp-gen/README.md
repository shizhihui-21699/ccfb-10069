# seccomp-gen

Turn `strace` output of a C++ service into a **minimal seccomp-bpf
allow-list**, compile it to classic BPF, and prove every allow/deny decision
by replaying the raw call sequence through a from-scratch BPF interpreter.

Pure C++17, no third-party dependencies, no kernel headers needed at build
time. Builds and runs on macOS (for development and testing) and targets
Linux seccomp filters for both **x86_64** and **aarch64**.

## Why the filter is a linear program (important design note)

cBPF conditional and unconditional jumps encode their target as an **8-bit
relative offset (0..255 instructions)**. A binary-search dispatch over
hundreds of syscalls therefore emits jumps that overflow that field. The
usual fix — inserting a trampoline between the jump and its target — does
not actually work in isolation: any instruction inserted between a jump at
`S` and its target at `T` shifts `T` by exactly the inserted amount, so the
distance `T - S` is invariant and never shrinks to fit.

The compiler instead emits a **strictly linear, adjacent layout**:

```
for each allowed syscall number N:
    LD  seccomp_data.nr
    JEQ N -> match ; JNE -> after this block
  match:
    <rule conditions, each a short local branch to its rule-fail label>
    RET  action
    RET  default            # rule-fail lands here
  after:                     # next block starts here
...
RET default                  # nr matched nothing
```

Every jump is a short, local, forward branch that can never exceed 255, so
no trampolines are required and no jump can overflow. The cost is O(number
of syscalls) comparisons in the worst case, which stays well inside the
kernel's 4096-instruction filter cap (a 137-syscall policy here is 914
insns). An architecture guard (`AUDIT_ARCH`) precedes everything so a
filter built for one ABI always rejects the other.

## Pipeline

1. **Parse** `strace -f -tt` logs: PID/TID prefixes, `<unfinished ...>` /
   `<... resumed>` split calls (merged per thread), thread and forked-child
   tracking, signal/exit noise, and a boot→runtime phase marker.
2. **Model** distinct syscalls per phase, optionally inferring
   argument-level constraints from observed scalar values (`--auto-args`).
3. **Overlay** hand-written DSL rules (denials placed first so they win).
4. **Compile** to cBPF with a label emitter that resolves and range-checks
   every 8-bit offset, then run a static verifier (bounds, div-by-zero,
   terminal RET).
5. **Verify** by building `seccomp_data` buffers and running them through
   this project's own BPF interpreter — every observed call (must be
   allowed), mutated negative cases and never-seen syscalls (must hit the
   default), plus a foreign-architecture case for every entry.
6. **Emit** a binary filter blob, a C `sock_filter[]` header for
   `prctl(PR_SET_SECCOMP)`, the policy in DSL form, and a Markdown report.

## Build

```
make            # produces bin/seccomp-gen
make selftest   # end-to-end synthetic trace, both arches and phases
make test       # full integration suite
```

## Usage

Capture a trace that follows threads and children, and mark the point where
startup finishes (the marker is a syscall name your service never really
issues; the generator treats it purely as a phase boundary):

```
strace -f -tt -o svc.strace /usr/bin/svc     # run until ready, then exercise
# add a line like:  <pid> <ts> SECCMP_READY() = 0   at the ready boundary
```

Generate a runtime policy with argument constraints:

```
seccomp-gen gen svc.strace --arch x86_64 --phase runtime --auto-args \
    --marker SECCMP_READY --out-prefix policy
# -> policy.bpf  policy.h  policy.dsl  policy.md
```

Useful flags:

| Flag | Meaning |
|---|---|
| `--arch x86_64\|aarch64` | target ABI; selects the syscall number table |
| `--phase boot\|runtime\|all` | which trace phase to model |
| `--auto-args` | infer `argN == value` constraints from observed scalars |
| `--max-in-set N` | cap distinct values per constrained slot |
| `--default KILL\|ERRNO\|LOG` | action for non-allowed calls |
| `--dsl rules.dsl` | hand-written overlay (repeatable); denials go first |
| `--marker NAME` | boot→runtime boundary syscall name |

Other commands:

```
seccomp-gen parse  svc.strace --out events.json   # inspect parsed events
seccomp-gen verify policy.bpf svc.strace --auto-args
seccomp-gen disasm policy.bpf                     # dump cBPF instructions
seccomp-gen selftest
```

## Installing the generated filter on Linux

`policy.h` contains a ready `struct sock_filter[]` / `struct sock_fprog`.
Load it after `prctl(PR_SET_NO_NEW_PRIVS, 1, ...)` (or with
`CAP_SYS_ADMIN`):

```c
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include "policy.h"   /* runtime_filter / runtime_fprog */

prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &runtime_fprog);
```

## Layout

```
src/
  common.h/.cpp        shared types, actions, software policy evaluator
  syscall_table.*      x86_64 + aarch64 number tables, symbolic constants
  strace_parser.*      trace parsing, thread/fork tracking, phase split
  policy.*             trace->policy inference and the rule DSL
  bpf.h/.cpp           cBPF model, emitter, interpreter, verifier, codec
  compiler.*           policy -> linear cBPF program
  verifier.*           replay case builder + Markdown report
  main.cpp             CLI (parse|gen|verify|disasm|selftest)
tests/                 integration script, sample trace, big-trace generator
docs/DSL.md            rule language reference
docs/sample-report.md  example generated human report
```

## Scope and caveats

- Argument inference only freezes small, ABI-like scalars (values ≤ 4096);
  pointers, buffer addresses and large sizes are never constrained, since
  doing so would break legitimate runs.
- A trace only proves what it observed. Cover error paths, several request
  shapes and both boot/runtime before trusting a policy in production, and
  prefer `--default ERRNO` during a canary before switching to `KILL`.
- Syscall numbers are verified against musl's `arch/*/bits/syscall.h`
  tables (generic numbers through 470).

# Design notes

These are the decisions that shaped the tool, and the reasons behind them.
Read this before changing the compiler or the verifier: several of the
invariants below are load-bearing.

## Two filters, not one

A seccomp filter is installed once and applies to every thread from then on.
The service needs a different rule set while it is starting (the loader, config
parsing, socket setup all look nothing like the steady state), so the tool
produces two programs and expects the caller to install the second at the ready
point.

The start-up filter **also admits runtime allowances**, because threads share
the process: worker A can reach the ready point and issue a runtime syscall
while the main thread is still installing the runtime filter on itself. A
start-up filter that omitted those allowances would kill a healthy worker.
Runtime *denials* are not folded into the start-up filter: "allow `execve` at
startup, deny it afterwards" is a coherent policy, and merging the deny into
the start-up filter would turn it into a conflict.

## The verifier does not trust the compiler

`VerifyTrace` runs every recorded call through two independent paths:

* the generated BPF program, via `Execute()` — what the kernel will do;
* `EvaluatePolicy()` — a direct evaluation of the DSL rules.

The two are compared per call. They share the `Policy` IR but nothing else: if
the compiler emits a jump with the wrong offset, or an `in` test with the
polarity reversed, the interpreter executes the wrong branch and the mismatch
surfaces. This is how the bugs found during development (a reversed
`EmitIn`, a stale label table) were caught; neither would have shown up in a
"does the policy text look right" review.

A mismatch in the direction *filter allows what the policy denies* is an error
(the kernel is more permissive than the policy says). A filter that merely uses
a different deny mechanism than the policy is still a mismatch and is reported,
because silent divergence is how a compiler bug hides.

## A recorded call the policy denies is a failure

If the trace shows the service calling `epoll_wait` and the policy denies it,
the service will fail at that line. That is the finding the tool exists to
produce, so it fails verification (exit 1) and lists the syscalls and lines,
rather than printing a green summary with warnings nobody reads.

## Argument restrictions come from observations, conservatively

The generator pins an argument only when the evidence supports it:

* `socket(domain)`: an equality when one family was seen, an `in` list when
  several were, nothing above `--max-in-list`.
* `socket(type)`: the **type nibble** is pinned (`type & 0xf == SOCK_STREAM`)
  and the flag bits are left free. Pinning the whole word would break the
  service the first time it used a different `SOCK_*` flag; ignoring the type
  would let it create sockets it never needed.
* File descriptors, sizes and pointers are never pinned. Their observed values
  are properties of one run, not of the policy. The report says so instead of
  emitting a rule that would break the next run.
* `protocol` is not pinned: `0` and `IPPROTO_TCP` are the same request for a
  TCP socket, and the family/type already determine it.

## 64-bit comparisons are explicit

`struct seccomp_data.args` is `__u64[6]`; cBPF works on 32 bits. Every equality
compares the high half before the low half, and every ordering compares high
halves first with a three-way split. A filter that compared only the low half
would let `arg0 == 0x100000001` pass a rule for `arg0 == 1`; there is a test
for exactly that.

## Jump relaxation is part of the assembler

cBPF conditional jumps have an 8-bit displacement. A dispatch table for a
hundred syscalls easily puts a target more than 255 instructions away, so the
assembler resolves labels to a fixed point, routes far branches through `JA`
trampolines (32-bit displacement), and only then paints `jt`/`jf`. The
trampolines change instruction addresses, which is why the resolution is
iterated: a naive single pass produces the off-by-N jumps that this design
avoids.

The validator then rejects anything the kernel would reject: backward jumps,
out-of-range targets, loads outside `seccomp_data`, unreachable code, unknown
actions, `ERRNO` above 4095, and programs over 4096 instructions.

## Trace parsing assumes nothing

`strace -f` output interleaves threads, prints `<unfinished ...>` on one line
and `<... resumed>` on another, abbreviates strings with `...`, and shows
symbolic names (`AF_INET`, `O_RDONLY|O_CLOEXEC`). The parser:

* pairs unfinished/resumed calls per pid and refuses to merge arguments when
  the completing call is a different syscall (a reused pid or a truncated log),
  recording a diagnostic instead of inventing arguments;
* classifies pids by the `clone`/`clone3` result and the `CLONE_THREAD` bit,
  which strace may print inside a struct (`clone3`) or as a named field
  (`flags=CLONE_VM|...`);
* resolves symbolic arguments to numbers, so `AF_INET` compares equal to `2`;
* keeps `-y` fd annotations for the report.

Unknown syscall names produce a diagnostic rather than being dropped, because
dropping them would silently produce an over-permissive or over-strict policy.

## The tables are generated, and their origin is auditable

`src/syscalls_generated.inc` and `src/constants_generated.inc` come from the
kernel sources vendored under `tools/linux-uapi/` (Linux v6.6). The generator
is a small C preprocessor plus an enum/`#define` evaluator — enough for these
headers, small enough to audit. `make check-tables` fails if the committed
tables do not match the sources, so a hand edit cannot slip in.

aarch64 numbers come from `include/asm-generic/unistd.h` preprocessed with the
`__ARCH_WANT_*` settings from `arch/arm64`, which is how the kernel derives them
too. Getting this wrong is not subtle — `futex` is 202 on x86_64 and 98 on
aarch64 — and there are tests pinning the numbers that differ.

## The policy text is the source of truth

`generate` writes the policy, then **re-parses the file it wrote** and verifies
that policy. A round-trip failure (a mask that does not re-parse, a phase that
moves) fails the command. That is why the DSL has an explicit `& mask` syntax
and why the formatter and parser share `DescribeCondition`.

## Where the design stops

* Memory is invisible to seccomp. A path check would need `SECCOMP_RET_USER_NOTIF`
  and a supervisor reading `/proc/pid/mem`; this tool deliberately does not go
  there and says so in every report.
* A trace is one sample. The tool cannot prove a syscall is *unnecessary*; it
  can only show what is sufficient for the workload it saw. The reports say
  this in as many words.
* The generator folds every process's observations into one policy. Per-process
  policies would be tighter for a multi-process service, but the filter is
  inherited across `fork`, so the parent's filter has to cover the child
  anyway.

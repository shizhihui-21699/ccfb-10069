# sctrace — seccomp-bpf policies from strace output

`sctrace` reads a trace of a C++ service, builds the smallest seccomp-bpf
filter that admits what the service actually does, proves the filter behaves as
intended by replaying the trace through an interpreter, and writes a policy
document a human can review and sign off.

It is a single self-contained C++20 program — no libseccomp, no runtime
dependencies, no network access at build time.

```
$ strace -f -tt -yy -s 4096 -o service.log ./service
$ sctrace generate --trace service.log \
      --write-policy service.policy \
      --report service-policy.md \
      --c-source service-policy.c
startup: 9 calls (9 allowed, 0 denied, 0 denials intended by the policy)
runtime: 11 calls (11 allowed, 0 denied, 0 denials intended by the policy)
verified: the generated filter matches the policy on all 20 recorded calls
wrote policy service.policy
wrote report service-policy.md
wrote C source service-policy.c
```

## What it does

1. **Parses the trace, including threads and forks.** `strace -f` output is
   keyed by tid; the parser follows `clone`/`fork`/`vfork` results to classify
   each pid as a thread of the same process or a separate forked child, pairs
   `<unfinished ...>` with `<... resumed>` across interleaved lines, resolves
   symbolic arguments (`AF_INET`, `O_RDONLY|O_CLOEXEC`) to numbers, and keeps
   the `-y` fd path annotations for the report.
2. **Splits start-up from runtime.** The boundary is the first successful
   `listen`/`accept`/`epoll_wait`/`poll` (or `--ready-syscall NAME`,
   `--ready-after SECONDS`, `--ready-after-calls N`). Two filters are produced;
   the start-up one also admits runtime allowances because a thread can reach
   the ready point before the second filter is installed on it.
3. **Generates a policy.** Every syscall the trace contains is allowed, and
   arguments are constrained only where the trace proves a constraint:
   `socket(domain == AF_INET)`, `socket(type & 0xf == SOCK_STREAM)` (so
   `SOCK_CLOEXEC` stays free), `setsockopt(optname in [...])`,
   `openat(flags has O_CLOEXEC)`. File descriptors, sizes and pointers are never
   pinned — their values belong to one run, not to the policy — and the report
   says which arguments were left open and why.
4. **Compiles to seccomp-bpf** for x86_64 or aarch64, with an architecture check
   first, a kill for foreign ABIs, and 64-bit-safe argument comparisons
   (the high half of each argument is compared before the low half).
5. **Verifies the filter by executing it.** A self-contained cBPF interpreter
   runs the generated program over every recorded call, and the same calls are
   evaluated a second time directly from the policy's rules. The two verdicts
   are compared call by call. A compiler bug cannot pass silently: the
   interpreter and the rule evaluator are independent code paths.
6. **Writes two documents**: a Markdown policy guide (what is allowed, what each
   restriction means, what was verified, what the trace could not prove) and a C
   file containing both `sock_filter` arrays plus install functions.

## Building

```sh
make            # build/sctrace
make test       # build/sctrace_tests
make check-tables   # verify the generated syscall/constant tables are current
```

Requires a C++20 compiler and `make`. `python3` is needed only to regenerate the
architecture tables (`tools/gen_tables.py`), not to build or run.

## The policy DSL

Rules are line-oriented and read like the thing they describe:

```
policy "orders"
default kill

startup {
    allow @fs_read, @memory, @thread
    allow socket where domain == AF_INET, type & 0xf == SOCK_STREAM
    allow setsockopt where level == SOL_SOCKET,
                          optname in [SO_REUSEADDR, SO_KEEPALIVE]
}

runtime {
    allow read, write, close, epoll_wait, epoll_ctl
    allow accept4 where flags has SOCK_CLOEXEC
    deny execve, execveat -> errno(EPERM)
    allow getrandom where flags == 0 -> trace(3)
}
```

Argument names are per-syscall (`domain`, `flags`, `optname`, `whence`, …);
`arg0`…`arg5` always work. Constants resolve from the kernel headers vendored
under `tools/linux-uapi/`, with the argument's own family taking precedence:
`SO_` for `setsockopt(optname)`, `IPPROTO_` for `socket(protocol)`, `SIG` for a
signal number, `E` for an errno. See [docs/DSL.md](docs/DSL.md).

`allow *` is available for a permissive phase; a wildcard deny is rejected
because the `default` action already covers it.

## Repository layout

```
src/
  bpf.{h,cpp}           cBPF encoding, assembler with jump relaxation,
                        validator, and the independent interpreter
  syscalls.{h,cpp}      syscall tables and per-argument semantics
  strace_parser.{h,cpp} trace parsing, thread/fork tracking, phase split
  policy.{h,cpp}        the policy IR and its actions
  groups.cpp            built-in syscall groups (@net, @fs_read, ...)
  dsl.{h,cpp}           the policy language: lexer, parser, formatter
  compiler.{h,cpp}      policy -> two BPF programs
  generator.{h,cpp}     trace -> policy, including argument inference
  verifier.{h,cpp}      replay: interpreter vs. rule evaluation
  report.{h,cpp}        the Markdown guide and the C source
  cli.{h,cpp}, main.cpp the command line
  syscalls_generated.inc, constants_generated.inc
                        generated from tools/linux-uapi/ (Linux v6.6)
tools/
  gen_tables.py         regenerates the two .inc files
  ccpp.py               a small C preprocessor used by the generator
  linux-uapi/           vendored kernel UAPI sources (syscall tables, headers)
tests/                  unit and end-to-end tests (make test)
examples/               a sample trace and a hand-written policy
docs/DSL.md             the language reference
```

## Limitations worth reading before you rely on it

* A filter sees scalars, not memory. Paths, `struct sockaddr` and
  `struct clone_args` are pointers; only integer and flag arguments can be
  constrained. The report marks what it could not pin.
* A trace is a sample. Syscalls reached only on error paths, other configs or
  under load are missing from it. Run the service under realistic traffic
  before trusting a generated policy, and consider `log`/`trace` actions for a
  canary period.
* The 4096-instruction kernel limit is enforced while assembling; very large
  per-syscall dispatch tables can hit it, and the tool says so rather than
  emitting a filter the kernel would reject.
* `SECCOMP_RET_ERRNO` values are capped at 4095; `kill` terminates the calling
  thread immediately.

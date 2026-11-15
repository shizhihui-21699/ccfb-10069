# Rule DSL

The DSL describes one seccomp policy. A document has an optional `policy`
header followed by zero or more rules. Rules are evaluated **first match
wins**, top to bottom; if no rule matches, the policy default action runs.

## Header

```
policy {
    arch "x86_64";      # or "aarch64"
    phase "runtime";    # "boot" | "runtime" | "all"
    default KILL;       # KILL | KILL_THREAD | ERRNO(n) | TRAP | LOG | ALLOW
}
```

## Rules

```
ACTION SYSCALL;
ACTION SYSCALL WHERE CONDITION [AND CONDITION ...];
```

- `ACTION` is one of `ALLOW`, `KILL`, `KILL_THREAD`, `TRAP`, `LOG`, or
  `ERRNO(n)` where `n` is the errno returned to the process.
- `SYSCALL` is the generic Linux name (e.g. `socket`, `openat`). The
  generator resolves it to the architecture-specific number at compile time,
  so the same DSL works on both x86_64 and aarch64.
- Conditions are a conjunction (AND). Each condition tests one argument
  slot `arg0`..`arg5` against a constant.

## Conditions

| Syntax | Meaning | BPF emitted |
|---|---|---|
| `argN == VALUE` | argument equals constant | `LD argN; JEQ VALUE` |
| `argN != VALUE` | argument differs from constant | `LD argN; JEQ VALUE` (inverted branches) |
| `argN &= MASK == VALUE` | `(argument & MASK) == VALUE` | `LD argN; AND MASK; JEQ VALUE` |
| any of the above followed by ` @64` | true 64-bit compare | `LD_DW` (low word in A, high in X) |

`VALUE` and `MASK` are either integers (decimal, `0x` hex, `0` octal) or
symbolic constants the generator knows: address families (`AF_INET`,
`AF_INET6`, `AF_UNIX`, ...), socket types (`SOCK_STREAM`, `SOCK_DGRAM`,
`SOCK_CLOEXEC`, ...), open flags (`O_RDONLY`, `O_CLOEXEC`, ...), clone
flags (`CLONE_*`), futex ops (`FUTEX_*`), errno names, and many more.
OR-combined flags written with `|` are folded to their numeric union.

## Example: only IPv4 TCP sockets

```
policy { arch "x86_64"; phase "runtime"; default KILL; }

# Reject IPv6/other families explicitly even if a later trace rule is broad.
ERRNO(1) socket WHERE arg0 == AF_INET6;
ALLOW    socket WHERE arg0 == AF_INET AND arg1 &= 7 == SOCK_STREAM;

# Never allow process inspection.
KILL ptrace;
```

## Comments

`#` to end of line, and `//` to end of line.

## How trace-generated rules use the DSL

The `gen` command emits the same grammar. With `--auto-args`, each
constrained argument combination becomes its own `ALLOW ... WHERE ...`
rule; hand-written overlay files (`--dsl`) are placed ahead of the
trace-derived rules so explicit denials always win.

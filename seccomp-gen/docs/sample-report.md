# Seccomp policy report

- Architecture: **x86_64** (AUDIT_ARCH 0xc000003e)
- Phase: **all**
- Default action: **KILL**
- Filter size: **108 instructions** (864 bytes)
- Trace events parsed: 15 across 2 task(s), 18 raw lines
- Unfinished/resumed pairs merged: 1/1
- Phase marker hit at line 12

## Allowed syscalls (14)

| syscall | nr | argument constraints | source |
|---|---:|---|---|
| `brk` | 12 | arg0 == 0 | trace+autoargs |
| `clone` | 56 | arg1 == 0 AND arg2 == 0 | trace+autoargs |
| `close` | 3 | arg0 == 4 | trace+autoargs |
| `connect` | 42 | arg0 == 3 AND arg2 == 16 | trace+autoargs |
| `epoll_wait` | 232 | arg0 == 5 AND arg2 == 64 | trace+autoargs |
| `execve` | 59 | arg2 == 2047 | trace+autoargs |
| `futex` | 202 | arg2 == 0 AND arg3 == 0 | trace+autoargs |
| `getrandom` | 318 | arg1 == 32 AND arg2 == 1 | trace+autoargs |
| `mmap` | 9 | arg0 == 0 AND arg1 == 4096 | trace+autoargs |
| `openat` | 257 | arg2 == 0 | trace+autoargs |
| `read` | 0 | arg0 == 4 AND arg2 == 8 | trace+autoargs |
| `recvfrom` | 45 | arg0 == 3 AND arg2 == 5 | trace+autoargs |
| `socket` | 41 | arg0 == 2 AND arg2 == 6 | trace+autoargs |
| `write` | 1 | arg0 == 1 AND arg2 == 2 | trace+autoargs |

## Verification

- Cases executed (own arch): 14 positive, 394 negative
- Cross-architecture guard cases: 408
- Total VM evaluations: 816, passed: 816, failed: 0

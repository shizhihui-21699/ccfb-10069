# Generated policy.  Edit freely; this text is the source of truth.
#
# Recompile with:  scgen emit --policy this-file --arch x86_64

policy "generated"

note "Generated from a trace of 2 process(es), 19 distinct syscalls."
note "Argument restrictions come only from values the trace actually showed; arguments the trace could not resolve were left unconstrained on purpose."

default kill

startup {
    allow bind   # observed 1 time(s)
    allow brk   # observed 1 time(s)
    allow execve   # observed 1 time(s)
    allow listen   # observed 1 time(s)
    allow openat where
        flags has O_CLOEXEC   # observed 1 time(s)
    allow setsockopt   # observed 1 time(s)
    allow socket where
        domain == AF_INET
        and type & 0xf == SOCK_STREAM   # observed 1 time(s)
    allow close   # observed 2 time(s)
    allow read   # observed 2 time(s)
}

runtime {
    allow close   # observed 2 time(s)
    allow read   # observed 2 time(s)
    allow accept4 where
        flags has SOCK_CLOEXEC   # observed 1 time(s)
    allow clone   # observed 1 time(s)
    allow epoll_create1   # observed 1 time(s)
    allow epoll_ctl   # observed 1 time(s)
    allow epoll_wait   # observed 1 time(s)
    allow exit_group   # observed 1 time(s)
    allow futex   # observed 1 time(s)
    allow write   # observed 2 time(s)
}


// The policy DSL.
//
// The language is line-oriented and deliberately small.  A file looks like:
//
//     # comments start with '#'
//     policy "orders-service"
//
//     default kill              # what happens when no rule matches
//
//     startup {
//         allow @fs_read, @memory, @thread
//         allow socket(domain == AF_INET, type has SOCK_STREAM)
//         allow setsockopt(level == SOL_SOCKET, optname in [SO_REUSEADDR,
//                                                          SO_KEEPALIVE])
//     }
//
//     runtime {
//         allow read, write, close, epoll_wait, epoll_ctl
//         allow accept4(flags has SOCK_CLOEXEC)
//         allow socket(domain == AF_INET)
//         allow connect(2 == SOCK_STREAM) -> trace(7)
//         deny execve, execveat -> errno(EPERM)
//         kill * if ...
//     }
//
// Grammar (EBNF-ish):
//
//   file        := { statement }
//   statement   := "policy" STRING
//                | "default" action
//                | "note" STRING
//                | "phase" ("startup"|"runtime") block
//                | ("startup"|"runtime") block
//                | rule
//   block       := "{" { statement } "}"        (phase statements only)
//   rule        := action target { "," target } [ "where" cond_list ]
//   action      := "allow" | "deny" | "kill" | "kill_process" | "trap"
//                | "log" | "trace" "(" INT ")" | "notify" "(" INT ")"
//                | "errno" "(" (INT | ERRNO_NAME) ")"
//   target      := SYSCALL | "@" GROUP | "*"
//   cond_list   := cond { ("and" | ",") cond }
//   cond        := [ "not" ] atom
//   atom        := "(" cond_list ")" | argref cmp value
//   argref      := INT | IDENT | "arg" INT
//   cmp         := "==" | "!=" | "<" | "<=" | ">" | ">=" | "has" | "lacks"
//                | "in" | "not" "in" | "in" "range" | "in_range"
//   value       := INT | IDENT | "[" (INT|IDENT) { "," (INT|IDENT) } "]"
//                | "[" (INT|IDENT) ".." (INT|IDENT) "]"
//
// `has` / `lacks` treat the argument as a flag word: `has O_CLOEXEC` means
// (arg & O_CLOEXEC) == O_CLOEXEC; a value that is itself an OR-ed set means
// all of those bits.  A bare identifier is resolved against the constants the
// kernel headers define (AF_INET, O_CLOEXEC, SIGCHLD, EPERM, ...).
#pragma once

#include <string>
#include <string_view>
#include <vector>

#include "policy.h"

namespace scgen {

struct DslParseResult {
  Policy policy;
  std::vector<std::string> errors;
  std::vector<std::string> warnings;
};

// Parses a policy file.  Errors are collected, not thrown, so a caller can
// report every problem in a file at once.
DslParseResult ParsePolicyDsl(std::string_view text, std::string source_name,
                              Arch arch);

// Renders a policy back to DSL text (used by --print-policy and by the
// generator's default policy so the emitted policy matches the parser exactly).
std::string FormatPolicyDsl(const Policy& policy, Arch arch);

}  // namespace scgen

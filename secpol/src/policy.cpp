// policy.cpp — policy model, DSL, and generation from observed events.
#include "policy.h"
#include "tables.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <sstream>

namespace {

// Which arguments get value-set constraints, per syscall.
const std::map<std::string, std::vector<int>>& constraint_args() {
    static const std::map<std::string, std::vector<int>> m = {
        {"socket", {0}}, {"socketpair", {0}},
        {"ioctl", {1}},
        {"fcntl", {1}}, {"fcntl64", {1}},
        {"prctl", {0}},
        {"ptrace", {0}},
        {"setsockopt", {1}}, {"getsockopt", {1}},
        {"open", {1}}, {"openat", {2}},
        {"seccomp", {0}}, {"bpf", {0}},
        {"epoll_ctl", {1}}, {"eventfd2", {0}}, {"epoll_create1", {0}},
        {"inotify_init1", {0}}, {"signalfd4", {0}}, {"timerfd_create", {0}},
        {"memfd_create", {1}},
    };
    return m;
}

const size_t kMaxSetSize = 16;

// Preferred constant-name prefixes per (syscall, arg) for pretty printing.
std::vector<std::string> name_prefixes(const std::string& sys, int arg) {
    if ((sys == "socket" || sys == "socketpair") && arg == 0) return {"AF_"};
    if (sys == "ioctl" && arg == 1) return {"TC", "TIOC", "FION", "FIOC", "SIOC", "KD", "VT_", "EVIOC", "SND"};
    if ((sys == "fcntl" || sys == "fcntl64") && arg == 1) return {"F_"};
    if (sys == "prctl" && arg == 0) return {"PR_"};
    if (sys == "ptrace" && arg == 0) return {"PTRACE_"};
    if ((sys == "setsockopt" || sys == "getsockopt") && arg == 1) return {"SOL_"};
    if ((sys == "open" && arg == 1) || (sys == "openat" && arg == 2)) return {"O_"};
    if (sys == "seccomp" && arg == 0) return {"SECCOMP_"};
    if (sys == "bpf" && arg == 0) return {"BPF_"};
    if (sys == "epoll_ctl" && arg == 1) return {"EPOLL_CTL"};
    if (sys == "epoll_create1" && arg == 0) return {"EPOLL_CLOEXEC"};
    if (sys == "eventfd2" && arg == 0) return {"EFD_"};
    if (sys == "inotify_init1" && arg == 0) return {"IN_"};
    if (sys == "signalfd4" && arg == 0) return {"SFD_"};
    if (sys == "timerfd_create" && arg == 0) return {"CLOCK_"};
    if (sys == "memfd_create" && arg == 1) return {"MFD_", ""};
    return {};
}

} // namespace

uint32_t action_code(Action a, uint16_t errno_code) {
    switch (a) {
        case Action::Kill:  return 0x00000000u;              // SECCOMP_RET_KILL_PROCESS
        case Action::Trap:  return 0x00030000u;              // SECCOMP_RET_TRAP
        case Action::Errno: return 0x00050000u | errno_code; // SECCOMP_RET_ERRNO
        case Action::Log:   return 0x7ffc0000u;              // SECCOMP_RET_LOG
        case Action::Allow: return 0x7fff0000u;              // SECCOMP_RET_ALLOW
    }
    return 0;
}

std::string action_str(Action a, uint16_t errno_code) {
    switch (a) {
        case Action::Kill:  return "kill";
        case Action::Trap:  return "trap";
        case Action::Errno: return "errno " + std::to_string(errno_code);
        case Action::Log:   return "log";
        case Action::Allow: return "allow";
    }
    return "?";
}

std::string phase_str(Phase p) {
    switch (p) {
        case Phase::Startup: return "startup";
        case Phase::Runtime: return "runtime";
        case Phase::Always:  return "always";
    }
    return "?";
}

std::string fmt_value(const std::string& syscall, int arg, uint64_t v) {
    const auto& cs = constants();
    auto prefs = name_prefixes(syscall, arg);
    // 1) exact single-constant match, preferred prefixes first
    for (const auto& pref : prefs) {
        for (const auto& kv : cs) {
            if (kv.second == v && kv.first.rfind(pref, 0) == 0) return kv.first;
        }
    }
    for (const auto& kv : cs) {
        if (kv.second == v) return kv.first;
    }
    // 2) flag decomposition with preferred prefixes (e.g. O_RDWR|O_CLOEXEC)
    if (!prefs.empty()) {
        std::vector<std::pair<std::string, uint64_t>> cands;
        for (const auto& kv : cs) {
            for (const auto& pref : prefs) {
                if (kv.first.rfind(pref, 0) == 0 && kv.second != 0 &&
                    (kv.second & ~(uint64_t)0xFFFFFFFF) == 0) {
                    cands.push_back(kv);
                    break;
                }
            }
        }
        std::sort(cands.begin(), cands.end(),
                  [](const std::pair<std::string, uint64_t>& a,
                     const std::pair<std::string, uint64_t>& b) {
                      return a.second > b.second;
                  });
        uint64_t rem = v;
        std::vector<std::string> parts;
        for (const auto& kv : cands) {
            if ((rem & kv.second) == kv.second) {
                parts.push_back(kv.first);
                rem &= ~kv.second;
            }
        }
        if (rem == 0 && !parts.empty()) {
            std::string s = parts[0];
            for (size_t i = 1; i < parts.size(); i++) s += "|" + parts[i];
            return s;
        }
    }
    // 3) fall back to hex / decimal
    char buf[32];
    if (v >= 0x10000) {
        snprintf(buf, sizeof buf, "0x%llx", (unsigned long long)v);
        return buf;
    }
    return std::to_string(v);
}

// ---------------------------------------------------------------------------
// generation
// ---------------------------------------------------------------------------

Policy policy_generate(const std::vector<Event>& events, const std::string& arch,
                       bool use_constraints, GenInfo& info) {
    Policy pol;
    pol.arch = arch;

    std::map<std::string, Rule> rules;
    std::map<std::string, std::pair<bool, bool>> phase_seen; // startup, runtime
    std::map<std::string, std::map<int, std::set<uint64_t>>> vals;
    std::map<std::string, std::map<int, bool>> resolvable;
    std::set<std::string> unknown_warned;

    for (const auto& ev : events) {
        info.total_events++;
        info.pids.insert(ev.pid);
        info.per_pid[ev.pid][ev.name]++;
        if (ev.phase == 0) info.startup_events++;
        else info.runtime_events++;

        if (sys_nr(ev.name, arch) < 0) {
            if (!unknown_warned.count(ev.name)) {
                unknown_warned.insert(ev.name);
                info.unknown_syscalls.push_back(ev.name);
            }
            continue;
        }

        Rule& r = rules[ev.name];
        r.syscall = ev.name;
        r.count++;
        r.pids.insert(ev.pid);
        auto& ps = phase_seen[ev.name];
        if (ev.phase == 0) ps.first = true; else ps.second = true;

        if (use_constraints) {
            auto ca = constraint_args().find(ev.name);
            if (ca != constraint_args().end()) {
                for (int ai : ca->second) {
                    bool ok = (size_t)ai < ev.args.size() && ev.arg_ok[ai];
                    if (ok) {
                        vals[ev.name][ai].insert(ev.arg_vals[ai]);
                    } else {
                        resolvable[ev.name][ai] = false;
                    }
                }
            }
        }
    }

    for (auto& kv : rules) {
        Rule& r = kv.second;
        const auto& ps = phase_seen[r.syscall];
        r.phase = (ps.first && ps.second) ? Phase::Always
                : ps.first                ? Phase::Startup
                                          : Phase::Runtime;

        if (use_constraints) {
            auto ca = constraint_args().find(r.syscall);
            if (ca != constraint_args().end()) {
                for (int ai : ca->second) {
                    bool ok = true;
                    auto rit = resolvable[r.syscall].find(ai);
                    if (rit != resolvable[r.syscall].end() && !rit->second) ok = false;
                    const auto& vset = vals[r.syscall][ai];
                    if (!ok) {
                        info.notes.push_back(r.syscall + " arg" + std::to_string(ai) +
                            ": 部分调用的参数无法解析为数值（指针/字符串/结构体），"
                            "放弃该参数的限制，改为不限制");
                        continue;
                    }
                    if (vset.empty()) continue;
                    if (vset.size() > kMaxSetSize) {
                        info.notes.push_back(r.syscall + " arg" + std::to_string(ai) +
                            ": 观测到 " + std::to_string(vset.size()) +
                            " 个不同取值，超过上限 " + std::to_string(kMaxSetSize) +
                            "，放弃该参数的限制");
                        continue;
                    }
                    ArgConstraint c;
                    c.arg = ai;
                    c.values.assign(vset.begin(), vset.end());
                    r.constraints.push_back(c);
                }
            }
        }
        pol.rules.push_back(r);
    }

    std::sort(pol.rules.begin(), pol.rules.end(),
              [](const Rule& a, const Rule& b) { return a.syscall < b.syscall; });
    return pol;
}

// ---------------------------------------------------------------------------
// DSL emit
// ---------------------------------------------------------------------------

std::string policy_to_dsl(const Policy& pol, const GenInfo* info) {
    std::ostringstream o;
    o << "# secpol policy\n";
    if (info) {
        o << "# events: " << info->total_events
          << " (startup " << info->startup_events
          << ", runtime " << info->runtime_events << ")"
          << ", tasks: " << info->pids.size() << "\n";
        if (info->has_marker)
            o << "# phase marker: " << info->marker_desc << "\n";
    }
    o << "arch " << pol.arch << "\n";
    o << "default " << action_str(pol.default_action, pol.errno_code) << "\n\n";

    const char* headers[3] = {
        "# ---- 仅启动期 (startup only) ----",
        "# ---- 仅运行期 (runtime only) ----",
        "# ---- 启动期与运行期 (always) ----",
    };
    Phase order[3] = {Phase::Startup, Phase::Runtime, Phase::Always};
    for (int g = 0; g < 3; g++) {
        bool printed_header = false;
        for (const auto& r : pol.rules) {
            if (r.phase != order[g]) continue;
            if (!printed_header) { o << headers[g] << "\n"; printed_header = true; }
            o << "allow " << r.syscall;
            if (r.constraints.empty()) {
                o << "\n";
            } else {
                o << " {\n";
                o << "  phase " << phase_str(r.phase) << "\n";
                for (const auto& c : r.constraints) {
                    o << "  arg" << c.arg << " in { ";
                    for (size_t i = 0; i < c.values.size(); i++) {
                        if (i) o << ", ";
                        o << fmt_value(r.syscall, c.arg, c.values[i]);
                    }
                    o << " }\n";
                }
                o << "}\n";
            }
        }
        if (printed_header) o << "\n";
    }
    return o.str();
}

// ---------------------------------------------------------------------------
// DSL parse
// ---------------------------------------------------------------------------

namespace {

struct Lexer {
    const std::string& s;
    size_t pos = 0;
    int line = 1;

    explicit Lexer(const std::string& src) : s(src) {}

    // token: kind in {"id","num","{","}",",","==","end"}, text
    struct Tok { std::string kind, text; int line; };

    Tok next() {
        while (pos < s.size()) {
            char c = s[pos];
            if (c == '\n') { line++; pos++; continue; }
            if (isspace((unsigned char)c)) { pos++; continue; }
            if (c == '#') { while (pos < s.size() && s[pos] != '\n') pos++; continue; }
            break;
        }
        if (pos >= s.size()) return {"end", "", line};
        char c = s[pos];
        if (c == '{' || c == '}' || c == ',') { pos++; return {std::string(1, c), std::string(1, c), line}; }
        if (c == '=' && pos + 1 < s.size() && s[pos + 1] == '=') { pos += 2; return {"==", "==", line}; }
        if (c == '|') { pos++; return {"|", "|", line}; }
        if (isdigit((unsigned char)c)) {
            size_t b = pos;
            while (pos < s.size() && (isalnum((unsigned char)s[pos]) || s[pos] == 'x' || s[pos] == 'X')) pos++;
            return {"num", s.substr(b, pos - b), line};
        }
        if (isalpha((unsigned char)c) || c == '_') {
            size_t b = pos;
            while (pos < s.size() && (isalnum((unsigned char)s[pos]) || s[pos] == '_')) pos++;
            return {"id", s.substr(b, pos - b), line};
        }
        pos++;
        return {"?", std::string(1, c), line};
    }
};

struct Parser {
    Lexer lex;
    Lexer::Tok cur;
    std::string err;

    explicit Parser(const std::string& src) : lex(src) { cur = lex.next(); }

    bool fail(const std::string& msg) {
        err = "line " + std::to_string(cur.line) + ": " + msg;
        return false;
    }
    void adv() { cur = lex.next(); }
    bool expect(const std::string& kind) {
        if (cur.kind != kind) return fail("expected '" + kind + "', got '" + cur.text + "'");
        adv();
        return true;
    }
    bool accept(const std::string& kind) {
        if (cur.kind == kind) { adv(); return true; }
        return false;
    }

    bool parse_value(uint64_t& out) {
        uint64_t result = 0;
        bool first = true;
        while (true) {
            uint64_t v = 0;
            if (cur.kind == "num") {
                char* end = nullptr;
                v = strtoull(cur.text.c_str(), &end, 0);
                if (!end || *end != '\0') {
                    // retry decimal for things like "08"
                    end = nullptr;
                    v = strtoull(cur.text.c_str(), &end, 10);
                    if (!end || *end != '\0') return fail("bad number '" + cur.text + "'");
                }
                adv();
            } else if (cur.kind == "id") {
                const auto& cs = constants();
                auto it = cs.find(cur.text);
                if (it == cs.end()) return fail("unknown constant '" + cur.text + "'");
                v = it->second;
                adv();
            } else {
                return fail("expected value, got '" + cur.text + "'");
            }
            if (first) { result = v; first = false; }
            else result |= v;
            if (!accept("|")) break;
        }
        out = result;
        return true;
    }

    bool parse_action(Action& a, uint16_t& ecode) {
        if (cur.kind != "id") return fail("expected action");
        std::string w = cur.text;
        if (w == "kill") { a = Action::Kill; adv(); return true; }
        if (w == "trap") { a = Action::Trap; adv(); return true; }
        if (w == "log")  { a = Action::Log;  adv(); return true; }
        if (w == "allow"){ a = Action::Allow;adv(); return true; }
        if (w == "errno") {
            a = Action::Errno;
            adv();
            if (cur.kind == "num") {
                ecode = (uint16_t)strtoul(cur.text.c_str(), nullptr, 0);
                adv();
            } else if (cur.kind == "id") {
                const auto& es = errno_names();
                auto it = es.find(cur.text);
                if (it == es.end()) return fail("unknown errno '" + cur.text + "'");
                ecode = (uint16_t)it->second;
                adv();
            } // default: keep current
            return true;
        }
        return fail("unknown action '" + w + "'");
    }

    bool parse(Policy& pol) {
        while (cur.kind != "end") {
            if (cur.kind != "id") return fail("expected statement, got '" + cur.text + "'");
            std::string kw = cur.text;
            if (kw == "arch") {
                adv();
                if (cur.kind != "id") return fail("expected arch name");
                if (!valid_arch(cur.text)) return fail("unknown arch '" + cur.text + "' (want x86_64|aarch64)");
                pol.arch = cur.text;
                adv();
            } else if (kw == "default") {
                adv();
                if (!parse_action(pol.default_action, pol.errno_code)) return false;
            } else if (kw == "allow") {
                adv();
                if (cur.kind != "id") return fail("expected syscall name after 'allow'");
                Rule r;
                r.syscall = cur.text;
                r.action = Action::Allow;
                adv();
                if (accept("{")) {
                    while (cur.kind != "}" && cur.kind != "end") {
                        if (cur.kind != "id") return fail("expected rule item");
                        if (cur.text == "phase") {
                            adv();
                            if (cur.kind != "id") return fail("expected phase name");
                            if (cur.text == "startup") r.phase = Phase::Startup;
                            else if (cur.text == "runtime") r.phase = Phase::Runtime;
                            else if (cur.text == "always") r.phase = Phase::Always;
                            else return fail("unknown phase '" + cur.text + "'");
                            adv();
                        } else if (cur.text.size() == 4 && cur.text.rfind("arg", 0) == 0 &&
                                   isdigit((unsigned char)cur.text[3])) {
                            int ai = cur.text[3] - '0';
                            adv();
                            ArgConstraint c;
                            c.arg = ai;
                            if (accept("in") || (cur.kind == "id" && cur.text == "in" && (adv(), true))) {
                                if (!expect("{")) return false;
                                while (cur.kind != "}") {
                                    uint64_t v;
                                    if (!parse_value(v)) return false;
                                    c.values.push_back(v);
                                    if (!accept(",")) break;
                                }
                                if (!expect("}")) return false;
                            } else if (accept("==")) {
                                uint64_t v;
                                if (!parse_value(v)) return false;
                                c.values.push_back(v);
                            } else {
                                return fail("expected 'in' or '==' after arg" + std::to_string(ai));
                            }
                            r.constraints.push_back(c);
                        } else {
                            return fail("unknown rule item '" + cur.text + "'");
                        }
                    }
                    if (!expect("}")) return false;
                }
                pol.rules.push_back(r);
            } else {
                return fail("unknown statement '" + kw + "'");
            }
        }
        return true;
    }
};

} // namespace

bool policy_from_dsl(const std::string& text, Policy& out, std::string& err) {
    Parser p(text);
    if (!p.parse(out)) { err = p.err; return false; }
    return true;
}

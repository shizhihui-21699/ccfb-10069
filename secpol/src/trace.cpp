// trace.cpp — strace output parsing.
#include "trace.h"
#include "tables.h"

#include <cctype>
#include <cstdlib>
#include <fstream>
#include <map>

namespace {

std::string trim(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && isspace((unsigned char)s[a])) a++;
    while (b > a && isspace((unsigned char)s[b - 1])) b--;
    return s.substr(a, b - a);
}

bool all_digits(const std::string& s) {
    if (s.empty()) return false;
    for (char c : s)
        if (!isdigit((unsigned char)c)) return false;
    return true;
}

bool is_timestamp(const std::string& s) {
    if (s.empty()) return false;
    bool has_sep = false;
    for (char c : s) {
        if (c == '.' || c == ':') { has_sep = true; continue; }
        if (!isdigit((unsigned char)c)) return false;
    }
    return has_sep;
}

bool is_ident(const std::string& s) {
    if (s.empty() || !(isalpha((unsigned char)s[0]) || s[0] == '_')) return false;
    for (char c : s)
        if (!(isalnum((unsigned char)c) || c == '_')) return false;
    return true;
}

} // namespace

std::vector<std::string> split_args(const std::string& s) {
    std::vector<std::string> out;
    std::string cur;
    int depth = 0;
    bool in_str = false, esc = false;
    for (char c : s) {
        if (in_str) {
            cur += c;
            if (esc) esc = false;
            else if (c == '\\') esc = true;
            else if (c == '"') in_str = false;
            continue;
        }
        if (c == '"') { in_str = true; cur += c; continue; }
        if (c == '(' || c == '[' || c == '{') depth++;
        if (c == ')' || c == ']' || c == '}') depth--;
        if (c == ',' && depth == 0) {
            out.push_back(trim(cur));
            cur.clear();
            continue;
        }
        cur += c;
    }
    std::string t = trim(cur);
    if (!t.empty()) out.push_back(t);
    return out;
}

namespace {

bool resolve_atom(const std::string& tok, uint64_t& out) {
    std::string t = trim(tok);
    if (t.empty()) return false;
    if (t == "NULL") { out = 0; return true; }
    // key=value (e.g. clone's child_stack=NULL)
    size_t eq = t.find('=');
    if (eq != std::string::npos && eq > 0 && t.find('=' , eq + 1) == std::string::npos) {
        std::string key = t.substr(0, eq);
        bool key_ok = true;
        for (char c : key)
            if (!(isalnum((unsigned char)c) || c == '_')) { key_ok = false; break; }
        if (key_ok) return resolve_atom(t.substr(eq + 1), out);
    }
    // negative number
    if (t[0] == '-') {
        uint64_t v;
        if (!resolve_atom(t.substr(1), v)) return false;
        out = (uint64_t)(-(int64_t)v);
        return true;
    }
    // named constant
    const auto& cs = constants();
    auto it = cs.find(t);
    if (it != cs.end()) { out = it->second; return true; }
    // number: hex / octal / decimal
    if (isdigit((unsigned char)t[0])) {
        char* end = nullptr;
        uint64_t v = strtoull(t.c_str(), &end, 0);
        if (end && *end == '\0') { out = v; return true; }
        // e.g. "08" is not valid octal; retry decimal
        end = nullptr;
        v = strtoull(t.c_str(), &end, 10);
        if (end && *end == '\0') { out = v; return true; }
        return false;
    }
    return false;
}

} // namespace

bool resolve_value(const std::string& token, uint64_t& out) {
    std::string t = trim(token);
    if (t.empty()) return false;
    // strip trailing strace comment: "0x7f /* 12 vars */"
    size_t cmt = t.find("/*");
    if (cmt != std::string::npos) t = trim(t.substr(0, cmt));
    if (t.empty()) return false;
    // flag combination: A|B|C
    if (t.find('|') != std::string::npos) {
        uint64_t sum = 0;
        size_t pos = 0;
        while (true) {
            size_t bar = t.find('|', pos);
            std::string part = trim(t.substr(pos, bar == std::string::npos ? bar : bar - pos));
            uint64_t v;
            if (!resolve_atom(part, v)) return false;
            sum |= v;
            if (bar == std::string::npos) break;
            pos = bar + 1;
        }
        out = sum;
        return true;
    }
    return resolve_atom(t, out);
}

namespace {

struct Pending {
    std::string name;
    std::string partial_args;
    int line_no = 0;
    std::string raw;
};

// Parse a "normal" syscall line (after pid/timestamp stripping).
// Input looks like: name(args) = ret   (ret part optional)
bool parse_call(const std::string& s, Event& ev) {
    size_t lp = s.find('(');
    if (lp == std::string::npos) return false;
    // syscall name = identifier immediately before '('
    size_t ne = lp;
    size_t nb = ne;
    while (nb > 0 && (isalnum((unsigned char)s[nb - 1]) || s[nb - 1] == '_')) nb--;
    std::string name = s.substr(nb, ne - nb);
    if (!is_ident(name)) return false;
    if (!trim(s.substr(0, nb)).empty()) return false; // junk before name
    // find matching close paren
    int depth = 0;
    bool in_str = false, esc = false;
    size_t rp = std::string::npos;
    for (size_t i = lp; i < s.size(); i++) {
        char c = s[i];
        if (in_str) {
            if (esc) esc = false;
            else if (c == '\\') esc = true;
            else if (c == '"') in_str = false;
            continue;
        }
        if (c == '"') { in_str = true; continue; }
        if (c == '(') depth++;
        else if (c == ')') {
            depth--;
            if (depth == 0) { rp = i; break; }
        }
    }
    if (rp == std::string::npos) return false;
    ev.name = name;
    ev.args_str = s.substr(lp + 1, rp - lp - 1);
    std::string rest = trim(s.substr(rp + 1));
    if (rest.size() >= 1 && rest[0] == '=') ev.ret_str = trim(rest.substr(1));
    ev.args = split_args(ev.args_str);
    ev.arg_vals.resize(ev.args.size());
    ev.arg_ok.resize(ev.args.size());
    for (size_t i = 0; i < ev.args.size(); i++)
        ev.arg_ok[i] = resolve_value(ev.args[i], ev.arg_vals[i]);
    return true;
}

// Strip leading pid and/or timestamp tokens. Returns remaining text.
std::string strip_prefix(const std::string& line, int& pid) {
    pid = 0;
    std::string s = trim(line);
    for (int iter = 0; iter < 3; iter++) {
        size_t sp = s.find(' ');
        if (sp == std::string::npos) break;
        std::string tok = s.substr(0, sp);
        std::string rest = trim(s.substr(sp + 1));
        if (rest.empty()) break;
        if (all_digits(tok)) {
            // Could be a pid (strace -f) or epoch seconds (strace -ttt).
            // Treat as pid only if what follows is not another number/timestamp
            // and looks like the start of a syscall line.
            bool next_is_num = false;
            size_t sp2 = rest.find(' ');
            std::string tok2 = sp2 == std::string::npos ? rest : rest.substr(0, sp2);
            if (all_digits(tok2) || is_timestamp(tok2)) next_is_num = true;
            bool next_is_call = rest.rfind("<... ", 0) == 0 ||
                                rest.rfind("+++", 0) == 0 || rest.rfind("---", 0) == 0 ||
                                is_ident(tok2);
            if (!next_is_num && next_is_call) { pid = atoi(tok.c_str()); s = rest; continue; }
            if (next_is_num) { pid = atoi(tok.c_str()); s = rest; continue; }
            break;
        }
        if (is_timestamp(tok)) { s = rest; continue; }
        break;
    }
    return s;
}

} // namespace

TraceParseResult parse_strace_files(const std::vector<std::string>& paths) {
    TraceParseResult res;
    std::map<int, Pending> pending; // per-pid unfinished calls

    for (const auto& path : paths) {
        std::ifstream in(path);
        if (!in) {
            res.warnings.push_back("cannot open trace file: " + path);
            continue;
        }
        std::string line;
        int line_no = 0;
        while (std::getline(in, line)) {
            line_no++;
            res.lines_total++;
            if (!line.empty() && line.back() == '\r') line.pop_back();
            std::string t = trim(line);
            if (t.empty()) { res.lines_skipped++; continue; }
            if (t.rfind("strace:", 0) == 0) { res.lines_skipped++; continue; }

            int pid = 0;
            std::string s = strip_prefix(t, pid);

            // control lines: exits and signals
            if (s.rfind("+++", 0) == 0 || s.rfind("---", 0) == 0) {
                res.lines_skipped++;
                continue;
            }

            // resumed call: "<... name resumed> rest"
            if (s.rfind("<... ", 0) == 0) {
                size_t tag = s.find(" resumed>");
                if (tag == std::string::npos) { res.lines_skipped++; continue; }
                std::string name = s.substr(5, tag - 5);
                std::string rest = trim(s.substr(tag + 9));
                auto it = pending.find(pid);
                std::string partial, raw0;
                int ln0 = line_no;
                if (it != pending.end() && it->second.name == name) {
                    partial = it->second.partial_args;
                    ln0 = it->second.line_no;
                    pending.erase(it);
                }
                Event ev;
                ev.pid = pid;
                ev.line_no = ln0;
                ev.file = path;
                ev.raw = line;
                if (!parse_call(name + "(" + partial + rest, ev)) {
                    res.warnings.push_back(path + ":" + std::to_string(line_no) +
                                           ": failed to parse resumed call: " + line);
                    res.lines_skipped++;
                    continue;
                }
                ev.pid = pid; ev.line_no = ln0; ev.file = path; ev.raw = line;
                res.events.push_back(std::move(ev));
                res.lines_parsed++;
                continue;
            }

            // unfinished call: "name(args <unfinished ...>"
            if (s.size() >= 16 && s.compare(s.size() - 16, 16, "<unfinished ...>") == 0) {
                std::string head = trim(s.substr(0, s.size() - 16));
                size_t lp = head.find('(');
                if (lp != std::string::npos) {
                    size_t nb = lp;
                    while (nb > 0 && (isalnum((unsigned char)head[nb - 1]) || head[nb - 1] == '_')) nb--;
                    Pending p;
                    p.name = head.substr(nb, lp - nb);
                    p.partial_args = head.substr(lp + 1);
                    p.line_no = line_no;
                    p.raw = line;
                    pending[pid] = p;
                }
                res.lines_skipped++;
                continue;
            }

            Event ev;
            if (!parse_call(s, ev)) {
                res.lines_skipped++;
                continue;
            }
            ev.pid = pid;
            ev.line_no = line_no;
            ev.file = path;
            ev.raw = line;
            res.events.push_back(std::move(ev));
            res.lines_parsed++;
        }
    }
    for (const auto& kv : pending) {
        res.warnings.push_back("pid " + std::to_string(kv.first) + ": syscall '" +
                               kv.second.name + "' was never resumed (line " +
                               std::to_string(kv.second.line_no) + ")");
    }
    return res;
}

int find_marker(const std::vector<Event>& events,
                const std::string& marker_string,
                const std::string& marker_call) {
    for (size_t i = 0; i < events.size(); i++) {
        if (!marker_call.empty() && events[i].name == marker_call) return (int)i;
        if (!marker_string.empty() && events[i].raw.find(marker_string) != std::string::npos)
            return (int)i;
    }
    return -1;
}

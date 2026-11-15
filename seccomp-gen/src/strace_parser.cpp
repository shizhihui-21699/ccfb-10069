// SPDX-License-Identifier: MIT
#include "strace_parser.h"
#include "syscall_table.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <regex>
#include <sstream>

namespace scg {

namespace {

std::string trim(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && std::isspace((unsigned char)s[a])) ++a;
    while (b > a && std::isspace((unsigned char)s[b - 1])) --b;
    return s.substr(a, b - a);
}

bool startsWith(const std::string& s, const char* p) {
    return s.compare(0, std::strlen(p), p) == 0;
}

// Parse an integer-ish token: decimal, 0x-hex, 0-octal, with optional sign.
std::optional<uint64_t> parseInteger(const std::string& t) {
    if (t.empty()) return std::nullopt;
    bool neg = false;
    size_t i = 0;
    if (t[0] == '-' || t[0] == '+') { neg = t[0] == '-'; i = 1; }
    if (i >= t.size()) return std::nullopt;
    int base = 10;
    if (t.size() - i >= 2 && t[i] == '0' &&
        (t[i + 1] == 'x' || t[i + 1] == 'X'))
        base = 16;
    else if (t.size() - i >= 1 && t[i] == '0' && t.size() - i > 1)
        base = 8;
    char* end = nullptr;
    errno = 0;
    unsigned long long v = std::strtoull(t.c_str() + (base == 16 ? i : 0),
                                         &end, base);
    if (errno != 0 || end == t.c_str() || *end != '\0') return std::nullopt;
    if (neg) v = (uint64_t)(-(int64_t)v);
    return (uint64_t)v;
}

// Split a "..." string from strace, respecting backslash escapes.
std::string unquote(const std::string& t) {
    if (t.size() < 2 || t.front() != '"') return t;
    std::string out;
    for (size_t i = 1; i + 1 < t.size() + 1 && i < t.size(); ++i) {
        char c = t[i];
        if (c == '"' && i == t.find_last_of('"')) break;
        if (c == '\\' && i + 1 < t.size()) {
            char n = t[++i];
            switch (n) {
                case 'n': out.push_back('\n'); break;
                case 't': out.push_back('\t'); break;
                case 'r': out.push_back('\r'); break;
                case '\\': out.push_back('\\'); break;
                case '"': out.push_back('"'); break;
                case '0': out.push_back('\0'); break;
                default: out.push_back(n); break;
            }
        } else {
            out.push_back(c);
        }
    }
    return out;
}

} // namespace

std::optional<uint64_t> parseScalar(const std::string& tokenIn) {
    std::string t = trim(tokenIn);
    if (t.empty() || t == "NULL" || t == "nullptr") {
        if (t == "NULL" || t == "nullptr") return 0ULL;
        return std::nullopt;
    }
    // OR-combined flags: every component must resolve.
    if (t.find('|') != std::string::npos) {
        uint64_t acc = 0;
        size_t start = 0;
        while (start <= t.size()) {
            size_t p = t.find('|', start);
            std::string part = trim(t.substr(start, p == std::string::npos
                                                         ? std::string::npos
                                                         : p - start));
            auto v = parseScalar(part);
            if (!v) return std::nullopt;
            acc |= *v;
            if (p == std::string::npos) break;
            start = p + 1;
        }
        return acc;
    }
    // Numeric first.
    if (auto n = parseInteger(t)) return n;
    // Symbolic constant (strip trailing array subscripts etc.).
    if (auto c = resolveConstant(t)) return c;
    return std::nullopt;
}

std::optional<ArgValue> parseArgToken(const std::string& rawIn) {
    std::string raw = trim(rawIn);
    if (raw.empty()) return std::nullopt;
    ArgValue av;
    av.raw = raw;
    if (raw.front() == '"') {
        av.isString = true;
        av.strValue = unquote(raw);
        return av; // string args are not numeric constraints
    }
    // Take the leading scalar before any space or '[': e.g. "SOCK_STREAM [1]",
    // "AF_INET 2", "FUTEX_WAIT_PRIVATE|FUTEX_CLOCK_REALTIME (1|256)".
    std::string head = raw;
    size_t sp = raw.find_first_of(" \t[({");
    if (sp != std::string::npos) head = raw.substr(0, sp);
    if (head.empty()) return av;
    av.number = parseScalar(head);
    return av;
}

std::vector<std::string> splitArgs(const std::string& text) {
    std::vector<std::string> out;
    int depth = 0;
    bool inStr = false;
    size_t start = 0;
    for (size_t i = 0; i < text.size(); ++i) {
        char c = text[i];
        if (inStr) {
            if (c == '\\' && i + 1 < text.size()) { ++i; continue; }
            if (c == '"') inStr = false;
            continue;
        }
        if (c == '"') { inStr = true; continue; }
        if (c == '(' || c == '[' || c == '{' || c == '<') ++depth;
        else if (c == ')' || c == ']' || c == '}' || c == '>') depth = std::max(0, depth - 1);
        else if (c == ',' && depth == 0) {
            out.push_back(trim(text.substr(start, i - start)));
            start = i + 1;
        }
    }
    std::string tail = trim(text.substr(start));
    if (!tail.empty() || !out.empty()) out.push_back(tail);
    return out;
}

bool StraceParser::isRuntime(int tid) {
    if (globalRuntime_) return true;
    auto it = tidRuntime_.find(tid);
    return it != tidRuntime_.end() && it->second;
}

void StraceParser::noteForkLike(const SysEvent& e) {
    if (e.syscall != "clone" && e.syscall != "clone3" &&
        e.syscall != "fork" && e.syscall != "vfork")
        return;
    if (!e.hasResult || e.failed || e.result <= 0) return;
    int childTid = (int)e.result;
    // Child inherits the phase state of its creator.
    tidRuntime_[childTid] = isRuntime(e.tid);
}

namespace {

// Strip "PID  " or "[pid NNN] " plus optional timestamp; return tid and rest.
bool stripPrefix(const std::string& line, int& tid, std::string& rest) {
    static const std::regex reBracket(
        R"(^\[pid\s+(\d+)\]\s+([0-9:.]+\s+)?(.*)$)");
    static const std::regex rePlain(
        R"(^(\d+)\s+([0-9:.]+\s+)?(.*)$)");
    std::smatch m;
    if (std::regex_match(line, m, reBracket)) {
        tid = std::stoi(m[1]);
        rest = m[3];
        return true;
    }
    if (std::regex_match(line, m, rePlain)) {
        tid = std::stoi(m[1]);
        rest = m[3];
        return true;
    }
    return false;
}

// Split "syscall(args)" and optional " = result" tail. Balanced parens.
bool splitCall(const std::string& body, std::string& name,
               std::string& argsText, std::string& tail) {
    size_t p = body.find('(');
    if (p == std::string::npos) return false;
    name = trim(body.substr(0, p));
    if (name.empty() ||
        !std::all_of(name.begin(), name.end(),
                     [](char c) { return std::isalnum((unsigned char)c) ||
                                          c == '_' || c == '.'; }))
        return false;
    int depth = 0;
    bool inStr = false;
    for (size_t i = p; i < body.size(); ++i) {
        char c = body[i];
        if (inStr) {
            if (c == '\\' && i + 1 < body.size()) { ++i; continue; }
            if (c == '"') inStr = false;
            continue;
        }
        if (c == '"') { inStr = true; continue; }
        if (c == '(') ++depth;
        else if (c == ')') {
            --depth;
            if (depth == 0) {
                argsText = body.substr(p + 1, i - p - 1);
                tail = trim(body.substr(i + 1));
                return true;
            }
        }
    }
    return false;
}

void parseResult(const std::string& tail, SysEvent& ev) {
    if (tail.empty() || tail[0] != '=') return;
    ev.hasResult = true;
    std::string rhs = trim(tail.substr(1));
    // "?" means strace couldn't know (e.g. killed mid-call).
    if (rhs == "?") { ev.hasResult = false; return; }
    // errno form: "-1 EINVAL (Invalid argument)"
    static const std::regex reErr(R"(^-1\s+E[A-Z0-9_]+\b.*$)");
    if (std::regex_match(rhs, reErr)) {
        ev.failed = true;
        std::istringstream iss(rhs);
        std::string minusOne, errName;
        iss >> minusOne >> errName;
        if (auto n = resolveConstant(errName)) ev.errNo = (int)*n;
        ev.result = -1;
        return;
    }
    // Plain number (possibly signed / hex), or enum "name (123)".
    std::string head = rhs;
    size_t sp = rhs.find(' ');
    if (sp != std::string::npos) head = rhs.substr(0, sp);
    if (auto n = parseScalar(head)) ev.result = (int64_t)*n;
    else if (auto m = parseScalar(rhs)) ev.result = (int64_t)*m;
}

} // namespace

ParseResult StraceParser::parse(std::istream& in) {
    ParseResult res;
    std::string line;
    while (std::getline(in, line)) {
        ++res.stats.lines;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (trim(line).empty()) continue;

        int tid = 0;
        std::string body;
        if (!stripPrefix(line, tid, body)) {
            ++res.stats.parseErrors;
            res.warnings.push_back("line " + std::to_string(res.stats.lines) +
                                   ": cannot parse prefix: " + line);
            continue;
        }
        res.stats.tids.insert(tid);
        if (!tidRuntime_.count(tid)) tidRuntime_[tid] = false;

        // Noise: signals, process exits, seccomp notices.
        if (startsWith(body, "--- ") || startsWith(body, "+++ ") ||
            startsWith(body, "seccomp ")) {
            ++res.stats.noiseLines;
            continue;
        }

        // Continuation of an unfinished call.
        static const std::regex reResume(
            R"(^<\.\.\.\s*([A-Za-z0-9_.]+)\s+resumed>\s*(.*)$)");
        std::smatch rm;
        if (std::regex_match(body, rm, reResume)) {
            ++res.stats.resumed;
            auto it = pending_.find(tid);
            if (it == pending_.end()) {
                ++res.stats.parseErrors;
                res.warnings.push_back(
                    "line " + std::to_string(res.stats.lines) +
                    ": resumed with no pending call on tid " +
                    std::to_string(tid));
                continue;
            }
            Pending pend = it->second;
            pending_.erase(it);

            std::string tail = trim(rm[2]);
            // resumed line usually ends "= 0"; may itself carry nothing.
            SysEvent ev;
            ev.pid = pend.pid;
            ev.tid = pend.tid;
            ev.syscall = pend.syscall;
            ev.lineNo = res.stats.lines;
            for (auto& a : splitArgs(pend.argsText)) {
                if (auto av = parseArgToken(a)) ev.args.push_back(*av);
            }
            parseResult(tail, ev);
            ev.phase = isRuntime(tid) ? "runtime" : "boot";
            if (!marker_.empty() && ev.syscall == marker_ && !globalRuntime_) {
                globalRuntime_ = true;
                res.stats.markerSeen = true;
                res.stats.markerLine = ev.lineNo;
                for (auto& kv : tidRuntime_) kv.second = true;
                ev.phase = "runtime";
            }
            res.events.push_back(ev);
            ++res.stats.events;
            noteForkLike(ev);
            continue;
        }

        std::string name, argsText, tail;
        if (!splitCall(body, name, argsText, tail)) {
            ++res.stats.noiseLines;
            continue;
        }

        // Unfinished start: stash and wait for the resumed line.
        if (tail.find("<unfinished ...>") != std::string::npos) {
            ++res.stats.unfinished;
            pending_[tid] = Pending{name, argsText, res.stats.lines, tid, tid};
            continue;
        }

        SysEvent ev;
        ev.pid = tid;
        ev.tid = tid;
        ev.syscall = name;
        ev.lineNo = res.stats.lines;
        for (auto& a : splitArgs(argsText)) {
            if (auto av = parseArgToken(a)) ev.args.push_back(*av);
        }
        parseResult(tail, ev);
        ev.phase = isRuntime(tid) ? "runtime" : "boot";

        if (!marker_.empty() && ev.syscall == marker_ && !globalRuntime_) {
            globalRuntime_ = true;
            res.stats.markerSeen = true;
            res.stats.markerLine = ev.lineNo;
            for (auto& kv : tidRuntime_) kv.second = true;
            ev.phase = "runtime";
        }

        res.events.push_back(ev);
        ++res.stats.events;
        noteForkLike(ev);
    }

    for (const auto& [tid, pend] : pending_) {
        res.warnings.push_back(
            "tid " + std::to_string(tid) + ": unfinished syscall " +
            pend.syscall + " from line " + std::to_string(pend.startLine) +
            " never resumed; dropped");
        ++res.stats.parseErrors;
    }

    if (!marker_.empty() && !res.stats.markerSeen) {
        res.warnings.push_back(
            "phase marker syscall '" + marker_ +
            "' never observed; all " + std::to_string(res.events.size()) +
            " events classified as boot");
    }
    return res;
}

} // namespace scg

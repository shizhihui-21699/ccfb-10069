// SPDX-License-Identifier: MIT
// seccomp-gen command line.
#include "bpf.h"
#include "common.h"
#include "compiler.h"
#include "policy.h"
#include "strace_parser.h"
#include "syscall_table.h"
#include "verifier.h"

#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>

using namespace scg;

namespace {

struct Args {
    std::map<std::string, std::string> opt;
    std::vector<std::string> positional;
    std::vector<std::string> multi(const std::string& key) const {
        std::vector<std::string> out;
        for (auto it = opt.lower_bound(key);
             it != opt.end() && it->first == key; ++it)
            out.push_back(it->second);
        return out;
    }
    std::string get(const std::string& k, const std::string& dflt = "") const {
        auto it = opt.find(k);
        return it == opt.end() ? dflt : it->second;
    }
    bool has(const std::string& k) const { return opt.count(k) > 0; }
};

Args parseArgs(int argc, char** argv) {
    Args a;
    for (int i = 1; i < argc; ++i) {
        std::string t = argv[i];
        if (t.rfind("--", 0) == 0) {
            std::string key = t.substr(2);
            std::string val = "1";
            auto eq = key.find('=');
            if (eq != std::string::npos) {
                val = key.substr(eq + 1);
                key = key.substr(0, eq);
            } else if (i + 1 < argc && argv[i + 1][0] != '-') {
                val = argv[++i];
            }
            a.opt.emplace(key, val);
        } else {
            a.positional.push_back(t);
        }
    }
    return a;
}

std::ifstream openInput(const std::string& path) {
    std::ifstream f(path);
    if (!f) throw Error("cannot open input: " + path);
    return f;
}

void writeFile(const std::string& path, const std::string& content) {
    std::ofstream f(path);
    if (!f) throw Error("cannot write: " + path);
    f << content;
}

std::string jsonEscape(const std::string& s) {
    std::string o;
    for (char c : s) {
        switch (c) {
            case '"': o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n"; break;
            case '\t': o += "\\t"; break;
            default:
                if ((unsigned char)c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof buf, "\\u%04x", c);
                    o += buf;
                } else o += c;
        }
    }
    return o;
}

std::string eventsJson(const ParseResult& r) {
    std::ostringstream os;
    os << "[\n";
    for (size_t i = 0; i < r.events.size(); ++i) {
        const auto& e = r.events[i];
        os << "  {\"line\":" << e.lineNo << ",\"tid\":" << e.tid
           << ",\"phase\":\"" << e.phase << "\",\"syscall\":\""
           << jsonEscape(e.syscall) << "\",\"args\":[";
        for (size_t j = 0; j < e.args.size(); ++j) {
            if (j) os << ',';
            os << "{\"raw\":\"" << jsonEscape(e.args[j].raw) << "\"";
            if (e.args[j].number)
                os << ",\"num\":" << *e.args[j].number;
            os << '}';
        }
        os << "],\"failed\":" << (e.failed ? "true" : "false") << "}";
        if (i + 1 < r.events.size()) os << ',';
        os << '\n';
    }
    os << "]\n";
    return os.str();
}

int cmdParse(const Args& a) {
    if (a.positional.size() < 2)
        throw Error("usage: parse <strace.log> --out events.json [--marker X]");
    auto in = openInput(a.positional[1]);
    StraceParser parser(a.get("marker", "SECCMP_READY"));
    auto res = parser.parse(in);
    std::cout << "parsed " << res.stats.events << " events from "
              << res.stats.lines << " lines; tasks="
              << res.stats.tids.size()
              << " unfinished=" << res.stats.unfinished
              << " resumed=" << res.stats.resumed
              << " markerSeen=" << (res.stats.markerSeen ? "yes" : "NO")
              << '\n';
    for (const auto& w : res.warnings) std::cout << "warning: " << w << '\n';
    if (a.has("out")) writeFile(a.get("out"), eventsJson(res));
    return 0;
}

int cmdGen(const Args& a) {
    if (a.positional.size() < 2)
        throw Error("usage: gen <strace.log> --arch x86_64 [options]");
    auto arch = archFromName(a.get("arch", "x86_64"));
    if (!arch) throw Error("bad --arch");
    auto in = openInput(a.positional[1]);
    StraceParser parser(a.get("marker", "SECCMP_READY"));
    auto trace = parser.parse(in);

    GenOptions opt;
    opt.arch = *arch;
    opt.phase = a.get("phase", "runtime");
    if (opt.phase != "boot" && opt.phase != "runtime" && opt.phase != "all")
        throw Error("--phase must be boot|runtime|all");
    opt.phaseMarker = a.get("marker", "SECCMP_READY");
    opt.autoArgs = a.has("auto-args");
    opt.maxInSet = (unsigned)std::stoul(a.get("max-in-set", "8"));
    opt.includeFailed = a.has("include-failed");
    if (a.has("default")) {
        std::string d = a.get("default");
        if (d == "KILL") opt.defaultAction = SeccompAction::KILL;
        else if (d == "ERRNO") opt.defaultAction = SeccompAction::ERRNO;
        else if (d == "LOG") opt.defaultAction = SeccompAction::LOG;
        else throw Error("bad --default");
    }
    opt.dslFiles = a.multi("dsl");

    SyscallTable table(*arch);
    GenReport gen;
    Policy pol = buildPolicy(trace, table, opt, gen);
    CompileResult cr = compilePolicy(pol, table);

    auto cases = buildCases(trace, pol, table);
    VerifyOutcome vo = runVerification(cr.blob.prog, cases, *arch);

    std::cout << "generated " << cr.blob.prog.size()
              << " BPF insns for " << archName(*arch) << "/"
              << pol.phase << "; rules=" << pol.rules.size()
              << " verify: " << vo.passed << "/" << vo.total
              << " passed, " << vo.failed << " failed\n";
    for (const auto& w : gen.warnings) std::cout << "warning: " << w << '\n';
    for (const auto& w : trace.warnings)
        std::cout << "warning: " << w << '\n';
    if (vo.failed)
        for (const auto& f : vo.failures)
            std::cout << "VERIFY FAIL: " << f.cs.syscall << ": "
                      << f.detail << '\n';

    std::string base = a.get("out-prefix", "policy");
    auto blobBytes = serializeFilter(cr.blob);
    writeFile(base + ".bpf",
              std::string((const char*)blobBytes.data(), blobBytes.size()));
    writeFile(base + ".dsl", emitDsl(pol));
    writeFile(base + ".h", emitCArray(cr.blob));
    writeFile(base + ".md", renderReport(pol, table, trace, gen, cr.blob, vo));
    std::cout << "wrote " << base << ".{bpf,dsl,h,md}\n";
    return vo.failed ? 2 : 0;
}

int cmdVerify(const Args& a) {
    if (a.positional.size() < 3)
        throw Error("usage: verify <policy.bpf> <strace.log> [--marker X]");
    std::ifstream bf(a.positional[1], std::ios::binary);
    if (!bf) throw Error("cannot open filter");
    std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(bf)),
                               std::istreambuf_iterator<char>());
    FilterBlob blob = deserializeFilter(bytes);
    auto verr = bpfVerify(blob.prog);
    if (!verr.empty())
        for (const auto& e : verr)
            std::cout << "filter verify error pc=" << e.pc << ": "
                      << e.message << '\n';

    auto arch = archFromName(blob.archName);
    if (!arch) throw Error("filter has unknown arch");
    SyscallTable table(*arch);
    auto in = openInput(a.positional[2]);
    StraceParser parser(a.get("marker", "SECCMP_READY"));
    auto trace = parser.parse(in);

    // Reconstruct a policy oracle from the trace using the filter's
    // phase/default and the same code-generation switches the blob was
    // built with (pass --auto-args to replay an argument-constrained
    // filter), then compare VM decisions event by event.
    GenOptions opt;
    opt.arch = *arch;
    opt.phase = blob.phase;
    opt.phaseMarker = a.get("marker", "SECCMP_READY");
    opt.defaultAction = blob.defaultAction;
    opt.defaultErrno = blob.defaultErrno;
    opt.autoArgs = a.has("auto-args");
    GenReport gen;
    Policy oracle = buildPolicy(trace, table, opt, gen);

    auto cases = buildCases(trace, oracle, table);
    VerifyOutcome vo = runVerification(blob.prog, cases, *arch);
    std::cout << "replayed " << vo.total << " evaluations: "
              << vo.passed << " passed, " << vo.failed << " failed ("
              << vo.positiveCases << " positive, " << vo.negativeCases
              << " negative, " << vo.crossArchCases << " cross-arch)\n";
    for (const auto& f : vo.failures)
        std::cout << "FAIL line=" << f.cs.lineNo << " " << f.cs.syscall
                  << " [" << f.cs.mutation << "]: " << f.detail << '\n';
    return vo.failed ? 2 : 0;
}

int cmdSelftest() {
    // End-to-end synthetic trace exercising threading, fork, unfinished
    // lines, phase marker, arg constraints and both architectures.
    const char* sample =
        "1000  0.000000 execve(\"/usr/bin/svc\", [\"svc\"], 0x7ff) = 0\n"
        "1000  0.000001 brk(NULL) = 0x55550000\n"
        "1000  0.000002 mmap(NULL, 4096, PROT_READ|PROT_WRITE, "
        "MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f00\n"
        "1000  0.000003 clone(CLONE_VM|CLONE_FS|CLONE_THREAD|CLONE_SIGHAND, "
        "0, 0, 0, 0) = 1001\n"
        "1001  0.000004 futex(0x7f00, FUTEX_WAIT_PRIVATE, 0, NULL) = 0\n"
        "1000  0.000005 socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, "
        "IPPROTO_TCP) = 3 <unfinished ...>\n"
        "1000  0.000006 <... socket resumed> ) = 3\n"
        "1000  0.000007 connect(3, {sa_family=AF_INET, sin_port=htons(80)}, "
        "16) = 0\n"
        "1000  0.000008 openat(AT_FDCWD, \"/etc/svc.conf\", O_RDONLY) = 4\n"
        "1000  0.000009 read(4, \"config=1\", 8) = 8\n"
        "1000  0.000010 close(4) = 0\n"
        "1000  0.000011 SECCMP_READY() = 0\n"
        "1000  0.000012 epoll_wait(5, [{EPOLLIN, {u32=3, u64=3}}], 64, -1) = 1\n"
        "1001  0.000013 recvfrom(3, \"hello\", 5, 0, NULL, NULL) = 5\n"
        "1000  0.000014 write(1, \"ok\", 2) = 2\n"
        "1000  0.000015 getrandom(0x7f10, 32, GRND_NONBLOCK) = 32\n"
        "1000  0.000016 --- SIGTERM {si_signo=SIGTERM} ---\n"
        "1000  0.000017 +++ exited with 0 +++\n";

    int rc = 0;
    for (Arch arch : {Arch::X86_64, Arch::AARCH64}) {
        std::istringstream in(sample);
        StraceParser parser("SECCMP_READY");
        auto trace = parser.parse(in);
        if (!trace.stats.markerSeen)
            throw Error("selftest: marker not detected");
        if (trace.stats.tids.size() != 2)
            throw Error("selftest: expected 2 tasks, got " +
                        std::to_string(trace.stats.tids.size()));
        if (trace.stats.unfinished != 1 || trace.stats.resumed != 1)
            throw Error("selftest: unfinished/resumed merge failed");

        SyscallTable table(arch);
        GenOptions opt;
        opt.arch = arch;
        opt.phase = "runtime";
        opt.autoArgs = true;
        GenReport gen;
        Policy pol = buildPolicy(trace, table, opt, gen);

        // Explicit deny overlay semantics.
        {
            std::istringstream dsl("KILL ptrace;\n");
            Policy overlay = parseDsl(dsl, "selftest", pol);
            const Rule& last = overlay.rules.back();
            if (last.syscall != "ptrace" ||
                last.action != SeccompAction::KILL)
                throw Error("selftest: DSL overlay rule wrong");
            if (overlay.rules.size() != pol.rules.size() + 1)
                throw Error("selftest: DSL overlay must append one rule");
        }

        CompileResult cr = compilePolicy(pol, table);
        auto verr = bpfVerify(cr.blob.prog);
        if (!verr.empty())
            throw Error("selftest: verifier rejected generated filter");

        // Round-trip the binary blob through (de)serialization.
        auto bytes = serializeFilter(cr.blob);
        FilterBlob again = deserializeFilter(bytes);
        if (again.prog != cr.blob.prog)
            throw Error("selftest: filter blob round-trip mismatch");

        auto cases = buildCases(trace, pol, table);
        VerifyOutcome vo = runVerification(cr.blob.prog, cases, arch);
        std::cout << "[" << archName(arch) << "] events=" << trace.stats.events
                  << " insns=" << cr.blob.prog.size()
                  << " cases=" << vo.total << " passed=" << vo.passed
                  << " failed=" << vo.failed << "\n";
        if (vo.failed) {
            for (const auto& f : vo.failures) {
                std::cout << "  FAIL " << f.cs.syscall << " ["
                          << f.cs.mutation << "] args=";
                for (uint64_t v : f.cs.args) std::cout << v << ",";
                std::cout << " : " << f.detail << "\n";
            }
            rc = 2;
        }

        // Boot filter too, so the startup path is covered.
        GenOptions bopt = opt;
        bopt.phase = "boot";
        GenReport bgen;
        Policy bpol = buildPolicy(trace, table, bopt, bgen);
        CompileResult bcr = compilePolicy(bpol, table);
        auto bc = buildCases(trace, bpol, table);
        VerifyOutcome bvo = runVerification(bcr.blob.prog, bc, arch);
        std::cout << "[" << archName(arch) << "/boot] insns="
                  << bcr.blob.prog.size() << " cases=" << bvo.total
                  << " failed=" << bvo.failed << "\n";
        for (size_t i = 0; i < bvo.failures.size() && i < 8; ++i) {
            const auto& f = bvo.failures[i];
            std::cout << "  boot FAIL " << f.cs.syscall << " nr=" << f.cs.nr
                      << " [" << f.cs.mutation << "] args=";
            for (uint64_t v : f.cs.args) std::cout << v << ",";
            std::cout << " : " << f.detail << "\n";
        }
        if (bvo.failed) rc = 2;
    }
    if (!rc) std::cout << "selftest OK\n";
    return rc;
}

int cmdDisasm(const Args& a) {
    if (a.positional.size() < 2)
        throw Error("usage: disasm <policy.bpf>");
    std::ifstream bf(a.positional[1], std::ios::binary);
    if (!bf) throw Error("cannot open filter");
    std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(bf)),
                               std::istreambuf_iterator<char>());
    FilterBlob blob = deserializeFilter(bytes);
    const char* cls[] = {"LD","LDX","ST","STX","ALU","JMP","RET","MISC"};
    for (size_t i = 0; i < blob.prog.size(); ++i) {
        const auto& in = blob.prog[i];
        uint8_t c = in.code & 7;
        std::ostringstream os;
        os << std::setw(4) << i << ": code=" << std::hex << std::setw(4)
           << std::setfill('0') << in.code << std::dec << std::setfill(' ')
           << " " << cls[c] << " jt=" << (unsigned)in.jt
           << " jf=" << (unsigned)in.jf << " k=" << in.k;
        if (c == 6) {
            os << "  ; RET 0x" << std::hex << in.k << std::dec;
        }
        std::cout << os.str() << '\n';
    }
    return 0;
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr <<
            "usage: seccomp-gen <parse|gen|verify|selftest> [args...]\n"
            "  parse   <strace.log> [--marker M] [--out events.json]\n"
            "  gen     <strace.log> --arch x86_64|aarch64 [--phase boot|runtime|all]\n"
            "          [--auto-args] [--max-in-set N] [--default KILL|ERRNO|LOG]\n"
            "          [--dsl rules.dsl]... [--marker M] [--out-prefix base]\n"
            "  verify  <policy.bpf> <strace.log> [--marker M]\n"
            "  selftest\n";
        return 1;
    }
    try {
        Args a = parseArgs(argc, argv);
        std::string cmd = a.positional.empty() ? "" : a.positional[0];
        if (cmd == "parse") return cmdParse(a);
        if (cmd == "gen") return cmdGen(a);
        if (cmd == "verify") return cmdVerify(a);
        if (cmd == "disasm") return cmdDisasm(a);
        if (cmd == "selftest") return cmdSelftest();
        throw Error("unknown command: " + cmd);
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << '\n';
        return 1;
    }
}

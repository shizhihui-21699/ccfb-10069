// End-to-end through the CLI: a generated policy must verify, a policy that
// would break the service must not, and the written files must round-trip.
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>

#include "test_harness.h"

namespace {

std::string TempDir() {
  const char* tmp = std::getenv("TMPDIR");
  return std::string(tmp ? tmp : "/tmp");
}

std::string WriteTemp(const std::string& name, const std::string& content) {
  std::string path = TempDir() + "/sctrace-test-" + name;
  std::ofstream out(path, std::ios::binary);
  out << content;
  return path;
}

std::string ReadAll(const std::string& path) {
  std::ifstream in(path, std::ios::binary);
  std::ostringstream buffer;
  buffer << in.rdbuf();
  return buffer.str();
}

std::string ShellQuote(const std::string& s) { return "'" + s + "'"; }

const char* kTrace =
    "1  0.1 execve(\"/s\", [\"s\"], 0x1) = 0\n"
    "1  0.2 socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 3\n"
    "1  0.3 bind(3, {sa_family=AF_INET}, 16) = 0\n"
    "1  0.4 listen(3, 5) = 0\n"
    "1  0.5 epoll_wait(4, [], 8, -1) = 1\n"
    "1  0.6 accept4(3, NULL, NULL, SOCK_CLOEXEC) = 5\n"
    "1  0.7 read(5, \"x\", 1) = 1\n"
    "1  0.8 write(5, \"y\", 1) = 1\n";

int RunSctrace(const std::string& args, std::string* output) {
  std::string command = ShellQuote(SCTRACE_BINARY) + " " + args + " 2>&1";
  FILE* pipe = popen(command.c_str(), "r");
  if (!pipe) return -1;
  std::string text;
  char buffer[4096];
  while (fgets(buffer, sizeof(buffer), pipe)) text += buffer;
  int status = pclose(pipe);
  if (output) *output = text;
  return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

}  // namespace

TEST(cli_generate_writes_a_verifiable_policy) {
  std::string trace = WriteTemp("e2e.log", kTrace);
  std::string policy = TempDir() + "/sctrace-test-e2e.dsl";
  std::string report = TempDir() + "/sctrace-test-e2e.md";
  std::string source = TempDir() + "/sctrace-test-e2e.c";
  std::string output;
  int rc = RunSctrace("generate --trace " + ShellQuote(trace) + " --write-policy " +
                          ShellQuote(policy) + " --report " + ShellQuote(report) +
                          " --c-source " + ShellQuote(source),
                      &output);
  CHECK_EQ(rc, 0);
  CHECK(output.find("verified") != std::string::npos);

  std::string policy_text = ReadAll(policy);
  CHECK(policy_text.find("default kill") != std::string::npos);
  CHECK(policy_text.find("socket") != std::string::npos);
  // The generated policy constrains the socket family.
  CHECK(policy_text.find("AF_INET") != std::string::npos);

  std::string report_text = ReadAll(report);
  CHECK(report_text.find("Verification against the trace") != std::string::npos);
  CHECK(report_text.find("Result: every recorded call") != std::string::npos);

  // The C file must contain both programs and the install entry points.
  std::string c_text = ReadAll(source);
  CHECK(c_text.find("sctrace_startup_program") != std::string::npos);
  CHECK(c_text.find("sctrace_runtime_program") != std::string::npos);
  CHECK(c_text.find("SECCOMP_SET_MODE_FILTER") != std::string::npos);
  CHECK(c_text.find("PR_SET_NO_NEW_PRIVS") != std::string::npos);

  // Re-verifying the written policy must agree.
  rc = RunSctrace("verify --trace " + ShellQuote(trace) + " --policy " +
                      ShellQuote(policy),
                  &output);
  CHECK_EQ(rc, 0);
}

TEST(cli_verify_fails_when_the_policy_blocks_the_service) {
  std::string trace = WriteTemp("block.log", kTrace);
  std::string policy = WriteTemp(
      "block.dsl", "default kill\nruntime { allow read }\n");
  std::string output;
  int rc = RunSctrace("verify --trace " + ShellQuote(trace) + " --policy " +
                          ShellQuote(policy),
                      &output);
  CHECK_EQ(rc, 1);
  CHECK(output.find("the policy denies") != std::string::npos);
  CHECK(output.find("FAILED") != std::string::npos);
}

TEST(cli_reports_usage_errors_with_exit_code_2) {
  std::string output;
  CHECK_EQ(RunSctrace("generate", &output), 2);
  CHECK(output.find("--trace is required") != std::string::npos);
  CHECK_EQ(RunSctrace("verify --trace /nonexistent --policy /nonexistent", &output), 2);
  CHECK_EQ(RunSctrace("bogus-command", &output), 2);
}

TEST(cli_dump_prints_the_split_trace) {
  std::string trace = WriteTemp("dump.log", kTrace);
  std::string output;
  CHECK_EQ(RunSctrace("dump --trace " + ShellQuote(trace), &output), 0);
  CHECK(output.find("startup") != std::string::npos);
  CHECK(output.find("runtime") != std::string::npos);
  CHECK(output.find("epoll_wait") != std::string::npos);
}

TEST(cli_tables_prints_numbers_for_the_architecture) {
  std::string output;
  CHECK_EQ(RunSctrace("tables --arch aarch64", &output), 0);
  CHECK(output.find("63 read") != std::string::npos);
  CHECK_EQ(RunSctrace("tables --arch x86_64", &output), 0);
  CHECK(output.find("0 read") != std::string::npos);
}

TEST(cli_examples_in_the_repository_are_consistent) {
  // The committed example policy must verify against the committed example
  // trace; otherwise the documentation teaches something that does not work.
  std::string output;
  int rc = RunSctrace("verify --trace " SCTRACE_SOURCE_DIR
                      "/examples/sample-trace.log --policy " SCTRACE_SOURCE_DIR
                      "/examples/http-service.policy",
                      &output);
  CHECK_EQ(rc, 0);
  CHECK(output.find("verified") != std::string::npos);
}

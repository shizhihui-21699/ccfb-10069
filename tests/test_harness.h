// A tiny test harness: no dependency, clear output, non-zero exit on failure.
#pragma once

#include <cmath>
#include <cstdio>
#include <ostream>
#include <type_traits>
#include <functional>
#include <sstream>
#include <string>
#include <vector>

namespace sctest {

struct TestCase {
  std::string name;
  std::function<void()> body;
};

inline std::vector<TestCase>& Registry() {
  static std::vector<TestCase> tests;
  return tests;
}

struct Registrar {
  Registrar(const char* name, std::function<void()> body) {
    Registry().push_back({name, std::move(body)});
  }
};

struct Failure {
  std::string message;
};

inline int& FailureCount() {
  static int count = 0;
  return count;
}

inline const char*& CurrentTest() {
  static const char* name = "";
  return name;
}

inline std::string ToText(const std::string& v) { return "\"" + v + "\""; }
inline std::string ToText(const char* v) { return std::string("\"") + v + "\""; }
inline std::string ToText(bool v) { return v ? "true" : "false"; }
inline std::string ToText(unsigned long long v) { return std::to_string(v); }
inline std::string ToText(long long v) { return std::to_string(v); }
inline std::string ToText(unsigned v) { return std::to_string(v); }
inline std::string ToText(int v) { return std::to_string(v); }
template <typename T>
std::string ToText(const T& v) {
  if constexpr (std::is_enum_v<T>) {
    return std::to_string(static_cast<long long>(v));
  } else if constexpr (requires(std::ostream& os, const T& value) { os << value; }) {
    std::ostringstream out;
    out << v;
    return out.str();
  } else {
    return "<value>";
  }
}

inline void ReportFailure(const char* file, int line, const std::string& message) {
  ++FailureCount();
  std::fprintf(stderr, "FAIL %s\n  %s:%d: %s\n", CurrentTest(), file, line,
               message.c_str());
}

inline int RunAll(const char* filter) {
  int run = 0;
  int failed_tests = 0;
  for (auto& test : Registry()) {
    if (filter && *filter && test.name.find(filter) == std::string::npos) continue;
    ++run;
    int before = FailureCount();
    CurrentTest() = test.name.c_str();
    try {
      test.body();
    } catch (const Failure& failure) {
      ReportFailure("<thrown>", 0, failure.message);
    } catch (const std::exception& error) {
      ReportFailure("<exception>", 0, error.what());
    } catch (...) {
      ReportFailure("<unknown>", 0, "unknown exception");
    }
    if (FailureCount() != before) {
      ++failed_tests;
    } else {
      std::printf("ok   %s\n", test.name.c_str());
    }
  }
  std::printf("\n%d test(s), %d failed check(s) in %d test(s)\n", run,
              FailureCount(), failed_tests);
  return FailureCount() == 0 ? 0 : 1;
}

}  // namespace sctest

#define TEST(name)                                                    \
  static void test_##name();                                          \
  static ::sctest::Registrar registrar_##name(#name, test_##name);    \
  static void test_##name()

#define CHECK(condition)                                                     \
  do {                                                                       \
    if (!(condition)) {                                                      \
      ::sctest::ReportFailure(__FILE__, __LINE__, "CHECK failed: " #condition); \
      return;                                                                \
    }                                                                        \
  } while (0)

#define CHECK_EQ(actual, expected)                                            \
  do {                                                                        \
    const auto& a_ = (actual);                                                \
    const auto& e_ = (expected);                                              \
    if (!(a_ == e_)) {                                                        \
      ::sctest::ReportFailure(__FILE__, __LINE__,                             \
                              "CHECK_EQ failed: " #actual " == " #expected    \
                              "\n    actual:   " +                            \
                                  ::sctest::ToText(a_) +                      \
                              "\n    expected: " + ::sctest::ToText(e_));     \
      return;                                                                 \
    }                                                                         \
  } while (0)

#define EXPECT(condition)                                                    \
  do {                                                                       \
    if (!(condition)) {                                                      \
      ::sctest::ReportFailure(__FILE__, __LINE__, "EXPECT failed: " #condition); \
    }                                                                        \
  } while (0)

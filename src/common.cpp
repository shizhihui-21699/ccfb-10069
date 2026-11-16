#include "common.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>

namespace scgen {

std::string SourceLoc::ToString() const {
  if (!valid()) return "<unknown>";
  std::string out;
  if (!file.empty()) out += file + ":";
  out += std::to_string(line);
  if (column > 0) out += ":" + std::to_string(column);
  return out;
}

Error::Error(SourceLoc loc, std::string message)
    : std::runtime_error([&] {
        std::string prefix = loc.ToString();
        return (prefix.empty() ? std::string() : prefix + ": ") + message;
      }()),
      loc_(std::move(loc)) {}

std::string_view Trim(std::string_view s) {
  size_t begin = 0;
  while (begin < s.size() && std::isspace(static_cast<unsigned char>(s[begin]))) ++begin;
  size_t end = s.size();
  while (end > begin && std::isspace(static_cast<unsigned char>(s[end - 1]))) --end;
  return s.substr(begin, end - begin);
}

std::string ToLower(std::string_view s) {
  std::string out(s);
  std::transform(out.begin(), out.end(), out.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return out;
}

std::string ToUpper(std::string_view s) {
  std::string out(s);
  std::transform(out.begin(), out.end(), out.begin(),
                 [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
  return out;
}

bool StartsWith(std::string_view s, std::string_view prefix) {
  return s.size() >= prefix.size() && s.substr(0, prefix.size()) == prefix;
}

bool EndsWith(std::string_view s, std::string_view suffix) {
  return s.size() >= suffix.size() &&
         s.substr(s.size() - suffix.size(), suffix.size()) == suffix;
}

std::vector<std::string_view> Split(std::string_view s, char sep) {
  std::vector<std::string_view> out;
  size_t start = 0;
  for (size_t i = 0; i <= s.size(); ++i) {
    if (i == s.size() || s[i] == sep) {
      out.push_back(s.substr(start, i - start));
      start = i + 1;
    }
  }
  return out;
}

std::vector<std::string_view> SplitAny(std::string_view s, std::string_view seps) {
  std::vector<std::string_view> out;
  size_t start = 0;
  for (size_t i = 0; i <= s.size(); ++i) {
    bool is_sep = i == s.size() || seps.find(s[i]) != std::string_view::npos;
    if (is_sep) {
      out.push_back(s.substr(start, i - start));
      start = i + 1;
    }
  }
  return out;
}

std::string Join(const std::vector<std::string>& parts, std::string_view sep) {
  std::string out;
  for (size_t i = 0; i < parts.size(); ++i) {
    if (i) out += sep;
    out += parts[i];
  }
  return out;
}

std::string ReplaceAll(std::string s, std::string_view from, std::string_view to) {
  if (from.empty()) return s;
  size_t pos = 0;
  while ((pos = s.find(from, pos)) != std::string::npos) {
    s.replace(pos, from.size(), to);
    pos += to.size();
  }
  return s;
}

std::string Hex(uint64_t value) {
  char buf[32];
  std::snprintf(buf, sizeof(buf), "0x%llx", static_cast<unsigned long long>(value));
  return buf;
}

std::string Decimal(uint64_t value) {
  char buf[32];
  std::snprintf(buf, sizeof(buf), "%llu", static_cast<unsigned long long>(value));
  return buf;
}

std::optional<uint64_t> ParseInteger(std::string_view text) {
  std::string_view s = Trim(text);
  // Strip C integer suffixes.
  while (!s.empty() && (s.back() == 'u' || s.back() == 'U' || s.back() == 'l' ||
                        s.back() == 'L')) {
    s.remove_suffix(1);
  }
  if (s.empty()) return std::nullopt;
  bool negative = false;
  if (s.front() == '-') {
    negative = true;
    s.remove_prefix(1);
  } else if (s.front() == '+') {
    s.remove_prefix(1);
  }
  if (s.empty()) return std::nullopt;

  uint64_t value = 0;
  int base = 10;
  if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
    base = 16;
    s.remove_prefix(2);
  } else if (s.size() > 1 && s[0] == '0') {
    base = 8;
    s.remove_prefix(1);
  }
  if (s.empty()) return negative ? std::optional<uint64_t>(0) : std::nullopt;
  for (char c : s) {
    int digit;
    if (c >= '0' && c <= '9') {
      digit = c - '0';
    } else if (c >= 'a' && c <= 'f') {
      digit = c - 'a' + 10;
    } else if (c >= 'A' && c <= 'F') {
      digit = c - 'A' + 10;
    } else {
      return std::nullopt;
    }
    if (digit >= base) return std::nullopt;
    if (value > (UINT64_MAX - static_cast<uint64_t>(digit)) /
                    static_cast<uint64_t>(base)) {
      return std::nullopt;
    }
    value = value * static_cast<uint64_t>(base) + static_cast<uint64_t>(digit);
  }
  if (negative) value = static_cast<uint64_t>(0) - value;
  return value;
}

std::string MarkdownEscape(std::string_view text) {
  std::string out;
  out.reserve(text.size());
  for (char c : text) {
    if (c == '|' || c == '`') out += '\\';
    out += c;
  }
  return out;
}

bool ContainsInsensitive(std::string_view haystack, std::string_view needle) {
  return ToLower(haystack).find(ToLower(needle)) != std::string::npos;
}

}  // namespace scgen

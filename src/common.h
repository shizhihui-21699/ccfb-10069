// Shared helpers: string handling, diagnostics, small value types.
#pragma once

#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace scgen {

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

struct SourceLoc {
  int line = 0;
  int column = 0;
  std::string file;

  bool valid() const { return line > 0; }
  std::string ToString() const;
};

class Error : public std::runtime_error {
 public:
  explicit Error(std::string message) : std::runtime_error(std::move(message)) {}
  Error(SourceLoc loc, std::string message);

  const SourceLoc& loc() const { return loc_; }

 private:
  SourceLoc loc_;
};

// ---------------------------------------------------------------------------
// Strings
// ---------------------------------------------------------------------------

std::string_view Trim(std::string_view s);
std::string ToLower(std::string_view s);
std::string ToUpper(std::string_view s);
bool StartsWith(std::string_view s, std::string_view prefix);
bool EndsWith(std::string_view s, std::string_view suffix);
std::vector<std::string_view> Split(std::string_view s, char sep);
std::vector<std::string_view> SplitAny(std::string_view s, std::string_view seps);
std::string Join(const std::vector<std::string>& parts, std::string_view sep);
std::string ReplaceAll(std::string s, std::string_view from, std::string_view to);
std::string Hex(uint64_t value);
std::string Decimal(uint64_t value);

// Parses an integer literal in the forms strace prints: decimal, 0x hex,
// octal with a leading 0, optionally with a trailing U/L suffix or a leading
// '-' for signed values.
std::optional<uint64_t> ParseInteger(std::string_view text);

// ---------------------------------------------------------------------------
// Misc
// ---------------------------------------------------------------------------

// Escapes a string for inclusion in a generated markdown table cell.
std::string MarkdownEscape(std::string_view text);

// Returns true if `haystack` contains `needle` case-insensitively.
bool ContainsInsensitive(std::string_view haystack, std::string_view needle);

}  // namespace scgen

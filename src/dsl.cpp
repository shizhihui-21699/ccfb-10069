#include "dsl.h"

#include <cctype>
#include <map>
#include <set>
#include <sstream>

#include "bpf.h"
#include "common.h"

namespace scgen {
namespace {

// ---------------------------------------------------------------------------
// Tokenizer
// ---------------------------------------------------------------------------

enum class TokenKind { kWord, kNumber, kString, kPunct, kEnd };

struct Token {
  TokenKind kind = TokenKind::kEnd;
  std::string text;
  int line = 0;
  int column = 0;

  bool Is(std::string_view s) const { return kind != TokenKind::kString && text == s; }
  bool IsPunct(char c) const { return kind == TokenKind::kPunct && text.size() == 1 && text[0] == c; }
};

class Lexer {
 public:
  Lexer(std::string_view text, std::string file) : text_(text), file_(std::move(file)) {}

  std::vector<Token> Run() {
    std::vector<Token> out;
    while (true) {
      SkipSpaceAndComments();
      if (pos_ >= text_.size()) break;
      char c = text_[pos_];
      if (c == '"') {
        out.push_back(LexString());
      } else if (std::isdigit(static_cast<unsigned char>(c)) ||
                 (c == '-' && pos_ + 1 < text_.size() &&
                  std::isdigit(static_cast<unsigned char>(text_[pos_ + 1])))) {
        out.push_back(LexNumber());
      } else if (std::isalpha(static_cast<unsigned char>(c)) || c == '_') {
        out.push_back(LexWord());
      } else {
        out.push_back(LexPunct());
      }
    }
    Token end;
    end.kind = TokenKind::kEnd;
    end.line = line_;
    end.column = column_;
    out.push_back(end);
    return out;
  }

  bool had_error() const { return had_error_; }
  const std::string& error() const { return error_; }

 private:
  void SkipSpaceAndComments() {
    while (pos_ < text_.size()) {
      char c = text_[pos_];
      if (c == '\n') {
        ++line_;
        column_ = 1;
        ++pos_;
      } else if (c == ' ' || c == '\t' || c == '\r') {
        ++column_;
        ++pos_;
      } else if (c == '#') {
        while (pos_ < text_.size() && text_[pos_] != '\n') ++pos_;
      } else {
        break;
      }
    }
  }

  Token LexString() {
    Token t;
    t.kind = TokenKind::kString;
    t.line = line_;
    t.column = column_;
    ++pos_;
    ++column_;
    std::string value;
    while (pos_ < text_.size()) {
      char c = text_[pos_++];
      ++column_;
      if (c == '"') {
        t.text = value;
        return t;
      }
      if (c == '\n') {
        had_error_ = true;
        error_ = "unterminated string literal";
        return t;
      }
      if (c == '\\' && pos_ < text_.size()) {
        char esc = text_[pos_++];
        ++column_;
        switch (esc) {
          case 'n': value += '\n'; break;
          case 't': value += '\t'; break;
          case '"': value += '"'; break;
          case '\\': value += '\\'; break;
          default: value += esc; break;
        }
        continue;
      }
      value += c;
    }
    had_error_ = true;
    error_ = "unterminated string literal";
    return t;
  }

  Token LexNumber() {
    Token t;
    t.kind = TokenKind::kNumber;
    t.line = line_;
    t.column = column_;
    size_t start = pos_;
    if (text_[pos_] == '-') ++pos_;
    if (pos_ + 1 < text_.size() && text_[pos_] == '0' &&
        (text_[pos_ + 1] == 'x' || text_[pos_ + 1] == 'X')) {
      pos_ += 2;
      while (pos_ < text_.size() && std::isxdigit(static_cast<unsigned char>(text_[pos_]))) ++pos_;
    } else {
      while (pos_ < text_.size() && std::isdigit(static_cast<unsigned char>(text_[pos_]))) ++pos_;
    }
    t.text = std::string(text_.substr(start, pos_ - start));
    column_ += static_cast<int>(pos_ - start);
    return t;
  }

  Token LexWord() {
    Token t;
    t.kind = TokenKind::kWord;
    t.line = line_;
    t.column = column_;
    size_t start = pos_;
    while (pos_ < text_.size() &&
           (std::isalnum(static_cast<unsigned char>(text_[pos_])) || text_[pos_] == '_')) {
      ++pos_;
    }
    t.text = std::string(text_.substr(start, pos_ - start));
    column_ += static_cast<int>(pos_ - start);
    return t;
  }

  Token LexPunct() {
    Token t;
    t.kind = TokenKind::kPunct;
    t.line = line_;
    t.column = column_;
    // Two-character operators.
    static const char* kTwo[] = {"==", "!=", "<=", ">=", "->", ".."};
    if (pos_ + 1 < text_.size()) {
      std::string two(text_.substr(pos_, 2));
      for (const char* op : kTwo) {
        if (two == op) {
          t.text = two;
          pos_ += 2;
          column_ += 2;
          return t;
        }
      }
    }
    t.text = std::string(1, text_[pos_]);
    ++pos_;
    ++column_;
    return t;
  }

  std::string_view text_;
  std::string file_;
  size_t pos_ = 0;
  int line_ = 1;
  int column_ = 1;
  bool had_error_ = false;
  std::string error_;
};

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

class Parser {
 public:
  Parser(std::vector<Token> tokens, std::string file, Arch arch)
      : tokens_(std::move(tokens)), file_(std::move(file)), arch_(arch) {}

  DslParseResult Run() {
    DslParseResult result;
    result.policy.name = "";
    PhaseScope scope;
    while (!AtEnd()) {
      if (MatchWord("policy")) {
        if (auto name = ExpectString("policy name")) result.policy.name = *name;
        continue;
      }
      if (MatchWord("default")) {
        if (Action action; ParseAction(&action)) {
          result.policy.default_action = action;
          result.policy.default_action.kind = action.kind;
        }
        continue;
      }
      if (MatchWord("note")) {
        if (auto note = ExpectString("note text")) result.policy.notes.push_back(*note);
        continue;
      }
      if (AtWord("startup") || AtWord("runtime")) {
        bool startup = AtWord("startup");
        Advance();
        if (!ExpectPunct('{', "block opening brace")) break;
        PhaseScope inner;
        inner.phase = startup ? Phase::kStartup : Phase::kRuntime;
        ParseStatements(result, inner);
        if (!ExpectPunct('}', "block closing brace")) break;
        continue;
      }
      size_t before = index_;
      ParseRule(result, scope);
      if (index_ == before) Advance();
    }
    result.errors = errors_;
    if (!result.errors.empty()) result.policy.rules.clear();

    // Post-parse validation: resolve syscalls and constants.
    if (result.errors.empty()) Validate(result);
    return result;
  }

 private:
  struct PhaseScope {
    Phase phase = Phase::kAny;
    Action inherited_action;
    bool has_inherited_action = false;
  };

  static constexpr int kMaxConditions = 32;

  bool AtEnd() const { return tokens_[index_].kind == TokenKind::kEnd; }
  const Token& Peek(int offset = 0) const {
    size_t at = std::min<size_t>(index_ + offset, tokens_.size() - 1);
    return tokens_[at];
  }
  void Advance() {
    if (!AtEnd()) {
      if (tokens_[index_].kind != TokenKind::kPunct || tokens_[index_].text != "\n") {
        last_line_ = tokens_[index_].line;
      }
      ++index_;
    }
  }
  bool AtWord(std::string_view word) const {
    return Peek().kind == TokenKind::kWord && Peek().text == word;
  }
  bool MatchWord(std::string_view word) {
    if (!AtWord(word)) return false;
    Advance();
    return true;
  }
  bool MatchPunct(char c) { return MatchPunct(std::string_view(&c, 1)); }
  bool MatchPunct(std::string_view p) {
    if (Peek().kind != TokenKind::kPunct || Peek().text != p) return false;
    Advance();
    return true;
  }
  bool ExpectPunct(char c, const char* what) {
    if (MatchPunct(std::string(1, c))) return true;
    Error(std::string("expected ") + what + " ('" + c + "')");
    return false;
  }
  std::optional<std::string> ExpectString(const char* what) {
    if (Peek().kind == TokenKind::kString) {
      std::string value = Peek().text;
      Advance();
      return value;
    }
    Error(std::string("expected ") + what + " (a quoted string)");
    return std::nullopt;
  }

  void Error(const std::string& message) {
    if (error_count_ > 50) return;  // avoid cascades
    ++error_count_;
    errors_.push_back(file_ + ":" + std::to_string(Peek().line) + ":" +
                      std::to_string(Peek().column) + ": " + message);
  }

  void ParseStatements(DslParseResult& result, PhaseScope& scope) {
    while (!AtEnd() && !Peek().IsPunct('}')) {
      if (AtWord("startup") || AtWord("runtime")) {
        Error("nested phase blocks are not allowed");
        SkipBlock();
        continue;
      }
      // Error recovery: a rule that fails to parse may stop without consuming
      // its tokens.  Guarantee progress so the parser terminates and reports
      // the next problem rather than spinning on one token.
      size_t before = index_;
      ParseRule(result, scope);
      if (index_ == before) Advance();
    }
  }

  void SkipBlock() {
    int depth = 0;
    while (!AtEnd()) {
      if (Peek().IsPunct('{')) ++depth;
      if (Peek().IsPunct('}')) {
        if (depth == 0) return;
        --depth;
      }
      Advance();
    }
  }

  // A rule: action target[, target...] [where conds]
  void ParseRule(DslParseResult& result, PhaseScope& scope) {
    Rule rule;
    rule.source_file = file_;
    rule.source_line = Peek().line;
    rule.phase = scope.phase;
    if (!ParseAction(&rule.action)) return;

    if (MatchWord("where")) {
      // action-less conditional form is not supported
      Error("'where' must follow a syscall target");
      return;
    }

    std::vector<std::string> targets;
    while (true) {
      if (AtEnd()) {
        Error("expected a syscall name, group or '*'");
        return;
      }
      const Token& t = Peek();
      if (t.kind == TokenKind::kWord) {
        targets.push_back(t.text);
        Advance();
      } else if (t.kind == TokenKind::kPunct && t.text == "*") {
        targets.push_back("*");
        Advance();
      } else if (t.kind == TokenKind::kPunct && t.text == "@") {
        Advance();
        if (Peek().kind != TokenKind::kWord) {
          Error("expected a group name after '@'");
          return;
        }
        targets.push_back("@" + Peek().text);
        Advance();
      } else if (t.kind == TokenKind::kPunct && (t.text == "(" || t.text == "[")) {
        Error("expected a syscall name; 'where' conditions are not allowed "
              "after this point");
        return;
      } else {
        Error("expected a syscall name, group or '*'");
        return;
      }
      if (!MatchPunct(",")) break;
      if (AtWord("where")) {
        Error("trailing ',' before 'where'");
        return;
      }
    }

    // Conditions are parsed against a representative target: named arguments
    // ("domain", "flags") resolve through the syscall's argument table, so the
    // name has to be known before the conditions are read.  When a rule lists
    // several targets the name is the first one; a named argument that does not
    // exist for that syscall is then reported per target below.
    std::string condition_context;
    for (const std::string& target : targets) {
      if (!target.empty() && target[0] != '@' && target != "*" &&
          ParseInteger(target) == std::nullopt) {
        condition_context = target;
        break;
      }
    }
    rule.syscall = condition_context;
    if (MatchWord("where") || MatchWord("if")) {
      ParseConditions(&rule, result);
    }
    rule.syscall.clear();

    // "allow x -> errno(EPERM)" and "deny x -> trace(7)" read better than
    // making the action the first word; accept both spellings.
    if (MatchPunct("->")) {
      Action action;
      if (!ParseAction(&action)) return;
      rule.action = action;
    }

    for (const std::string& target : targets) {
      Rule copy = rule;
      copy.conditions = rule.conditions;
      if (target == "*") {
        copy.wildcard = true;
      } else if (!target.empty() && target[0] == '@') {
        copy.group.push_back(target.substr(1));
      } else if (auto number = ParseInteger(target);
                 number && target.find_first_not_of("0123456789") == std::string::npos) {
        copy.syscall_number = static_cast<int>(*number);
      } else {
        copy.syscall = target;
      }
      result.policy.rules.push_back(std::move(copy));
    }
  }

  bool ParseAction(Action* action) {
    if (AtWord("allow")) {
      Advance();
      *action = Action::Allow();
      return true;
    }
    if (AtWord("deny")) {
      Advance();
      *action = Action::Errno(1);  // EPERM
      if (MatchPunct('(')) {
        uint32_t value;
        if (!ParseErrnoValue(&value)) return false;
        action->errno_value = value;
      }
      return true;
    }
    if (AtWord("kill")) {
      Advance();
      *action = Action::Kill();
      return true;
    }
    if (AtWord("kill_process")) {
      Advance();
      *action = Action::KillProcess();
      return true;
    }
    if (AtWord("trap")) {
      Advance();
      *action = Action::Trap();
      return true;
    }
    if (AtWord("log")) {
      Advance();
      *action = Action::Log();
      return true;
    }
    if (AtWord("trace") || AtWord("notify")) {
      bool trace = AtWord("trace");
      Advance();
      uint32_t data = 0;
      if (MatchPunct('(')) {
        if (auto v = ParseUInt()) {
          data = static_cast<uint32_t>(*v);
        } else {
          return false;
        }
        if (!ExpectPunct(')', "closing parenthesis")) return false;
      }
      *action = trace ? Action::Trace(data) : Action::Notify(data);
      return true;
    }
    if (AtWord("errno")) {
      Advance();
      if (!ExpectPunct('(', "opening parenthesis")) return false;
      uint32_t value;
      if (!ParseErrnoValue(&value)) return false;
      if (!ExpectPunct(')', "closing parenthesis")) return false;
      *action = Action::Errno(value);
      return true;
    }
    if (Peek().kind == TokenKind::kWord) {
      Error("expected an action (allow, deny, kill, kill_process, trap, log, "
            "trace(N), notify(N) or errno(E)) before '" + Peek().text + "'");
    } else {
      Error("expected an action (allow, deny, kill, kill_process, trap, log, "
            "trace(N), notify(N) or errno(E))");
    }
    return false;
  }

  bool ParseErrnoValue(uint32_t* out) {
    if (auto number = ParseUInt()) {
      if (*number > kMaxErrno) {
        Error("errno value " + std::to_string(*number) + " exceeds 4095");
        return false;
      }
      *out = static_cast<uint32_t>(*number);
      return true;
    }
    if (Peek().kind == TokenKind::kWord) {
      std::string name = Peek().text;
      auto value = LookupConstant(name, "E");
      if (!value || name[0] != 'E') {
        Error("unknown errno name '" + name + "'");
        return false;
      }
      Advance();
      *out = static_cast<uint32_t>(*value);
      return true;
    }
    Error("expected an errno number or name");
    return false;
  }

  std::optional<uint64_t> ParseUInt() {
    if (Peek().kind == TokenKind::kNumber) {
      auto v = ParseInteger(Peek().text);
      if (v) {
        Advance();
        return v;
      }
    }
    return std::nullopt;
  }

  // Conditions: a conjunction.  `and`, `&&` and ',' all mean AND.  `or` is
  // deliberately absent: every rule must be a conjunction of argument
  // predicates so that it maps onto a straight-line BPF program.
  void ParseConditions(Rule* rule, DslParseResult& result) {
    (void)result;
    while (true) {
      if (!ParseCondition(rule)) return;
      if (MatchWord("and") || MatchPunct(",") || MatchPunct("&&")) continue;
      // A newline-equivalent: rules end at a keyword for the next rule.
      break;
    }
  }

  bool ParseCondition(Rule* rule) {
    // Parenthesised conjunction.
    if (MatchPunct('(')) {
      while (true) {
        if (!ParseCondition(rule)) return false;
        if (MatchWord("and") || MatchPunct(",")) continue;
        break;
      }
      if (!ExpectPunct(')', "closing parenthesis")) return false;
      return true;
    }
    // Optional leading negation: not (A) / not arg0 == X.  Negation is
    // restricted to a single comparison so the compiler can keep a
    // conjunction (De Morgan into the comparison itself).
    bool negate = false;
    if (MatchWord("not")) negate = true;

    Condition cond;
    cond.source_file = file_;
    cond.source_line = Peek().line;

    // Argument reference.
    if (Peek().kind == TokenKind::kNumber) {
      auto v = ParseInteger(Peek().text);
      if (!v || *v >= 6) {
        Error("argument index must be 0..5");
        return false;
      }
      cond.arg = static_cast<int>(*v);
      Advance();
    } else if (AtWord("arg")) {
      Advance();
      if (auto v = ParseUInt(); v && *v < 6) {
        cond.arg = static_cast<int>(*v);
      } else {
        Error("expected an argument index 0..5 after 'arg'");
        return false;
      }
    } else if (Peek().kind == TokenKind::kWord &&
               Peek().text.size() == 4 && StartsWith(Peek().text, "arg") &&
               Peek().text[3] >= '0' && Peek().text[3] <= '5') {
      // Explicit positional form arg0..arg5, accepted even when the syscall
      // has a friendlier name for that argument.
      cond.arg = Peek().text[3] - '0';
      Advance();
    } else if (Peek().kind == TokenKind::kWord) {
      // Named argument: resolve through the syscall's argument table.
      std::string name = Peek().text;
      int index = -1;
      if (rule->syscall_number) {
        std::string_view sc = SyscallName(arch_, *rule->syscall_number);
        if (!sc.empty()) index = ArgIndexByName(std::string(sc), name);
      } else if (!rule->syscall.empty()) {
        index = ArgIndexByName(rule->syscall, name);
      }
      if (index < 0) {
        Error("unknown argument name '" + name + "' for " +
              (rule->syscall.empty() ? std::string("this rule") : rule->syscall) +
              "; use arg0..arg5");
        return false;
      }
      cond.arg = index;
      Advance();
    } else {
      Error("expected an argument (arg0..arg5 or an argument name)");
      return false;
    }

    // Optional mask: `type & 0xf == SOCK_STREAM` compares only the bits the
    // mask keeps.  It is written without parentheses so the grammar stays
    // unambiguous next to the conjunction syntax.
    if (MatchPunct('&')) {
      uint64_t mask;
      if (!ParseConstantOrNumber(&mask)) return false;
      if (mask == 0) {
        Error("a zero mask compares nothing; drop the '& mask' instead");
        return false;
      }
      cond.mask = mask;
    }

    // Operator.
    CompareOp op;
    if (MatchPunct("==")) {
      op = CompareOp::kEq;
    } else if (MatchPunct("!=")) {
      op = CompareOp::kNe;
    } else if (MatchPunct("<=")) {
      op = CompareOp::kLe;
    } else if (MatchPunct(">=")) {
      op = CompareOp::kGe;
    } else if (MatchPunct('<')) {
      op = CompareOp::kLt;
    } else if (MatchPunct('>')) {
      op = CompareOp::kGt;
    } else if (MatchWord("has") || MatchWord("mask")) {
      op = CompareOp::kMask;
    } else if (MatchWord("lacks")) {
      op = CompareOp::kNotMask;
    } else if (MatchWord("in_range")) {
      op = CompareOp::kRange;
    } else if (AtWord("in") && Peek(1).Is("range")) {
      Advance();  // in
      Advance();  // range
      op = CompareOp::kRange;
    } else if (MatchWord("in")) {
      op = CompareOp::kIn;
    } else if (MatchWord("not")) {
      if (!MatchWord("in")) {
        Error("expected 'in' after 'not'");
        return false;
      }
      op = CompareOp::kNotIn;
    } else {
      Error("expected a comparison operator (==, !=, <, <=, >, >=, has, lacks, "
            "in, not in, in_range)");
      return false;
    }
    if (negate) {
      // Flip the comparison rather than wrapping it in a NOT.
      switch (op) {
        case CompareOp::kEq: op = CompareOp::kNe; break;
        case CompareOp::kNe: op = CompareOp::kEq; break;
        case CompareOp::kMask: op = CompareOp::kNotMask; break;
        case CompareOp::kNotMask: op = CompareOp::kMask; break;
        case CompareOp::kIn: op = CompareOp::kNotIn; break;
        case CompareOp::kNotIn: op = CompareOp::kIn; break;
        case CompareOp::kLt: op = CompareOp::kGe; break;
        case CompareOp::kLe: op = CompareOp::kGt; break;
        case CompareOp::kGt: op = CompareOp::kLe; break;
        case CompareOp::kGe: op = CompareOp::kLt; break;
        case CompareOp::kRange:
          Error("'not' cannot be applied to an in_range test");
          return false;
      }
    }
    cond.cmp.op = op;
    cond.is_flags = (op == CompareOp::kMask || op == CompareOp::kNotMask);

    // Values.
    if (op == CompareOp::kIn || op == CompareOp::kNotIn) {
      if (!MatchPunct('[')) {
        Error("expected a '[' list after 'in'");
        return false;
      }
      while (true) {
        uint64_t value;
        if (!ParseConstantOrNumber(&value)) return false;
        cond.cmp.set.push_back(value);
        if (MatchPunct(',')) continue;
        break;
      }
      if (!ExpectPunct(']', "closing bracket")) return false;
      if (cond.cmp.set.empty()) {
        Error("empty 'in' list");
        return false;
      }
    } else if (op == CompareOp::kRange) {
      if (!MatchPunct('[')) {
        Error("expected a '[' range after 'in_range'");
        return false;
      }
      uint64_t low, high;
      if (!ParseConstantOrNumber(&low)) return false;
      bool exclusive = MatchPunct('(');
      if (!MatchPunct("..") && !MatchPunct("to") && !MatchWord("to")) {
        Error("expected '..' in a range");
        return false;
      }
      if (!ParseConstantOrNumber(&high)) return false;
      if (exclusive && !ExpectPunct(')', "closing parenthesis")) return false;
      if (!ExpectPunct(']', "closing bracket")) return false;
      if (low > high) {
        Error("range lower bound is greater than the upper bound");
        return false;
      }
      cond.cmp.a = low;
      cond.cmp.b = high;
    } else {
      uint64_t value;
      if (!ParseConstantOrNumber(&value)) return false;
      cond.cmp.a = value;
    }

    cond.comment = std::string(ArgIndexLabel(rule, cond.arg)) + " " +
                   cond.cmp.ToString();
    rule->conditions.push_back(std::move(cond));
    if (static_cast<int>(rule->conditions.size()) > kMaxConditions) {
      Error("too many conditions on one rule");
      return false;
    }
    return true;
  }

  std::string_view ArgIndexLabel(const Rule* rule, int index) const {
    if (!rule->syscall.empty()) {
      std::string_view name = SyscallArgName(rule->syscall, index);
      if (!name.empty()) return name;
    }
    return "";
  }

  static int ArgIndexByName(const std::string& syscall, const std::string& name) {
    for (int i = 0; i < 6; ++i) {
      if (SyscallArgName(syscall, i) == name) return i;
    }
    return -1;
  }

  // A value is a number, a constant name, or constants OR-ed with '|'
  // ("has O_CLOEXEC|O_NONBLOCK").  The OR form is what the kernel itself uses
  // to describe flag words, so it is accepted everywhere a value is.
  bool ParseConstantOrNumber(uint64_t* out) {
    uint64_t value;
    if (!ParseOneConstantOrNumber(&value)) return false;
    while (MatchPunct('|')) {
      uint64_t next;
      if (!ParseOneConstantOrNumber(&next)) return false;
      value |= next;
    }
    *out = value;
    return true;
  }

  bool ParseOneConstantOrNumber(uint64_t* out) {
    if (Peek().kind == TokenKind::kNumber) {
      auto v = ParseInteger(Peek().text);
      if (!v) {
        Error("invalid number '" + Peek().text + "'");
        return false;
      }
      Advance();
      *out = *v;
      return true;
    }
    if (Peek().kind == TokenKind::kWord) {
      std::string name = Peek().text;
      // Allow "SIGCHLD" and "CHLD"; also "AF_INET" and "INET".
      std::string prefix_hint;
      if (StartsWith(name, "AF_") || StartsWith(name, "SOCK_") ||
          StartsWith(name, "O_") || StartsWith(name, "SIG") ||
          StartsWith(name, "PROT_") || StartsWith(name, "MAP_") ||
          StartsWith(name, "CLONE_") || StartsWith(name, "FUTEX_") ||
          StartsWith(name, "EPOLL_") || StartsWith(name, "SO_") ||
          StartsWith(name, "SOL_") || StartsWith(name, "PR_") ||
          StartsWith(name, "F_") || StartsWith(name, "AT_") ||
          StartsWith(name, "S_") || StartsWith(name, "E")) {
        prefix_hint = "";
      }
      auto v = LookupConstant(name, prefix_hint);
      if (!v) {
        auto errno_value = LookupConstant(name, "E");
        if (errno_value && name[0] == 'E') v = errno_value;
      }
      if (!v) {
        Error("unknown constant '" + name + "'");
        return false;
      }
      Advance();
      *out = static_cast<uint64_t>(*v);
      return true;
    }
    Error("expected a number or a kernel constant name");
    return false;
  }

  void Validate(DslParseResult& result) {
    // Resolve against both architectures: a policy should name syscalls that
    // exist on the target it will be compiled for, but naming an x86-only call
    // is a mistake on aarch64 and we want to say so.
    ResolveResult resolved = ResolvePolicy(result.policy, arch_);
    for (auto& error : resolved.errors) result.errors.push_back(error);
    if (!resolved.errors.empty()) return;

    // Semantic checks that need the syscall's argument shape.
    for (const Rule& rule : result.policy.rules) {
      for (const Condition& cond : rule.conditions) {
        if (!rule.syscall.empty()) {
          std::string_view prefix = SyscallArgConstantPrefix(rule.syscall, cond.arg);
          if (cond.is_flags) {
            ArgKind kind = SyscallArgKind(rule.syscall, cond.arg);
            if (kind == ArgKind::kPointer || kind == ArgKind::kBuffer) {
              result.warnings.push_back(
                  "line " + std::to_string(cond.source_line) + ": rule uses 'has' "
                  "on " + std::string(rule.syscall) + "'s " +
                  std::string(SyscallArgName(rule.syscall, cond.arg)) +
                  ", which is a pointer; the filter cannot inspect the memory it "
                  "points at");
            }
            (void)prefix;
          }
          int argc = SyscallArgCount(rule.syscall);
          if (cond.arg >= argc && argc < 6) {
            result.warnings.push_back(
                "line " + std::to_string(cond.source_line) + ": " +
                std::string(rule.syscall) + " takes " + std::to_string(argc) +
                " argument(s) but the rule constrains arg" +
                std::to_string(cond.arg) + " (it is zero on the kernel side, so "
                "the condition will not behave as intended)");
          }
        }
      }
    }
  }

  std::vector<Token> tokens_;
  std::string file_;
  Arch arch_;
  size_t index_ = 0;
  int last_line_ = 1;
  int error_count_ = 0;
  std::vector<std::string> errors_;
};

}  // namespace

DslParseResult ParsePolicyDsl(std::string_view text, std::string source_name,
                              Arch arch) {
  Lexer lexer(text, source_name);
  std::vector<Token> tokens = lexer.Run();
  if (lexer.had_error()) {
    DslParseResult result;
    result.errors.push_back(source_name + ": " + lexer.error());
    return result;
  }
  Parser parser(std::move(tokens), source_name, arch);
  return parser.Run();
}

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------

namespace {


std::string FormatCondition(const Condition& cond, const Rule& rule) {
  std::string arg;
  if (!rule.syscall.empty()) {
    std::string_view name = SyscallArgName(rule.syscall, cond.arg);
    if (!name.empty()) arg = std::string(name);
  }
  if (arg.empty() || arg == "arg" + std::to_string(cond.arg)) {
    arg = "arg" + std::to_string(cond.arg);
  }
  if (cond.mask != 0) {
    arg = arg + " & " + Hex(cond.mask);
  }
  std::string prefix;
  if (!rule.syscall.empty()) {
    prefix = std::string(SyscallArgConstantPrefix(rule.syscall, cond.arg));
  }

  std::ostringstream out;
  switch (cond.cmp.op) {
    case CompareOp::kIn:
    case CompareOp::kNotIn: {
      out << arg << " " << CompareOpName(cond.cmp.op) << " [";
      for (size_t i = 0; i < cond.cmp.set.size(); ++i) {
        if (i) out << ", ";
        bool flags = cond.cmp.op == CompareOp::kMask;
        out << (flags ? RenderFlagWord(cond.cmp.set[i], prefix)
                      : FormatConstantValue(cond.cmp.set[i], prefix));
      }
      out << "]";
      return out.str();
    }
    case CompareOp::kRange:
      out << arg << " in_range [" << FormatConstantValue(cond.cmp.a, prefix) << " .. "
          << FormatConstantValue(cond.cmp.b, prefix) << "]";
      return out.str();
    default:
      // A `has`/`lacks` operand is a flag word; render every bit so the file
      // reads like the kernel's own flag descriptions.
      if (cond.cmp.op == CompareOp::kMask || cond.cmp.op == CompareOp::kNotMask) {
        out << arg << " " << CompareOpName(cond.cmp.op) << " "
            << RenderFlagWord(cond.cmp.a, prefix);
      } else {
        out << arg << " " << CompareOpName(cond.cmp.op) << " "
            << FormatConstantValue(cond.cmp.a, prefix);
      }
      return out.str();
  }
}

}  // namespace

std::string FormatPolicyDsl(const Policy& policy, Arch arch) {
  std::ostringstream out;
  out << "# Generated policy.  Edit freely; this text is the source of truth.\n";
  out << "#\n";
  out << "# Recompile with:  scgen emit --policy this-file --arch "
      << ArchName(arch) << "\n\n";
  if (!policy.name.empty()) out << "policy \"" << policy.name << "\"\n\n";
  for (const std::string& note : policy.notes) out << "note \"" << note << "\"\n";
  if (!policy.notes.empty()) out << "\n";
  out << "default " << policy.default_action.ToString() << "\n\n";

  auto emit_rules = [&](Phase phase, const char* title) {
    std::vector<const Rule*> selected;
    for (const Rule& r : policy.rules) {
      if (phase == Phase::kStartup && r.phase != Phase::kStartup &&
          r.phase != Phase::kBoth) {
        continue;
      }
      if (phase == Phase::kRuntime && r.phase != Phase::kRuntime &&
          r.phase != Phase::kBoth) {
        continue;
      }
      if (phase == Phase::kAny && r.phase != Phase::kAny) continue;
      selected.push_back(&r);
    }
    if (selected.empty()) return;
    out << title << " {\n";
    for (const Rule* rule : selected) {
      out << "    ";
      std::vector<std::string> targets;
      if (rule->wildcard) {
        targets.push_back("*");
      }
      if (!rule->syscall.empty()) targets.push_back(rule->syscall);
      if (rule->syscall_number) {
        std::string_view name = SyscallName(arch, *rule->syscall_number);
        targets.push_back(name.empty() ? std::to_string(*rule->syscall_number)
                                       : std::string(name));
      }
      for (const auto& g : rule->group) targets.push_back("@" + g);
      out << rule->action.ToString() << " " << Join(targets, ", ");
      if (!rule->conditions.empty()) {
        out << " where\n";
        for (size_t i = 0; i < rule->conditions.size(); ++i) {
          out << "        ";
          if (i) out << "and ";
          out << FormatCondition(rule->conditions[i], *rule);
          if (i + 1 < rule->conditions.size()) out << "\n";
        }
      }
      if (!rule->note.empty()) out << "   # " << rule->note;
      out << "\n";
    }
    out << "}\n\n";
  };

  emit_rules(Phase::kStartup, "startup");
  emit_rules(Phase::kRuntime, "runtime");
  emit_rules(Phase::kAny, "phase any");
  return out.str();
}

}  // namespace scgen

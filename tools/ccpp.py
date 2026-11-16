#!/usr/bin/env python3
"""Minimal C preprocessor, sufficient for the kernel UAPI headers vendored
under tools/linux-uapi/.

It supports: #include, #define (object- and function-like, with variadic
suffix "..."), #undef, #if/#ifdef/#ifndef/#elif/#else/#endif, line comments,
block comments, and evaluation of the integer constant expressions the kernel
headers use.  It is *not* a general purpose preprocessor: no #pragma, no
#line, no token pasting beyond what these headers need (## is implemented for
the few places it appears), no conditional-expression ?: beyond &&/||/!.

The point is to make syscall-number and constant extraction reproducible and
auditable from sources checked into the repository, instead of hard-coding a
table in the generator.
"""

import os
import re

__all__ = ["Preprocessor", "PreprocessorError"]


class PreprocessorError(Exception):
    pass


class Macro:
    __slots__ = ("name", "params", "variadic", "body")

    def __init__(self, name, params, variadic, body):
        self.name = name
        self.params = params        # None for object-like
        self.variadic = variadic
        self.body = body


_TOKEN_RE = re.compile(
    r"""
      (?P<ws>\s+)
    | (?P<num>0[xX][0-9a-fA-F]+[uUlL]*|0[bB][01]+[uUlL]*|\d+[uUlL]*)
    | (?P<ident>[A-Za-z_][A-Za-z_0-9]*)
    | (?P<op><<|>>|<=|>=|==|!=|&&|\|\||\#\#|->|[-+*/%&|^~!<>?:()\[\]{},;\#=.])
    """,
    re.VERBOSE,
)


def strip_comments(text):
    """Remove /* */ and // comments, preserving string literals."""
    out = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == '"' or c == "'":
            q = c
            out.append(c)
            i += 1
            while i < n:
                out.append(text[i])
                if text[i] == "\\" and i + 1 < n:
                    i += 1
                    out.append(text[i])
                elif text[i] == q:
                    i += 1
                    break
                i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            j = text.find("*/", i + 2)
            if j < 0:
                raise PreprocessorError("unterminated block comment")
            # keep newlines so line numbers stay roughly right
            out.append("\n" * text.count("\n", i, j))
            i = j + 2
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        out.append(c)
        i += 1
    return "".join(out)


def tokenize(text):
    toks = []
    pos = 0
    while pos < len(text):
        m = _TOKEN_RE.match(text, pos)
        if not m:
            raise PreprocessorError("cannot tokenize at %r" % text[pos:pos + 40])
        pos = m.end()
        if m.lastgroup == "ws":
            continue
        if m.lastgroup == "ident":
            toks.append(m.group())
        else:
            toks.append(m.group())
    return toks


def split_include_dirs(paths):
    return [os.path.abspath(p) for p in paths]


class Preprocessor:
    def __init__(self, include_dirs, predefined=None, ignore_missing_includes=False):
        self.include_dirs = split_include_dirs(include_dirs)
        self.macros = {}
        self.enums = {}
        self.in_enum = False
        self._enum_pending = ""
        self.once = set()
        self.include_depth = 0
        self.ignore_missing_includes = ignore_missing_includes
        for k, v in (predefined or {}).items():
            self.macros[k] = Macro(k, None, False, str(v))

    # ---------------------------------------------------------------- files
    def resolve(self, name, current_dir):
        cands = [os.path.join(current_dir, name)]
        cands += [os.path.join(d, name) for d in self.include_dirs]
        for c in cands:
            if os.path.isfile(c):
                return os.path.abspath(c)
        return None

    def process_file(self, path):
        path = os.path.abspath(path)
        if path in self.once:
            return
        if self.include_depth > 40:
            raise PreprocessorError("#include nested too deeply at %s" % path)
        with open(path, "r", encoding="utf-8") as f:
            text = f.read()
        self.include_depth += 1
        try:
            self._process_text(text, os.path.dirname(path))
        finally:
            self.include_depth -= 1

    # ------------------------------------------------------------ expansion
    def _expand(self, tokens, hide=frozenset(), depth=0):
        """Expand object-like and function-like macros in a token list."""
        if depth > 60:
            raise PreprocessorError("macro expansion too deep")
        out = []
        i = 0
        n = len(tokens)
        while i < n:
            t = tokens[i]
            m = self.macros.get(t)
            if m is None or t in hide:
                out.append(t)
                i += 1
                continue
            if m.params is None:
                # function-like macro name used without '(' is not expanded
                body = tokenize(m.body)
                out.extend(self._expand(body, hide | {t}, depth + 1))
                i += 1
                continue
            # function-like: need '(' next (whitespace already stripped)
            if i + 1 >= n or tokens[i + 1] != "(":
                out.append(t)
                i += 1
                continue
            args, consumed = self._collect_args(tokens, i + 1)
            if consumed < 0:
                out.append(t)
                i += 1
                continue
            # bind params
            env = {}
            for idx, p in enumerate(m.params):
                if m.variadic and idx == len(m.params) - 1:
                    rest = args[idx:] if idx < len(args) else []
                    env[p] = ",".join(rest)
                else:
                    env[p] = args[idx] if idx < len(args) else ""
            body = self._substitute(m.body, env)
            expanded = tokenize(body)
            out.extend(self._expand(expanded, hide | {t}, depth + 1))
            i = i + 1 + consumed
        return out

    def _collect_args(self, tokens, lparen):
        assert tokens[lparen] == "("
        depth = 0
        args = []
        cur = []
        i = lparen
        n = len(tokens)
        while i < n:
            t = tokens[i]
            if t == "(":
                depth += 1
                if depth > 1:
                    cur.append(t)
            elif t == ")":
                depth -= 1
                if depth == 0:
                    args.append(" ".join(cur))
                    return args if args != [""] else [], i - lparen
                cur.append(t)
            elif t == "," and depth == 1:
                args.append(" ".join(cur))
                cur = []
            else:
                cur.append(t)
            i += 1
        return [], -1

    def _substitute(self, body, env):
        toks = tokenize(body)
        out = []
        i = 0
        for t in toks:
            if t in env:
                out.append("(" + env[t] + ")")
            elif t == "##":
                # token paste: join previous and next
                if out and i + 1 < len(toks) and toks[i + 1] in env:
                    out[-1] = out[-1] + env[toks[i + 1]]
                    toks[i + 1] = ""
                    continue
                continue
            elif t == "":
                continue
            else:
                out.append(t)
            i += 1
        return " ".join(out)

    # ----------------------------------------------------------- expressions
    def _eval_if(self, expr):
        toks = tokenize(expr)
        toks = self._resolve_defined(toks)
        toks = self._expand(toks)
        try:
            return bool(self._expr(toks, 0)[0])
        except PreprocessorError:
            return False

    def _resolve_defined(self, toks):
        """Replace `defined X` / `defined(X)` with 1/0 *before* expansion.

        The operand of defined must not be macro-expanded; doing so would
        turn `defined(FOO)` into `defined()` whenever FOO is defined, which
        is exactly backwards.
        """
        out = []
        i = 0
        n = len(toks)
        while i < n:
            if toks[i] == "defined":
                if i + 1 < n and toks[i + 1] == "(":
                    if i + 3 >= n or toks[i + 3] != ")":
                        raise PreprocessorError("malformed defined()")
                    name = toks[i + 2]
                    out.append("1" if name in self.macros else "0")
                    i += 4
                else:
                    if i + 1 >= n:
                        raise PreprocessorError("defined with no operand")
                    out.append("1" if toks[i + 1] in self.macros else "0")
                    i += 2
                continue
            out.append(toks[i])
            i += 1
        return out

    def _expr(self, toks, i):
        val, i = self._or(toks, i)
        return val, i

    def _or(self, toks, i):
        val, i = self._and(toks, i)
        while i < len(toks) and toks[i] == "||":
            rhs, i = self._and(toks, i + 1)
            val = 1 if (val or rhs) else 0
        return val, i

    def _and(self, toks, i):
        val, i = self._bitor(toks, i)
        while i < len(toks) and toks[i] == "&&":
            rhs, i = self._bitor(toks, i + 1)
            val = 1 if (val and rhs) else 0
        return val, i

    def _bitor(self, toks, i):
        val, i = self._bitxor(toks, i)
        while i < len(toks) and toks[i] == "|":
            rhs, i = self._bitxor(toks, i + 1)
            val |= rhs
        return val, i

    def _bitxor(self, toks, i):
        val, i = self._bitand(toks, i)
        while i < len(toks) and toks[i] == "^":
            rhs, i = self._bitand(toks, i + 1)
            val ^= rhs
        return val, i

    def _bitand(self, toks, i):
        val, i = self._eq(toks, i)
        while i < len(toks) and toks[i] == "&":
            rhs, i = self._eq(toks, i + 1)
            val &= rhs
        return val, i

    def _eq(self, toks, i):
        val, i = self._rel(toks, i)
        while i < len(toks) and toks[i] in ("==", "!="):
            op = toks[i]
            rhs, i = self._rel(toks, i + 1)
            val = 1 if ((val == rhs) if op == "==" else (val != rhs)) else 0
        return val, i

    def _rel(self, toks, i):
        val, i = self._add(toks, i)
        while i < len(toks) and toks[i] in ("<", ">", "<=", ">="):
            op = toks[i]
            rhs, i = self._add(toks, i + 1)
            val = 1 if {
                "<": val < rhs, ">": val > rhs,
                "<=": val <= rhs, ">=": val >= rhs}[op] else 0
        return val, i

    def _add(self, toks, i):
        val, i = self._shift(toks, i)
        while i < len(toks) and toks[i] in ("+", "-"):
            op = toks[i]
            rhs, i = self._shift(toks, i + 1)
            val = val + rhs if op == "+" else val - rhs
        return val, i

    def _shift(self, toks, i):
        val, i = self._mul(toks, i)
        while i < len(toks) and toks[i] in ("<<", ">>"):
            op = toks[i]
            rhs, i = self._mul(toks, i + 1)
            val = (val << rhs) if op == "<<" else (val >> rhs)
        return val, i

    def _mul(self, toks, i):
        val, i = self._unary(toks, i)
        while i < len(toks) and toks[i] in ("*", "/", "%"):
            op = toks[i]
            rhs, i = self._unary(toks, i + 1)
            if op == "*":
                val = val * rhs
            elif rhs == 0:
                raise PreprocessorError("division by zero")
            elif op == "/":
                val = val // rhs
            else:
                val = val % rhs
        return val, i

    def _unary(self, toks, i):
        if i >= len(toks):
            raise PreprocessorError("unexpected end of expression")
        t = toks[i]
        if t == "!":
            v, i = self._unary(toks, i + 1)
            return (0 if v else 1), i
        if t == "~":
            v, i = self._unary(toks, i + 1)
            return (~v) & 0xFFFFFFFFFFFFFFFF, i
        if t == "-":
            v, i = self._unary(toks, i + 1)
            return -v, i
        if t == "+":
            return self._unary(toks, i + 1)
        if t == "(":
            v, j = self._expr(toks, i + 1)
            if j >= len(toks) or toks[j] != ")":
                raise PreprocessorError("expected ')' in %r" % (toks,))
            return v, j + 1
        if t == "defined":
            # defined X / defined(X)
            if i + 1 < len(toks) and toks[i + 1] == "(":
                name = toks[i + 2]
                return (1 if name in self.macros else 0), i + 4
            name = toks[i + 1]
            return (1 if name in self.macros else 0), i + 2
        return self._primary(toks, i)

    def _primary(self, toks, i):
        t = toks[i]
        if re.match(r"^0[xX][0-9a-fA-F]+", t):
            return int(t.rstrip("uUlL"), 16), i + 1
        if re.match(r"^0[bB][01]+", t):
            return int(t.rstrip("uUlL")[2:], 2), i + 1
        if re.match(r"^\d+", t):
            s = t.rstrip("uUlL")
            if len(s) > 1 and s[0] == "0":
                return int(s, 8), i + 1
            return int(s, 10), i + 1
        if t in ("<<", ">>"):
            raise PreprocessorError("unexpected shift op")
        if re.match(r"^[A-Za-z_]\w*$", t):
            # undefined identifiers are 0 in #if
            return 0, i + 1
        raise PreprocessorError("unexpected token %r in expression" % t)

    # --------------------------------------------------------- directive loop
    def _process_text(self, text, cur_dir):
        text = strip_comments(text)
        # join continued lines
        lines = []
        buf = ""
        for raw in text.split("\n"):
            if raw.endswith("\\"):
                buf += raw[:-1] + " "
                continue
            lines.append(buf + raw)
            buf = ""
        if buf:
            lines.append(buf)

        # stack of (active, any_taken, parent_active)
        stack = []
        active = True

        for lineno, line in enumerate(lines, 1):
            s = line.strip()
            if not s:
                continue
            if not s.startswith("#"):
                if active and s:
                    self._eval_statement(s)
                continue
            body = s[1:].strip()
            if not body:
                continue
            parts = body.split(None, 1)
            d = parts[0]
            rest = parts[1] if len(parts) > 1 else ""

            if d in ("if", "ifdef", "ifndef"):
                parent = active
                if not parent:
                    stack.append([False, True, False])
                    continue
                if d == "if":
                    cond = self._eval_if(rest)
                elif d == "ifdef":
                    cond = rest.strip() in self.macros
                else:
                    cond = rest.strip() not in self.macros
                stack.append([bool(cond), bool(cond), True])
                active = bool(cond)
                continue

            if d == "elif":
                if not stack:
                    raise PreprocessorError("#elif without #if")
                frame = stack[-1]
                if not frame[2]:          # parent inactive
                    continue
                if frame[1]:
                    active = False
                    frame[0] = False
                else:
                    cond = self._eval_if(rest)
                    frame[0] = bool(cond)
                    frame[1] = bool(cond)
                    active = bool(cond)
                continue

            if d == "else":
                if not stack:
                    raise PreprocessorError("#else without #if")
                frame = stack[-1]
                if not frame[2]:
                    continue
                cond = not frame[1]
                frame[0] = cond
                frame[1] = True
                active = cond
                continue

            if d == "endif":
                if not stack:
                    raise PreprocessorError("#endif without #if")
                stack.pop()
                active = stack[-1][0] if stack else True
                continue

            if not active:
                continue

            if d == "include":
                m = re.match(r'^[<"]([^>"]+)[>"]', rest.strip())
                if not m:
                    raise PreprocessorError("bad #include: %r" % rest)
                target = self.resolve(m.group(1), cur_dir)
                if target is None:
                    if self.ignore_missing_includes:
                        continue
                    raise PreprocessorError("include not found: %r" % m.group(1))
                self.process_file(target)
                continue

            if d == "define":
                self._do_define(rest, lineno)
                continue

            if d == "undef":
                self.macros.pop(rest.strip().split()[0] if rest.strip() else "", None)
                continue

            if d in ("pragma", "error", "warning", "line", "undef_"):
                continue

            # unknown directive: ignore (kernel headers use #ident etc.)
        if stack:
            raise PreprocessorError("unterminated #if")

    def _eval_statement(self, s):
        """Collect enumerators from `enum [tag] { NAME [= expr], ... };`.

        The kernel headers define AF_*, SOCK_*, SHUT_* and similar constant
        families as C enums rather than #defines, so a #define-only reader
        would silently miss them.  We do not care about struct/typedef text.
        """
        if not self.in_enum:
            if re.search(r"\benum\b[^;{]*\{", s):
                self.in_enum = True
                s = s[s.index("{") + 1:]
            else:
                return
        # split the (possibly multi-line) body on top-level commas
        if "}" in s:
            body, _, tail = s.partition("}")
            self._enum_pending += " " + body
            self._flush_enum()
            self.in_enum = False
            # trailing declarators after the closing brace are irrelevant
            return
        self._enum_pending += " " + s

    def _flush_enum(self):
        body = self._enum_pending
        self._enum_pending = ""
        if not body.strip():
            return
        nextval = 0
        for item in body.split(","):
            item = item.strip()
            if not item:
                continue
            if "=" in item:
                name, expr = item.split("=", 1)
                name = name.strip()
                expr = expr.strip()
                toks = self._expand(tokenize(expr))
                try:
                    val = self._expr(toks, 0)[0]
                except PreprocessorError:
                    val = nextval
                nextval = val + 1
            else:
                name = item.strip()
                val = nextval
                nextval += 1
            if not re.match(r"^[A-Za-z_]\w*$", name):
                continue
            if name not in self.macros:   # a #define wins over the enum
                self.enums[name] = val

    def _do_define(self, spec, lineno):
        # NAME or NAME(args) [variadic] rest
        m = re.match(r"^([A-Za-z_]\w*)(\([^)]*\))?\s*(.*)$", spec, re.S)
        if not m:
            raise PreprocessorError("bad #define at line %d: %r" % (lineno, spec))
        name, paramspec, body = m.group(1), m.group(2), m.group(3).strip()
        if paramspec is None:
            # `#define NAME NAME` is how the kernel exposes an enumerator under
            # its own name (IPPROTO_TCP and friends).  Treating it as a macro
            # would expand to itself and lose the value, so drop it and let the
            # enumerator stand.
            if body == name:
                self.macros.pop(name, None)
                return
            self.macros[name] = Macro(name, None, False, body)
            return
        inner = paramspec[1:-1].strip()
        params, variadic = [], False
        if inner:
            for p in inner.split(","):
                p = p.strip()
                if p == "...":
                    variadic = True
                    params.append("__VA_ARGS__")
                elif p.endswith("..."):
                    variadic = True
                    params.append(p[:-3].strip())
                else:
                    params.append(p)
        self.macros[name] = Macro(name, params, variadic, body)

    # ------------------------------------------------------------- accessors
    def value_of(self, name):
        """Fully expand a macro to a python int, or None."""
        if name not in self.macros:
            return self.enums.get(name)
        toks = self._expand([name])
        try:
            v, i = self._expr(toks, 0)
        except PreprocessorError:
            return None
        # allow trailing non-expression junk to fail the caller
        if i != len(toks):
            # e.g. type casts like "(unsigned int) 5"; try to salvage last int
            for t in reversed(toks):
                if re.match(r"^(0[xX])?[0-9a-fA-F]+[uUlL]*$", t):
                    try:
                        return int(t.rstrip("uUlL"), 0)
                    except ValueError:
                        continue
            return None
        return v

    def int_macros(self, prefix=None):
        out = {}
        for name in list(self.macros):
            if prefix and not name.startswith(prefix):
                continue
            v = self.value_of(name)
            if v is not None:
                out[name] = v
        return out

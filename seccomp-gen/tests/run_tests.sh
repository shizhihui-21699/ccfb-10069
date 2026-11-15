#!/usr/bin/env bash
# Integration tests for seccomp-gen. Build first with `make`.
set -u
cd "$(dirname "$0")/.."
BIN=./bin/seccomp-gen
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
fail=0

check() { # desc, expected-zero?
  if [ "$2" -eq 0 ]; then echo "PASS: $1"; else echo "FAIL: $1"; fail=1; fi
}

# 1. selftest (both arches, both phases, VM replay)
$BIN selftest > "$TMP/self.log" 2>&1
check "selftest all green" $?
grep -q "selftest OK" "$TMP/self.log"
check "selftest prints OK" $?

# 2. parse: unfinished/resumed merge + thread tracking + marker
$BIN parse tests/samples/svc.strace --out "$TMP/events.json" > "$TMP/parse.log" 2>&1
check "parse runs" $?
grep -q "tasks=2" "$TMP/parse.log"; check "two tasks tracked" $?
grep -q "unfinished=1 resumed=1" "$TMP/parse.log"; check "unfinished merged" $?
grep -q "markerSeen=yes" "$TMP/parse.log"; check "phase marker detected" $?
grep -q '"phase":"boot"' "$TMP/events.json"; check "boot phase tagged" $?
grep -q '"phase":"runtime"' "$TMP/events.json"; check "runtime phase tagged" $?

# 3. gen runtime x86_64 with auto-args; socket must be constrained to AF_INET
$BIN gen tests/samples/svc.strace --arch x86_64 --phase runtime --auto-args \
     --out-prefix "$TMP/rt64" > "$TMP/gen.log" 2>&1
check "gen x86_64 runtime" $?
grep -qE "0 failed" "$TMP/gen.log"; check "x86_64 runtime verify clean" $?
# 3b. boot phase carries the startup socket call, constrained to AF_INET
$BIN gen tests/samples/svc.strace --arch x86_64 --phase boot --auto-args \
     --out-prefix "$TMP/boot64" > "$TMP/genboot.log" 2>&1
check "gen x86_64 boot" $?
grep -qE "0 failed" "$TMP/genboot.log"; check "x86_64 boot verify clean" $?
grep -q "socket WHERE arg0 == 2" "$TMP/boot64.dsl"
check "socket restricted to AF_INET (nr 2)" $?
test -s "$TMP/rt64.bpf" -a -s "$TMP/rt64.h" -a -s "$TMP/rt64.md"
check "all artifacts emitted" $?

# 4. aarch64 numbers differ: same syscalls, different nr in the C array
$BIN gen tests/samples/svc.strace --arch aarch64 --phase runtime --auto-args \
     --out-prefix "$TMP/rtaa" > "$TMP/genaa.log" 2>&1
check "gen aarch64 runtime" $?
grep -qE "0 failed" "$TMP/genaa.log"; check "aarch64 runtime verify clean" $?
# read happens during boot; check the aarch64 boot DSL names it (nr 63)
$BIN gen tests/samples/svc.strace --arch aarch64 --phase boot --auto-args \
     --out-prefix "$TMP/aaboot" > "$TMP/genaaboot.log" 2>&1
check "gen aarch64 boot" $?
grep -q "ALLOW read" "$TMP/aaboot.dsl"; check "aarch64 DSL names read" $?

# 5. DSL overlay: explicit KILL rule is honored and replayed
cat > "$TMP/overlay.dsl" <<'DSL'
policy { arch "x86_64"; phase "runtime"; default KILL; }
KILL ptrace;
ERRNO(1) socket WHERE arg0 == AF_INET6;
DSL
$BIN gen tests/samples/svc.strace --arch x86_64 --phase runtime --auto-args \
     --dsl "$TMP/overlay.dsl" --out-prefix "$TMP/ov" > "$TMP/ov.log" 2>&1
check "gen with DSL overlay" $?
grep -q "KILL ptrace" "$TMP/ov.dsl"; check "ptrace deny present" $?
grep -qE "0 failed" "$TMP/ov.log"; check "overlay verify clean" $?

# 6. verify subcommand on the serialized blob round-trip
$BIN verify "$TMP/rt64.bpf" tests/samples/svc.strace --auto-args \
     > "$TMP/verify.log" 2>&1
check "verify subcommand" $?
grep -qE "[1-9][0-9]* passed, 0 failed" "$TMP/verify.log"
check "verify has passes and no failures" $?
grep -q "cross-arch" "$TMP/verify.log"; check "cross-arch cases run" $?

# 7. jump-distance stress: >255-instruction filter must still verify
python3 -I tests/make_big_trace.py "$TMP/big.strace"
$BIN gen "$TMP/big.strace" --arch x86_64 --phase all --auto-args \
     --out-prefix "$TMP/big" > "$TMP/big.log" 2>&1
check "large filter generated" $?
grep -qE "0 failed" "$TMP/big.log"; check "large filter verifies (trampolines)" $?
insns=$(grep -c "{" "$TMP/big.h" || true)
[ "${insns:-0}" -gt 255 ]; check "large filter exceeds 255 insns ($insns)" $?

# 8. malformed input must produce a warning, not a crash
printf 'garbage line without prefix\n1000 read(4, "x", 1) = 1\n' \
  > "$TMP/bad.strace"
$BIN parse "$TMP/bad.strace" > "$TMP/bad.log" 2>&1
check "malformed line handled" $?
grep -q "cannot parse prefix" "$TMP/bad.log"; check "parse error reported" $?

# 9. boot phase policy is stricter than runtime and excludes runtime calls
$BIN gen tests/samples/svc.strace --arch x86_64 --phase boot \
     --out-prefix "$TMP/boot" > "$TMP/boot.log" 2>&1
if grep -q "epoll_wait" "$TMP/boot.dsl"; then
  echo "FAIL: boot policy leaks runtime syscall epoll_wait"; fail=1
else
  echo "PASS: boot/runtime separation"
fi

echo
if [ "$fail" -eq 0 ]; then echo "ALL TESTS PASSED"; else echo "TESTS FAILED"; fi
exit "$fail"

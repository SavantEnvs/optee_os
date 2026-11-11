#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# The oracle is mayhem/kat/kat.c: a known-answer probe built by build.sh with NORMAL flags (no
# sanitizers), dynamically linked, from the same OP-TEE sources the fuzzers exercise (libfdt, zlib,
# QCBOR, base64, vendored mbedtls). Each subcommand prints computed values; this script asserts the
# exact expected lines, so a patch that makes the libraries (or the probe) exit 0 / print nothing /
# compute something else fails here.
KAT="$SRC/out/mayhem-kat/kat"
[ -x "$KAT" ] || { echo "missing $KAT: mayhem/build.sh did not build the probe" >&2; emit_ctrf "optee-kat" 0 1 0; exit 1; }

passed=0
failed=0

# expect <subcommand> <expected output, newline separated>
expect() {
  local sub="$1" want="$2" got
  got=$("$KAT" "$sub" 2>&1)
  if [ "$got" == "$want" ]; then
    echo "PASS kat $sub"
    passed=$((passed + 1))
  else
    echo "FAIL kat $sub" >&2
    printf '  want: %s\n  got:  %s\n' "$want" "$got" >&2
    failed=$((failed + 1))
  fi
}

expect fdt 'fdt: cpus-reg=4 compatible=foo,bar match=0'
expect inflate 'inflate: rc=1 out=hello world adler=436929629'
expect base64 'base64: dec=1 foobar enc=1 Zm9vYmFyIQ=='
expect qcbor 'qcbor: dec-err=0 v=42 sum=6
qcbor: enc=a201182a62686983010203'
expect x509 'x509: subject=C=SE, O=OP-TEE, CN=optee-mayhem version=3 bits=256 pk=EC selfverify=0 flags=0
pk: parse=0 bits=256 name=EC'

emit_ctrf "optee-kat" "$passed" "$failed" 0

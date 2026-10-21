#!/usr/bin/env bash
# Probe accepted --label values for kv-encrypt.
#
# This is an exploratory test: it prints a matrix of label lengths/symbols that
# the current binary accepts, then searches for the largest ASCII --label length
# that can be passed through this shell/OS environment.
#
# Notes:
# - POSIX argv strings cannot contain NUL bytes, so --label can never carry NUL.
#   Use --label-hex for binary labels; this script includes a NUL-byte hex probe.
# - The practical maximum --label length is usually imposed by ARG_MAX / execve,
#   not by kv-encrypt itself.

set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

BIN="./kv-encrypt"
PUBKEY="${PUBKEY:-pub.pem}"
INPUT="${INPUT:-tests/test_kvs.txt}"
TMP_DIR="${TMP_DIR:-$(mktemp -d)}"
LOG_DIR="${LOG_DIR:-$TMP_DIR/logs}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-5}"
CLEANUP_LOGS="${CLEANUP_LOGS:-0}"
mkdir -p "$LOG_DIR"
if [[ "$CLEANUP_LOGS" == "1" ]]; then
  trap 'rm -rf "$TMP_DIR"' EXIT
fi
PASS_COUNT=0
FAIL_COUNT=0
TIMEOUT_COUNT=0

run_with_timeout() {
  perl -e '
    my $timeout = shift @ARGV;
    my $pid = fork();
    die "fork failed: $!\n" unless defined $pid;
    if ($pid == 0) {
      exec @ARGV;
      die "exec failed: $!\n";
    }
    local $SIG{ALRM} = sub {
      kill "TERM", $pid;
      select undef, undef, undef, 0.2;
      kill "KILL", $pid;
      exit 124;
    };
    alarm $timeout;
    waitpid($pid, 0);
    my $status = $?;
    alarm 0;
    exit($status & 127 ? 128 + ($status & 127) : $status >> 8);
  ' "$TIMEOUT_SECONDS" "$@"
}

if [[ ! -x "$BIN" ]]; then
  echo "Building $BIN ..."
  make
fi

if [[ ! -f "$PUBKEY" ]]; then
  echo "Missing public key: $PUBKEY" >&2
  echo "Generate one with: openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out priv.pem && openssl pkey -in priv.pem -pubout -out pub.pem" >&2
  exit 1
fi

if [[ ! -f "$INPUT" ]]; then
  echo "Missing input file: $INPUT" >&2
  exit 1
fi

PREFLIGHT_LOG="$LOG_DIR/preflight.log"
run_with_timeout "$BIN" --label preflight "$PUBKEY" "$INPUT" >"$PREFLIGHT_LOG" 2>&1
status=$?
if [[ $status -ne 0 ]]; then
  echo "Preflight invocation failed or timed out: status=$status log=$PREFLIGHT_LOG" >&2
  echo "Cannot infer --label restrictions until a basic --label invocation completes." >&2
  exit "$status"
fi

run_label() {
  local name="$1"
  local label="$2"
  local log="$LOG_DIR/${name//[^A-Za-z0-9_.-]/_}.log"

  run_with_timeout "$BIN" --label "$label" "$PUBKEY" "$INPUT" >"$log" 2>&1
  local status=$?
  local bytes
  bytes=$(printf '%s' "$label" | wc -c | tr -d ' ')

  if [[ $status -eq 0 ]]; then
    PASS_COUNT=$((PASS_COUNT + 1))
    printf 'PASS label    %-28s bytes=%7s\n' "$name" "$bytes"
  elif [[ $status -eq 124 ]]; then
    TIMEOUT_COUNT=$((TIMEOUT_COUNT + 1))
    printf 'TIMEOUT label %-28s bytes=%7s after=%ss log=%s\n' "$name" "$bytes" "$TIMEOUT_SECONDS" "$log"
  else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    printf 'FAIL label    %-28s bytes=%7s status=%s log=%s\n' "$name" "$bytes" "$status" "$log"
  fi
  return "$status"
}

run_label_hex() {
  local name="$1"
  local hex="$2"
  local log="$LOG_DIR/${name//[^A-Za-z0-9_.-]/_}.log"

  run_with_timeout "$BIN" --label-hex "$hex" "$PUBKEY" "$INPUT" >"$log" 2>&1
  local status=$?
  local bytes=$(( ${#hex} / 2 ))

  if [[ $status -eq 0 ]]; then
    PASS_COUNT=$((PASS_COUNT + 1))
    printf 'PASS labelhex %-28s bytes=%7s hexchars=%s\n' "$name" "$bytes" "${#hex}"
  elif [[ $status -eq 124 ]]; then
    TIMEOUT_COUNT=$((TIMEOUT_COUNT + 1))
    printf 'TIMEOUT labelhex %-25s bytes=%7s after=%ss log=%s\n' "$name" "$bytes" "$TIMEOUT_SECONDS" "$log"
  else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    printf 'FAIL labelhex %-28s bytes=%7s status=%s log=%s\n' "$name" "$bytes" "$status" "$log"
  fi
  return "$status"
}

make_label() {
  local length="$1"
  # Generate exactly $length ASCII bytes without storing fixtures in the repo.
  perl -e 'print "A" x shift' "$length"
}

printf '\n== Symbol / character probes ==\n'
run_label 'empty-string' ''
run_label 'plain-ascii' 'ctx-v1'
run_label 'spaces' 'context with spaces'
run_label 'punctuation' '!"#$%&'"'"'()*+,-./:;<=>?@[\]^_`{|}~'
run_label 'unicode-umlaut' 'Kontext-äöü-ß'
run_label 'unicode-emoji' 'context-🔐-🚀'
run_label 'tab-character' $'context\twith\ttabs'
run_label 'newline-character' $'context\nwith\nnewlines'

printf '\n== Binary label probes via --label-hex ==\n'
run_label_hex 'single-nul-byte' '00'
run_label_hex 'nul-and-ff-bytes' '0001027fff'
run_label_hex 'empty-hex-invalid' '' || true
run_label_hex 'odd-hex-invalid' '0' || true
run_label_hex 'non-hex-invalid' 'zz' || true

printf '\n== Fixed length probes ==\n'
for length in 0 1 2 31 32 33 127 128 255 256 1024 4096 16384 65536; do
  label="$(make_label "$length")"
  run_label "len-$length" "$label" || true
done

printf '\n== Searching practical maximum --label length ==\n'
arg_max="$(getconf ARG_MAX 2>/dev/null || printf '262144')"
# Stay below ARG_MAX to leave room for environment, executable path, other args,
# and shell overhead. Users can override with MAX_PROBE_LENGTH=...
high="${MAX_PROBE_LENGTH:-$(( arg_max > 8192 ? arg_max - 8192 : arg_max ))}"
low=0
best=0
first_fail='none'

while (( low <= high )); do
  mid=$(( (low + high) / 2 ))
  label="$(make_label "$mid")"
  log="$LOG_DIR/max-probe-$mid.log"
  run_with_timeout "$BIN" --label "$label" "$PUBKEY" "$INPUT" >"$log" 2>&1
  status=$?
  if [[ $status -eq 0 ]]; then
    best=$mid
    low=$(( mid + 1 ))
  else
    first_fail="length=$mid status=$status log=$log"
    high=$(( mid - 1 ))
  fi
done

printf 'Largest passing ASCII --label length in this environment: %s bytes\n' "$best"
printf 'First failing probe observed during search: %s\n' "$first_fail"
printf '\nSummary: pass=%s fail=%s timeout=%s\n' "$PASS_COUNT" "$FAIL_COUNT" "$TIMEOUT_COUNT"
if (( PASS_COUNT == 0 )); then
  printf 'Conclusion: no probe completed successfully; the binary appears to fail or hang even for baseline labels. Fix that before interpreting --label restrictions.\n'
elif (( FAIL_COUNT == 0 && TIMEOUT_COUNT == 0 )); then
  printf 'Conclusion: all tested non-NUL text labels are accepted. NUL requires --label-hex because argv cannot carry NUL bytes. Maximum --label length is environment-dependent.\n'
else
  printf 'Conclusion: some probes failed or timed out; inspect the per-probe logs printed above to identify the effective restrictions in this environment. NUL still requires --label-hex because argv cannot carry NUL bytes.\n'
fi

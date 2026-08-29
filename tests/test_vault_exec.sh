#!/usr/bin/env bash
# Smoke-test vault-exec without sgid: allowlist /usr/bin/true (or /bin/true),
# deny /bin/sh and /bin/echo.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="${ROOT}/vault-exec.c"

if [[ ! -f "${SRC}" ]]; then
    echo "FAIL: missing ${SRC}" >&2
    exit 1
fi

TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

BIN="${TMP}/vault-exec"
echo "[*] compiling vault-exec (-O2 -Wall -Werror)"
gcc -O2 -Wall -Werror -o "${BIN}" "${SRC}"

pick_bin() {
    local n="$1"
    if [[ -x "/usr/bin/${n}" ]]; then
        realpath "/usr/bin/${n}"
    elif [[ -x "/bin/${n}" ]]; then
        realpath "/bin/${n}"
    else
        echo "FAIL: no ${n} binary" >&2
        exit 1
    fi
}
TRUE="$(pick_bin true)"
SH="$(pick_bin sh)"
ECHO="$(pick_bin echo)"

ALLOW="${TMP}/allowed-apps"
printf '%s\n' "# test allowlist" "${TRUE}" > "${ALLOW}"

echo "[*] allowlist:"
cat "${ALLOW}"

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "PASS: $*"; }

# argc < 2
set +e
"${BIN}" >/dev/null 2>"${TMP}/err"
rc=$?
set -e
[[ "${rc}" -eq 2 ]] || fail "argc<2 should exit 2, got ${rc}"
pass "argc<2 refused (exit 2)"

# missing binary after -t
set +e
"${BIN}" -t "${ALLOW}" >/dev/null 2>"${TMP}/err"
rc=$?
set -e
[[ "${rc}" -eq 2 ]] || fail "-t without program should exit 2, got ${rc}"
pass "-t without program refused"

# allowed: true
set +e
"${BIN}" -t "${ALLOW}" "${TRUE}"
rc=$?
set -e
[[ "${rc}" -eq 0 ]] || fail "allowed ${TRUE} should succeed, got ${rc}"
pass "allowed ${TRUE} exec ok"

# also via /bin/true if it realpaths to the same place
if [[ -e /bin/true ]]; then
    set +e
    "${BIN}" -t "${ALLOW}" /bin/true
    rc=$?
    set -e
    [[ "${rc}" -eq 0 ]] || fail "/bin/true (realpath) should succeed, got ${rc}"
    pass "/bin/true matches allowlist via realpath"
fi

# denied: sh
set +e
out="$("${BIN}" -t "${ALLOW}" "${SH}" -c 'echo pwned' 2>&1)"
rc=$?
set -e
[[ "${rc}" -ne 0 ]] || fail "denied ${SH} should fail, got 0; out=${out}"
printf '%s\n' "${out}" | grep -q "not an allowed app" || fail "deny message missing for sh: ${out}"
pass "denied ${SH}"

# denied: echo (must not run)
set +e
out="$("${BIN}" -t "${ALLOW}" "${ECHO}" pwned 2>&1)"
rc=$?
set -e
[[ "${rc}" -ne 0 ]] || fail "denied ${ECHO} should fail, got 0; out=${out}"
printf '%s\n' "${out}" | grep -q "pwned" && fail "echo ran despite deny: ${out}"
printf '%s\n' "${out}" | grep -q "not an allowed app" || fail "deny message missing for echo: ${out}"
pass "denied ${ECHO}"

# --allowlist long flag
set +e
"${BIN}" --allowlist "${ALLOW}" "${TRUE}"
rc=$?
set -e
[[ "${rc}" -eq 0 ]] || fail "--allowlist flag failed, got ${rc}"
pass "--allowlist flag works"

echo
echo "All vault-exec smoke tests passed."

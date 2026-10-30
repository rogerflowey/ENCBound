#!/usr/bin/env bash
#
# ENCBound restart - pinned upstream host/test evidence runner
# (docs/legacy/steps/09-original-api-and-sessions.md; oracle repair in
# docs/legacy/steps/10-evaluation-campaign.md E0).
#
# Builds are done by the Makefile; this runner executes the pinned upstream host
# app/app.cpp with its ECALL call sites unchanged:
#
#   1. `-t` runs app/test.cpp's happy path: create, add x2, change, remove, show
#      on ONE enclave instance (the original sequential session).
#   2. A cross-process CLI sequence (create, add, show, change, remove, show)
#      exercises the same public ECALLs and the filesystem OCALLs with the sealed
#      wallet persisting in wallet.seal between processes.
#   3. A wrong master password is an ordinary application error, not a crash.
#
# Every row asserts BOTH the process exit status and the expected output text.
# A process that prints the expected line and then fails (nonzero status) or
# reports an unexpected [ERROR] no longer passes. Raw per-case output and a
# binary/signed-image identity record are retained in a unique run directory.
#
# use --selftest to check the checker itself against synthetic transcripts.
#
# This is CLI/behaviour evidence on SDK SIM; it is not the dedicated evaluation
# harness and makes no hardware claim.
#
# usage: run_upstream_host.sh <build-dir> [sgx-sdk]
#        run_upstream_host.sh --selftest
set -euo pipefail

usage() {
    echo "usage: $0 <build-dir> [sgx-sdk] | --selftest" >&2
    exit 2
}

# --- checker ---------------------------------------------------------------
# verdict <rc> <output-file> <expect-substring> <allow-error:0|1>
# Echoes "ok" or prints the failure reason and echoes "fail". Returns 0/1.
verdict() {
    local rc=$1 outfile=$2 expect=$3 allow_error=$4
    if [ "$rc" -ne 0 ]; then
        echo "exit status $rc (expected 0)"; return 1
    fi
    if ! grep -qF -- "$expect" "$outfile"; then
        echo "missing expected text '$expect'"; return 1
    fi
    if [ "$allow_error" = 0 ] && grep -q '\[ERROR\]' "$outfile"; then
        echo "reported an unexpected [ERROR]"; return 1
    fi
    return 0
}

if [ "${1:-}" = "--selftest" ]; then
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT
    selftest_fail=0
    selftest_case() { # <name> <want:pass|fail> <rc> <body>
        local name=$1 want=$2 rc=$3 body=$4 f="$tmp/$1.txt"
        printf '%s\n' "$body" > "$f"
        if verdict "$rc" "$f" "All tests successfully passed." 0 >/dev/null 2>&1; then
            got=pass
        else
            got=fail
        fi
        if [ "$got" != "$want" ]; then
            echo "selftest: FAIL: $name: wanted $want got $got" >&2
            selftest_fail=1
        else
            echo "selftest: ok: $name ($want)"
        fi
    }
    selftest_case "success" pass 0 "All tests successfully passed."
    selftest_case "success_then_crash" fail 132 "All tests successfully passed."
    selftest_case "missing_text" fail 0 "some other output"
    selftest_case "error_plus_success" fail 0 \
        "All tests successfully passed.
[ERROR] unrelated failure"
    if [ "$selftest_fail" = 0 ]; then
        echo "UPSTREAM HOST ORACLE SELFTEST PASS"
        exit 0
    fi
    echo "UPSTREAM HOST ORACLE SELFTEST FAIL" >&2
    exit 1
fi

artifact_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
BUILD=${1:-}
SGX_SDK=${2:-${SGX_SDK:-$artifact_root/deps/sgxsdk}}
if [ -z "$BUILD" ]; then usage; fi
if [ ! -d "$BUILD" ]; then
    echo "upstream-host: FAIL: no build directory $BUILD" >&2
    exit 1
fi
BUILD=$(cd "$BUILD" && pwd)

ENCLAVE_DIR="$BUILD/enclave"
HOST_BIN="$BUILD/host/host-upstream"
for f in "$HOST_BIN" "$ENCLAVE_DIR/enclave.signed.so"; do
    if [ ! -e "$f" ]; then
        echo "upstream-host: FAIL: missing $f" >&2
        exit 1
    fi
done

export LD_LIBRARY_PATH="$SGX_SDK/lib64${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
EVIDENCE="$REPO_ROOT/tools/evaluation_evidence.py"
LOGROOT=${ENCBOUND_UPSTREAM_LOGDIR:-${ENCBOUND_EVIDENCE_ROOT:-$REPO_ROOT/build/evaluation-runs}}
LOGDIR=$(python3 "$EVIDENCE" new --build "$BUILD" --kind wallet-upstream --root "$LOGROOT")
python3 "$EVIDENCE" capture --run-dir "$LOGDIR" --build "$BUILD" \
    --runner "$0" --host "$HOST_BIN"
fail=0

reset_wallet() {
    rm -f "$ENCLAVE_DIR/wallet.seal"
}

# run_expect <name> <expect> <allow-error:0|1> <args...>
run_expect() {
    local name=$1 expect=$2 allow_error=$3
    shift 3
    local out rc
    set +e
    out=$(cd "$ENCLAVE_DIR" && "$HOST_BIN" "$@" 2>&1)
    rc=$?
    set -e
    printf '%s\n' "$out" > "$LOGDIR/$name.out"
    printf '%s\n' "$rc" > "$LOGDIR/$name.exit-status"
    local reason
    if reason=$(verdict "$rc" "$LOGDIR/$name.out" "$expect" "$allow_error"); then
        echo "upstream-host: ok: $name (rc=$rc)"
    else
        echo "upstream-host: FAIL: $name: $reason" >&2
        sed 's/^/    /' "$LOGDIR/$name.out" >&2
        fail=1
    fi
}

# 1. Pinned test suite on a single enclave (create/add/add/change/remove/show).
reset_wallet
run_expect "test-suite" "All tests successfully passed." 0 -t

# 2. Cross-process CLI session (one public ECALL per process, sealed file persists).
reset_wallet
run_expect "cli-create" "Wallet successfully created." 0 -n password123
run_expect "cli-add" "Item successfully added" 0 \
    -p password123 -a -x mail -y alice -z secret123
run_expect "cli-show-after-add" "Number of items: 1" 0 -p password123 -s
run_expect "cli-change" "Master-password successfully changed." 0 \
    -p password123 -c password456
run_expect "cli-remove" "Item successfully removed" 0 -p password456 -r 0
run_expect "cli-show-after-remove" "Number of items: 0" 0 -p password456 -s

# 3. A wrong password is an ordinary application error (int status), not a crash.
run_expect "cli-wrong-password" "Wrong master password." 1 -p nope -s
reset_wallet

if [ "$fail" = 0 ]; then
    echo "UPSTREAM HOST PASS (logs: $LOGDIR)"
    exit 0
fi
echo "UPSTREAM HOST FAIL" >&2
exit 1

#!/usr/bin/env bash
#
# ENCBound restart - durable original-access RANGE attribution runner
# (docs/legacy/steps/09-original-api-and-sessions.md; oracle repair in
# docs/legacy/steps/10-evaluation-campaign.md E0).
#
# Runs the SHOW overflow probe under gdb with the enclave symbol table at the
# fixed SIM load base and requires the terminal stop to be the original
# 30112-byte assignment's compiler-inserted check, reached through the
# modified Intel bridge:
#
#   encbound_abort(code=4 RANGE) <- encbound_require(width=30112, kind=2)
#   <- ecall_show_wallet (enclave.cpp:155, original app definition)
#   <- sgx_ecall_show_wallet (pinned Intel trusted bridge)
#
# The EDL `wallet_size` controls both SDK marshaling and the protected
# application allocation: with wallet_size=16 the application writes 30112 bytes
# through a 16-byte checked allocation. The host backing-buffer size is a
# host-side variation and does not change marshaling or allocation.
#
# Observed geometry is asserted, not just requested: the aborting capability's
# radix must match a slot of the requested wallet_size (here 16 bytes -> radix
# 4) and the host must have reported the requested backing size. Loader errors,
# unrelated crashes and ordinary early boundary refusals fail the check.
#
# `--selftest` checks the checker against synthetic transcripts (success text
# followed by a crash, wrong width, wrong allocation geometry, missing frames,
# unrelated crash). This is SDK SIM evidence; it is not a hardware or
# general-mechanism claim.
#
# usage: run_overflow_attribution.sh <build-dir> <host-backing> [wallet-size] [sdk]
#        run_overflow_attribution.sh --selftest
set -euo pipefail

usage() {
    echo "usage: $0 <build-dir> <host-backing> [wallet-size] [sgx-sdk] | --selftest" >&2
    exit 2
}

# --- checker ---------------------------------------------------------------
# verify_transcript <logfile> <wallet-size> <host-backing>; returns 0/1 and
# reports problems on stderr.
verify_transcript() {
    local log=$1 wallet=$2 cap=$3
    local ok=1
    local want_radix caphex radix
    require() { # <pattern> <description>
        if ! grep -qE "$1" "$log"; then
            echo "missing: $2" >&2
            ok=0
        fi
    }
    require 'Program received signal SIGILL' 'terminal signal is SIGILL'
    require '#0 +.*encbound_abort \(code=4\)' 'abort code 4 (RANGE)'
    require ' in ecall_show_wallet .*enclave\.cpp:155' \
        'caller is the original assignment enclave.cpp:155'
    if grep -q 'encbound_ecalls\.c' "$log"; then
        echo "obsolete companion adapter frame present" >&2
        ok=0
    fi
    require 'sgx_ecall_show_wallet .*enclave_t\.c' \
        'honoured the pinned Intel trusted bridge'

    # Observed RANGE geometry must be the 30112-byte copy, not some other one.
    if grep -qE 'ENCBOUND_GEO capability=0x[0-9a-f]+ width=30112 kind=2' "$log"; then
        caphex=$(grep -oE 'ENCBOUND_GEO capability=0x[0-9a-f]+' "$log" | head -1 \
            | grep -oE '0x[0-9a-f]+')
    elif grep -qE 'encbound_require \((capability=)?0x[0-9a-f]+,? width=30112, kind=2' "$log"; then
        caphex=$(grep -oE '0x[0-9a-f]+' <(grep -E 'encbound_require .*width=30112, kind=2' "$log" | head -1) | head -1)
    else
        echo "missing: RANGE requirement width=30112 kind=2" >&2
        caphex=""
        ok=0
    fi
    if [ -n "$caphex" ]; then
        radix=$(python3 -c "print(int('$caphex', 16) >> 59)")
        want_radix=$(python3 -c "print(($wallet).bit_length() - 1)")
        if [ "$radix" != "$want_radix" ]; then
            echo "wrong allocation geometry: capability $caphex radix $radix, expected slot radix $want_radix for wallet_size $wallet" >&2
            ok=0
        fi
    fi

    # The host must have reported the requested backing size at run time.
    if ! grep -qE "overflow probe: sizeof\(wallet_t\)=30112 wallet_size=$wallet host_backing=$cap" "$log"; then
        echo "missing: observed host geometry wallet_size=$wallet host_backing=$cap" >&2
        ok=0
    fi

    if grep -qE 'SIGSEGV|SIGABRT|SIGBUS' "$log"; then
        echo "unrelated crash signal present" >&2
        ok=0
    fi
    [ "$ok" = 1 ]
}

if [ "${1:-}" = "--selftest" ]; then
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT
    base="$tmp/base.log"
    cat > "$base" <<'EOF'
overflow probe: sizeof(wallet_t)=30112 wallet_size=16 host_backing=16
Program received signal SIGILL, Illegal instruction.
encbound_abort (code=4) at /x/platform_layout.c:407
#0  encbound_abort (code=4) at /x/platform_layout.c:407
#1  0x0000000040006b38 in encbound_require (capability=0x2000000000000000, width=30112, kind=2) at /x/capability.c:184
ENCBOUND_GEO capability=0x2000000000000000 width=30112 kind=2
#2  0x000000004000136c in ecall_show_wallet (x=1) at /src/enclave/enclave.cpp:155
#4  0x0000000040003cc0 in sgx_ecall_show_wallet (x=1) at /g/enclave_t.c:159
EOF
    st_fail=0
    st_case() { # <name> <want:pass|fail> <file>
        local name=$1 want=$2 f=$3 got
        if verify_transcript "$f" 16 16 >/dev/null 2>&1; then got=pass; else got=fail; fi
        if [ "$got" != "$want" ]; then
            echo "selftest: FAIL: $name: wanted $want got $got" >&2
            st_fail=1
        else
            echo "selftest: ok: $name ($want)"
        fi
    }
    st_case "positive" pass "$base"
    sed 's/enclave.cpp:155/other.cpp:155/' "$base" > "$tmp/wrong_app.log"
    st_case "wrong_application_frame" fail "$tmp/wrong_app.log"
    sed 's/enclave_t.c/encbound_ecalls.c/' "$base" > "$tmp/old_bridge.log"
    st_case "obsolete_adapter_path" fail "$tmp/old_bridge.log"
    sed 's/Program received signal SIGILL/Program received signal SIGSEGV/' "$base" > "$tmp/crash.log"
    st_case "success_then_unrelated_crash" fail "$tmp/crash.log"
    sed 's/width=30112/width=8/g' "$base" > "$tmp/wrong_width.log"
    st_case "wrong_width" fail "$tmp/wrong_width.log"
    sed 's/0x2000000000000000/0x1000000000000000/g' "$base" > "$tmp/wrong_geom.log"
    st_case "wrong_allocation_geometry" fail "$tmp/wrong_geom.log"
    sed 's/host_backing=16/host_backing=999/' "$base" > "$tmp/wrong_host.log"
    st_case "wrong_host_backing" fail "$tmp/wrong_host.log"
    grep -v 'ecall_show_wallet' "$base" > "$tmp/no_frame.log"
    st_case "missing_application_frame" fail "$tmp/no_frame.log"
    grep -v 'encbound_abort' "$base" > "$tmp/no_abort.log"
    st_case "unrelated_stop" fail "$tmp/no_abort.log"
    if [ "$st_fail" = 0 ]; then
        echo "OVERFLOW ATTRIBUTION ORACLE SELFTEST PASS"
        exit 0
    fi
    echo "OVERFLOW ATTRIBUTION ORACLE SELFTEST FAIL" >&2
    exit 1
fi

artifact_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
BUILD=${1:-}
CAP=${2:-}
WALLET=${3:-16}
SGX_SDK=${4:-${SGX_SDK:-$artifact_root/deps/sgxsdk}}
if [ -z "$BUILD" ] || [ -z "$CAP" ]; then usage; fi
if [ ! -d "$BUILD" ]; then
    echo "attribution: FAIL: no build directory $BUILD" >&2
    exit 1
fi
BUILD=$(cd "$BUILD" && pwd)

ENCLAVE_SO="$BUILD/enclave/enclave.so"
ENCLAVE_DIR="$BUILD/enclave"
HOST_BIN="$BUILD/host/host"
for f in "$ENCLAVE_SO" "$HOST_BIN" "$ENCLAVE_DIR/enclave.signed.so"; do
    if [ ! -e "$f" ]; then
        echo "attribution: FAIL: missing $f" >&2
        exit 1
    fi
done

# .text is linked at its RVA (image base 0); the SIM loader maps the image at
# 0x40000000, so the loaded text base is 0x40000000 + .text RVA.
TEXT_RVA=$(readelf -SW "$ENCLAVE_SO" \
    | grep -oE '\.text[[:space:]]+PROGBITS[[:space:]]+[0-9a-f]+' \
    | grep -oE '[0-9a-f]+$' | head -1 || true)
if [ -z "$TEXT_RVA" ]; then
    echo "attribution: FAIL: cannot locate .text in $ENCLAVE_SO" >&2
    exit 1
fi
TEXT_ADDR=$(printf '0x%x' $((0x$TEXT_RVA + 0x40000000)))

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
EVIDENCE="$REPO_ROOT/tools/evaluation_evidence.py"
LOGROOT=${ENCBOUND_ATTRIBUTION_DIR:-${ENCBOUND_EVIDENCE_ROOT:-$REPO_ROOT/build/evaluation-runs}}
LOGDIR=$(python3 "$EVIDENCE" new --build "$BUILD" --kind wallet-overflow --root "$LOGROOT")
python3 "$EVIDENCE" capture --run-dir "$LOGDIR" --build "$BUILD" --runner "$0"
LOG="$LOGDIR/wallet${WALLET}-cap${CAP}.gdb"

cd "$ENCLAVE_DIR"
LD_LIBRARY_PATH="$SGX_SDK/lib64${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
    gdb -q -batch \
        -ex "add-symbol-file $ENCLAVE_SO $TEXT_ADDR" \
        -ex "set pagination off" \
        -ex "run --overflow --wallet-size $WALLET --capacity $CAP" \
        -ex "bt 12" \
        -ex "frame 1" -ex "print width" -ex "print kind" \
        -ex "printf \"ENCBOUND_GEO capability=0x%lx width=%lu kind=%d\\n\", capability, width, kind" \
        --args "$HOST_BIN" >"$LOG" 2>&1 || true

# Retain the transcript by default in the run directory (also honour an
# explicit caller destination).
if [ -n "${ENCBOUND_ATTRIBUTION_LOG:-}" ]; then
    cp "$LOG" "$ENCBOUND_ATTRIBUTION_LOG"
fi

if verify_transcript "$LOG" "$WALLET" "$CAP"; then
    echo "OVERFLOW ATTRIBUTION PASS (wallet_size $WALLET, host backing $CAP; log $LOG)"
    exit 0
fi
echo "--- gdb transcript (first 40 lines) ---" >&2
sed -n '1,40p' "$LOG" >&2
echo "OVERFLOW ATTRIBUTION FAIL (wallet_size $WALLET, host backing $CAP; log $LOG)" >&2
exit 1

#!/usr/bin/env bash
# ENCBound restart - instrument one application translation unit.
#
# Fixed pipeline (step 4): normalize opted-in VLA sizes before frontend
# optimization, run memory instrumentation once on optimized LLVM IR, then
# emit machine code with no later general IR pipeline or
# LTO. Trusted objects are not compiled through this driver.
# ENCBOUND_CODEGEN_OPT selects machine-code optimization only (-O0 by default,
# or experimental -O2); frontend flags are supplied independently by the caller.
#
# Usage: encbound-cc.sh <input.c> <output.o> [clang flags...]
set -euo pipefail

CLANG=${CLANG:-clang-21}
OPT=${OPT:-opt-21}
PLUGIN=${ENCBOUND_PLUGIN:-$(cd "$(dirname "$0")/.." && pwd)/build/pass/encbound_pass.so}

if [ "$#" -lt 2 ]; then
    echo "usage: $0 <input.c> <output.o> [clang flags...]" >&2
    exit 2
fi

src=$1
out=$2
shift 2

profile=${ENCBOUND_PROFILE:?ENCBOUND_PROFILE must be BASELINE, RADIX_ONLY, or MAC27}
case "$profile" in
    BASELINE|RADIX_ONLY|MAC27) ;;
    *) echo "unsupported ENCBound profile: $profile" >&2; exit 2 ;;
esac
app_errno=${ENCBOUND_APP_ERRNO:-0}
case "$app_errno" in
    0|1) ;;
    *) echo "unsupported ENCBOUND_APP_ERRNO: $app_errno" >&2; exit 2 ;;
esac
application_environment=()
if [ "$app_errno" = 1 ]; then
    application_root=$(cd "$(dirname "$0")/.." && pwd)
    application_environment=("-I$application_root/include/encbound_app_libc" "-I$application_root/include")
fi
codegen_opt=${ENCBOUND_CODEGEN_OPT:--O0}
case "$codegen_opt" in
    -O0|-O2) ;;
    *) echo "unsupported ENCBound code-generation level: $codegen_opt" >&2; exit 2 ;;
esac

keep_gep_flags=${ENCBOUND_KEEP_GEP_FLAGS:-0}
post_instcombine=${ENCBOUND_POST_INSTCOMBINE:-0}
for option in "$keep_gep_flags" "$post_instcombine"; do
    case "$option" in
        0|1) ;;
        *) echo "unsupported ENCBound GEP/InstCombine experiment setting: $option" >&2; exit 2 ;;
    esac
done

check_reuse=${ENCBOUND_CHECK_REUSE:-off}
case "$check_reuse" in
    off|block|loop) ;;
    *) echo "unsupported ENCBound check reuse: $check_reuse" >&2; exit 2 ;;
esac

local_proofs=${ENCBOUND_LOCAL_PROOFS:-0}
case "$local_proofs" in
    0|1) ;;
    *) echo "unsupported ENCBound local proofs: $local_proofs" >&2; exit 2 ;;
esac

fast_paths=${ENCBOUND_FAST_PATHS:-off}
case "$fast_paths" in
    off|inline|loops) ;;
    *) echo "unsupported ENCBound fast paths: $fast_paths" >&2; exit 2 ;;
esac

integration=()
for feature in CALLBACKS CXX_ALLOCATIONS AGGREGATE_ABI ATOMICS VIRTUALS VARIADICS PROTECTED_GLOBALS CXX_LIFECYCLE VLA CXX_EH; do
    variable="ENCBOUND_$feature"
    value=${!variable:-0}
    case "$value" in 0|1) ;; *) echo "unsupported $variable: $value" >&2; exit 2 ;; esac
    option=${feature,,}
    integration+=("-encbound-${option//_/-}=$value")
done
if [ "${ENCBOUND_CXX_EH:-0}" = 1 ] && { [ "$check_reuse" != off ] || [ "$local_proofs" != 0 ] || [ "$fast_paths" != off ] || [ "$post_instcombine" != 0 ]; }; then
    echo "ENCBound: EH optimization combination is not validated" >&2
    exit 2
fi

# Keep the same frontend and code-generation pipeline in all three profiles.
# Retain IR as review evidence; publish the object only after a successful build.
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
admit=()
if [ -n "${ENCBOUND_ADMITTED:-}" ]; then
    admit=("-encbound-admitted-file=$ENCBOUND_ADMITTED")
fi
if [ -n "${ENCBOUND_CXX_EH_ENTRIES:-}" ]; then
    admit+=("-encbound-cxx-eh-entries=$ENCBOUND_CXX_EH_ENTRIES")
fi
frontend_plugins=()
vla_frontend=0
if [ "$profile" != BASELINE ] && [ "${ENCBOUND_VLA:-0}" = 1 ]; then
    frontend_plugins=("-fpass-plugin=$PLUGIN")
    vla_frontend=1
fi
ENCBOUND_VLA_FRONTEND="$vla_frontend" "$CLANG" -S -emit-llvm "${application_environment[@]}" "$@" "${frontend_plugins[@]}" -MMD -MF "${out%.o}.d" -MT "$out" \
    "$src" -o "$tmp/input.ll"
if [ "$vla_frontend" = 1 ] && ! grep -q '"encbound.vla.sizing", i32 1' "$tmp/input.ll"; then
    echo "ENCBound: VLA sizing pass did not run before frontend optimization" >&2
    exit 2
fi
if [ "$profile" = BASELINE ]; then
    if [ "${ENCBOUND_CXX_ALLOCATIONS:-0}${ENCBOUND_VARIADICS:-0}${ENCBOUND_CXX_LIFECYCLE:-0}" != 000 ]; then
        "$OPT" -load-pass-plugin="$PLUGIN" "${admit[@]}" "${integration[@]}" -encbound-profile="$profile" -passes=encbound-variadic-baseline,encbound-cxx-baseline,verify -S "$tmp/input.ll" -o "$tmp/checked.ll"
    else
        "$OPT" -passes=verify -S "$tmp/input.ll" -o "$tmp/checked.ll"
    fi
else
    "$OPT" -load-pass-plugin="$PLUGIN" -passes=encbound,encbound-verify,encbound-reuse,encbound-verify,encbound-local-proofs,encbound-verify,encbound-fast,encbound-fast-verify,verify "${admit[@]}" \
        "${integration[@]}" -encbound-keep-gep-flags="$keep_gep_flags" -encbound-profile="$profile" -encbound-check-reuse="$check_reuse" -encbound-local-proofs="$local_proofs" -encbound-fast-paths="$fast_paths" -S "$tmp/input.ll" -o "$tmp/checked.ll"
fi
if [ "$post_instcombine" = 1 ]; then
    # Validate both sides of the experiment. A changed output shape must pass
    # the same access/escape checks before an object can be published.
    cp "$tmp/checked.ll" "$tmp/pre-instcombine.ll"
    if [ "$profile" = BASELINE ]; then
        "$OPT" -passes=instcombine,verify -S "$tmp/pre-instcombine.ll" -o "$tmp/checked.ll"
    else
        "$OPT" -passes=instcombine,verify -S "$tmp/pre-instcombine.ll" -o "$tmp/post-instcombine.ll"
        "$OPT" -load-pass-plugin="$PLUGIN" "${integration[@]}" \
            -encbound-keep-gep-flags="$keep_gep_flags" \
            -encbound-local-proofs="$local_proofs" -encbound-fast-paths="$fast_paths" \
            -passes=encbound-post-instcombine,encbound-fast-verify,verify \
            -S "$tmp/post-instcombine.ll" -o "$tmp/checked.ll"
    fi
fi
"$CLANG" -c "$codegen_opt" -Xclang -disable-llvm-passes "$tmp/checked.ll" -o "$tmp/output.o"
cp "$tmp/input.ll" "${out%.o}.input.ll"
cp "$tmp/checked.ll" "${out%.o}.checked.ll"
if [ "$post_instcombine" = 1 ]; then
    cp "$tmp/pre-instcombine.ll" "${out%.o}.pre-instcombine.ll"
    if [ "$profile" != BASELINE ]; then
        cp "$tmp/post-instcombine.ll" "${out%.o}.post-instcombine.ll"
    fi
fi
mv "$tmp/output.o" "$out"
if [ "$app_errno${ENCBOUND_CALLBACKS:-0}${ENCBOUND_AGGREGATE_ABI:-0}${ENCBOUND_CXX_ALLOCATIONS:-0}${ENCBOUND_ATOMICS:-0}${ENCBOUND_VIRTUALS:-0}${ENCBOUND_VARIADICS:-0}${ENCBOUND_PROTECTED_GLOBALS:-0}${ENCBOUND_CXX_LIFECYCLE:-0}${ENCBOUND_VLA:-0}" != 0000000000 ]; then
    python3 "$(dirname "$0")/record_integration_unit.py" "$src" "$out" "$PLUGIN" "$CLANG" "${application_environment[@]}" "$@"
fi
checks=$(grep -c 'call i64 @encbound_require' "$tmp/checked.ll" || true)
echo "ENCBOUND-CC => $out (profile: $profile, checks: $checks, codegen: $codegen_opt, reuse: $check_reuse, local proofs: $local_proofs, fast paths: $fast_paths, GEP flags kept: $keep_gep_flags, post InstCombine: $post_instcombine, later general IR optimization: disabled)"

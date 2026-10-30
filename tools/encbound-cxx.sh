#!/usr/bin/env bash
# Core C++17 application frontend; no linked STL implementation.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
sdk=${SGX_SDK:-$root/deps/sgxsdk}
overlay=${ENCBOUND_CXX_HEADERS:-$root/build/integration/cxx-headers}
python3 "$root/tools/prepare_cxx_headers.py" --sdk "$sdk" --out "$overlay" >/dev/null
export ENCBOUND_CXX_ALLOCATIONS=1
guards=()
if [ "${ENCBOUND_CXX_LIFECYCLE:-0}" != 1 ]; then guards=(-fno-threadsafe-statics); fi
eh=(-fno-exceptions -fno-rtti)
if [ "${ENCBOUND_CXX_EH:-0}" = 1 ]; then eh=(-fexceptions -frtti); fi
exec "$root/tools/encbound-cc.sh" "$@" -x c++ -std=c++17 "${eh[@]}" \
    "${guards[@]}" -fno-common -fno-builtin -nostdinc -nostdinc++ \
    -I"$overlay" -I"$sdk/include/libcxx" -I"$sdk/include/tlibc" -I"$sdk/include"

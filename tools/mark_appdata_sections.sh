#!/usr/bin/env bash
#
# ENCBound restart - move one instrumented object's read-only data into the
# app-owned COMPAT section collected by sdk/enclave_sections.lds.
#
# usage: mark_appdata_sections.sh <input.o> <output.o>
#
# Only this object's own .rodata* sections are renamed; the build calls this per
# app-owned object, so SDK/runtime rodata is never moved. Fails closed if any
# .rodata* section survives the rename.
set -euo pipefail

if [ "${ENCBOUND_WRITABLE_GLOBALS:-0}" = 1 ]; then
    exec python3 "$(dirname "$0")/mark_app_globals.py" "$@"
fi
if [ "${ENCBOUND_WRITABLE_GLOBALS:-0}" != 0 ]; then
    echo "invalid ENCBOUND_WRITABLE_GLOBALS" >&2; exit 2
fi

if [ "$#" -ne 2 ]; then
    echo "usage: $0 <input.o> <output.o>" >&2
    exit 2
fi

input=$1
output=$2

if [ ! -f "$input" ]; then
    echo "mark_appdata_sections: no input $input" >&2
    exit 1
fi

cp "$input" "$output"

mapfile -t sections < <(readelf -SW "$output" | grep -oE '^ *\[ *[0-9]+\] +\.rodata[^ ]*' | grep -oE '\.rodata[^ ]*' | sort -u)
for sec in "${sections[@]}"; do
    objcopy --rename-section "$sec=.encbound.appdata$sec,alloc,load,readonly,data,contents" \
        "$output"
done

if readelf -SW "$output" | grep -qE '^ *\[ *[0-9]+\] +\.rodata'; then
    echo "mark_appdata_sections: .rodata section remains in $output" >&2
    exit 1
fi

count=$(readelf -SW "$output" | grep -cE '^ *\[ *[0-9]+\] +\.encbound\.appdata' || true)
echo "APPDATA => $output ($count read-only section(s) moved to COMPAT)"

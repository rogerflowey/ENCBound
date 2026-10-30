#!/usr/bin/env bash
# Run an integration command and its children with the complete feature preset.
set -euo pipefail
if [ "$#" -eq 0 ]; then
    echo "usage: $0 <command> [args...]" >&2
    exit 2
fi
root=$(cd "$(dirname "$0")/.." && pwd)
. "$root/config/integration.env"
exec "$@"

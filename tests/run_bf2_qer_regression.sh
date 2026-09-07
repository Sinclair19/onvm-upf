#!/usr/bin/env bash
set -euo pipefail

repo=${1:-"$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"}
source_header="$repo/5gc/upf_c/upf_hw_offload.h"
wire_header="$repo/onvm/upf/hw_offload_msg.h"
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

for file in "$source_header" "$wire_header"; do
    if [[ ! -f "$file" ]]; then
        echo "missing required production header: $file" >&2
        exit 2
    fi
done

# Copy the complete function definitions from production. The harness supplies
# only lightweight UPF/list types, so no DPDK or DOCA dependency is required.
awk '
  /^static inline UpfQER \*/ { copying=1 }
  copying { print }
  copying && /^\/\* ═/ { exit }
' "$source_header" | sed '$d' > "$tmpdir/extracted_qer_helpers.h"

for symbol in upf_session_qer_for_dir upf_pdr_is_gbr upf_stamp_qer_identity; do
    if ! grep -Eq "^${symbol}\\(" "$tmpdir/extracted_qer_helpers.h"; then
        echo "failed to extract production helper: $symbol" >&2
        exit 2
    fi
done

cc -std=c11 -Wall -Wextra -Werror \
   -I"$repo" -I"$tmpdir" \
   "$here/bf2_qer_regression.c" -o "$tmpdir/bf2_qer_regression"
"$tmpdir/bf2_qer_regression"

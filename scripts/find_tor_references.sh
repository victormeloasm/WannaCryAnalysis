#!/usr/bin/env bash
set -euo pipefail
root=${1:?usage: $0 EXTRACTED_PAYLOAD_DIR}
find "$root" -type f -print0 |
while IFS= read -r -d '' f; do
    hits=$(
        {
            strings -a -n 6 "$f"
            strings -a -el -n 6 "$f"
        } | grep -Ei 'tor\.exe|Data[\/]+Tor|torrc|SocksPort|ControlPort|9050|9150|\.onion' || true
    )
    if [[ -n "$hits" ]]; then
        printf '
===== %s =====
%s
' "$f" "$hits"
    fi
done

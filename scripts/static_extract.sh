#!/usr/bin/env bash
set -euo pipefail

sample=${1:?usage: $0 SAMPLE.exe [OUTDIR]}
out=${2:-static_extract}
mkdir -p "$out/resources" "$out/payload"

wrestool -x --raw --type='XIA' --name=2058 --language=1033 \
  -o "$out/resources" "$sample"

dd if="$sample" of="$out/wannacry_payload.zip" bs=1 \
   skip=$((0x100f0)) count=3446325 status=progress

7z l -p'WNcry@2ol7' "$out/wannacry_payload.zip"
7z x -p'WNcry@2ol7' -o"$out/payload" "$out/wannacry_payload.zip"
chmod -R a-x "$out"
find "$out/payload" -type f -print0 | sort -z | xargs -0 sha256sum \
  > "$out/payload_sha256.txt"

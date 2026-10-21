#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="$(node -p "require('$ROOT/package.json').version")"
OUT="$ROOT/governance-assets"
rm -rf "$OUT" && mkdir -p "$OUT"
tar -czf "$OUT/sst-security-control-openclaw-${VERSION}-linux.tar.gz" -C "$ROOT/install" .
tar -czf "$OUT/sst-security-control-openclaw-${VERSION}-macos.tar.gz" -C "$ROOT/install" .
(cd "$ROOT/install" && zip -qr "$OUT/sst-security-control-openclaw-${VERSION}-windows.zip" .)
for file in "$OUT"/*.tar.gz "$OUT"/*.zip; do
  name="$(basename "$file")"
  digest="$(node -e "const fs=require('fs'),crypto=require('crypto'); process.stdout.write(crypto.createHash('sha256').update(fs.readFileSync(process.argv[1])).digest('hex'))" "$file")"
  printf '%s  %s\n' "$digest" "$name" > "$file.sha256"
done

#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Git Bash 下 $ROOT 是 msys 形式（/e/code/...）。tar/zip 认这个形式，**Windows 上
# 的 node 不认**——它只接受 Windows 形式或相对路径，于是
# require('/e/code/.../package.json') 报 MODULE_NOT_FOUND。
#
# 不要用 `pwd -W` 转换来绕：那只是 MSYS coreutils 的扩展，换个 bash 环境就没有，
# 而且同一脚本里 tar 又需要 msys 形式，两套路径来回转迟早再打架。改成让 node
# 一律走**相对路径**：cwd 由 shell 设置，node 从内核拿到的必然是本平台形式，
# Linux/macOS 上行为完全不变。
VERSION="$(cd "$ROOT" && node -p "require('./package.json').version")"

OUT="$ROOT/governance-assets"
rm -rf "$OUT" && mkdir -p "$OUT"
tar -czf "$OUT/sst-security-control-openclaw-${VERSION}-linux.tar.gz" -C "$ROOT/install" .
tar -czf "$OUT/sst-security-control-openclaw-${VERSION}-macos.tar.gz" -C "$ROOT/install" .
(cd "$ROOT/install" && zip -qr "$OUT/sst-security-control-openclaw-${VERSION}-windows.zip" .)

# sha256 同理：输入路径是 $OUT 拼出来的绝对 msys 路径，同样要相对化。
(
  cd "$OUT"
  for file in *.tar.gz *.zip; do
    name="$(basename "$file")"
    digest="$(node -e "const fs=require('fs'),crypto=require('crypto'); process.stdout.write(crypto.createHash('sha256').update(fs.readFileSync(process.argv[1])).digest('hex'))" "$name")"
    printf '%s  %s\n' "$digest" "$name" > "$file.sha256"
  done
)

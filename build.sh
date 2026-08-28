#!/usr/bin/env bash
# silverfox-cleaner 一键清理重建脚本
# 用法: ./build.sh
# 说明: ZCode 终端的 argv[0] 包装器会破坏 rustup 代理,
#       本脚本直接使用工具链真身二进制, 不依赖 rustup 代理.
set -euo pipefail
cd "$(dirname "$0")"

TC="$HOME/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin"
export RUSTUP_TOOLCHAIN="stable-x86_64-unknown-linux-gnu"
export PATH="$TC:$PATH"

echo "[*] cargo clean..."
"$TC/cargo" clean

echo "[*] cargo build --release --target x86_64-pc-windows-gnu..."
"$TC/cargo" build --release --target x86_64-pc-windows-gnu

OUT="target/x86_64-pc-windows-gnu/release/silverfox-cleaner.exe"
if [ ! -f "$OUT" ]; then
    echo "[!] 构建失败: 未找到 $OUT"
    exit 1
fi

cp "$OUT" ../vm-monitor/silverfox-cleaner.exe
echo "[OK] 构建完成:"
ls -lh "$OUT" ../vm-monitor/silverfox-cleaner.exe
sha256sum ../vm-monitor/silverfox-cleaner.exe

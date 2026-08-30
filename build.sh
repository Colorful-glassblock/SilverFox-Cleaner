#!/bin/bash
# SilverFox Cleaner C — 重写版 (NT6+, 默认 UCRT 链接, 目标机需含 api-ms-win-* CRT)
set -e
cd "$(dirname "$0")"
OUT=../vm-monitor
mkdir -p "$OUT"

FLAGS="-O2 -s -Wall -Wno-pointer-sign \
 -D_WIN32_WINNT=0x0601 -DWINVER=0x0601 \
 -finput-charset=UTF-8 -fexec-charset=GBK -mwindows"

# 可选: 存在驱动/证书时 xxd 生成内嵌头 (CI 或手动放置 SFCleanerDrv.sys + SFCleanerCert.cer)
if [ -f SFCleanerDrv.sys ] && [ -f SFCleanerCert.cer ]; then
  echo "[embed] 生成 embed_drv.h + embed_cer.h (驱动+证书将内嵌进 exe)"
  xxd -i -n sfc_drv SFCleanerDrv.sys > embed_drv.h
  xxd -i -n sfc_cer SFCleanerCert.cer > embed_cer.h
else
  echo "[embed] 未找到 SFCleanerDrv.sys/SFCleanerCert.cer, 跳过内嵌 (需外部文件)"
  rm -f embed_drv.h embed_cer.h
fi

echo "[1/2] x86  (UCRT, subsystem 6.1, requireAdministrator manifest)"
i686-w64-mingw32-windres -o /tmp/mf32.o sfcleaner.rc
i686-w64-mingw32-gcc $FLAGS -march=i686 -Wl,--major-subsystem-version,6 -Wl,--minor-subsystem-version,1 \
  -o "$OUT/SFCleaner_x86.exe" sfcleaner.c /tmp/mf32.o -lwintrust

echo "[2/2] x64"
x86_64-w64-mingw32-windres -o /tmp/mf64.o sfcleaner.rc
x86_64-w64-mingw32-gcc $FLAGS -Wl,--major-subsystem-version,6 -Wl,--minor-subsystem-version,1 \
  -o "$OUT/SFCleaner_x64.exe" sfcleaner.c /tmp/mf64.o -lwintrust

echo "--- imports (预期含 api-ms-win-crt-*, NT6+ 目标机需带 UCRT) ---"
i686-w64-mingw32-objdump -p "$OUT/SFCleaner_x86.exe" | grep "DLL Name"
echo "==="
x86_64-w64-mingw32-objdump -p "$OUT/SFCleaner_x64.exe" | grep "DLL Name"
ls -la "$OUT"/SFCleaner_x8*.exe

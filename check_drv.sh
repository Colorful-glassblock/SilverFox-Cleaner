#!/bin/bash
# 驱动本地语法检查 — 推送前必跑 (CI 环境差异仍以 CI 为准, 但能抓 99% 编译错误)
cd "$(dirname "$0")"
CC1=/usr/lib/gcc/x86_64-pc-linux-gnu/16/cc1
[ -x "$CC1" ] || CC1=$(ls /usr/lib/gcc/x86_64-pc-linux-gnu/*/cc1 | tail -1)
"$CC1" -quiet -fsyntax-only -I sfcleaner_drv -Wall -Wno-pointer-sign sfcleaner_drv/Driver.c \
  && echo "[OK] Driver.c 语法检查通过" \
  || echo "[!!] Driver.c 有错误 — 修完再推"

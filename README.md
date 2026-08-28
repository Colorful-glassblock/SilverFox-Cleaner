# SilverFox Cleaner C (NT6+)

银狐检测清除工具 — C 重写版 (x86/x64)。UCRT 直链（目标机需含 api-ms-win-crt-*），requireAdministrator 清单，GUI + CLI，SFQENC1 加密隔离/还原/清空，极端模式（安全模式两阶段蓝屏+自毁），不客气模式（自定义证书+内核驱动装载）。

`sfcleaner_drv/Driver.c` — 不客气模式配套内核驱动源码（WDK 构建 + 测试签名）。

构建: GitHub Actions (mingw-w64 双架构)。

License: 0BSD

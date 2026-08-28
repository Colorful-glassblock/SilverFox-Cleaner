# SilverFox Cleaner v5 (WinUI 3)

银狐木马 (dmo/client Go RAT) 检测清除工具的 WinUI 3 版本，检测引擎自 Rust v4 (`silverfox-cleaner/`) 等价移植。

## 构建环境（需 Windows，Linux 上无法编译）

- Windows 10 19041+ / Windows 11
- .NET 8 SDK（含 Windows Desktop 工作负载）
- Windows App SDK 1.5（NuGet 自动还原）
- VS 2022 需勾选「WinUI 应用程序开发」工作负载；纯 CLI 构建不需要 VS

## 构建

一键出三个变体（Windows 侧执行）：

```bat
build_all.bat
```

产物在 `dist\`：

| 变体 | 路径 | 目标机要求 |
|---|---|---|
| 框架依赖 | `dist\framework-dependent\SFCleaner.exe` | 需装 .NET 8 Desktop Runtime + Windows App SDK Runtime（均为 x64） |
| 全自包含 | `dist\self-contained\SFCleaner.exe` | 无任何依赖，文件夹拷走即用 |
| 单文件 | `dist\single-file\SFCleaner.exe` | 零依赖单 exe；首次运行自解压到 %TEMP%\.net\，启动稍慢，AV 启发式可能更敏感 |
| MSIX 侧载包 | `dist\*.msix` | 先跑 `setup_msix_trust.bat` 导入测试证书并开启侧载 |

MSIX 变体的说明：

- 首次构建时 `build_all.bat` 自动生成自签名测试证书 `SFCleaner_TemporaryKey.pfx`（CN=SFCleaner Research，密码 `sf-cleaner-test`），与 `Package.appxmanifest` 的 Publisher 严格一致
- 等价手动命令：`dotnet publish -c Release -p:Platform=x64 -p:WindowsPackageType=MSIX -p:SelfContained=true`
- **注意**：打包后从开始菜单启动时 app.manifest 的 `requireAdministrator` 可能被忽略（MSIX 启动链不走 UAC 清单），实际清理建议用非打包版；MSIX 主要用于规范化分发/卸载验证。清单已声明 `allowElevation` 能力

手动构建单个变体：

```bat
:: 框架依赖
dotnet publish -c Release -p:Platform=x64 -p:SelfContained=false
:: 全自包含
dotnet publish -c Release -p:Platform=x64 -p:SelfContained=true
```

## 运行

双击 `SFCleaner.exe` — app.manifest 声明 `requireAdministrator`，会弹 UAC 自动提权到管理员。配合 SYSTEM 权限与 takeown/icacls（TrustedInstaller 式）实现受保护文件删除。

## 功能对照（Rust v4 → WinUI3 v5）

| 功能 | 实现 |
|---|---|
| 计划任务扫描 | `C:\Windows\System32\Tasks` 深度 4 遍历，ASCII+UTF16LE 匹配 `EkxZJr`/`SrL.exe`（高）、`cd /d`+`&& start`（结构） |
| 服务扫描 | 注册表 Services 树原生遍历（等价 `reg query /s /f /d`），按模式优先级去重 |
| 进程扫描 | `SrL.exe` 检出 + 全进程互斥体探测 `Global\P_<倒序PID>` |
| ctfmon 内存扫描 | VirtualQueryEx 全区域遍历，搜索 C2 IOC：`4d.skendh.com`、`de.sjd82.org`、`skendh.com`、`sjd82.org`、`dmo/client` |
| 文件扫描 | `C:\Drivers`、%TEMP%、%APPDATA%、%LOCALAPPDATA%、%ProgramData%；名称特征 `ekxzjr/dd9ocged/srl.exe/wdybq.dll/drivers.dat/.0/itqe.*`；>100KB 读头 16 字节查 `STEGR1Xp`/`JELG`/PNG 伪装 |
| 清除 | taskkill / schtasks /delete / sc stop+delete / takeown+icacls 后隔离到 `C:\ProgramData\sf_quarantine\<时间戳>\` |
| 加密隔离 | 隔离文件封装为 `*.qenc`（SFQENC1 头：明文长度+原路径+密文体），密钥流以清理时间戳为种的 xorshift64*——明文 PE 不落盘，残余组件把文件搬回原位也无法执行复活 |
| 应用内还原 | 「隔离区」按钮列出全部 `.qenc`（含原路径），支持还原选中/全部；解密回写原路径后删除容器。与 Rust v4.x 的 `restore` 子命令字节级兼容 |
| 清空隔离区 | 统计条数/体积 → 二次确认 → 整目录抹除，不可恢复 |
| 极端模式 | 两阶段崩溃-清除序列：①提权→写 HKLM Run 自启动+阶段标记→扫描清除→`NtRaiseHardError(0xC0000420)` 蓝屏；②重启后自启动拉起→再次清除→解除自启动→改名自身+`MoveFileEx(DELAY_UNTIL_REBOOT)` 计划自毁→再蓝屏。CLI：`--extreme` 进入、`--extreme-abort` 解除、`--wipe-quarantine` 清空隔离区 |
| ctfmon 处置 | 存在内存注入时先重启 ctfmon 再清其余项 |
| UI | Mica 背景暗色 Fluent，进度环 + 结果列表 + 日志面板 + 统计条 |

相对 Rust 版的差异：

- 清除完成后自动复扫验证（v4 需手动再点扫描）
- 目录遍历不进入 reparse point（junction 环保护，比 Rust 的深度截断更稳）
- 服务扫描改用注册表 API（免起 reg.exe 子进程，更快）

## 注意

- 仅用于本课题研究环境的清除验证；生产环境请用商业 EDR。
- 隔离区路径含 `sf_quarantine`，扫描时会自动跳过自身，避免二次检出。
- **单文件变体（`dist\single-file\`）已知失败**：WinUI3 官方不支持 PublishSingleFile——XAML 的 `resources.pri` 在自解压临时目录中，MRT Core 找不到即启动崩溃。请使用 `dist\self-contained\` 文件夹版或 MSIX。
- **CLI 无头模式**（自启动链路依赖）：`--extreme`（两阶段蓝屏+自毁）、`--extreme-abort`（解除）、`--wipe-quarantine`、`scan`。自启动写入的 `"exe" --extreme` 由此处理。

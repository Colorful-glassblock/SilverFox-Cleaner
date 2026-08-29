/* ============================================================================
 * SFCleanerDrv — 不客气模式内核清理驱动 (WDM, 测试签名)
 * 构建: WDK 环境 (VS2022 + WDK) 新建 "Empty WDM Driver" 工程编译, 或:
 *   cl.exe /c /GS- /Gs- /kernel Driver.c
 *   link.exe /SUBSYSTEM:NATIVE /ENTRY:DriverEntry /DRIVER ntoskrnl.lib bufferoverflowfastfailk.lib Driver.obj
 * 签名: 测试证书 SignTool sign /v /fd sha256 /a SFCleanerDrv.sys → 或 inf2cat+makecert 链
 * 行为 (完全自足, 不读任何注册表配置):
 *        内建检测器每 2s 一轮 × 15 分钟 (SYSTEM_START 加载, 早于恶意软件):
 *        - 进程: 终止 srl.exe / itqe.exe
 *        - 路径: C:\Drivers 整树 (EkxZJr / dd9OCGeD / WJ / drivers.dat*)
 *        - H+S 属性可执行: C:\Users\*\AppData + C:\ProgramData 走树
 *        - 随机名 bat: C:\Windows 根, 内容校验后删
 *        - 计划任务: System32\Tasks 内容引用恶意路径 → 删
 *        - 服务黑名单键: vafdska / MiniFilterDrv / vmservice / ... → ZwDeleteKey
 *        删除梯: 直接删 → delete-pending+FSCTL 清零 → SUPERSEDE → 全系统拔柄 → 强拆映射段
 * 注意: 仅限授权研究环境; 与用户态 SFCleaner 的 --nomore 配套
 * ==========================================================================*/
#include "ntos.h"

#define REG_KEY_PATH  L"\\Registry\\Machine\\SOFTWARE\\SFCleaner"

/* 内核无 CRT: 自备字符串辅助 */
static inline ULONG drv_wcslen(PCWSTR s)
{
    ULONG n = 0;
    while (s && *s++) n++;
    return n;
}

static inline ULONG strnlen_w(const WCHAR *s, ULONG max)
{
    ULONG n = 0;
    while (n < max && s[n]) n++;
    return n;
}

static void drv_reg_close(HANDLE h)
{
    if (h) ZwClose(h);
}

/* 按名找 PID → ZwOpenProcess → ZwTerminateProcess */
static void drv_kill_by_name(PCWSTR name)
{
    ULONG need = 0;
    PSYSTEM_PROCESS_INFORMATION spi = NULL;
    NTSTATUS st;
    UNICODE_STRING probeW;

    RtlInitUnicodeString(&probeW, name);

    st = ZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &need);
    if (st != STATUS_INFO_LENGTH_MISMATCH || need == 0) return;
    spi = (PSYSTEM_PROCESS_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, need, 'fcsD');
    if (!spi) return;
    st = ZwQuerySystemInformation(SystemProcessInformation, spi, need, &need);
    if (NT_SUCCESS(st)) {
        PSYSTEM_PROCESS_INFORMATION cur = spi;
        for (;;) {
            UNICODE_STRING im = cur->ImageName;
            im.Length = (USHORT)(strnlen_w(im.Buffer, im.MaximumLength / 2) * 2);
            if (RtlEqualUnicodeString(&im, &probeW, TRUE)) {
                HANDLE ph = NULL;
                OBJECT_ATTRIBUTES oa;
                CLIENT_ID cid = {0};
                cid.UniqueProcess = ULONG_TO_HANDLE(cur->UniqueProcessId);
                InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
                if (NT_SUCCESS(ZwOpenProcess(&ph, PROCESS_TERMINATE, &oa, &cid))) {
                    ZwTerminateProcess(ph, 0xDEADC0DE);
                    ZwClose(ph);
                }
                /* 一次命中也继续 (同名多个实例) */
            }
            if (cur->NextEntryOffset == 0) break;
            cur = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)cur + cur->NextEntryOffset);
        }
    }
    ExFreePoolWithTag(spi, 'fcsD');
}

static int drv_tail_eqi(PCWSTR name, ULONG len, PCWSTR ext);

/* ---- 句柄强制剥离 (偏移无关版 ForceCloseAllHandles):
   SystemExtendedHandleInformation 全系统枚举 (64 位 Object 地址精确匹配 FILE_OBJECT),
   对持有者进程 ZwDuplicateObject(DUPLICATE_CLOSE_SOURCE) 直接拔柄 — 不触发任何回调 ---- */
static void drv_strip_file_handles(PCWSTR dosNt, ULONG *stripped)
{
    UNICODE_STRING us; OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK iosb;
    HANDLE fh = NULL, ph = NULL, dup = NULL;
    NTSTATUS st;
    PUCHAR buf = NULL;
    ULONG cap = 1 << 20, need = 0, count = 0, i;
    ULONG_PTR targetObj = 0;
    PSFC_HANDLE_EX ex;

    *stripped = 0;

    /* 1) 自开目标文件 → 在全表里以 (pid=4, handle) 定位 FILE_OBJECT 地址 */
    us.Length = (USHORT)(drv_wcslen(dosNt) * sizeof(WCHAR));
    us.MaximumLength = (USHORT)(us.Length + 2); us.Buffer = (PWSTR)dosNt;
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    if (!NT_SUCCESS(ZwCreateFile(&fh, FILE_GENERIC_READ, &oa, &iosb, NULL,
                                 FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                 FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0)))
        return;
    for (;;) {
        buf = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, cap, 'fcsD');
        if (!buf) { ZwClose(fh); return; }
        st = ZwQuerySystemInformation(SystemExtendedHandleInformation, buf, cap, &need);
        if (st == STATUS_INFO_LENGTH_MISMATCH && cap < (32u << 20)) {
            ExFreePoolWithTag(buf, 'fcsD'); buf = NULL;
            cap *= 2;
            continue;
        }
        break;
    }
    if (NT_SUCCESS(st)) {
        count = (ULONG)(((PSFC_HANDLE_INFO)buf)->NumberOfHandles); /* 复用头部 8B: 前 8 字节即数量 */
        ex = (PSFC_HANDLE_EX)(buf + 16);                            /* 头 16B (NumberOfHandles+Reserved) */
        for (i = 0; i < count && targetObj == 0; i++) {
            if (ex[i].UniqueProcessId == 4 && ex[i].Handle == (ULONG_PTR)fh)
                targetObj = ex[i].Object;
        }
        /* 2) 所有指向同一 FILE_OBJECT 的句柄 → 从持有进程拔除 */
        if (targetObj) {
            for (i = 0; i < count; i++) {
                CLIENT_ID cid;
                if (ex[i].Object != targetObj) continue;
                if (ex[i].UniqueProcessId == 4) continue;   /* 自己的已关 */
                cid.UniqueProcess = ULONG_TO_HANDLE(ex[i].UniqueProcessId);
                cid.UniqueThread = NULL;
                InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
                if (!NT_SUCCESS(ZwOpenProcess(&ph, PROCESS_DUP_HANDLE, &oa, &cid))) continue;
                if (NT_SUCCESS(ZwDuplicateObject(ph, (HANDLE)ex[i].Handle, NULL, &dup, 0, 0,
                                                 DUPLICATE_CLOSE_SOURCE))) {
                    if (dup) { ZwClose(dup); dup = NULL; }
                    (*stripped)++;
                }
                ZwClose(ph);
            }
        }
    }
    if (buf) ExFreePoolWithTag(buf, 'fcsD');
    ZwClose(fh);
}

/* 5 级删除梯: 直接删 → delete-on-close → SUPERSEDE → FSCTL 清零 → 拔柄后重试 */
static void drv_delete_file(PCWSTR path)
{
    UNICODE_STRING us; OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK iosb;
    HANDLE h = NULL;
    FILE_DISPOSITION_INFORMATION disp;
    NTSTATUS st;
    USHORT l = (USHORT)(drv_wcslen(path) * sizeof(WCHAR));

    us.Length = l; us.MaximumLength = l + 2; us.Buffer = (PWSTR)path;
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    /* 1) 直接删除 */
    st = ZwDeleteFile(&oa);
    if (NT_SUCCESS(st)) return;

    /* 2) 打开 + delete-pending (最后一个句柄关闭即消失) */
    st = ZwCreateFile(&h, DELETE | FILE_WRITE_DATA | SYNCHRONIZE, &oa, &iosb, NULL,
                      FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
                      FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (NT_SUCCESS(st)) {
        SFC_STANDARD_INFO std;
        SFC_ZERO_DATA_INFO zd;
        /* 4) 内容清零: 就算删不掉, 数据也先踩掉 (.sys 跳过 — 正在运行的镜像清零会当场蓝屏) */
        if (!drv_tail_eqi(path, drv_wcslen(path), L".sys")
            && NT_SUCCESS(ZwQueryInformationFile(h, &iosb, &std, sizeof std, FileStandardInformation))) {
            zd.FileOffset.QuadPart = 0;
            zd.BeyondFinalZero = std.EndOfFile;
            ZwFsControlFile(h, NULL, NULL, NULL, &iosb, FSCTL_SET_ZERO_DATA,
                            &zd, sizeof zd, NULL, 0);
        }
        disp.DeleteFile = TRUE;
        ZwSetInformationFile(h, &iosb, &disp, sizeof disp, FileDispositionInformation);
        ZwClose(h);
        return;
    }

    /* 3) SUPERSEDE 覆盖占位 (同时清掉全部备用数据流) */
    st = ZwCreateFile(&h, DELETE | SYNCHRONIZE, &oa, &iosb, NULL,
                      FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE,
                      FILE_SUPERSEDE, FILE_NON_DIRECTORY_FILE, NULL, 0);
    if (NT_SUCCESS(st)) {
        disp.DeleteFile = TRUE;
        ZwSetInformationFile(h, &iosb, &disp, sizeof disp, FileDispositionInformation);
        ZwClose(h);
        return;
    }

    /* 5) 全系统拔柄 → 强关映射段 (内存映射文件锁源) → 重试 */
    {
        ULONG stripped = 0;
        drv_strip_file_handles(path, &stripped);
        /* MmForceSectionClosed: 拆掉 SectionObjectPointer 上的数据段, 解除 MmMapViewOfFile 锁 */
        {
            HANDLE fh2 = NULL;
            PVOID fobj = NULL;
            st = ZwCreateFile(&fh2, FILE_GENERIC_READ, &oa, &iosb, NULL,
                              FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
            if (NT_SUCCESS(st)) {
                if (NT_SUCCESS(ObReferenceObjectByHandle(fh2, 0, IoFileObjectType, KernelMode,
                                                         &fobj, NULL))) {
                    PSFC_FILE_OBJECT fo = (PSFC_FILE_OBJECT)fobj;
                    PSFC_SEC_OBJ sp = fo->SectionObjectPointer;
                    if (sp && (sp->DataSectionObject || sp->ImageSectionObject))
                        MmForceSectionClosed(sp, TRUE);   /* 有实际映射段才强关 */
                    ObDereferenceObject(fobj);
                }
                ZwClose(fh2);
            }
        }
        if (NT_SUCCESS(ZwDeleteFile(&oa))) return;
        st = ZwCreateFile(&h, DELETE | FILE_WRITE_DATA | SYNCHRONIZE, &oa, &iosb, NULL,
                          FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
                          FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
        if (NT_SUCCESS(st)) {
            SFC_STANDARD_INFO std;
            SFC_ZERO_DATA_INFO zd;
            if (!drv_tail_eqi(path, drv_wcslen(path), L".sys")
                && NT_SUCCESS(ZwQueryInformationFile(h, &iosb, &std, sizeof std, FileStandardInformation))) {
                zd.FileOffset.QuadPart = 0;
                zd.BeyondFinalZero = std.EndOfFile;
                ZwFsControlFile(h, NULL, NULL, NULL, &iosb, FSCTL_SET_ZERO_DATA,
                                &zd, sizeof zd, NULL, 0);
            }
            disp.DeleteFile = TRUE;
            ZwSetInformationFile(h, &iosb, &disp, sizeof disp, FileDispositionInformation);
            ZwClose(h);
        }
    }
}

/* ---- 目录树枚举删除 (EkxZJr/dd9OCGeD/WJ 整树, 不再只删 6 个硬编码文件) ---- */
static void drv_wipe_dir_rec(PCWSTR dirNt, int depth)
{
    UNICODE_STRING us;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    HANDLE h = NULL;
    NTSTATUS st;
    PUCHAR buf;
    BOOLEAN restart = TRUE;
    USHORT l;

    if (depth > 3) return;
    buf = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, 16384, 'fcsD');
    if (!buf) return;
    l = (USHORT)(drv_wcslen(dirNt) * sizeof(WCHAR));
    us.Length = l; us.MaximumLength = (USHORT)(l + 2); us.Buffer = (PWSTR)dirNt;
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    st = ZwCreateFile(&h, FILE_LIST_DIRECTORY | SYNCHRONIZE, &oa, &iosb, NULL,
                      FILE_ATTRIBUTE_NORMAL,
                      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                      FILE_OPEN, FILE_DIRECTORY_FILE, NULL, 0);
    if (NT_SUCCESS(st)) {
        for (;;) {
            PFILE_DIRECTORY_INFORMATION di;
            st = ZwQueryDirectoryFile(h, NULL, NULL, NULL, &iosb, buf, 16384,
                                      FileDirectoryInformation, FALSE, NULL, restart);
            restart = FALSE;
            if (!NT_SUCCESS(st)) break;   /* 含 NO_MORE_FILES */
            di = (PFILE_DIRECTORY_INFORMATION)buf;
            for (;;) {
                ULONG nlen = di->FileNameLength / sizeof(WCHAR);
                ULONG bl = drv_wcslen(dirNt);
                if (nlen && !(nlen == 1 && di->FileName[0] == L'.') &&
                    !(nlen == 2 && di->FileName[0] == L'.' && di->FileName[1] == L'.') &&
                    bl + 1 + nlen < 598) {
                    WCHAR full[600];
                    RtlCopyMemory(full, dirNt, bl * sizeof(WCHAR));
                    full[bl] = L'\\';
                    RtlCopyMemory(full + bl + 1, di->FileName, nlen * sizeof(WCHAR));
                    full[bl + 1 + nlen] = 0;
                    if (di->FileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                        drv_wipe_dir_rec(full, depth + 1);
                    else
                        drv_delete_file(full);
                }
                if (di->NextEntryOffset == 0) break;
                di = (PFILE_DIRECTORY_INFORMATION)((PUCHAR)di + di->NextEntryOffset);
            }
        }
        ZwClose(h);
        drv_delete_file(dirNt);   /* 清空后删目录本体 */
    }
    ExFreePoolWithTag(buf, 'fcsD');
}

static void drv_wipe_subtree(PCWSTR dirPattern)
{
    /* 目录树整删 + 核心文件兜底 (phase1 扫描结果另经 DrvPaths 喂入) */
    (void)dirPattern;
    drv_wipe_dir_rec(L"\\??\\C:\\Drivers\\EkxZJr", 0);
    drv_wipe_dir_rec(L"\\??\\C:\\Drivers\\dd9OCGeD", 0);
    drv_wipe_dir_rec(L"\\??\\C:\\Drivers\\WJ", 0);
    drv_delete_file(L"\\??\\C:\\Drivers\\drivers.dat");
    drv_delete_file(L"\\??\\C:\\Drivers\\drivers.dat.0");
}

/* ---- 内建检测器: 不依赖用户态喂单, 防 DrvPaths 注册表被篡改 ----
   1) C:\Drivers 整树 (本战役落盘根)
   2) AppData/ProgramData 走树: H+S 属性的可执行扩展名文件 → 删 (EkxZJr 插件/白加黑 DLL 特征)
   3) C:\Windows 根随机名 bat: 内容含 EkxZJr/dd9OCGeD/C:\Drivers 才删 (内容校验防误报)
   4) System32\Tasks 单层: 内容引用恶意路径的任务 XML → 删
   5) 服务黑名单键删除 */

#define DRV_DELETE_ACCESS 0x00010000L

static int drv_is_random_wc(PCWSTR name, ULONG len, int minL, int maxL)
{
    ULONG i, dig = 0, up = 0;
    if (len < (ULONG)minL || len > (ULONG)maxL) return 0;
    for (i = 0; i < len; i++) {
        WCHAR c = name[i];
        if (c >= L'0' && c <= L'9') { dig++; continue; }
        if (c >= L'A' && c <= L'Z') { up++; continue; }
        if (c >= L'a' && c <= L'z') continue;
        return 0;
    }
    return (dig >= 2 || up || len >= 8) ? 1 : 0;
}

static int drv_tail_eqi(PCWSTR name, ULONG len, PCWSTR ext)
{
    ULONG el = drv_wcslen(ext);
    ULONG i;
    if (len <= el) return 0;
    for (i = 0; i < el; i++) {
        WCHAR a = name[len - el + i], b = ext[i];
        if (a >= L'A' && a <= L'Z') a += 0x20;
        if (a != b) return 0;
    }
    return 1;
}

static int drv_ext_exec(PCWSTR name, ULONG len)
{
    return drv_tail_eqi(name, len, L".exe") || drv_tail_eqi(name, len, L".dll") ||
           drv_tail_eqi(name, len, L".sys") || drv_tail_eqi(name, len, L".xl") ||
           drv_tail_eqi(name, len, L".xlez");
}

static void drv_join_del(PCWSTR dir, PCWSTR name, ULONG nlen)
{
    WCHAR full[600];
    ULONG bl = drv_wcslen(dir);
    if (bl + 1 + nlen >= 598) return;
    RtlCopyMemory(full, dir, bl * sizeof(WCHAR));
    full[bl] = L'\\';
    RtlCopyMemory(full + bl + 1, name, nlen * sizeof(WCHAR));
    full[bl + 1 + nlen] = 0;
    drv_delete_file(full);
}

/* 读文件前 8KB: ASCII(bat/ansi) 与 UTF-16LE(任务 XML) 双通道子串匹配 */
static int drv_content_has(PCWSTR path, PCWSTR needleW)
{
    UNICODE_STRING us; OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK iosb;
    HANDLE h = NULL; NTSTATUS st;
    UCHAR buf[8192];
    ULONG i, j, nl = drv_wcslen(needleW);
    CHAR na[64];
    WCHAR nw[64];
    int hitA = 0, hitW = 0;
    USHORT l = (USHORT)(drv_wcslen(path) * sizeof(WCHAR));

    if (nl >= 63) return 0;
    for (i = 0; i < nl; i++) { na[i] = (CHAR)needleW[i]; nw[i] = needleW[i]; }
    na[nl] = 0; nw[nl] = 0;

    us.Length = l; us.MaximumLength = (USHORT)(l + 2); us.Buffer = (PWSTR)path;
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    st = ZwCreateFile(&h, FILE_GENERIC_READ, &oa, &iosb, NULL, FILE_ATTRIBUTE_NORMAL,
                      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                      FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (!NT_SUCCESS(st)) return 0;
    st = ZwReadFile(h, NULL, NULL, NULL, &iosb, buf, sizeof buf, NULL, NULL);
    ZwClose(h);
    if (!NT_SUCCESS(st) && st != STATUS_END_OF_FILE) return 0;
    {
        ULONG cb = (ULONG)iosb.Information;
        if (cb >= nl) {
            for (i = 0; i + nl <= cb && !hitA; i++) {
                hitA = 1;
                for (j = 0; j < nl; j++)
                    if (buf[i + j] != (UCHAR)na[j]) { hitA = 0; break; }
            }
            if (cb / 2 >= nl) {
                ULONG wn = cb / 2;
                for (i = 0; i + nl <= wn && !hitW; i++) {
                    hitW = 1;
                    for (j = 0; j < nl; j++)
                        if (buf[i*2] != (UCHAR)nw[j] || buf[i*2+1] != (UCHAR)(nw[j] >> 8)) { hitW = 0; break; }
                }
            }
        }
    }
    return hitA || hitW;
}

/* H+S 可执行文件清扫 (AppData/ProgramData 走树) */
static void drv_scan_hs_dir(PCWSTR dir, int depth)
{
    UNICODE_STRING us; OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK iosb;
    HANDLE h = NULL; NTSTATUS st;
    PUCHAR buf; PFILE_DIRECTORY_INFORMATION di;
    BOOLEAN restart = TRUE;
    USHORT l;

    if (depth > 4) return;
    buf = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, 16384, 'fcsD');
    if (!buf) return;
    l = (USHORT)(drv_wcslen(dir) * sizeof(WCHAR));
    us.Length = l; us.MaximumLength = (USHORT)(l + 2); us.Buffer = (PWSTR)dir;
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    st = ZwCreateFile(&h, FILE_LIST_DIRECTORY | SYNCHRONIZE, &oa, &iosb, NULL,
                      FILE_ATTRIBUTE_NORMAL,
                      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                      FILE_OPEN, FILE_DIRECTORY_FILE, NULL, 0);
    if (NT_SUCCESS(st)) {
        for (;;) {
            st = ZwQueryDirectoryFile(h, NULL, NULL, NULL, &iosb, buf, 16384,
                                      FileDirectoryInformation, FALSE, NULL, restart);
            restart = FALSE;
            if (!NT_SUCCESS(st)) break;
            di = (PFILE_DIRECTORY_INFORMATION)buf;
            for (;;) {
                ULONG nlen = di->FileNameLength / sizeof(WCHAR);
                ULONG bl = drv_wcslen(dir);
                int dot = 0, k;
                for (k = 0; k < (int)nlen; k++) if (di->FileName[k] == L'.') { dot = 1; break; }
                if (nlen && !(nlen == 1 && di->FileName[0] == L'.') &&
                    !(nlen == 2 && di->FileName[0] == L'.' && di->FileName[1] == L'.') &&
                    bl + 1 + nlen < 598 && dot) {
                    WCHAR full[600];
                    if (di->FileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                        if (!(di->FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
                            RtlCopyMemory(full, dir, bl * sizeof(WCHAR));
                            full[bl] = L'\\';
                            RtlCopyMemory(full + bl + 1, di->FileName, nlen * sizeof(WCHAR));
                            full[bl + 1 + nlen] = 0;
                            drv_scan_hs_dir(full, depth + 1);
                        }
                    } else if ((di->FileAttributes & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM))
                               && drv_ext_exec(di->FileName, nlen)) {
                        drv_join_del(dir, di->FileName, nlen);
                    }
                }
                if (di->NextEntryOffset == 0) break;
                di = (PFILE_DIRECTORY_INFORMATION)((PUCHAR)di + di->NextEntryOffset);
            }
        }
        ZwClose(h);
    }
    ExFreePoolWithTag(buf, 'fcsD');
}

/* C:\Users\*\AppData + ProgramData 各根走树 */
static void drv_scan_hs_roots(void)
{
    static const PCWSTR sub[2] = { L"\\AppData\\Local", L"\\AppData\\Roaming" };
    UNICODE_STRING us; OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK iosb;
    HANDLE h = NULL; NTSTATUS st;
    PUCHAR buf; PFILE_DIRECTORY_INFORMATION di;
    BOOLEAN restart = TRUE;

    drv_scan_hs_dir(L"\\??\\C:\\ProgramData", 0);
    buf = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, 16384, 'fcsD');
    if (!buf) return;
    RtlInitUnicodeString(&us, L"\\??\\C:\\Users");
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    st = ZwCreateFile(&h, FILE_LIST_DIRECTORY | SYNCHRONIZE, &oa, &iosb, NULL,
                      FILE_ATTRIBUTE_NORMAL,
                      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                      FILE_OPEN, FILE_DIRECTORY_FILE, NULL, 0);
    if (NT_SUCCESS(st)) {
        for (;;) {
            st = ZwQueryDirectoryFile(h, NULL, NULL, NULL, &iosb, buf, 16384,
                                      FileDirectoryInformation, FALSE, NULL, restart);
            restart = FALSE;
            if (!NT_SUCCESS(st)) break;
            di = (PFILE_DIRECTORY_INFORMATION)buf;
            for (;;) {
                ULONG nlen = di->FileNameLength / sizeof(WCHAR);
                int s;
                if (nlen && !(nlen == 1 && di->FileName[0] == L'.') &&
                    !(nlen == 2 && di->FileName[0] == L'.' && di->FileName[1] == L'.') &&
                    (di->FileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
                    !(di->FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
                    WCHAR user[300];
                    ULONG bl = 13; /* \??\C:\Users\ */
                    RtlCopyMemory(user, L"\\??\\C:\\Users\\", bl * sizeof(WCHAR));
                    RtlCopyMemory(user + bl, di->FileName, nlen * sizeof(WCHAR));
                    bl += nlen; user[bl] = 0;
                    for (s = 0; s < 2; s++) {
                        WCHAR root[400];
                        ULONG sl = drv_wcslen(sub[s]);
                        RtlCopyMemory(root, user, bl * sizeof(WCHAR));
                        RtlCopyMemory(root + bl, sub[s], sl * sizeof(WCHAR));
                        root[bl + sl] = 0;
                        drv_scan_hs_dir(root, 0);
                    }
                }
                if (di->NextEntryOffset == 0) break;
                di = (PFILE_DIRECTORY_INFORMATION)((PUCHAR)di + di->NextEntryOffset);
            }
        }
        ZwClose(h);
    }
    ExFreePoolWithTag(buf, 'fcsD');
}

/* C:\Windows 根随机名 bat: 内容含恶意路径引用才删 (内容校验防误报) */
static void drv_scan_windir_bats(void)
{
    UNICODE_STRING us; OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK iosb;
    HANDLE h = NULL; NTSTATUS st;
    PUCHAR buf; PFILE_DIRECTORY_INFORMATION di;
    BOOLEAN restart = TRUE;

    buf = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, 16384, 'fcsD');
    if (!buf) return;
    RtlInitUnicodeString(&us, L"\\??\\C:\\Windows");
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    st = ZwCreateFile(&h, FILE_LIST_DIRECTORY | SYNCHRONIZE, &oa, &iosb, NULL,
                      FILE_ATTRIBUTE_NORMAL,
                      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                      FILE_OPEN, FILE_DIRECTORY_FILE, NULL, 0);
    if (NT_SUCCESS(st)) {
        for (;;) {
            st = ZwQueryDirectoryFile(h, NULL, NULL, NULL, &iosb, buf, 16384,
                                      FileDirectoryInformation, FALSE, NULL, restart);
            restart = FALSE;
            if (!NT_SUCCESS(st)) break;
            di = (PFILE_DIRECTORY_INFORMATION)buf;
            for (;;) {
                ULONG nlen = di->FileNameLength / sizeof(WCHAR);
                if (nlen && !(nlen == 1 && di->FileName[0] == L'.') &&
                    !(nlen == 2 && di->FileName[0] == L'.' && di->FileName[1] == L'.') &&
                    !(di->FileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
                    drv_tail_eqi(di->FileName, nlen, L".bat") &&
                    drv_is_random_wc(di->FileName, nlen - 4, 6, 16)) {
                    WCHAR full[600];
                    ULONG bl = 14; /* \??\C:\Windows */
                    RtlCopyMemory(full, L"\\??\\C:\\Windows", bl * sizeof(WCHAR));
                    full[bl] = L'\\';
                    RtlCopyMemory(full + bl + 1, di->FileName, nlen * sizeof(WCHAR));
                    full[bl + 1 + nlen] = 0;
                    if (drv_content_has(full, L"EkxZJr") ||
                        drv_content_has(full, L"dd9OCGeD") ||
                        drv_content_has(full, L"C:\\Drivers") ||
                        drv_content_has(full, L"AppData\\Local\\exter"))
                        drv_delete_file(full);
                }
                if (di->NextEntryOffset == 0) break;
                di = (PFILE_DIRECTORY_INFORMATION)((PUCHAR)di + di->NextEntryOffset);
            }
        }
        ZwClose(h);
    }
    ExFreePoolWithTag(buf, 'fcsD');
}

/* System32\Tasks 单层: 内容引用恶意路径的任务 XML → 删 */
static void drv_scan_tasks(void)
{
    UNICODE_STRING us; OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK iosb;
    HANDLE h = NULL; NTSTATUS st;
    PUCHAR buf; PFILE_DIRECTORY_INFORMATION di;
    BOOLEAN restart = TRUE;

    buf = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, 16384, 'fcsD');
    if (!buf) return;
    RtlInitUnicodeString(&us, L"\\??\\C:\\Windows\\System32\\Tasks");
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    st = ZwCreateFile(&h, FILE_LIST_DIRECTORY | SYNCHRONIZE, &oa, &iosb, NULL,
                      FILE_ATTRIBUTE_NORMAL,
                      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                      FILE_OPEN, FILE_DIRECTORY_FILE, NULL, 0);
    if (NT_SUCCESS(st)) {
        for (;;) {
            st = ZwQueryDirectoryFile(h, NULL, NULL, NULL, &iosb, buf, 16384,
                                      FileDirectoryInformation, FALSE, NULL, restart);
            restart = FALSE;
            if (!NT_SUCCESS(st)) break;
            di = (PFILE_DIRECTORY_INFORMATION)buf;
            for (;;) {
                ULONG nlen = di->FileNameLength / sizeof(WCHAR);
                if (nlen && !(nlen == 1 && di->FileName[0] == L'.') &&
                    !(nlen == 2 && di->FileName[0] == L'.' && di->FileName[1] == L'.') &&
                    !(di->FileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    WCHAR full[600];
                    ULONG bl = 29; /* \??\C:\Windows\System32\Tasks */
                    RtlCopyMemory(full, L"\\??\\C:\\Windows\\System32\\Tasks", bl * sizeof(WCHAR));
                    full[bl] = L'\\';
                    RtlCopyMemory(full + bl + 1, di->FileName, nlen * sizeof(WCHAR));
                    full[bl + 1 + nlen] = 0;
                    if (drv_content_has(full, L"EkxZJr") ||
                        drv_content_has(full, L"dd9OCGeD") ||
                        drv_content_has(full, L"C:\\Drivers"))
                        drv_delete_file(full);
                }
                if (di->NextEntryOffset == 0) break;
                di = (PFILE_DIRECTORY_INFORMATION)((PUCHAR)di + di->NextEntryOffset);
            }
        }
        ZwClose(h);
    }
    ExFreePoolWithTag(buf, 'fcsD');
}

/* 服务黑名单键删除 (存在即删, 有子键则失败忽略) */
/* 递归删键: 先清子键 (Parameters/Security 常驻) 再删本体 */
static void drv_del_key_path(WCHAR *full, ULONG len)
{
    UNICODE_STRING us; OBJECT_ATTRIBUTES oa; HANDLE h = NULL; NTSTATUS st;
    PUCHAR buf; PKEY_FULL_INFORMATION fi;
    us.Length = (USHORT)(len * sizeof(WCHAR));
    us.MaximumLength = (USHORT)(us.Length + 2); us.Buffer = full;
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    st = ZwOpenKey(&h, KEY_ENUMERATE_SUBKEYS | DRV_DELETE_ACCESS, &oa);
    if (!NT_SUCCESS(st)) return;
    buf = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, 4096, 'fcsD');
    if (buf) {
        ULONG need = 0;
        if (NT_SUCCESS(ZwQueryKey(h, KeyFullInformation, buf, 4096, &need))) {
            fi = (PKEY_FULL_INFORMATION)buf;
            if (fi->SubKeys > 0 && fi->SubKeys < 32) {
                ULONG bl = len, n, k;
                WCHAR names[32][64];
                ULONG got = 0;
                for (n = 0; n < fi->SubKeys && got < 32; n++) {
                    PKEY_BASIC_INFORMATION bi = (PKEY_BASIC_INFORMATION)buf;
                    ULONG nl2;
                    if (!NT_SUCCESS(ZwEnumerateKey(h, n, KeyBasicInformation, buf, 4096, &need)))
                        break;
                    nl2 = bi->NameLength / sizeof(WCHAR);
                    if (nl2 >= 63) continue;
                    k = 0;
                    while (k < nl2) { names[got][k] = bi->Name[k]; k++; }
                    names[got][k] = 0;
                    got++;
                    (void)bl; (void)nl2;
                }
                for (n = 0; n < got; n++) {
                    ULONG cl = drv_wcslen(names[n]);
                    ULONG tl = len;
                    WCHAR child[220];
                    if (tl + 1 + cl >= 218) continue;
                    RtlCopyMemory(child, full, tl * sizeof(WCHAR));
                    child[tl] = L'\\';
                    RtlCopyMemory(child + tl + 1, names[n], cl * sizeof(WCHAR));
                    child[tl + 1 + cl] = 0;
                    drv_del_key_path(child, tl + 1 + cl);
                }
                (void)bl;
            }
        }
        ExFreePoolWithTag(buf, 'fcsD');
        /* 重新以 DELETE 打开删本体 (枚举句柄模式删除亦可用, 直接复用 h) */
        if (!NT_SUCCESS(ZwDeleteKey(h))) {
            /* 子键残留 (删除被占用等) — 放弃本轮, 下轮清扫重试 */
        }
        ZwClose(h);
        return;
    }
    ZwClose(h);
    (void)st;
}

static void drv_del_service_key(PCWSTR name)
{
    WCHAR full[200];
    ULONG bl = 52; /* \Registry\Machine\SYSTEM\CurrentControlSet\Services\ */
    ULONG nl = drv_wcslen(name);
    RtlCopyMemory(full, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\", bl * sizeof(WCHAR));
    RtlCopyMemory(full + bl, name, nl * sizeof(WCHAR));
    full[bl + nl] = 0;
    drv_del_key_path(full, bl + nl);
}

static void drv_builtin_scan(void)
{
    static const PCWSTR blkl[4] = { L"vafdska", L"MiniFilterDrv", L"vmservice",
                                    L"MicrosoftSoftware2ShadowCop4yProvider" };
    int i;
    drv_wipe_dir_rec(L"\\??\\C:\\Drivers", 0);
    drv_scan_hs_roots();
    drv_scan_windir_bats();
    drv_scan_tasks();
    for (i = 0; i < 4; i++) drv_del_service_key(blkl[i]);
}

/* ---- 清扫线程: 无头自动版 —— 先杀进程再删文件, 2s 一轮 × 15 分钟, 卸载即停 ---- */
static KEVENT g_StopEvent;
static HANDLE g_Thread = NULL;

static void drv_sweep_once(void)
{
    /* 纯内建: 不读任何注册表配置 (DrvPaths 通道已移除 — 恶意软件可反向利用
       该通道指鹿为马让驱动删系统文件), 目标全部由内建检测器现场判定 */
    drv_kill_by_name(L"srl.exe");
    drv_kill_by_name(L"itqe.exe");
    drv_wipe_subtree(NULL);
    drv_builtin_scan();
}

static VOID NTAPI SfcThreadStart(PVOID ctx)
{
    int passes = 0;
    LARGE_INTEGER iv;
    (void)ctx;
    iv.QuadPart = -50000000LL;               /* 首轮前 5s: 等 smss 阶段完全就绪 */
    KeWaitForSingleObject(&g_StopEvent, Executive, KernelMode, FALSE, &iv);
    for (;;) {
        drv_sweep_once();
        if (++passes >= 450) break;          /* 2s × 450 ≈ 15 分钟 */
        iv.QuadPart = -20000000LL;           /* 相对 2s (100ns 单位) */
        if (KeWaitForSingleObject(&g_StopEvent, Executive, KernelMode, FALSE, &iv)
            != STATUS_TIMEOUT)
            break;                            /* 卸载信号 */
    }
    PsTerminateSystemThread(STATUS_SUCCESS);
}

/* ---- 内核无 CRT: 编译器按名引用的内存例程自实现 ---- */
void *memcpy(void *dst, const void *src, size_t n)
{
    char *d = (char *)dst;
    const char *s = (const char *)src;
    while (n--) *d++ = *s++;
    return dst;
}

void *memset(void *dst, int c, size_t n)
{
    unsigned char *d = (unsigned char *)dst;
    while (n--) *d++ = (unsigned char)c;
    return dst;
}

DRIVER_UNLOAD DrvUnload;

VOID DrvUnload(PDRIVER_OBJECT d)
{
    LARGE_INTEGER iv;
    PVOID tobj = NULL;
    UNREFERENCED_PARAMETER(d);
    KeSetEvent(&g_StopEvent, 0, FALSE);
    {
        HANDLE th = g_Thread;
        g_Thread = NULL;
        g_Thread = th;   /* 单写者 (仅 DriverEntry/Unload), 保持原样; 卸载重入由 IoManager 串行化 */
    }
    if (g_Thread) {
        /* ★ PsCreateSystemThread 返回的是句柄; KeWaitForSingleObject 要对象指针.
           直接把句柄值当指针解引用 = IRQL_NOT_LESS_OR_EQUAL (登录期 phase2 停驱动的 BSOD 根因) */
        if (NT_SUCCESS(ObReferenceObjectByHandle(g_Thread, SYNCHRONIZE, NULL, KernelMode, &tobj, NULL))) {
            iv.QuadPart = -100000000LL;   /* 最多等 10s 让清扫线程退出 */
            KeWaitForSingleObject(tobj, Executive, KernelMode, FALSE, &iv);
            ObDereferenceObject(tobj);
        }
        ZwClose(g_Thread);
        g_Thread = NULL;
    }
    DbgPrint("[SFCleanerDrv] unloaded\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT drv, PUNICODE_STRING regPath)
{
    HANDLE th = NULL;
    OBJECT_ATTRIBUTES oa;
    PCLIENT_ID cid = NULL;

    UNREFERENCED_PARAMETER(regPath);
    drv->DriverUnload = DrvUnload;
    KeInitializeEvent(&g_StopEvent, NotificationEvent, FALSE);
    DbgPrint("[SFCleanerDrv] no-mercy engaged (boot sweeper)\n");

    /* SYSTEM_START 加载: 此刻早于恶意软件 auto 服务, 清扫从启动即开始.
       扫描结果由用户态 phase1 写入 DrvPaths/DrvProcs, 每轮照单执行 */
    InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    if (NT_SUCCESS(PsCreateSystemThread(&th, THREAD_ALL_ACCESS, &oa, NULL, cid,
                                        SfcThreadStart, NULL)))
        g_Thread = th;

    return STATUS_SUCCESS;
}
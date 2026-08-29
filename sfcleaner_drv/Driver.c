/* ============================================================================
 * SFCleanerDrv — 不客气模式内核清理驱动 (WDM, 测试签名)
 * 构建: WDK 环境 (VS2022 + WDK) 新建 "Empty WDM Driver" 工程编译, 或:
 *   cl.exe /c /GS- /Gs- /kernel Driver.c
 *   link.exe /SUBSYSTEM:NATIVE /ENTRY:DriverEntry /DRIVER ntoskrnl.lib bufferoverflowfastfailk.lib Driver.obj
 * 签名: 测试证书 SignTool sign /v /fd sha256 /a SFCleanerDrv.sys → 或 inf2cat+makecert 链
 * 行为: 读取 HKLM\SOFTWARE\SFCleaner\DrvTargets
 *        - DrvPaths (MULTI_SZ): 逐个强删 (忽略锁定句柄, 驱逐+删除)
 *        - DrvProcs (MULTI_SZ): 按进程名枚举并 ZwTerminateProcess
 *        无配置时按内置银狐特征清理:
 *        - 路径: C:\Drivers\* (EkxZJr / dd9OCGeD / itqe.* / *.xlez / drivers.dat*)
 *        - 进程: srl.exe
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

/* 读 MULTI_SZ: 返回 PAGED 池缓冲, 调用方 ExFreePoolWithTag */
static PWSTR drv_reg_read_msz(PCWSTR valueName, ULONG *cbOut)
{
    UNICODE_STRING path;
    OBJECT_ATTRIBUTES oa;
    HANDLE hKey = NULL;
    PKEY_VALUE_PARTIAL_INFORMATION pi = NULL;
    PWSTR out = NULL;
    ULONG len = 0, need = 256;
    NTSTATUS st;

    RtlInitUnicodeString(&path, REG_KEY_PATH);
    InitializeObjectAttributes(&oa, &path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    st = ZwOpenKey(&hKey, KEY_READ, &oa);
    if (!NT_SUCCESS(st)) return NULL;

    st = STATUS_BUFFER_TOO_SMALL;
    while (st == STATUS_BUFFER_TOO_SMALL || st == STATUS_BUFFER_OVERFLOW) {
        if (pi) ExFreePoolWithTag(pi, 'fcsD');
        pi = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(PagedPool, need, 'fcsD');
        if (!pi) break;
        RtlInitUnicodeString(&path, (PWSTR)valueName);
        st = ZwQueryValueKey(hKey, &path, KeyValuePartialInformation, pi, need, &need);
        if (NT_SUCCESS(st) && pi->Type == REG_MULTI_SZ && pi->DataLength > 4) {
            out = (PWSTR)ExAllocatePoolWithTag(PagedPool, pi->DataLength, 'fcsD');
            if (out) {
                RtlCopyMemory(out, pi->Data, pi->DataLength);
                *cbOut = pi->DataLength;
            }
            break;
        }
        if (st != STATUS_BUFFER_TOO_SMALL && st != STATUS_BUFFER_OVERFLOW) break;
    }
    if (pi) ExFreePoolWithTag(pi, 'fcsD');
    drv_reg_close(hKey);
    return out;
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

    /* 2) 打开 + FILE_DELETE_ON_CLOSE */
    st = ZwCreateFile(&h, DELETE | SYNCHRONIZE, &oa, &iosb, NULL,
                      FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
                      FILE_OPEN, FILE_NON_DIRECTORY_FILE, NULL, 0);
    if (NT_SUCCESS(st)) { ZwClose(h); ZwDeleteFile(&oa); return; }

    /* 3) SUPERSEDE 覆盖占位 */
    st = ZwCreateFile(&h, DELETE | SYNCHRONIZE, &oa, &iosb, NULL,
                      FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE,
                      FILE_SUPERSEDE, FILE_NON_DIRECTORY_FILE, NULL, 0);
    if (NT_SUCCESS(st)) {
        disp.DeleteFile = TRUE;
        ZwSetInformationFile(h, &iosb, &disp, sizeof disp, FileDispositionInformation);
        ZwClose(h);
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
                    bl < 550) {
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

/* ---- 清扫线程: 无头自动版 —— 先杀进程再删文件, 2s 一轮 × 15 分钟, 卸载即停 ---- */
static KEVENT g_StopEvent;
static HANDLE g_Thread = NULL;

static void drv_sweep_once(void)
{
    PWSTR paths, procs, p;
    ULONG cb;

    procs = drv_reg_read_msz(L"DrvProcs", &cb);
    if (procs) {
        for (p = procs; *p; p += drv_wcslen(p) + 1) drv_kill_by_name(p);
        ExFreePoolWithTag(procs, 'fcsD');
    }
    drv_kill_by_name(L"srl.exe");
    drv_kill_by_name(L"itqe.exe");

    paths = drv_reg_read_msz(L"DrvPaths", &cb);
    if (paths) {
        for (p = paths; *p; p += drv_wcslen(p) + 1) drv_delete_file(p);
        ExFreePoolWithTag(paths, 'fcsD');
    }
    drv_wipe_subtree(NULL);
}

static VOID NTAPI SfcThreadStart(PVOID ctx)
{
    int passes = 0;
    LARGE_INTEGER iv;
    (void)ctx;
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
    UNREFERENCED_PARAMETER(d);
    KeSetEvent(&g_StopEvent, 0, FALSE);
    if (g_Thread) {
        iv.QuadPart = -100000000LL;   /* 最多等 10s 让清扫线程退出 */
        KeWaitForSingleObject(g_Thread, Executive, KernelMode, FALSE, &iv);
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
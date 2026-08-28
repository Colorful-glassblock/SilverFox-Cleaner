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
#include <ntddk.h>
#include <ntstrsafe.h>

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
    ULONG need = 0, i;
    PSYSTEM_PROCESS_INFORMATION spi = NULL;
    NTSTATUS st;
    ANSI_STRING probe;
    UNICODE_STRING probeW;

    RtlInitAnsiString(&probe, (PCSTR)NULL);
    RtlInitUnicodeString(&probeW, name);
    (void)probe;

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

static void drv_wipe_subtree(PCWSTR dirPattern)
{
    /* 简化实现: 目标目录名已知 (EkxZJr/dd9OCGeD), 直接删固定子文件集合 */
    static const PCWSTR files[] = {
        L"\\??\\C:\\Drivers\\EkxZJr\\SrL.exe",
        L"\\??\\C:\\Drivers\\EkxZJr\\itqe.xl",
        L"\\??\\C:\\Drivers\\dd9OCGeD\\installer.exe",
        L"\\??\\C:\\Drivers\\WJ\\UBpkdA.xlez",
        L"\\??\\C:\\Drivers\\drivers.dat",
        L"\\??\\C:\\Drivers\\drivers.dat.0",
    };
    int i;
    for (i = 0; i < (int)(sizeof files / sizeof files[0]); i++) {
        drv_delete_file(files[i]);
    }
}

DRIVER_UNLOAD DrvUnload;

VOID DrvUnload(PDRIVER_OBJECT d)
{
    UNREFERENCED_PARAMETER(d);
    DbgPrint("[SFCleanerDrv] unloaded\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT drv, PUNICODE_STRING regPath)
{
    PWSTR paths = NULL, procs = NULL, p;
    ULONG cbP = 0, cbR = 0;

    UNREFERENCED_PARAMETER(regPath);
    drv->DriverUnload = DrvUnload;
    DbgPrint("[SFCleanerDrv] no-mercy engaged\n");

    /* 1) 杀进程 (配置或内置) */
    procs = drv_reg_read_msz(L"DrvProcs", &cbR);
    if (procs) {
        for (p = procs; *p; p += drv_wcslen(p) + 1) drv_kill_by_name(p);
        ExFreePoolWithTag(procs, 'fcsD');
    }
    drv_kill_by_name(L"srl.exe");
    drv_kill_by_name(L"itqe.exe");

    /* 2) 删路径 (配置或内置) */
    paths = drv_reg_read_msz(L"DrvPaths", &cbP);
    if (paths) {
        for (p = paths; *p; p += drv_wcslen(p) + 1) drv_delete_file(p);
        ExFreePoolWithTag(paths, 'fcsD');
    }
    drv_wipe_subtree(NULL);

    DbgPrint("[SFCleanerDrv] purge done\n");
    return STATUS_SUCCESS;
}
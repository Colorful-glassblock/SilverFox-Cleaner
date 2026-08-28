/* ntos.h — SFCleanerDrv 最小内核头 (x64)
 * 替代 WDK 的 ntddk.h, 仅声明本驱动所需类型/常量/原型, 使纯 MSVC (无 WDK) 可编译 */
#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef LONG    NTSTATUS;
typedef LONG    KPRIORITY;
typedef ULONG   ACCESS_MASK;
typedef ULONG   POOL_TYPE;
typedef ULONG   SYSTEM_INFORMATION_CLASS;
typedef ULONG   KEY_VALUE_INFORMATION_CLASS;
typedef ULONG   FILE_INFORMATION_CLASS;

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

/* ---- UNICODE_STRING / OBJECT_ATTRIBUTES ---- */
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
typedef const UNICODE_STRING *PCUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

#define InitializeObjectAttributes(p, n, a, r, s) \
    do { (p)->Length = sizeof(OBJECT_ATTRIBUTES); (p)->RootDirectory = (r); \
         (p)->Attributes = (a); (p)->ObjectName = (n); \
         (p)->SecurityDescriptor = (s); (p)->SecurityQualityOfService = NULL; } while (0)

#define OBJ_CASE_INSENSITIVE 0x00000040
#define OBJ_KERNEL_HANDLE    0x00000200

/* ---- IO / CLIENT ---- */
typedef struct _IO_STATUS_BLOCK {
    union { NTSTATUS Status; PVOID Pointer; };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

#define ULONG_TO_HANDLE(x) ((HANDLE)(ULONG_PTR)(x))

/* ---- 访问权限/文件标志 ---- */
#ifndef DELETE
#define DELETE 0x00010000
#endif
#ifndef SYNCHRONIZE
#define SYNCHRONIZE 0x00100000
#endif
#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE 0x00000001
#endif
#ifndef KEY_READ
#define KEY_READ 0x00020019
#endif
#ifndef FILE_SHARE_READ
#define FILE_SHARE_READ 0x00000001
#endif
#ifndef FILE_SHARE_WRITE
#define FILE_SHARE_WRITE 0x00000002
#endif
#ifndef FILE_SHARE_DELETE
#define FILE_SHARE_DELETE 0x00000004
#endif
#ifndef FILE_OPEN
#define FILE_OPEN 0x00000001
#endif
#ifndef FILE_SUPERSEDE
#define FILE_SUPERSEDE 0x00000000
#endif
#ifndef FILE_NON_DIRECTORY_FILE
#define FILE_NON_DIRECTORY_FILE 0x00000040
#endif
#ifndef FILE_ATTRIBUTE_NORMAL
#define FILE_ATTRIBUTE_NORMAL 0x00000080
#endif
#define FileDispositionInformation 13
typedef struct _FILE_DISPOSITION_INFORMATION {
    BOOLEAN DeleteFile;
} FILE_DISPOSITION_INFORMATION, *PFILE_DISPOSITION_INFORMATION;

#define KeyValuePartialInformation 7
#ifndef REG_MULTI_SZ
#define REG_MULTI_SZ 7
#endif
#ifndef REG_SZ
#define REG_SZ 1
#endif
typedef struct _KEY_VALUE_PARTIAL_INFORMATION {
    ULONG TitleIndex;
    ULONG Type;
    ULONG DataLength;
    UCHAR Data[1];
} KEY_VALUE_PARTIAL_INFORMATION, *PKEY_VALUE_PARTIAL_INFORMATION;

/* ---- 进程快照 (SYSTEM_PROCESS_INFORMATION, x64 布局) ---- */
#define SystemProcessInformation 5
typedef struct _SFC_PROC_INFO {
    ULONG         NextEntryOffset;
    ULONG         NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG         HardFaultCount;
    ULONG         NumberOfThreadsHighWatermark;
    ULONGLONG     CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY      BasePriority;
    HANDLE         UniqueProcessId;
} SFC_PROC_INFO;
typedef SFC_PROC_INFO SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

/* ---- 内存池 ---- */
#define NonPagedPool 0
#define PagedPool    1

/* ---- 状态码 ---- */
#define STATUS_SUCCESS             ((NTSTATUS)0x00000000L)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#define STATUS_BUFFER_TOO_SMALL    ((NTSTATUS)0xC0000023L)
#define STATUS_BUFFER_OVERFLOW     ((NTSTATUS)0x80000005L)

/* ---- 驱动对象 ---- */
typedef struct _DRIVER_OBJECT {
    SHORT  Type;
    SHORT  Size;
    PVOID  DeviceObject;
    ULONG  Flags;
    PVOID  DriverStart;
    ULONG  DriverSize;
    PVOID  DriverSection;
    PVOID  DriverExtension;
    UNICODE_STRING DriverName;
    PVOID  HardwareDatabase;
    PVOID  FastIoDispatch;
    PVOID  DriverInit;
    PVOID  DriverStartIo;
    PVOID  DriverUnload;
} DRIVER_OBJECT, *PDRIVER_OBJECT;
typedef VOID (NTAPI DRIVER_UNLOAD)(PDRIVER_OBJECT DriverObject);
typedef DRIVER_UNLOAD *PDRIVER_UNLOAD;

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);

/* ---- 内核导出原型 (x64, 与 ntoskrnl.def 对应) ---- */
#ifndef NTSYSAPI
#define NTSYSAPI __declspec(dllimport)
#endif
#define NTAPI    __stdcall

NTSYSAPI VOID  NTAPI RtlInitUnicodeString(PUNICODE_STRING, PCWSTR);
NTSYSAPI BOOLEAN NTAPI RtlEqualUnicodeString(PCUNICODE_STRING, PCUNICODE_STRING, BOOLEAN);
NTSYSAPI PVOID NTAPI ExAllocatePoolWithTag(POOL_TYPE, SIZE_T, ULONG);
NTSYSAPI VOID  NTAPI ExFreePoolWithTag(PVOID, ULONG);
NTSYSAPI ULONG __cdecl DbgPrint(PCSTR, ...);

NTSYSAPI NTSTATUS NTAPI ZwClose(HANDLE);
NTSYSAPI NTSTATUS NTAPI ZwOpenKey(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
NTSYSAPI NTSTATUS NTAPI ZwQueryValueKey(HANDLE, PUNICODE_STRING, KEY_VALUE_INFORMATION_CLASS,
                                       PVOID, ULONG, PULONG);
NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
NTSYSAPI NTSTATUS NTAPI ZwOpenProcess(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
NTSYSAPI NTSTATUS NTAPI ZwTerminateProcess(HANDLE, NTSTATUS);
NTSYSAPI NTSTATUS NTAPI ZwDeleteFile(POBJECT_ATTRIBUTES);
NTSYSAPI NTSTATUS NTAPI ZwCreateFile(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
                                     PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
NTSYSAPI NTSTATUS NTAPI ZwSetInformationFile(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG,
                                            FILE_INFORMATION_CLASS);

/* 内核无 CRT: winnt.h 若没给 RtlCopyMemory 就自造循环版 */
#ifndef RtlCopyMemory
#define RtlCopyMemory(Dst, Src, Len) \
    do { SIZE_T _i; for (_i = 0; _i < (SIZE_T)(Len); _i++) ((char *)(Dst))[_i] = ((const char *)(Src))[_i]; } while (0)
#endif

#ifdef __cplusplus
}
#endif
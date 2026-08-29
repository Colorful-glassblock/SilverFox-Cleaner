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
#ifndef FILE_ATTRIBUTE_HIDDEN
#define FILE_ATTRIBUTE_HIDDEN   0x00000002
#endif
#ifndef FILE_ATTRIBUTE_SYSTEM
#define FILE_ATTRIBUTE_SYSTEM   0x00000004
#endif
#ifndef FILE_ATTRIBUTE_REPARSE_POINT
#define FILE_ATTRIBUTE_REPARSE_POINT 0x00000400
#endif
#define FileDirectoryInformation   1
#define FileDispositionInformation 13
typedef struct _FILE_DIRECTORY_INFORMATION {
    ULONG         NextEntryOffset;
    ULONG         FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG         FileAttributes;
    ULONG         FileNameLength;
    WCHAR         FileName[1];
} FILE_DIRECTORY_INFORMATION, *PFILE_DIRECTORY_INFORMATION;
typedef struct _FILE_DISPOSITION_INFORMATION {
    BOOLEAN DeleteFile;
} FILE_DISPOSITION_INFORMATION, *PFILE_DISPOSITION_INFORMATION;

#define KeyFullInformation        0
#define KeyBasicInformation       5
#define KEY_ENUMERATE_SUBKEYS     0x0008
typedef struct _KEY_FULL_INFORMATION {
    LARGE_INTEGER LastWriteTime;
    ULONG         TitleIndex;
    ULONG         ClassOffset;
    ULONG         ClassLength;
    ULONG         MaxClassLength;
    ULONG         SubKeys;
    ULONG         MaxNameLen;
    ULONG         MaxValueNameLen;
    ULONG         MaxValueDataLen;
} KEY_FULL_INFORMATION, *PKEY_FULL_INFORMATION;
typedef struct _KEY_BASIC_INFORMATION {
    LARGE_INTEGER LastWriteTime;
    ULONG         TitleIndex;
    ULONG         NameLength;
    WCHAR         Name[1];
} KEY_BASIC_INFORMATION, *PKEY_BASIC_INFORMATION;
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
#ifndef STATUS_TIMEOUT
#define STATUS_TIMEOUT             ((NTSTATUS)0x00000102L)
#endif
#ifndef STATUS_NO_MORE_FILES
#define STATUS_NO_MORE_FILES       ((NTSTATUS)0x80000006L)
#endif
#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif
#define SystemHandleInformation    16
#define ObjectNameInformation      1
#define FileStandardInformation    5
#define DUPLICATE_CLOSE_SOURCE     0x00000001
#define DUPLICATE_SAME_ACCESS      0x00000002
#ifndef THREAD_TERMINATE
#define THREAD_TERMINATE           0x0001L
#endif
#ifndef FSCTL_SET_ZERO_DATA
#define FSCTL_SET_ZERO_DATA        0x000980C8L   /* CTL_CODE(0x09, 50, BUFFERED, WRITE_DATA) */
#endif
typedef struct _SFC_HANDLE_INFO {          /* SystemHandleInformation(16), 12B 逐条 */
    ULONG NumberOfHandles;                 /* 头部 */
    UCHAR Raw[1];
} SFC_HANDLE_INFO, *PSFC_HANDLE_INFO;
typedef struct _SFC_ZERO_DATA_INFO {
    LARGE_INTEGER FileOffset;
    LARGE_INTEGER BeyondFinalZero;
} SFC_ZERO_DATA_INFO, *PSFC_ZERO_DATA_INFO;
typedef struct _SFC_STANDARD_INFO {
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG         NumberOfLinks;
    BOOLEAN       DeletePending;
    BOOLEAN       Directory;
} SFC_STANDARD_INFO, *PSFC_STANDARD_INFO;
#ifndef FILE_GENERIC_READ
#define FILE_GENERIC_READ       0x80000000L /* GENERIC_READ */
#endif
#ifndef FILE_SYNCHRONOUS_IO_NONALERT
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#endif
#ifndef STATUS_END_OF_FILE
#define STATUS_END_OF_FILE      ((NTSTATUS)0xC0000011L)
#endif
#ifndef FILE_LIST_DIRECTORY
#define FILE_LIST_DIRECTORY        0x00000001
#endif
#ifndef FILE_DIRECTORY_FILE
#define FILE_DIRECTORY_FILE        0x00000002
#endif
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
NTSYSAPI NTSTATUS NTAPI ZwDeleteKey(HANDLE);
NTSYSAPI NTSTATUS NTAPI ZwQueryKey(HANDLE, ULONG, PVOID, ULONG, PULONG);
NTSYSAPI NTSTATUS NTAPI ZwEnumerateKey(HANDLE, ULONG, ULONG, PVOID, ULONG, PULONG);
NTSYSAPI NTSTATUS NTAPI ZwReadFile(HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK,
                    PVOID, ULONG, PLARGE_INTEGER, PULONG);
NTSYSAPI NTSTATUS NTAPI ZwDuplicateObject(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG);
NTSYSAPI NTSTATUS NTAPI ZwQueryObject(HANDLE, ULONG, PVOID, ULONG, PULONG);
NTSYSAPI NTSTATUS NTAPI ZwOpenThread(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
NTSYSAPI NTSTATUS NTAPI ZwTerminateThread(HANDLE, NTSTATUS);
NTSYSAPI NTSTATUS NTAPI ZwFsControlFile(HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK,
                                        ULONG, PVOID, ULONG, PVOID, ULONG);
NTSYSAPI NTSTATUS NTAPI ZwQueryInformationFile(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, ULONG);
NTSYSAPI NTSTATUS NTAPI ZwDuplicateObjectEx(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG);
#define SystemExtendedHandleInformation 64
#ifndef PROCESS_DUP_HANDLE
#define PROCESS_DUP_HANDLE              0x0040L
#endif
typedef struct _SFC_SEC_OBJ { PVOID DataSectionObject; PVOID SharedCacheMap; PVOID ImageSectionObject; } SFC_SEC_OBJ, *PSFC_SEC_OBJ;
typedef struct _SFC_FILE_OBJECT {   /* FILE_OBJECT 头部视图 (x64, SectionObjectPointer@40 稳定) */
    SHORT  Type;
    SHORT  Size;
    PVOID  DeviceObject;
    PVOID  Vpb;
    PVOID  FsContext;
    PVOID  FsContext2;
    PSFC_SEC_OBJ SectionObjectPointer;
} SFC_FILE_OBJECT, *PSFC_FILE_OBJECT;

typedef int KPROCESSOR_MODE;
NTSYSAPI NTSTATUS NTAPI ObReferenceObjectByHandle(HANDLE, ACCESS_MASK, PVOID, KPROCESSOR_MODE, PVOID*, PVOID);
NTSYSAPI VOID    NTAPI ObDereferenceObject(PVOID);
extern PVOID IoFileObjectType;      /* 内核导出: 文件对象类型 */
NTSYSAPI BOOLEAN NTAPI MmForceSectionClosed(PSFC_SEC_OBJ, BOOLEAN);

typedef struct _SFC_HANDLE_EX {         /* SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, x64 = 40B */
    ULONG_PTR Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR Handle;
    ACCESS_MASK GrantedAccess;
    USHORT    CreatorBackTraceIndex;
    USHORT    SystemHandleCount;
    USHORT    KernelHandleCount;
    USHORT    Flags;
    ULONG     Reserved;
} SFC_HANDLE_EX, *PSFC_HANDLE_EX;
NTSYSAPI NTSTATUS NTAPI ZwCreateFile(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
                                     PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
NTSYSAPI NTSTATUS NTAPI ZwSetInformationFile(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG,
                                            FILE_INFORMATION_CLASS);
NTSYSAPI NTSTATUS NTAPI ZwQueryDirectoryFile(HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK,
                                             PVOID, ULONG, FILE_INFORMATION_CLASS,
                                             BOOLEAN, PUNICODE_STRING, BOOLEAN);

/* ---- 系统线程/事件 (清扫线程) ---- */
typedef ULONG EVENT_TYPE;
typedef ULONG WAIT_TYPE;
typedef int   KPROCESSOR_MODE;
typedef VOID (NTAPI *PKSTART_ROUTINE)(PVOID StartContext);
/* KEVENT 仅作存储占位 (x64 真实 DISPATCHER_HEADER 24B, 此处 32B 对齐安全) */
typedef struct _KEVENT { ULONG_PTR Header[4]; } KEVENT, *PKEVENT;

NTSYSAPI VOID    NTAPI KeInitializeEvent(PKEVENT, EVENT_TYPE, BOOLEAN);
NTSYSAPI LONG    NTAPI KeSetEvent(PKEVENT, KPRIORITY, BOOLEAN);
NTSYSAPI NTSTATUS NTAPI KeWaitForSingleObject(PVOID, WAIT_TYPE, KPROCESSOR_MODE,
                                              BOOLEAN, PLARGE_INTEGER);
NTSYSAPI NTSTATUS NTAPI PsCreateSystemThread(PHANDLE, ULONG, POBJECT_ATTRIBUTES, HANDLE,
                                             PCLIENT_ID, PKSTART_ROUTINE, PVOID);
NTSYSAPI NTSTATUS NTAPI PsTerminateSystemThread(NTSTATUS);

#ifndef THREAD_ALL_ACCESS
#define THREAD_ALL_ACCESS       0x001F03FFL
#endif
#define NotificationEvent       0
#define Executive               0
#define KernelMode              0

/* 内核无 CRT: winnt.h 若没给 RtlCopyMemory 就自造循环版 */
#ifndef RtlCopyMemory
#define RtlCopyMemory(Dst, Src, Len) \
    do { SIZE_T _i; for (_i = 0; _i < (SIZE_T)(Len); _i++) ((char *)(Dst))[_i] = ((const char *)(Src))[_i]; } while (0)
#endif

#ifdef __cplusplus
}
#endif
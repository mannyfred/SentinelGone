#include <windows.h>

#define PAGE_SIZE 0x1000

typedef struct _VECTORED_HANDLER_LIST {
    PVOID LockVEH;
    PVOID FirstVEH;
    PVOID LastVEH;
    PVOID LockVCH;
    PVOID FirstVCH;
    PVOID LastVCH;
} VECTORED_HANDLER_LIST, *PVECTORED_HANDLER_LIST;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING *PUNICODE_STRING;
typedef const UNICODE_STRING *PCUNICODE_STRING;

typedef LONG KPRIORITY;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _SYSTEM_THREAD_INFORMATION {
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    KPRIORITY Priority;
    KPRIORITY BasePriority;
    ULONG ContextSwitches;
    ULONG ThreadState;
    ULONG WaitReason;
} SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    BYTE Reserved1[48];
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    PVOID Reserved2;
    ULONG HandleCount;
    ULONG SessionId;
    PVOID Reserved3;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG Reserved4;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    PVOID Reserved5;
    SIZE_T QuotaPagedPoolUsage;
    PVOID Reserved6;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
    SYSTEM_THREAD_INFORMATION Threads[1];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;


typedef struct _PROCESS_BASIC_INFOMRATION {
	NTSTATUS ExitStatus;
	PVOID PebBaseAddres;
	KAFFINITY Affinitymask;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InjeritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemProcessInformation = 5
} SYSTEM_INFORMATION_CLASS;

typedef enum _PROCESSINFOCLASS {
    ProcessBasicInformation = 0,
} PROCESSINFOCLASS;

WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap();
WINBASEAPI HMODULE WINAPI KERNEL32$GetModuleHandleA(LPCSTR);
WINBASEAPI FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);

WINBASEAPI NTSTATUS NTAPI NTDLL$NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
WINBASEAPI NTSTATUS NTAPI NTDLL$NtQueryInformationProcess(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
WINBASEAPI NTSTATUS NTAPI NTDLL$NtReadVirtualMemory(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
WINBASEAPI NTSTATUS NTAPI NTDLL$NtQueueApcThreadEx(HANDLE, HANDLE, PVOID, PVOID, PVOID, PVOID);
WINBASEAPI NTSTATUS NTAPI NTDLL$RtlEncodeRemotePointer(HANDLE, PVOID, PVOID*);
WINBASEAPI NTSTATUS NTAPI NTDLL$NtProtectVirtualMemory(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
WINBASEAPI PVOID    NTAPI NTDLL$RtlAllocateHeap(PVOID, DWORD, SIZE_T);
WINBASEAPI NTSTATUS NTAPI NTDLL$RtlFreeHeap(PVOID, DWORD, PVOID);
WINBASEAPI NTSTATUS NTAPI NTDLL$NtClose(HANDLE);
WINBASEAPI VOID     NTAPI NTDLL$memcpy(PVOID, PVOID, SIZE_T);
WINBASEAPI NTSTATUS NTAPI NTDLL$NtOpenProcess(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
WINBASEAPI NTSTATUS NTAPI NTDLL$NtOpenThread(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
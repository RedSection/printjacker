#pragma once
#include<Windows.h>
/**
 *
 * @ brief : Locates an impersonation token for the
 * NT AUTHORITY\SYSTEM user within the target
 * process.
 *
 * @ arg HANDLE hProcess : Handle to an opened process
 * to enum for process handles.
 *
 * @ ret : Returns a pointer to a useable handle to
 * impersonate. The target must close the handle
 * when they are done.
 *
**/
HRESULT GetSystemTokenFromProcess(_In_ HANDLE ProcessHandle);
HRESULT GetServiceHandle(_In_ LPCWSTR ServiceName, _Out_ PHANDLE ProcessHandle);
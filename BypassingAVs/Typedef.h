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

typedef ULONGLONG(WINAPI* fnGetTickCount64)();

typedef LRESULT(WINAPI* fnCallNextHookEx)(HHOOK hhk, int nCode, WPARAM wParam, LPARAM lParam);

typedef HHOOK(WINAPI* fnSetWindowsHookExW)(int idHook, HOOKPROC lpfn, HINSTANCE hmod, DWORD dwThreadId);

typedef BOOL(WINAPI* fnGetMessageW)(LPMSG lpMsg, HWND hWnd, UINT wMsgFilterMin, UINT wMsgFilterMax);

typedef LRESULT(WINAPI* fnDefWindowProcW)(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);

typedef BOOL(WINAPI* fnUnhookWindowsHookEx)(HHOOK hhk);

typedef DWORD(WINAPI* fnGetModuleFileNameW)(HMODULE hModule, LPWSTR lpFilename, DWORD nSize);

typedef HANDLE(WINAPI* fnCreateFileW)(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);

typedef BOOL(WINAPI* fnSetFileInformationByHandle)(HANDLE hFile, FILE_INFO_BY_HANDLE_CLASS FileInformationClass, LPVOID lpFileInformation, DWORD dwBufferSize);



typedef struct _API_HASHING {

	fnFindResourceW					pFindResourceW;
	fnLoadResource					pLoadResource;
	fnLockResource					pLockResource;
	fnSizeofResource				pSizeofResource;
	fnOpenProcess                   pOpenProcess;
	fnGetTickCount64                pGetTickCount64;
	fnCallNextHookEx                pCallNextHookEx;
	fnSetWindowsHookExW             pSetWindowsHookExW;
	fnGetMessageW                   pGetMessageW;
	fnDefWindowProcW                pDefWindowProcW;
	fnUnhookWindowsHookEx           pUnhookWindowsHookEx;
	fnGetModuleFileNameW            pGetModuleFileNameW;
	fnCreateFileW                   pCreateFileW;
	fnSetFileInformationByHandle    pSetFileInformationByHandle;

}API_HASHING, * PAPI_HASHING;

extern API_HASHING g_Api;
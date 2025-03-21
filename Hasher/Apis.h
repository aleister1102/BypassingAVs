#pragma once
#include <Windows.h>

PCHAR NativeApis[] = {
	"NtCreateSection",
	"NtMapViewOfSection",
	"NtUnmapViewOfSection",
	"NtClose",
	"NtCreateThreadEx",
	"NtWaitForSingleObject",
	"NtQuerySystemInformation",
	"NtDelayExecution",
	"NtAllocateVirtualMemory",
	"NtProtectVirtualMemory",
	"NtWriteVirtualMemory",
	"NtQueueApcThread",
	"NtQueryInformationProcess",
	"NtRemoveProcessDebug",
	"NtFreeVirtualMemory",
	"NtOpenProcessToken",
	"NtQueryInformationToken"
};
// Remember to update this value if you add/remove any APIs
DWORD NativeApisCount = 17;

PCHAR WindowsApis[] = {
	"FindResourceW",
	"LoadResource",
	"LockResource",
	"SizeofResource",
	"GetTickCount64",
	"OpenProcess",
	"CallNextHookEx",
	"SetWindowsHookExW",
	"GetMessageW",
	"DefWindowProcW",
	"UnhookWindowsHookEx",
	"GetModuleFileNameW",
	"CreateFileW",
	"SetFileInformationByHandle",
	"SystemFunction032",
	"GetEnvironmentVariableA",
	"InitializeProcThreadAttributeList",
	"UpdateProcThreadAttribute",
	"CreateProcessA",
	"DeleteProcThreadAttributeList",
	"InternetOpenW",
	"InternetOpenUrlW",
	"InternetReadFile",	
	"InternetCloseHandle",
	"InternetSetOptionW",
	"LoadLibraryA",
};
// Remember to update this value if you add/remove any APIs
DWORD WindowsApisCount = 26;
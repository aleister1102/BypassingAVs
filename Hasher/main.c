#pragma once
#include <Windows.h>
#include <stdio.h>

UINT32 HashStringRotr32A(LPCSTR String);
SIZE_T StringLengthA(LPCSTR String);
UINT32 HashStringRotr32Sub(UINT32 Value, UINT Count);

#define INITIAL_SEED	0x7
#define HASH_VALUE_POSTFIX  "HashValue"
#define RTIME_HASHA(API) HashStringRotr32A((LPCSTR) API)

UINT32 HashStringRotr32A(LPCSTR String)
{
	UINT32 Value = 0;

	for (INT Index = 0; Index < StringLengthA(String); Index++)
		Value = String[Index] + HashStringRotr32Sub(Value, INITIAL_SEED);

	return Value;
}

SIZE_T StringLengthA(LPCSTR String)
{
	LPCSTR String2 = String;

	for (; *String2; ++String2);

	return (String2 - String);
}

UINT32 HashStringRotr32Sub(UINT32 Value, UINT Count)
{
	DWORD Mask = (CHAR_BIT * sizeof(Value) - 1);
	Count &= Mask;
#pragma warning( push )
#pragma warning( disable : 4146)
	return (Value >> Count) | (Value << ((-Count) & Mask));
#pragma warning( pop )
}


int main() {
	// Native APIs
	printf("===NT APIs===\n");
	printf("#define %s%s \t0x%0.8X \n",
		"NtCreateSection",
		HASH_VALUE_POSTFIX,
		HashStringRotr32A("NtCreateSection"));

	printf("#define %s%s \t0x%0.8X \n",
		"NtMapViewOfSection",
		HASH_VALUE_POSTFIX,
		HashStringRotr32A("NtMapViewOfSection"));

	printf("#define %s%s \t0x%0.8X \n",
		"NtUnmapViewOfSection",
		HASH_VALUE_POSTFIX,
		HashStringRotr32A("NtUnmapViewOfSection"));

	printf("#define %s%s \t0x%0.8X \n",
		"NtClose",
		HASH_VALUE_POSTFIX,
		HashStringRotr32A("NtClose"));

	printf("#define %s%s \t0x%0.8X \n",
		"NtCreateThreadEx",
		HASH_VALUE_POSTFIX,
		HashStringRotr32A("NtCreateThreadEx"));

	printf("#define %s%s \t0x%0.8X \n",
		"NtWaitForSingleObject",
		HASH_VALUE_POSTFIX,
		HashStringRotr32A("NtWaitForSingleObject"));

	printf("#define %s%s \t0x%0.8X \n",
		"NtQuerySystemInformation",
		HASH_VALUE_POSTFIX,
		HashStringRotr32A("NtQuerySystemInformation"));

	printf("#define %s%s \t0x%0.8X \n",
		"NtDelayExecution",
		HASH_VALUE_POSTFIX,
		HashStringRotr32A("NtDelayExecution"));

	// Windows API
	printf("===Windows APIs===\n");
	printf("#define %s%s \t0x%0.8X \n",
		"GetTickCount64",
		HASH_VALUE_POSTFIX,
		HashStringRotr32A("GetTickCount64"));

	printf("#define %s%s \t0x%0.8X \n",
		"OpenProcess",
		HASH_VALUE_POSTFIX,
		HashStringRotr32A("OpenProcess"));

	printf("#define %s%s \t0x%0.8X \n",
		"CallNextHookEx",
		HASH_VALUE_POSTFIX,
		HashStringRotr32A("CallNextHookEx"));

	printf("#define %s%s \t0x%0.8X \n",
		"SetWindowsHookExW",
		HASH_VALUE_POSTFIX,
		HashStringRotr32A("SetWindowsHookExW"));

	printf("#define %s%s \t0x%0.8X \n",
		"GetMessageW",
		HASH_VALUE_POSTFIX,
		HashStringRotr32A("GetMessageW"));

	printf("#define %s%s \t0x%0.8X \n",
		"DefWindowProcW",
		HASH_VALUE_POSTFIX,
		HashStringRotr32A("DefWindowProcW"));

	printf("#define %s%s \t0x%0.8X \n",
		"UnhookWindowsHookEx",
		HASH_VALUE_POSTFIX,
		HashStringRotr32A("UnhookWindowsHookEx"));

	printf("#define %s%s \t0x%0.8X \n",
		"GetModuleFileNameW",
		HASH_VALUE_POSTFIX,
		HashStringRotr32A("GetModuleFileNameW"));

	printf("#define %s%s \t0x%0.8X \n",
		"CreateFileW",
		HASH_VALUE_POSTFIX,
		HashStringRotr32A("CreateFileW"));

	printf("#define %s%s \t0x%0.8X \n",
		"SetFileInformationByHandle",
		HASH_VALUE_POSTFIX,
		HashStringRotr32A("SetFileInformationByHandle"));	
	
	printf("#define %s%s \t0x%0.8X \n",
		"USER32DLL",
		HASH_VALUE_POSTFIX,
		HashStringRotr32A("user32.dll"));

	printf("#define %s%s \t0x%0.8X \n",
		"KERNEL32DLL",
		HASH_VALUE_POSTFIX,
		HashStringRotr32A("kernel32.dll"));
	
	return 0;
}
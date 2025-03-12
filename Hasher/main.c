#pragma once
#include <Windows.h>
#include <stdio.h>

INT HashStringRotr32(LPCSTR String);
SIZE_T StringLength(LPCSTR String);
UINT32 HashStringRotr32Sub(UINT32 Value, UINT Count);

#define INITIAL_SEED	0x7
#define HASH_VALUE_POSTFIX  "HashValue"
#define RTIME_HASH(API) HashStringRotr32Sub((LPCSTR) API)

INT HashStringRotr32(LPCSTR String)
{
	INT Value = 0;

	for (INT Index = 0; Index < StringLength(String); Index++)
		Value = String[Index] + HashStringRotr32Sub(Value, INITIAL_SEED);

	return Value;
}

SIZE_T StringLength(LPCSTR String)
{
	LPCSTR String2 = String;

	for (String2 = String; *String2; ++String2);

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
	printf("#define %s%s \t0x%0.8X \n", "NtCreateSection", HASH_VALUE_POSTFIX, HashStringRotr32("NtCreateSection"));
	printf("#define %s%s \t0x%0.8X \n", "NtMapViewOfSection", HASH_VALUE_POSTFIX, HashStringRotr32("NtMapViewOfSection"));
	printf("#define %s%s \t0x%0.8X \n", "NtUnmapViewOfSection", HASH_VALUE_POSTFIX, HashStringRotr32("NtUnmapViewOfSection"));
	printf("#define %s%s \t0x%0.8X \n", "NtClose", HASH_VALUE_POSTFIX, HashStringRotr32("NtClose"));
	printf("#define %s%s \t0x%0.8X \n", "NtCreateThreadEx", HASH_VALUE_POSTFIX, HashStringRotr32("NtCreateThreadEx"));
	printf("#define %s%s \t0x%0.8X \n", "NtWaitForSingleObject", HASH_VALUE_POSTFIX, HashStringRotr32("NtWaitForSingleObject"));
	return 0;
}
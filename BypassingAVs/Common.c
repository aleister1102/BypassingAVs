#include "Common.h"

UINT32 HashStringRotr32(LPCSTR String)
{
	UINT32 Value = 0;

	for (INT Index = 0; Index < StringLength(String); Index++)
		Value = String[Index] + HashStringRotr32Sub(Value, INITIAL_SEED);

	return Value;
}

SIZE_T StringLength(LPCSTR String)
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

PTEB RtlGetThreadEnvironmentBlock()
{
#if _WIN64
	return (PTEB)__readgsqword(0x30);
#else
	return (PTEB)__readfsdword(0x16);
#endif
}

PVOID CopyMemoryEx(IN OUT PVOID Destination, IN CONST PVOID Source, IN SIZE_T Length)
{
	PBYTE D = (PBYTE)Destination;
	PBYTE S = (PBYTE)Source;

	while (Length--)
		*D++ = *S++;

	return Destination;
}

HANDLE GetCurrentProcessHandle() {
	return (HANDLE)-1;
}

HANDLE GetCurrentThreadHandle() {
	return (HANDLE)-2;
}

VOID PrintHexData(LPCSTR Name, PBYTE Data, SIZE_T Size) 
{
	printf("unsigned char %s[] = {", Name);

	for (int i = 0; i < Size; i++) {
		if (i % 16 == 0)
			printf("\n\t");

		if (i < Size - 1)
			printf("0x%0.2X, ", Data[i]);
		else
			printf("0x%0.2X ", Data[i]);
	}

	printf("};\n\n\n");
}
#include "Common.h"

UINT32 HashStringRotr32A(LPCSTR String)
{
	UINT32 Value = 0;

	for (INT Index = 0; Index < StringLengthA(String); Index++)
		Value = String[Index] + HashStringRotr32Sub(Value, INITIAL_SEED);

	return Value;
}

UINT32 HashStringRotr32W(LPCWSTR String)
{
	UINT32 Value = 0;

	for (INT Index = 0; Index < StringLengthW(String); Index++)
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

PTEB RtlGetThreadEnvironmentBlock()
{
#if _WIN64
	return (PTEB)__readgsqword(0x30);
#else
	return (PTEB)__readfsdword(0x16);
#endif
}

PPEB RtlGetProcessEnvironmentBlock()
{
#if _WIN64
	return (PPEB)__readgsqword(0x60);
#else
	return (PPEB)__readfsdword(0x30);
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
	PRINTA("unsigned char %s[] = {", Name);

	for (int i = 0; i < Size; i++) {
		if (i % 16 == 0)
			PRINTA("\n\t");

		if (i < Size - 1) {
			PRINTA("0x%0.2X, ", Data[i]);
		}
		else {
			PRINTA("0x%0.2X ", Data[i]);
		}
	}

	PRINTA("};\n\n");
}

VOID ZeroMemoryEx(IN OUT PVOID Destination, IN SIZE_T Size)
{
	PULONG Dest = (PULONG)Destination;
	SIZE_T Count = Size / sizeof(ULONG);

	while (Count > 0)
	{
		*Dest = 0;
		Dest++;
		Count--;
	}

	return;
}

INT StringCompareA(IN LPCSTR String1, IN LPCSTR String2)
{
	for (; *String1 == *String2; String1++, String2++)
	{
		if (*String1 == '\0')
			return 0;
	}

	return ((*(LPCSTR)String1 < *(LPCSTR)String2) ? -1 : +1);
}

INT StringCompareW(IN LPCWSTR String1, IN LPCWSTR String2)
{
	for (; *String1 == *String2; String1++, String2++)
	{
		if (*String1 == '\0')
			return 0;
	}

	return ((*(LPCWSTR)String1 < *(LPCWSTR)String2) ? -1 : +1);
}

SIZE_T StringLengthW(IN LPCWSTR String)
{
	LPCWSTR String2 = String;

	for (; *String2; ++String2);

	return (String2 - String);
}

WCHAR ToLowerCharW(IN WCHAR character)
{
	WCHAR lowerChar = 0x0;

	if ((UINT)character < 65 || (UINT)character > 90)
		return character;

	lowerChar = character + 32;

	return lowerChar;
}

CHAR ToLowerCharA(IN CHAR character)
{
	CHAR lowerChar = 0x0;

	if ((UINT)character < 65 || (UINT)character > 90)
		return character;

	lowerChar = character + 32;

	return lowerChar;
}

LPCWSTR LowerCaseStringW(IN LPCWSTR str) {
	if (!str)
		return NULL;

	// Get length of the string
	SIZE_T length = StringLengthW(str);

	// Allocate memory for the lowercase string
	PWSTR lowerString = (PWSTR)HeapAlloc(
		GetProcessHeap(),
		HEAP_ZERO_MEMORY,
		(length + 1) * sizeof(WCHAR)
	);

	if (!lowerString)
		return NULL;

	// Lowercasing the string
	for (SIZE_T i = 0; i < length; i++) {
		lowerString[i] = ToLowerCharW(str[i]);
	}
	lowerString[length] = L'\0';

	return lowerString;
}

LPCSTR LowerCaseStringA(IN LPCSTR str)
{
	if (!str)
		return NULL;

	// Get length of the string
	SIZE_T length = StringLengthA(str);

	// Allocate memory for the lowercase string
	PSTR lowerString = (PSTR)HeapAlloc(
		GetProcessHeap(),
		HEAP_ZERO_MEMORY,
		(length + 1) * sizeof(CHAR)
	);

	if (!lowerString)
		return NULL;

	// Lowercasing the string
	for (SIZE_T i = 0; i < length; i++) {
		lowerString[i] = ToLowerCharA(str[i]);
	}
	lowerString[length] = L'\0';

	return lowerString;
}

BOOL IsStringEqual(IN LPCWSTR Str1, IN LPCWSTR Str2)
{
	int		len1 = StringLengthW(Str1);
	int		len2 = StringLengthW(Str2);

	int		i = 0;
	int		j = 0;

	// Checking length. We dont want to overflow the buffers
	if (len1 >= MAX_PATH || len2 >= MAX_PATH)
		return FALSE;

	// Converting Str1 to lower case string (lStr1)
	PCWSTR	lStr1 = LowerCaseStringW(Str1);

	// Converting Str2 to lower case string (lStr2)
	PCWSTR	lStr2 = LowerCaseStringW(Str2);

	// Comparing the lower-case strings
	if (StringCompareW(lStr1, lStr2) == 0)
	{
		return TRUE;
	}

	return FALSE;
}

// Used by HeapAlloc
extern void* __cdecl memset(void*, int, size_t);
#pragma intrinsic(memset)
#pragma function(memset)

void* __cdecl memset(void* Destination, int Value, size_t Size) {
	unsigned char* p = (unsigned char*)Destination;
	while (Size > 0) {
		*p = (unsigned char)Value;
		p++;
		Size--;
	}
	return Destination;
}

// Used for randomly syscall address retrieval
#ifdef _MSC_VER  // If compiling with MSVC
#ifndef _DEBUG  // If it's a Release build
extern int __cdecl rand(void);
#pragma intrinsic(rand)
#pragma function(rand)

int __cdecl rand(void) {
	static unsigned int seed = 2463534242;
	seed ^= seed << 13;
	seed ^= seed >> 17;
	seed ^= seed << 5;
	return (int)(seed & 0x7FFFFFFF);  // Keep it within positive int range
}
#endif
#endif
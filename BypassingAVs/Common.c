#include "Common.h"

UINT32 HashStringRotr32(LPCSTR String)
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

BOOL ReadPayloadFromResource(OUT PVOID* ppPayloadAddress, OUT SIZE_T* pPayloadSize)
{
	HRSRC		hRsrc = NULL;
	HGLOBAL		hGlobal = NULL;

	// Get the location to the data stored in .rsrc by its id *IDR_RCDATA1*
	hRsrc = FindResourceW(NULL, MAKEINTRESOURCEW(IDR_RCDATA1), RT_RCDATA);
	if (hRsrc == NULL) {
		// in case of function failure 
		printf("[!] FindResourceW Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Get HGLOBAL, or the handle of the specified resource data since its required to call LockResource later
	hGlobal = LoadResource(NULL, hRsrc);
	if (hGlobal == NULL) {
		// in case of function failure 
		printf("[!] LoadResource Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Get the address of our payload in .rsrc section
	*ppPayloadAddress = LockResource(hGlobal);
	if (*ppPayloadAddress == NULL) {
		// in case of function failure 
		printf("[!] LockResource Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Get the size of our payload in .rsrc section
	*pPayloadSize = SizeofResource(NULL, hRsrc);
	if (*pPayloadSize == NULL) {
		// in case of function failure 
		printf("[!] SizeofResource Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	return TRUE;
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
	if (!character)
		return NULL;

	WCHAR lowerChar = NULL;

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



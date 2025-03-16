#include "Hasher.h"

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


UINT32 HashStringRotr32A(LPCSTR String)
{
	UINT32 Value = 0;

	for (INT Index = 0; Index < StringLengthA(String); Index++)
		Value = String[Index] + HashStringRotr32Sub(Value, INITIAL_SEED);

	return Value;
}
#pragma once
#include <Windows.h>

#define INITIAL_SEED	0x7

#define HASH_VALUE_POSTFIX  "HashValue"

#define RTIME_HASHA(API) HashStringRotr32A((LPCSTR) API)

SIZE_T StringLengthA(LPCSTR String);
UINT32 HashStringRotr32Sub(UINT32 Value, UINT Count);
UINT32 HashStringRotr32A(LPCSTR String);

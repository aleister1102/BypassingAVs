#include "Common.h"

#define HINT_BYTE 0xF5

unsigned char ProtectedKey[] = {
		0xE3, 0xF8, 0xBC, 0x97, 0x0A, 0x79, 0xDD, 0xA3, 0x2B, 0x4C, 0xB5, 0xF0, 0x16, 0x93, 0x29, 0x2D };

BYTE BruteForceDecryption(IN BYTE HintByte, IN PBYTE pProtectedKey, IN SIZE_T sKey, OUT PBYTE* ppRealKey) {

	BYTE            b = 0;
	INT             i = 0;
	PBYTE           pRealKey = (PBYTE)malloc(sKey);

	if (!pRealKey)
		return NULL;

	while (1) {

		if (((pProtectedKey[0] ^ b)) == HintByte)
			break;
		else
			b++;

	}

	printf("[i] Calculated 'b' to be : 0x%0.2X \n", b);

	for (int i = 0; i < sKey; i++) {
		pRealKey[i] = (BYTE)((pProtectedKey[i] ^ b) - i);
	}

	*ppRealKey = pRealKey;
	return b;
}

BOOL Rc4DecryptionViSystemFunc032(IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize)
{

	// the return of SystemFunction032
	NTSTATUS        STATUS = 0x0;
	PBYTE           pOriginalKey = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwRc4KeySize);
	BYTE			b = 0;

	// brute forcing the key
	b = BruteForceDecryption(HINT_BYTE, pRc4Key, dwRc4KeySize, &pOriginalKey);
	if (!b) {
		printf("[!] BruteForceDecryption Failed To Decrypt The ProtectedKey\n");
		return FALSE;
	}

	PrintHexData("OriginalKey", pOriginalKey, KEY_SIZE);

	// making 2 USTRING variables, 1 passed as key and one passed as the block of data to encrypt/decrypt
	USTRING         Key = {
		.Buffer = pOriginalKey,
		.Length = dwRc4KeySize,
		.MaximumLength = dwRc4KeySize
	};
	USTRING			Img = {
		.Buffer = pPayloadData,
		.Length = sPayloadSize,
		.MaximumLength = sPayloadSize
	};

	// since SystemFunction032 is exported from Advapi32.dll, we load it Advapi32 into the prcess,
	// and using its return as the hModule parameter in GetProcAddress
	fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)GetProcAddress(LoadLibraryA("Advapi32"), "SystemFunction032");

	// if SystemFunction032 calls failed it will return non zero value
	if ((STATUS = SystemFunction032(&Img, &Key)) != 0x0) {
		printf("[!] SystemFunction032 FAILED With Error : 0x%0.8X\n", STATUS);
		return FALSE;
	}

	return TRUE;
}


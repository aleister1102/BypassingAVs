#include "Common.h"

UCHAR Rc4Key[] = {
	0xF5, 0xED, 0xA8, 0x7E, 0x18, 0x6A, 0xC5, 0xAE, 0x35, 0x51, 0x99, 0xDB, 0xF4, 0x78, 0x31, 0x2C };

BOOL Rc4EncryptionViSystemFunc032(IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {

	// the return of SystemFunction032
	NTSTATUS        STATUS = 0x0;

	// making 2 USTRING variables, 1 passed as key and one passed as the block of data to encrypt/decrypt
	USTRING         Key = { .Buffer = pRc4Key,              .Length = dwRc4KeySize,         .MaximumLength = dwRc4KeySize },
		Img = { .Buffer = pPayloadData,         .Length = sPayloadSize,         .MaximumLength = sPayloadSize };


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


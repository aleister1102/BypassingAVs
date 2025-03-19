#include <Windows.h>
#include <stdio.h>


#include "Common.h"

char _AesDecryption[] =
"#include <Windows.h>\n"
"#include <stdio.h>\n"
"#include <bcrypt.h>\n"
"#pragma comment(lib, \"Bcrypt.lib\")\n\n\n"
"#define NT_SUCCESS(status)	        (((NTSTATUS)(status)) >= 0)\n"
"#define KEYSIZE\t\t32\n"
"#define IVSIZE\t\t16\n\n"
"typedef struct _AES {\n"
"	PBYTE\tpPlainText;\t\t// base address of the plain text data\n"
"	DWORD\tdwPlainSize;\t\t// size of the plain text data\n\n"
"	PBYTE\tpCipherText;\t\t// base address of the encrypted data\n"
"	DWORD\tdwCipherSize;\t\t// size of it (this can change from dwPlainSize in case there was padding)\n\n"
"	PBYTE\tpKey;\t\t\t// the 32 byte key\n"
"	PBYTE\tpIv;\t\t\t// the 16 byte iv\n"
"}AES, * PAES; \n\n"
"// the real decryption implemantation\n"
"BOOL InstallAesDecryption(PAES pAes) {\n\n"
"	BOOL				bSTATE = TRUE;\n\n"
"	BCRYPT_ALG_HANDLE		hAlgorithm = NULL;\n"
"	BCRYPT_KEY_HANDLE		hKeyHandle = NULL;\n\n"
"	ULONG				cbResult = NULL;\n"
"	DWORD				dwBlockSize = NULL;\n\n"
"	DWORD				cbKeyObject = NULL;\n"
"	PBYTE				pbKeyObject = NULL;\n\n"
"	PBYTE				pbPlainText = NULL;\n"
"	DWORD				cbPlainText = NULL;\n\n"
"	NTSTATUS			STATUS		= NULL;\n\n"
"	// intializing \"hAlgorithm\" as AES algorithm Handle\n"
"	STATUS = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);\n"
"	if (!NT_SUCCESS(STATUS)) {\n"
"		printf(\"[!] BCryptOpenAlgorithmProvider Failed With Error: 0x%0.8X \\n\", STATUS);\n"
"		bSTATE = FALSE; goto _EndOfFunc;\n"
"	}\n"
"	// getting the size of the key object variable *pbKeyObject* this is used for BCryptGenerateSymmetricKey function later\n"
"	STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbResult, 0); \n"
"	if (!NT_SUCCESS(STATUS)) {\n"
"		printf(\"[!] BCryptGetProperty[1] Failed With Error: 0x%0.8X \\n\", STATUS);\n"
"		bSTATE = FALSE; goto _EndOfFunc; \n"
"	}\n"
"	// getting the size of the block used in the encryption, since this is aes it should be 16 (this is what AES does)\n"
"	STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_BLOCK_LENGTH, (PBYTE)&dwBlockSize, sizeof(DWORD), &cbResult, 0); \n"
"	if (!NT_SUCCESS(STATUS)) {\n"
"		printf(\"[!] BCryptGetProperty[2] Failed With Error: 0x%0.8X \\n\", STATUS); \n"
"		bSTATE = FALSE; goto _EndOfFunc; \n"
"	}\n"
"	// checking if block size is 16\n"
"	if (dwBlockSize != 16) {\n"
"		bSTATE = FALSE; goto _EndOfFunc; \n"
"	}\n"
"	// allocating memory for the key object \n"
"	pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject); \n"
"	if (pbKeyObject == NULL) {\n"
"		bSTATE = FALSE; goto _EndOfFunc; \n"
"	}\n"
"	// setting Block Cipher Mode to CBC (32 byte key and 16 byte Iv)\n"
"	STATUS = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0); \n"
"	if (!NT_SUCCESS(STATUS)) {\n"
"		printf(\"[!] BCryptSetProperty Failed With Error: 0x%0.8X \\n\", STATUS); \n"
"		bSTATE = FALSE; goto _EndOfFunc; \n"
"	}\n"
"	// generating the key object from the aes key \"pAes->pKey\", the output will be saved in \"pbKeyObject\" of size \"cbKeyObject\" \n"
"	STATUS = BCryptGenerateSymmetricKey(hAlgorithm, &hKeyHandle, pbKeyObject, cbKeyObject, (PBYTE)pAes->pKey, KEYSIZE, 0); \n"
"	if (!NT_SUCCESS(STATUS)) {\n"
"		printf(\"[!] BCryptGenerateSymmetricKey Failed With Error: 0x%0.8X \\n\", STATUS); \n"
"		bSTATE = FALSE; goto _EndOfFunc; \n"
"	}\n"

"	// running BCryptDecrypt first time with NULL output parameters, thats to deduce the size of the output buffer, (the size will be saved in cbPlainText)\n"
"	STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText, (ULONG)pAes->dwCipherSize, NULL, pAes->pIv, IVSIZE, NULL, 0, &cbPlainText, BCRYPT_BLOCK_PADDING); \n"
"	if (!NT_SUCCESS(STATUS)) {\n"
"		printf(\"[!] BCryptDecrypt[1] Failed With Error: 0x%0.8X \\n\", STATUS); \n"
"		bSTATE = FALSE; goto _EndOfFunc; \n"
"	}\n"
"	// allocating enough memory (of size cbPlainText)\n"
"	pbPlainText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbPlainText); \n"
"	if (pbPlainText == NULL) {\n"
"		bSTATE = FALSE; goto _EndOfFunc; \n"
"	}\n"
"	// running BCryptDecrypt second time with \"pbPlainText\" as output buffer\n"
"	STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText, (ULONG)pAes->dwCipherSize, NULL, pAes->pIv, IVSIZE, pbPlainText, cbPlainText, &cbResult, BCRYPT_BLOCK_PADDING); \n"
"	if (!NT_SUCCESS(STATUS)) {\n"
"		printf(\"[!] BCryptDecrypt[2] Failed With Error: 0x%0.8X \\n\", STATUS); \n"
"		bSTATE = FALSE; goto _EndOfFunc; \n"
"	}\n"
"	// cleaning up\n"
"_EndOfFunc:\n"
"	if (hKeyHandle) {\n"
"		BCryptDestroyKey(hKeyHandle); \n"
"	}\n"
"	if (hAlgorithm) {\n"
"		BCryptCloseAlgorithmProvider(hAlgorithm, 0); \n"
"	}\n"
"	if (pbKeyObject) {\n"
"		HeapFree(GetProcessHeap(), 0, pbKeyObject); \n"
"	}\n"
"	if (pbPlainText != NULL && bSTATE) {\n"
"		// if everything went well, we save pbPlainText and cbPlainText\n"
"		pAes->pPlainText = pbPlainText; \n"
"		pAes->dwPlainSize = cbPlainText; \n"
"	}\n"
"	return bSTATE; \n"
"}\n\n\n"
"// wrapper function for InstallAesDecryption that make things easier\n"
"BOOL SimpleDecryption(IN PVOID pCipherTextData, IN DWORD sCipherTextSize, IN PBYTE pKey, IN PBYTE pIv, OUT PVOID * pPlainTextData, OUT DWORD * sPlainTextSize) {\n"
"	if (pCipherTextData == NULL || sCipherTextSize == NULL || pKey == NULL || pIv == NULL)\n"
"		return FALSE; \n\n"
"	AES Aes = { \n"
"		.pKey = pKey,\n"
"		.pIv = pIv,\n"
"		.pCipherText = pCipherTextData,\n"
"		.dwCipherSize = sCipherTextSize\n"
"	}; \n\n"
"	if (!InstallAesDecryption(&Aes)) {\n"
"		return FALSE; \n"
"	}\n\n"
"	*pPlainTextData = Aes.pPlainText; \n"
"	*sPlainTextSize = Aes.dwPlainSize; \n\n"
"	return TRUE; \n"
"}\n";






char _Rc4Decryption[] =
"#include <Windows.h>\n"
"#include <stdio.h>\n\n\n"
"// this is what SystemFunction032 function take as a parameter\n"
"typedef struct\n"
"{\n"
"DWORD	Length; \n"
"DWORD	MaximumLength; \n"
"PVOID	Buffer; \n"
"\n"
"} USTRING; \n\n"
"// defining how does the function look - more on this structure in the api hashing part\n"
"typedef NTSTATUS(NTAPI* fnSystemFunction032)(\n"
"	struct USTRING* Img, \n"
"	struct USTRING* Key\n"
"); \n\n"
"BOOL Rc4EncryptionViSystemFunc032(IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {\n"
"	\n"
"	// the return of SystemFunction032\n"
"	NTSTATUS	STATUS = NULL; \n"
"	\n"
"	// making 2 USTRING variables, 1 passed as key and one passed as the block of data to encrypt/decrypt\n"
"	USTRING		Key = { .Buffer = pRc4Key, 		.Length = dwRc4KeySize,		.MaximumLength = dwRc4KeySize }, \n"
"			Img = { .Buffer = pPayloadData, 	.Length = sPayloadSize,		.MaximumLength = sPayloadSize }; \n"
"	\n"
"	\n"
"	// since SystemFunction032 is exported from Advapi32.dll, we load it Advapi32 into the prcess,\n"
"	// and using its return as the hModule parameter in GetProcAddress\n"
"	fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)GetProcAddress(LoadLibraryA(\"Advapi32\"), \"SystemFunction032\"); \n"
"	\n"
"	// if SystemFunction032 calls failed it will return non zero value\n"
"	if ((STATUS = SystemFunction032(&Img, &Key)) != 0x0) {\n"
"		printf(\"[!] SystemFunction032 FAILED With Error : 0x%0.8X\\n\", STATUS); \n"
"		return FALSE; \n"
"	}\n\n"
"	return TRUE; \n"
"}\n";





VOID PrintDecodeFunctionality(IN INT TYPE) {
	if (TYPE == 0) {
		printf("[!] Missing Input Type (StringFunctions:177)\n");
		return;
	}

	switch (TYPE) {

	case AESENCRYPTION:
		printf("%s\n", _AesDecryption);
		break;

	case RC4ENCRYPTION:
		printf("%s\n", _Rc4Decryption);
		break;

	default:
		printf("[!] Unsupported Type Entered : 0x%0.8X \n", TYPE);
		break;
	}


}
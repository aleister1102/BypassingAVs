#include <Windows.h>
#include <stdio.h>


#include "Common.h"


// print help
INT PrintHelp(IN CHAR* _Argv0) {
	printf("\t\t\t ###########################################################\n");
	printf("\t\t\t # MiniShell - Designed By MalDevAcademy @NUL0x4C | @mrd0x #\n");
	printf("\t\t\t ###########################################################\n\n");

	printf("[!] Usage: %s <Input Payload FileName> <Enc *Option*>  <Output FileName> <Key FileName>\n", _Argv0);
	printf("[i] Encryption Options Can Be : \n");
	printf("\t1.>>> \"aes\"     ::: Output The File As A Encrypted File Using Aes-256 Algorithm With Random Key And Iv \n");
	printf("\t2.>>> \"rc4\"     ::: Output The File As A Encrypted File Using Rc4 Algorithm With Random Key \n");
	printf("\n[i] Both Options Support Outputting The Decryption Functionality \n");

	printf("\n[i] ");
	system("PAUSE");
	return -1;

}




/*
EXAMPLES:
	- .\MiniShell.exe .\calc.bin rc4 encpayload.bin ; use rc4 for encryption - write the encrypted bytes to 'encpayload.bin' -  output the decryption functionality to the console

	- .\MiniShell.exe .\calc.bin rc4 encpayload.bin > rc4.c ; use rc4 for encryption - write the encrypted bytes to 'encpayload.bin' -  output the decryption functionality to 'rc4.c'

	- .\MiniShell.exe .\calc.bin aes calcenc.bin ; use aes for encryption - write the encrypted bytes to 'calcenc.bin' -  output the decryption functionality to the console

	- .\MiniShell.exe .\calc.bin aes calcenc.bin > aes.c ; use aes for encryption - write the encrypted bytes to 'calcenc.bin' -  output the decryption functionality to 'aes.c'
*/



int main(int argc, char* argv[]) {


	// variables used for holding data on the read payload 
	PBYTE	pPayloadInput = NULL;
	DWORD	dwPayloadSize = NULL;

	// variables used for holding data on the encrypted payload (aes/rc4)
	PVOID	pCipherText = NULL;
	DWORD	dwCipherSize = NULL;

	// variables used for holding data of the key
	PVOID	pKeyInput = NULL;
	DWORD	dwKeySize = NULL;

	// checking input
	if (argc <= 4) {
		return PrintHelp(argv[0]);
	}


	if (strcmp(argv[2], "aes") != 0 && strcmp(argv[2], "rc4") != 0) {
		printf("<<<!>>> \"%s\" Is not Valid Input <<<!>>>\n", argv[2]);
		return PrintHelp(argv[0]);
	}

	// reading input payload
	if (!ReadPayloadFile(argv[1], &dwPayloadSize, &pPayloadInput)) {
		return -1;
	}

	if (strcmp(argv[2], "aes") == 0) {

		CHAR	KEY[AESKEYSIZE] = { 0 }, KEY2[AESKEYSIZE] = { 0 };
		CHAR	IV[AESIVSIZE] = { 0 }, IV2[AESIVSIZE] = { 0 };

		// reading key
		if (argc == 5) {
			if (ReadPayloadFile(argv[4], &dwKeySize, &pKeyInput)
				&& dwKeySize == AESKEYSIZE + AESIVSIZE) // Key and IV is stored in the same file
			{
				memcpy(KEY, pKeyInput, AESKEYSIZE);
				memcpy(IV, (PBYTE)pKeyInput + AESKEYSIZE, AESIVSIZE);
			}
			else {
				printf("[!] Failed To Read The Key File\n");
				return -1;
			}
		}
		else {
			srand(time(NULL));
			GenerateRandomBytes(KEY, AESKEYSIZE);
			srand(time(NULL) ^ KEY[0]);
			GenerateRandomBytes(IV, AESIVSIZE);
		}

		//saving the key and iv in case it got modified by the encryption algorithm
		memcpy(KEY2, KEY, AESKEYSIZE);
		memcpy(IV2, IV, AESIVSIZE);

		if (!SimpleEncryption(pPayloadInput, dwPayloadSize, KEY, IV, &pCipherText, &dwCipherSize)) {
			return -1;
		}

		PrintDecodeFunctionality(AESENCRYPTION);
		//PrintHexData("AesCipherText", pCipherText, dwCipherSize);
		PrintHexData("AesKey", KEY2, AESKEYSIZE);
		PrintHexData("AesIv", IV2, AESIVSIZE);


		if (!WritePayloadFile(argv[3], dwCipherSize, pCipherText)) {
			MessageBoxA(NULL, "Failed To Write The Encrypted Bin File", "ERROR !", MB_OK | MB_ICONERROR);
		}

		goto _EndOfFunction;
	}

	if (strcmp(argv[2], "rc4") == 0) {

		CHAR	KEY[RC4KEYSIZE] = { 0 }, KEY2[RC4KEYSIZE] = { 0 };

		// reading key
		if (argc == 5) {
			if (ReadPayloadFile(argv[4], &dwKeySize, &pKeyInput) && dwKeySize == RC4KEYSIZE)
			{
				memcpy(KEY, pKeyInput, RC4KEYSIZE);
			}
			else {
				printf("[!] Failed To Read The Key File\n");
				return -1;
			}
		}
		else {
			srand(time(NULL));
			GenerateRandomBytes(KEY, RC4KEYSIZE);
		}

		//saving the key in case it got modified by the encryption algorithm
		memcpy(KEY2, KEY, RC4KEYSIZE);

		if (!Rc4EncryptionViSystemFunc032(KEY, pPayloadInput, RC4KEYSIZE, dwPayloadSize)) {
			return -1;
		}

		PrintDecodeFunctionality(RC4ENCRYPTION);
		//PrintHexData("Rc4CipherText", pPayloadInput, dwPayloadSize);
		PrintHexData("Rc4Key", KEY2, RC4KEYSIZE);


		if (!WritePayloadFile(argv[3], dwPayloadSize, pPayloadInput)) {
			MessageBoxA(NULL, "Failed To Write The Encrypted Bin File", "ERROR !", MB_OK | MB_ICONERROR);
		}

		goto _EndOfFunction;
	}

_EndOfFunction:
	if (pPayloadInput != NULL)
		HeapFree(GetProcessHeap(), 0, pPayloadInput);
	if (pCipherText != NULL)
		HeapFree(GetProcessHeap(), 0, pCipherText);
	return 0;
}


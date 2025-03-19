#pragma once


#include <Windows.h>

#ifndef COMMON_H
#define COMMON_H




// to help identifying user input
#define AESENCRYPTION		0x311
#define RC4ENCRYPTION		0x133

// to help working with encryption algorithms
#define RC4KEYSIZE				16

#define AESKEYSIZE				32
#define AESIVSIZE				16




//-------------------------------------------------------------------------------------------------------------------------------
// 
// from IO.c
// read file from disk 
BOOL ReadPayloadFile(const char* FileInput, PDWORD sPayloadSize, unsigned char** pPayloadData);
// write file to disk
BOOL WritePayloadFile(const char* FileInput, DWORD sPayloadSize, unsigned char* pPayloadData);
//-------------------------------------------------------------------------------------------------------------------------------




//-------------------------------------------------------------------------------------------------------------------------------
// 
// from StringFunctions.c
// print the decryption / deobfuscation function (as a string) to the screen
VOID PrintDecodeFunctionality(IN INT TYPE);
//-------------------------------------------------------------------------------------------------------------------------------




//-------------------------------------------------------------------------------------------------------------------------------
// 
// from Encryption.c
// generate random bytes of size "sSize"
VOID GenerateRandomBytes(PBYTE pByte, SIZE_T sSize);
// print the input buffer as a hex char array (c syntax)
VOID PrintHexData(LPCSTR Name, PBYTE Data, SIZE_T Size);
//-------------------------------------------------------------------------------------------------------------------------------




//-------------------------------------------------------------------------------------------------------------------------------
// 
// from Encryption.c
// wrapper function for InstallAesEncryption that make things easier
BOOL SimpleEncryption(IN PVOID pPlainTextData, IN DWORD sPlainTextSize, IN PBYTE pKey, IN PBYTE pIv, OUT PVOID* pCipherTextData, OUT DWORD* sCipherTextSize);
// do the rc4 encryption
BOOL Rc4EncryptionViSystemFunc032(IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize);
//-------------------------------------------------------------------------------------------------------------------------------






#endif // !COMMON_H

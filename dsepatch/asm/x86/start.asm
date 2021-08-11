;;
;; Disables driver signing enforcement from
;; usermode, and loads a requested driver
;; into memory.
;;
;; Do to the lack of a driver and usage of
;; a userland bug, this project remains 
;; closed source.
;;
[BITS 32]

GLOBAL _NtUserSetInformationThread@16
GLOBAL _NtUserHardErrorControl@12
GLOBAL _Leave
GLOBAL _GetIp

[SECTION .text$E]

_NtUserSetInformationThread@16:
	mov	eax, 0xC0000002
	ret

_NtUserHardErrorControl@12:
	;;
	;; NOT IMPLEMENTED ON X86 YET
	;;
	mov	eax, 0xC0000002
	ret

_GetIp:
	;;
	;; Execute next instruction
	;;
	call	_get_ret_ptr

_get_ret_ptr:
	;;
	;; Pop address of stack
	;;
	pop	eax
	sub	eax, 5
	ret

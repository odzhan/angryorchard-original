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

GLOBAL _Start
GLOBAL _Leave
GLOBAL _GetIp
GLOBAL _Table

EXTERN _DsePatch

[SECTION .text$C]

_Start:
	;;
	;; Prepare the stack
	;;
	push	ebp
	mov	ebp, esp
	
	;;
	;; Disable DSE
	;;
	call	_DsePatch

	;;
	;; Cleanup the stack
	;;
	mov	esp, ebp
	pop	ebp

	;;
	;; Return
	;;
	ret

[SECTION .text$E]

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

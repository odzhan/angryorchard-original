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

GLOBAL _Leave
GLOBAL _GetIp

[SECTION .text$D]

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

_Leave:
	db 'E', 'N', 'D', 'O', 'F', 'C', 'O', 'D', 'E'

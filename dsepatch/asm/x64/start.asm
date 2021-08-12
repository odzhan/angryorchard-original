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

GLOBAL Leave
GLOBAL GetIp

[SECTION .text$D]

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

Leave:
	db 'E', 'N', 'D', 'O', 'F', 'C', 'O', 'D', 'E'

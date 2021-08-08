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

GLOBAL Start
GLOBAL Leave
GLOBAL GetIp
GLOBAL Table

EXTERN DsePatch

[SECTION .text$C]

Start:
	;;
	;; Prepare the stack
	;;
	push	rsi
	mov	rsi, rsp
	and	rsp, 0FFFFFFFFFFFFFFF0h

	;;
	;; Disable DSE
	;;
	call	DsePatch

	;;
	;; Cleanup
	;;
	mov	rsp, rsi
	pop	rsi

	;;
	;; Return
	;;
	ret

[SECTION .text$E]

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

;;
;; Disables driver signing enforcement from
;; usermode, and loads a requested driver
;; into memory.
;;
;; Do to the lack of a driver and usage of
;; a userland bug, this project remains 
;; closed source.
;;

GLOBAL	BofStart
GLOBAL _BofStart

[SECTION .text]

%ifidn __OUTPUT_FORMAT__, win32
	_BofStart:
		incbin "ppinject.x86.bin"
%else
	BofStart:
		incbin "ppinject.x64.bin"
%endif

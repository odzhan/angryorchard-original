CC_X64 := x86_64-w64-mingw32-gcc
CC_X86 := i686-w64-mingw32-gcc

CFLAGS := $(CFLAGS) -Os -fno-asynchronous-unwind-tables -nostdlib
CFLAGS := $(CFLAGS) -fno-ident -fpack-struct=8 -falign-functions=1
CFLAGS := $(CFLAGS) -s -ffunction-sections -falign-jumps=1 
CFLAGS := $(CFLAGS) -falign-labels=1 -fPIC
CFLAGS := $(CFLAGS) -Wl,-s,--no-seh,--enable-stdcall-fixup

all:
	##
	## Constructs the raw binary shellcode.
	##
	@ nasm -f win32 asm/x86/start.asm -o start.x86.o
	@ nasm -f win64 asm/x64/start.asm -o start.x64.o
	@ $(CC_X86) *.c start.x86.o -o ppinject.x86.exe $(CFLAGS)
	@ $(CC_X64) *.c start.x64.o -o ppinject.x64.exe $(CFLAGS)
	@ python3 python3/ExtractBin.py -f ppinject.x86.exe -o ppinject.x86.bin
	@ python3 python3/ExtractBin.py -f ppinject.x64.exe -o ppinject.x64.bin

clean:
	rm -rf *.o
	rm -rf *.exe
	rm -rf *.bin

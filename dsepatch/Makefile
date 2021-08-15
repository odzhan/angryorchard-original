CC_X64 := x86_64-w64-mingw32-gcc
LD_X64 := x86_64-w64-mingw32-ld
CC_X86 := i686-w64-mingw32-gcc
LD_X86 := i686-w64-mingw32-ld

CFLAGS := $(CFLAGS) -Os -fno-asynchronous-unwind-tables -nostdlib
CFLAGS := $(CFLAGS) -fno-ident -fpack-struct=8 -falign-functions=1
CFLAGS := $(CFLAGS) -s -ffunction-sections -falign-jumps=1 
CFLAGS := $(CFLAGS) -falign-labels=1 -fPIC
CFLAGS := $(CFLAGS) -Wl,-s,--no-seh,--enable-stdcall-fixup,-TSectionLink.ld

all:
	@ nasm -f win64 asm/x64/start.asm -o start.x64.o
	@ $(CC_X64) *.c start.x64.o -o dsepatch.x64.exe $(CFLAGS)
	@ python3 python3/ExtractBin.py -f dsepatch.x64.exe -o dsepatch.x64.bin
	@ nasm -f win64 bof/dsepatch.asm -o dsepatch_asm.x64.o
	@ $(CC_X64) bof/dsepatch.c -c -o dsepatch_bof.x64.o -Os -s -Qn
	@ $(LD_X64) -x -r dsepatch_bof.x64.o dsepatch_asm.x64.o -o dsepatch.x64.o

clean:
	rm -rf *.o
	rm -rf *.exe
	rm -rf *.bin

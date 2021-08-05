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
	@ nasm -f win32 asm/x86/start.asm -o start.x86.o
	@ nasm -f win64 asm/x64/start.asm -o start.x64.o
	@ $(CC_X86) *.c start.x86.o -o ppinject.x86.exe $(CFLAGS)
	@ $(CC_X64) *.c start.x64.o -o ppinject.x64.exe $(CFLAGS)
	@ python3 python3/ExtractBin.py -f ppinject.x86.exe -o ppinject.x86.bin
	@ python3 python3/ExtractBin.py -f ppinject.x64.exe -o ppinject.x64.bin
	@ nasm -f win32 bof/ppinject.asm -o ppinject_asm.x86.o
	@ nasm -f win64 bof/ppinject.asm -o ppinject_asm.x64.o
	@ $(CC_X86) bof/ppinject.c -c -o ppinject_bof.x86.o -Os -s -Qn
	@ $(CC_X64) bof/ppinject.c -c -o ppinject_bof.x64.o -Os -s -Qn
	@ $(LD_X86) -x -r ppinject_bof.x86.o ppinject_asm.x86.o -o ppinject.x86.o
	@ $(LD_X64) -x -r ppinject_bof.x64.o ppinject_asm.x64.o -o ppinject.x64.o

clean:
	rm -rf *.o
	rm -rf *.exe
	rm -rf *.bin

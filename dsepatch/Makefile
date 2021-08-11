CC_X64 := x86_64-w64-mingw32-gcc
LD_X64 := x86_64-w64-mingw32-ld
CC_X86 := i686-w64-mingw32-gcc
LD_X86 := i686-w64-mingw32-ld

CFLAGS := $(CFLAGS) -Os -fno-asynchronous-unwind-tables -shared -nostdlib
CFLAGS := $(CFLAGS) -fno-ident -fpack-struct=8 -falign-functions=1
CFLAGS := $(CFLAGS) -s -ffunction-sections -falign-jumps=1 
CFLAGS := $(CFLAGS) -falign-labels=1 -fPIC
CFLAGS := $(CFLAGS) -Wl,-s,--no-seh,--enable-stdcall-fixup,--exclude-all-symbols
LFLAGS := -lkernel32 -lntdll

all:
	@ nasm -f win32 asm/x86/start.asm -o start.x86.o
	@ nasm -f win64 asm/x64/start.asm -o start.x64.o
	@ $(CC_X86) *.c start.x86.o -o dsepatch.x86.dll $(LFLAGS) $(CFLAGS) -Wl,-e_DllMain
	@ $(CC_X64) *.c start.x64.o -o dsepatch.x64.dll $(LFLAGS) $(CFLAGS) -Wl,-eDllMain

clean:
	rm -rf *.o
	rm -rf *.dll

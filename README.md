# About

Abuses a usermode bug in CSRSS to elevate the current threads access level to that of KernelMode, allowing an attacker arbitrary read & write access to restricted memory through NTDLL!NtReadVirtualMemory and NTDLL!NtWriteVirtualMemory. The elevated thread will utilize this issue to disable Driver Signing Enforcement, and load an arbitrary driver on disk into memory.

Because of the bugs nature, despite it being a admin-kernel boundary for servicing by Microsoft, I cannot risk the issue being patched by the core developers, and as such, the source code will not be provided, and binaries must not be run on a compromised host or virtual machine where Microsoft Windows Defender may lift the objects from disk.

To access CSRSS from a privileged process, we abuse a bug in DefineDosServices to create a entry in KnownDLLs, and inject our payload DLL into a child protected process. This child protected process then re-injects itself into csrss before dying promptly. This issue remains documented and unfixed as of the latest versions of Windows.

## Build

Building the payload and injector requires a copy of `mingw-w64`, `nasm`, and `python3` installed on the development box. Once you have these depencies, it is recommended to then install the python dependencies from pip.

After you have completed these steps, please run `make` to construct the injector and payload.

## Release

If you choose not to build the files from source, I have provided signed release binaries. To ensure they have not been tampered with, my signature should be checked for validity.
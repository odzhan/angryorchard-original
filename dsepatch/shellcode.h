/**
 *
 * Disables driver signing enforcement from
 * usermode, and loads a requested driver
 * into memory.
 *
 * Do to the lack of a driver and usage of
 * a userland bug, this project remains 
 * closed source.
 *
**/

#pragma once

/**
 *
 * Purpose:
 *
 * Executes a kernel shellcode over a device
 * control request. Acts as a hook on Beep's
 * IRP_MJ_DEVICE_CONTROL routine
 *
**/
D_SEC( C ) NTSTATUS NTAPI KernelShellcode( _In_ PDRIVER_OBJECT Driver, _In_ PVOID Irp );

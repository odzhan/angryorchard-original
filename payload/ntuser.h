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

typedef enum 
{
	HardErrorDetachNoQueue = 6
} HARDERRORCONTROL;

typedef struct 
{
	HANDLE	pDeskRestore;
	HANDLE	pDeskNew;
} DESKTOPRESTOREDATA, *PDESKTOPRESTOREDATA;

NTSYSCALLAPI
UINT
NTAPI
NtUserHardErrorControl(
	_In_ HARDERRORCONTROL Command,
	_In_ HANDLE ThreadHandle,
	_Out_opt_ PDESKTOPRESTOREDATA RestoreData
);

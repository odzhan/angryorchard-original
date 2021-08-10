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
	UserThreadUseDesktop = 7
} USERTHREADINFOCLASS;

typedef enum 
{
	HardErrorDetachNoQueue = 6
} HARDERRORCONTROL;

typedef struct
{
	DWORD	Status;
} USERTHREAD_HANGSTATUS, *PUSERTHREAD_HUNGSTATUS;

typedef struct 
{
	HANDLE	pDeskRestore;
	HANDLE	pDeskNew;
} DESKTOPRESTOREDATA, *PDESKTOPRESTOREDATA;

typedef struct
{
	HANDLE			hThread;
	DESKTOPRESTOREDATA	Restore;
} USERTHREAD_USEDESKTOP, *PUSERTHREAD_USEDESKTOP;

NTSTATUS
NTAPI
NtUserQueryInformationThread(
	_In_ HANDLE Thread,
	_In_ ULONG ThreadInfoClass,
	_Out_ PVOID ThreadInformation,
	_In_ ULONG ThreadInformationLength,
	_In_ PULONG ReturnLength
);

NTSTATUS
NTAPI
NtUserSetInformationThread(
	_In_ HANDLE Thread,
	_In_ USERTHREADINFOCLASS Class,
	_In_ PVOID Information,
	_In_ ULONG InformationLength
);

NTSTATUS
NTAPI
NtUserHardErrorControl(
	_In_ HARDERRORCONTROL Command,
	_In_ HANDLE ThreadHandle,
	_Out_opt_ PDESKTOPRESTOREDATA RestoreData
);

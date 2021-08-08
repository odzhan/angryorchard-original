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

#include "common.h"

/**
 *
 * Purpose:
 *
 * Executes NtUserHardErrorControl in the context of 
 * CSRSS to elevate the current thread to KernelMode
 * and disable DSE.
 *
**/

D_SEC( B ) BOOL WINAPI DllMain( _In_ HINSTANCE Instance, _In_ DWORD Reason, _In_ LPVOID Parameter ) 
{
	return FALSE;
};

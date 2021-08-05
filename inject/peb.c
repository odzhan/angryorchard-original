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
 * Finds a loaded module in memory.
 *
**/

D_SEC( B ) PVOID PebGetModule( _In_ UINT32 Hash ) 
{
	PPEB			Peb = NULL;
	PLIST_ENTRY		Ent = NULL;
	PLIST_ENTRY		Hdr = NULL;
	PLDR_DATA_TABLE_ENTRY	Ldr = NULL;

	Peb = NtCurrentTeb()->ProcessEnvironmentBlock;
	Hdr = & Peb->Ldr->InLoadOrderModuleList;
	Ent = Hdr->Flink;

	for ( ; Hdr != Ent ; Ent = Ent->Flink ) {
		Ldr = C_PTR( Ent );

		if ( HashString( Ldr->BaseDllName.Buffer, Ldr->BaseDllName.Length ) == Hash ) {
			return C_PTR( Ldr->DllBase );
		};
	};
	return NULL;
};

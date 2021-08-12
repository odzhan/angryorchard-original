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
 * Performs a format string operation on an ANSI string,
 * and converts the result to Unicode. The resulting
 * buffer must be freed with LocalFree.
 *
**/

D_SEC( B ) LPWSTR StringPrintAToW( _In_ PAPI Api, _In_ LPSTR Format, ... ) 
{
	INT		Len = 0 ;
	LPSTR		aSt = NULL;
	LPWSTR		wSt = NULL;
	va_list		Lst = NULL;

	ANSI_STRING	Ani;
	UNICODE_STRING	Uni;

	RtlSecureZeroMemory( &Ani, sizeof( Ani ) );
	RtlSecureZeroMemory( &Uni, sizeof( Uni ) );

	va_start( Lst, Format );
	Len = Api->_vsnprintf( NULL, 0, Format, Lst );
	va_end( Lst );

	if ( ( aSt = Api->LocalAlloc( LPTR, Len + 1 ) ) ) {
		va_start( Lst, Format );
		Api->_vsnprintf( aSt, Len, Format, Lst );
		va_end( Lst );

		Api->RtlInitAnsiString( &Ani, aSt );
		Uni.MaximumLength = Api->RtlAnsiStringToUnicodeSize( &Ani );
		Uni.Length        = Api->RtlAnsiStringToUnicodeSize( &Ani );

		if ( ( Uni.Buffer = Api->LocalAlloc( LPTR, Uni.Length + 2 ) ) ) {
			Api->RtlAnsiStringToUnicodeString( &Uni, &Ani, FALSE );
			wSt = Uni.Buffer;
		};
		Api->LocalFree( aSt );
	};
	return wSt;
};

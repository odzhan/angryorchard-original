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
 * Performs a format string operation on an ANSI string,
 * and converts the result to Unicode. The resulting
 * buffer must be freed with LocalFree.
 *
**/

D_SEC( B ) LPWSTR StringPrintAToW( _In_ PAPI Api, _In_ LPSTR Format, ... );

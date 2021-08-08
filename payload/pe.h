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
 * Parses a PE for a specified export. 
 *
**/

D_SEC( D ) PVOID PeGetFuncEat( _In_ PVOID Image, _In_ UINT32 Hash );

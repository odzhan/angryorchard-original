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
 * Acquires a pointer to an object based on its
 * handle.
 *
**/

D_SEC( B ) PVOID ObjFromHandle( _In_ PBEACON_API BeaconApi, _In_ PAPI Api, _In_ HANDLE Pointer );

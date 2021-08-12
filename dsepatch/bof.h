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
 * Injects a arbitrary unsigned DLL into a protected
 * process. Leverages a bug in DefineDosServices and
 * Application Verifiers to force the DLL to load.
 *
**/

D_SEC( A ) VOID BofStart( _In_ PBEACON_API BeaconApi, _In_ PVOID Argv, _In_ INT Argc );

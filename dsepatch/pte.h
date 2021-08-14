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
 * Attempts to use the elevated thread to
 * to disable DSE by modifying the PTE
 * and overwriting g_CiOptions.
 *
**/

D_SEC( B ) VOID WINAPI DsePatchPte( _In_ PBEACON_API BeaconApi, _In_ PAPI Api );

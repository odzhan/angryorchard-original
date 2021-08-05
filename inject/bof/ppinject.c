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

#include "../common.h"

VOID SpawnProtectedProcessWithLibrary( _In_ PVOID Argv, _In_ INT Argc ) {
	BEACON_API	Api;

	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	Api.BeaconDataExtract = BeaconDataExtract;
	Api.BeaconDataParse   = BeaconDataParse;
	Api.BeaconIsAdmin     = BeaconIsAdmin;
	Api.BeaconPrintf      = BeaconPrintf;

	BofStart( &Api, Argv, Argc );
};

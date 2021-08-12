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

#ifndef CALLBACK_OUTPUT
#define CALLBACK_OUTPUT 0x00
#endif

#ifndef CALLBACK_ERROR
#define CALLBACK_ERROR	0x0d
#endif

typedef struct {
	PCHAR 	Original;
	PCHAR 	Buffer;
	INT	Length;
	INT 	Size;
} DATAP, *PDATAP;

DECLSPEC_IMPORT
PVOID
BeaconDataExtract(
	_Inout_ PDATAP Parser, 
	_Out_ PINT Size
);

DECLSPEC_IMPORT
VOID
BeaconDataParse(
	_Inout_ PDATAP Parser,
	_In_ PCHAR Buffer,
	_In_ INT Size
);

DECLSPEC_IMPORT
INT
BeaconDataInt(
	_Inout_ PDATAP Parser
);

DECLSPEC_IMPORT
BOOL
BeaconIsAdmin(
	_In_ VOID
);

DECLSPEC_IMPORT
VOID
BeaconPrintf(
	_In_ INT Type,
	_In_ PCHAR Format,
	...
);

typedef struct {
	D_API( BeaconDataExtract );
	D_API( BeaconDataParse );
	D_API( BeaconDataInt );
	D_API( BeaconIsAdmin );
	D_API( BeaconPrintf );
} BEACON_API, *PBEACON_API;


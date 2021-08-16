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

typedef struct __attribute__(( packed )) 
{
	ULONG_PTR	ExAllocatePool;
	ULONG_PTR	ExFreePool;
} KM_TABLE, *PKM_TABLE;

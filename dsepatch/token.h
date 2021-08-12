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
 * Locates a token matching the specified SID
 * and checks if it has the available number
 * of privileges.
 *
**/

D_SEC( B ) HANDLE TokenGetTokenWithSidAndPrivilegeCount( _In_ PAPI Api, _In_ PCHAR szSid, _In_ ULONG ulCount );

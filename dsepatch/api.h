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

#define InitializeObjectAttributes( p, n, a, r, s ) { \
	( p )->Length = sizeof( OBJECT_ATTRIBUTES );  \
	( p )->RootDirectory = r;		      \
	( p )->Attributes = a;			      \
	( p )->ObjectName = n;			      \
	( p )->SecurityDescriptor = s;		      \
	( p )->SecurityQualityOfService = NULL;	      \
}

typedef enum
{
	SystemModuleInformation = 11
} SYSTEM_INFORMATION_CLASS;

typedef struct 
{
	ULONG	Length;
	HANDLE	RootDirectory;
	PUNICODE_STRING	ObjectName;
	ULONG	Attributes;
	PVOID	SecurityDescriptor;
	PVOID	SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct
{
	HANDLE	Section;
	PVOID	MappedBase;
	PVOID	ImageBase;
	ULONG	ImageSize;
	ULONG	Flags;
	USHORT	LoadOrderIndex;
	USHORT	InitOrderIndex;
	USHORT	LoadCount;
	USHORT	OffsetToFileName;
	UCHAR	FullPathName[ MAX_PATH - 4 ];
} SYSTEM_MODULE_ENTRY, *PSYSTEM_MODULE_ENTRY ;

typedef struct
{
	ULONG			Count;
	SYSTEM_MODULE_ENTRY	Module[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

NTSYSCALLAPI
NTSTATUS
NTAPI
RtlAnsiStringToUnicodeString(
	_Inout_ PUNICODE_STRING UnicodeString,
	_In_ PANSI_STRING SourceString,
	_In_ PBOOLEAN AllocateDestinationString
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtCreateSymbolicLinkObject(
	_Out_ PHANDLE LinkHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_ PUNICODE_STRING UnicodeString
);

NTSYSCALLAPI
ULONG
NTAPI
RtlAnsiStringToUnicodeSize(
	_In_ PANSI_STRING AnsiString
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtCreateDirectoryObjectEx(
	_Out_ PHANDLE DirectoryHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_ HANDLE ShadowDirectoryHandle,
	_In_ ULONG Flags
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtQuerySystemInformation(
	_In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
	_In_ PVOID SystemInformation,
	_In_ ULONG SystemInformationLength,
	_In_ PVOID ReturnLength
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtAllocateVirtualMemory(
	_In_ HANDLE ProcessHandle,
	_Inout_ PVOID* BaseAddress,
	_In_ ULONG_PTR ZeroBits,
	_Inout_ PSIZE_T RegionSize,
	_In_ ULONG AllocationType,
	_In_ ULONG Protect
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtQueryInformationToken(
	_In_ HANDLE TokenHandle,
	_In_ TOKEN_INFORMATION_CLASS TokenInformationClass,
	_Out_ PVOID TokenInformation,
	_In_ ULONG TokenInformationLength,
	_Out_ PULONG ReturnLength
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtWaitForSingleObject(
	_In_ HANDLE Handle,
	_In_ BOOLEAN Alertable,
	_In_ PLARGE_INTEGER Timeout
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtWriteVirtualMemory(
	_In_ HANDLE ProcessHandle,
	_Out_ PVOID BaseAddress,
	_In_ LPVOID Buffer,
	_In_ SIZE_T BufferSize,
	_Out_opt_ PSIZE_T NumberOfBytesWritten
);

VOID
NTAPI
RtlInitUnicodeString(
	_Out_ PUNICODE_STRING UnicodeString,
	_In_opt_ PWSTR SourceString
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtCreateTransaction(
	_Out_ PHANDLE TransactionHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ LPGUID UoW,
	_In_opt_ HANDLE TmHandle,
	_In_opt_ ULONG CreateOptions,
	_In_opt_ ULONG IsolationLevel,
	_In_opt_ ULONG IsolationFlags,
	_In_opt_ PLARGE_INTEGER Timeout,
	_In_opt_ PUNICODE_STRING Description
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtReadVirtualMemory(
	_In_ HANDLE ProcessHandle,
	_In_opt_ PVOID BaseAddress,
	_Out_ PVOID Buffer,
	_In_ SIZE_T BufferSize,
	_Out_opt_ PSIZE_T NumberOfBytesRead
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtOpenProcessToken(
	_In_ HANDLE ProcessHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_Out_ PHANDLE TokenHandle
);

VOID
NTAPI
RtlInitAnsiString(
	_Out_ PANSI_STRING AnsiString,
	_In_opt_ LPSTR SourceString
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtGetNextProcess(
	_In_ HANDLE ProcessHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ ULONG HandleAttributes,
	_In_ ULONG Flags,
	_Out_ PHANDLE NewProcessHandle
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtCreateSection(
	_Out_ PHANDLE SectionHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PLARGE_INTEGER MaxmimumSize,
	_In_ ULONG SectionPageProtection,
	_In_ ULONG AllocationAttributes,
	_In_opt_ HANDLE FileHandle
);

NTSYSAPI
NTSTATUS
NTAPI
RtlGetVersion(
	_In_ PRTL_OSVERSIONINFOW Version
);

BOOLEAN
NTAPI
RtlEqualSid(
	_In_ PSID Sid1,
	_In_ PSID Sid2
);

INT
NTAPI
_vsnprintf(
	_Inout_ PCHAR String,
	_In_ SIZE_T Count,
	_In_ PCHAR Format,
	_In_ va_list Args
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtClose(
	_In_ HANDLE Handle
);

typedef struct {
	D_API( InitializeSecurityDescriptor );
	D_API( RtlAnsiStringToUnicodeString );
	D_API( NtCreateSymbolicLinkObject );
	D_API( RtlAnsiStringToUnicodeSize );
	D_API( SetSecurityDescriptorDacl );
	D_API( NtCreateDirectoryObjectEx );
	D_API( NtQuerySystemInformation );
	D_API( SetKernelObjectSecurity );
	D_API( NtQueryInformationToken );
	D_API( CreateProcessWithTokenW );
	D_API( NtAllocateVirtualMemory );
	D_API( ConvertStringSidToSidA );
	D_API( CreateFileTransactedW );
	D_API( NtWaitForSingleObject );
	D_API( NtWriteVirtualMemory );
	D_API( RtlInitUnicodeString );
	D_API( NtCreateTransaction );
	D_API( NtReadVirtualMemory );
	D_API( NtOpenProcessToken );
	D_API( RtlInitAnsiString );
	D_API( IsTokenRestricted );
	D_API( NtGetNextProcess );
	D_API( DuplicateTokenEx );
	D_API( DefineDosDeviceW );
	D_API( RegCreateKeyExW );
	D_API( NtCreateSection );
	D_API( RegSetValueExW );
	D_API( SetThreadToken );
	D_API( LoadLibraryExA );
	D_API( GetProcAddress );
	D_API( RtlGetVersion );
	D_API( FreeLibrary );
	D_API( RtlEqualSid );
	D_API( LocalAlloc );
	D_API( _vsnprintf );
	D_API( WriteFile );
	D_API( LocalFree );
	D_API( NtClose );
	D_API( Sleep );
} API, *PAPI ;

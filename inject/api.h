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

typedef struct 
{
	ULONG	Length;
	HANDLE	RootDirectory;
	PUNICODE_STRING	ObjectName;
	ULONG	Attributes;
	PVOID	SecurityDescriptor;
	PVOID	SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

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
NtQueryInformationToken(
	_In_ HANDLE TokenHandle,
	_In_ TOKEN_INFORMATION_CLASS TokenInformationClass,
	_Out_ PVOID TokenInformation,
	_In_ ULONG TokenInformationLength,
	_Out_ PULONG ReturnLength
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

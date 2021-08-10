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

typedef enum 
{
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT ;

typedef enum 
{
	SystemHandleInformation = 0x10
} SYSTEM_INFORMATION_CLASS ;

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
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION ;

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
NtQuerySystemInformation(
	_In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
	_Out_opt_ PVOID SystemInformation,
	_In_ ULONG SystemInformationLength,
	_Out_opt_ PULONG ReturnLength
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtWaitForSingleObject(
	_In_ HANDLE Handle,
	_In_ BOOLEAN Alertable,
	_In_opt_ PLARGE_INTEGER Timeout
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtUnmapViewOfSection(
	_In_ HANDLE ProcessHandle,
	_In_ PVOID BaseAddress
);

NTSYSAPI
NTSTATUS
NTAPI
RtlCreateUserThread(
	_In_ HANDLE Process,
	_In_opt_ PSECURITY_DESCRIPTOR SecurityDescriptor,
	_In_ BOOLEAN CreateSuspended,
	_In_opt_ ULONG ZeroBits,
	_In_opt_ SIZE_T MaximumCommitSize,
	_In_opt_ SIZE_T CommitedStackSize,
	_In_ PVOID StartAddress,
	_In_opt_ PVOID Parameter,
	_Out_opt_ PHANDLE Thread,
	_Out_opt_ PCLIENT_ID ClientId
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtMapViewOfSection(
	_In_ HANDLE SectionHandle,
	_In_ HANDLE ProcessHandle,
	_Inout_ PVOID* BaseAddres,
	_In_ ULONG_PTR ZeroBits,
	_In_ SIZE_T CommitSize,
	_Inout_opt_ PLARGE_INTEGER SectionOffset,
	_Inout_ PSIZE_T ViewSize,
	_In_ SECTION_INHERIT InheritDisposition,
	_In_ ULONG AllocationType,
	_In_ ULONG Win32Protect
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtGetContextThread(
	_In_ HANDLE ThreadHandle,
	_Inout_ PCONTEXT ThreadContext
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtSetContextThread(
	_In_ HANDLE ThreadHandle,
	_Inout_ PCONTEXT ThreadContext
);

NTSYSAPI
PVOID
NTAPI
RtlReAllocateHeap(
	_In_ PVOID HeapHandle,
	_In_ ULONG Flags,
	_Inout_opt_ PVOID BaseAddress,
	_In_ SIZE_T Size
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtQueueApcThread(
	_In_ HANDLE ThreadHandle,
	_In_ LPVOID ApcRoutine,
	_In_opt_ PVOID ApcArgument1,
	_In_opt_ PVOID ApcArgument2,
	_In_opt_ PVOID ApcArgument3
);

NTSYSAPI
PVOID
NTAPI
RtlAllocateHeap(
	_In_ PVOID HeapHandle,
	_In_ ULONG Flags,
	_In_ SIZE_T Size
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtCreateSection(
	_Out_ PHANDLE Section,
	_In_ ACCESS_MASK DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PLARGE_INTEGER MaximumSize,
	_In_ ULONG SectionPageProtection,
	_In_ ULONG AllocationAttributes,
	_In_opt_ HANDLE FileHandle
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtResumeThread(
	_In_ HANDLE Thread,
	_In_opt_ PULONG SuspendCount
);

NTSYSAPI
NTSTATUS
NTAPI
RtlGetVersion(
	_Out_ PRTL_OSVERSIONINFOW VersionInformation
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtOpenProcess(
	_Out_ PHANDLE ProcessHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_ PCLIENT_ID ClientId
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtOpenThread(
	_Out_ PHANDLE ThreadHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PCLIENT_ID ClientId
);

NTSYSAPI
BOOLEAN
NTAPI
RtlFreeHeap(
	_In_ PVOID HeapHandle,
	_In_opt_ ULONG Flags,
	_Inout_opt_ PVOID BaseAddress
);

NTSYSAPI
ULONG
__cdecl
DbgPrint(
	_In_ PCH Format,
	...
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtClose(
	_In_ HANDLE Handle
);

typedef struct {
	D_API( NtUserQueryInformationThread );
	D_API( NtQuerySystemInformation );
	D_API( NtWaitForSingleObject );
	D_API( NtUnmapViewOfSection );
	D_API( RtlCreateUserThread );
	D_API( NtMapViewOfSection );
	D_API( NtGetContextThread );
	D_API( NtSetContextThread );
	D_API( RtlReAllocateHeap );
	D_API( NtQueueApcThread );
	D_API( RtlAllocateHeap );
	D_API( NtCreateSection );
	D_API( NtResumeThread );
	D_API( RtlGetVersion );
	D_API( NtOpenProcess );
	D_API( NtOpenThread );
	D_API( RtlFreeHeap );
	D_API( DbgPrint );
	D_API( NtClose );
} API;

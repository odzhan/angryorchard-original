#pragma once

typedef union _KIDTENTRY64
{
	union
	{
		struct
		{
			USHORT OffsetLow;
			USHORT Selector;
			
			struct
			{
				USHORT IstIndex		: 3;
				USHORT Reserved0	: 5;
				USHORT Type		: 5;
				USHORT Dpl		: 2;
				USHORT Present		: 1;
			};
				
			USHORT 	OffsetMiddle;
			ULONG 	OffsetHigh;
			ULONG	Reserved1;

		};

		ULONGLONG Alignment;
	};
} KIDTENTRY64, *PKIDTENTRY64;

typedef struct _KPCR
{
	union
	{
		NT_TIB NtTib;
		
		struct
		{
			PVOID 		GdtBase;
			PVOID 		TssBase;
			PVOID 		UserRsp;
			struct _KPCR * 	Self;
			PVOID 		CurrentPcrb;
			PVOID 		LockArray;
			PVOID 		Used_Self;
		};
	};

	PKIDTENTRY64	IdtBase;
	ULONGLONG	Padding[2];
	UCHAR		Irql;
} KPCR, *PKPCR;

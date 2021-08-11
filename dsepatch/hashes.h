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

#define H_LIB_KERNELBASE			0x03ebb38b
#define H_LIB_WIN32U				0x9968d8d7
#define H_LIB_NTDLL				0x1edab0ed

#define H_API_NTUSERSETINFORMATIONTHREAD	0xd4bc0b70
#define H_API_NTUSERHARDERRORCONTROL		0xd8eea850

#define H_API_NTUSERQUERYINFORMATIONTHREAD	0xde40295a
#define H_API_NTQUERYSYSTEMINFORMATION		0x7bc23928
#define H_API_NTWAITFORSINGLEOBJECT		0xe8ac0c3c
#define H_API_NTUNMAPVIEWOFSECTION		0x6aa412cd
#define H_API_RTLCREATEUSERTHREAD		0x6c827322
#define H_API_NTMAPVIEWOFSECTION		0xd6649bca
#define H_API_NTGETCONTEXTTHREAD		0x6d22f884
#define H_API_NTSETCONTEXTTHREAD		0xffa0bf10
#define H_API_RTLREALLOCATEHEAP			0xaf740371
#define H_API_NTQUEUEAPCTHREAD			0x0a6664b8
#define H_API_CSRGETPROCESSID			0x469970b9
#define H_API_RTLALLOCATEHEAP			0x3be94c5a
#define H_API_NTCREATESECTION			0xb80f7b50
#define H_API_NTRESUMETHREAD			0x5a4bc3d0
#define H_API_RTLGETVERSION			0x0dde5cdd
#define H_API_NTOPENPROCESS			0x4b82f718
#define H_API_NTOPENTHREAD			0x968e0cb1
#define H_API_RTLFREEHEAP			0x73a9e4d7
#define H_API_DBGPRINT				0xc127a47f
#define H_API_NTCLOSE				0x40d6e69d

#define H_STR_DATA				0x0b65d0ad

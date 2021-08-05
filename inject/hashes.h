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

#define H_LIB_ADVAPI32				0x64bb3129
#define H_LIB_KERNEL32				0x6ddb9555
#define H_LIB_NTDLL				0x1edab0ed

#define H_API_RTLANSISTRINGTOUNICODESTRING 	0x6c606cba
#define H_API_NTCREATESYMBOLICLINKOBJECT	0xfbada4a2
#define H_API_RTLANSISTRINGTOUNICODESIZE	0xd7aa575e
#define H_API_NTCREATEDIRECTORYOBJECTEX		0x185c3c24
#define H_API_NTQUERYINFORMATIONTOKEN		0x0f371fe4
#define H_API_CONVERTSTRINGSIDTOSIDA		0x0d370be1
#define H_API_RTLINITUNICODESTRING		0xef52b589
#define H_API_NTCREATETRANSACTION		0x06e54201
#define H_API_NTOPENPROCESSTOKEN		0x350dca99
#define H_API_RTLINITANSISTRING			0xa0c8436d
#define H_API_ISTOKENRESTRICTED			0x8e8025fb
#define H_API_NTGETNEXTPROCESS			0x0963c3a5
#define H_API_DUPLICATETOKENEX			0x10ad057e
#define H_API_NTCREATESECTION			0xb80f7b50
#define H_API_RTLEQUALSID			0x5f7a694f
#define H_API_LOCALALLOC			0x72073b5b
#define H_API_VSNPRINTF				0xa59022ce
#define H_API_LOCALFREE				0x32030e92
#define H_API_NTCLOSE				0x40d6e69d

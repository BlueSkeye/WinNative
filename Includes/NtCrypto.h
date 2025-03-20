#pragma once

#ifndef _NTCRYPTOGRAPHY_
#define _NTCRYPTOGRAPHY_

#include "NtCommonDefs.h"

extern "C" {

	// NO UNRESOLVED FUNCTIONS

	typedef struct _A_SHA_CTX {
		ULONG 	flag;
		UCHAR 	hash[20];
		ULONG 	state[5];
		ULONG 	count[2];
		UCHAR 	buffer[64];
	} A_SHA_CTX, *PA_SHA_CTX;

	//https://skanthak.hier-im-netz.de/download/NTDLL.H
	typedef	struct _MD4_CTX {
		DWORD	State[4];	// = {0x67452301UL, 0xEFCDAB89UL, 0x98BADCFEUL, 0x10325476UL}
		DWORD	Count[2];	// = {0UL, 0UL}
		BYTE	Buffer[64];
		BYTE	Digest[16];
	} MD4_CTX, *LPMD4_CTX, *PMD4_CTX;

	//https://skanthak.hier-im-netz.de/download/NTDLL.H
	typedef	struct _MD5_CTX
	{
		DWORD	Count[2];	// = {0UL, 0UL}
		DWORD	State[4];	// = {0x67452301UL, 0xEFCDAB89UL, 0x98BADCFEUL, 0x10325476UL}
		BYTE	Buffer[64];
		BYTE	Digest[16];
	} MD5_CTX, *LPMD5_CTX, *PMD5_CTX;

	// https://processhacker.sourceforge.io/doc/sha_8h.html
	NTSYSCALLAPI VOID NTAPI A_SHAFinal(
		_Inout_ PA_SHA_CTX Context,
		_Out_writes_bytes_(20) UCHAR* Hash);

	// https://processhacker.sourceforge.io/doc/sha_8h.html
	NTSYSCALLAPI VOID NTAPI A_SHAInit(
		_Inout_ PA_SHA_CTX Context);

	// https://processhacker.sourceforge.io/doc/sha_8h.html
	NTSYSCALLAPI void NTAPI A_SHAUpdate(
		_Inout_ PA_SHA_CTX Context,
		_In_ PUCHAR Buffer,
		unsigned int BufferSize);

	//https://skanthak.hier-im-netz.de/download/NTDLL.H
	NTSYSCALLAPI VOID NTAPI	MD4Final(
		PMD4_CTX Context);

	//https://skanthak.hier-im-netz.de/download/NTDLL.H
	NTSYSCALLAPI VOID NTAPI MD4Init(
		PMD4_CTX Context);

	//https://skanthak.hier-im-netz.de/download/NTDLL.H
	NTSYSCALLAPI VOID NTAPI MD4Update(PMD4_CTX Context,
		LPCVOID Buffer,
		DWORD   BufferSize);

	//https://skanthak.hier-im-netz.de/download/NTDLL.H
	NTSYSCALLAPI VOID NTAPI MD5Final(
		MD5_CTX* Context);

	//https://skanthak.hier-im-netz.de/download/NTDLL.H
	NTSYSCALLAPI VOID NTAPI MD5Init(
		MD5_CTX* Context);

	//https://skanthak.hier-im-netz.de/download/NTDLL.H
	NTSYSCALLAPI VOID NTAPI MD5Update(MD5_CTX* Context,
		LPCVOID Buffer,
		DWORD   BufferSize);

}

#endif // _NTCRYPTOGRAPHY_
#pragma once

#ifndef _NTCRYPTOGRAPHY_
#define _NTCRYPTOGRAPHY_

#include "NtCommonDefs.h"

extern "C" {

	// NO UNRESOLVED FUNCTIONS

	//https://skanthak.hier-im-netz.de/download/NTDLL.H
	typedef	struct _MD4_CTX
	{
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

	// https://learn.microsoft.com/fr-fr/windows/win32/seccrypto/a-shafinal
	NTSYSCALLAPI VOID RSA32API A_SHAFinal(
		_Inout_ A_SHA_CTX* Context,
		_Out_   UNSIGNED CHAR Result);

	// https://learn.microsoft.com/fr-fr/windows/win32/seccrypto/a-shainit
	NTSYSCALLAPI void RSA32API A_SHAInit(
		_Inout_ A_SHA_CTX* Context);

	//https://learn.microsoft.com/fr-fr/windows/win32/seccrypto/a-shaupdate
	NTSYSCALLAPI void RSA32API A_SHAUpdate(
		_Inout_ A_SHA_CTX* Context,
		_In_    UNSIGNED CHAR* Buffer,
		UNSIGNED INT  BufferSize);

	//https://skanthak.hier-im-netz.de/download/NTDLL.H
	NTSYSCALLAPI VOID NTAPI	MD4Final(
		MD4_CTX* Context);

	//https://skanthak.hier-im-netz.de/download/NTDLL.H
	NTSYSCALLAPI VOID NTAPI MD4Init(
		MD4_CTX* Context);

	//https://skanthak.hier-im-netz.de/download/NTDLL.H
	NTSYSCALLAPI VOID NTAPI MD4Update(MD4_CTX* Context,
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
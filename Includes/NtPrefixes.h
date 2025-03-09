#pragma once

#ifndef _NTPREFIXES_
#define _NTPREFIXES_

#include "NtCommonDefs.h"

extern "C" {

	// NO UNRESOLVED FUNCTIONS

	//https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI PPREFIX_TABLE_ENTRY NTAPI PfxFindPrefix(
		_In_ PPREFIX_TABLE PrefixTable,
		_In_ PSTRING FullName);

	//https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI VOID NTAPI PfxInitialize(
		_Out_ PPREFIX_TABLE PrefixTable);

	//https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI BOOLEAN NTAPI PfxInsertPrefix(
		_In_ PPREFIX_TABLE PrefixTable,
		_In_ PSTRING Prefix,
		_Out_ PPREFIX_TABLE_ENTRY PrefixTableEntry);

	//https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI VOID NTAPI PfxRemovePrefix(
		_In_ PPREFIX_TABLE PrefixTable,
		_In_ PPREFIX_TABLE_ENTRY PrefixTableEntry);

}

#endif // _NTPREFIXES_
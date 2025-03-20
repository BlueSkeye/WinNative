#pragma once

#ifndef _NTPREFIXES_
#define _NTPREFIXES_

#include "NtCommonDefs.h"

extern "C" {

	// NO UNRESOLVED FUNCTIONS

	// https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntrtl.h#L2445C1-L2452C44
	typedef struct _PREFIX_TABLE_ENTRY {
		CSHORT NodeTypeCode;
		CSHORT NameLength;
		struct _PREFIX_TABLE_ENTRY* NextPrefixTree;
		RTL_SPLAY_LINKS Links;
		PSTRING Prefix;
	} PREFIX_TABLE_ENTRY, * PPREFIX_TABLE_ENTRY;

	// https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntrtl.h#L2454C1-L2459C32
	typedef struct _PREFIX_TABLE {
		CSHORT NodeTypeCode;
		CSHORT NameLength;
		PPREFIX_TABLE_ENTRY NextPrefixTree;
	} PREFIX_TABLE, * PPREFIX_TABLE;

	// =========================== functions

	// https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntrtl.h#L2485
	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
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
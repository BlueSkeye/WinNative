#pragma once

#ifndef _NTRUNTIMEFUNCTIONS_
#define _NTRUNTIMEFUNCTIONS_

#include "NtCommonDefs.h"

extern "C" {

	typedef struct _IMAGE_RUNTIME_FUNCTION_ENTRY {
		DWORD BeginAddress;
		DWORD EndAddress;
		union {
			DWORD UnwindInfoAddress;
			DWORD UnwindData;
		} DUMMYUNIONNAME;
	} _IMAGE_RUNTIME_FUNCTION_ENTRY, RUNTIME_FUNCTION, * _PIMAGE_RUNTIME_FUNCTION_ENTRY, * PRUNTIME_FUNCTION;

	// From winnt.h
#define IMAGE_SIZEOF_SHORT_NAME 8
	typedef struct _IMAGE_SECTION_HEADER {
		BYTE Name[IMAGE_SIZEOF_SHORT_NAME];
		union {
			DWORD   PhysicalAddress;
			DWORD   VirtualSize;
		} Misc;
		DWORD   VirtualAddress;
		DWORD   SizeOfRawData;
		DWORD   PointerToRawData;
		DWORD   PointerToRelocations;
		DWORD   PointerToLinenumbers;
		WORD    NumberOfRelocations;
		WORD    NumberOfLinenumbers;
		DWORD   Characteristics;
	} IMAGE_SECTION_HEADER, * PIMAGE_SECTION_HEADER;

	typedef PRUNTIME_FUNCTION(NTAPI* PGET_RUNTIME_FUNCTION_CALLBACK)(
		_In_ DWORD64 ControlPc,
		_In_opt_ PVOID Context);

}

#endif // _NTRUNTIMEFUNCTIONS_
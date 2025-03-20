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
	} _IMAGE_RUNTIME_FUNCTION_ENTRY, * _PIMAGE_RUNTIME_FUNCTION_ENTRY;

	typedef struct _IMAGE_RUNTIME_FUNCTION_ENTRY RUNTIME_FUNCTION, * PRUNTIME_FUNCTION;

}

#endif // _NTRUNTIMEFUNCTIONS_
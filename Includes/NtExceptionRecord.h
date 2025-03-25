#pragma once

#ifndef _NTEXCEPTIONRECORD_
#define _NTEXCEPTIONRECORD_

#include "NtCommonDefs.h"

#ifdef __cplusplus
extern "C" {
#endif

#define EXCEPTION_MAXIMUM_PARAMETERS 15

	typedef struct _EXCEPTION_RECORD EXCEPTION_RECORD, * PEXCEPTION_RECORD;

	// https://doxygen.reactos.org/d5/dde/struct__EXCEPTION__RECORD.html
	struct _EXCEPTION_RECORD {
		DWORD ExceptionCode;
		DWORD ExceptionFlags;
		PEXCEPTION_RECORD ExceptionRecord;
		PVOID ExceptionAddress;
		DWORD NumberParameters;
		ULONG_PTR ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
	};

#ifdef __cplusplus
}
#endif

#endif // _NTEXCEPTIONRECORD_
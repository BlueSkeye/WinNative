#pragma once

#ifndef _NTEXCEPTIONS_
#define _NTEXCEPTIONS_

#include "NtCommonDefs.h"
#include "NtRuntimeFunctions.h"

#ifdef __cplusplus
extern "C" {
#endif

	// NO UNRESOLVED FUNCTIONS

	typedef struct _EXCEPTION_POINTERS {
		PEXCEPTION_RECORD ExceptionRecord;
		PCONTEXT          ContextRecord;
	} EXCEPTION_POINTERS, * PEXCEPTION_POINTERS;

	// From errhandlingapi.h
	typedef LONG(NTAPI* PTOP_LEVEL_EXCEPTION_FILTER)(
		_In_ struct _EXCEPTION_POINTERS* ExceptionInfo);
	typedef PTOP_LEVEL_EXCEPTION_FILTER LPTOP_LEVEL_EXCEPTION_FILTER;

	// From rtlsupportapi.h
#define UNWIND_HISTORY_TABLE_SIZE 12
	typedef struct _UNWIND_HISTORY_TABLE_ENTRY {
		ULONG_PTR ImageBase;
		PRUNTIME_FUNCTION FunctionEntry;
	} UNWIND_HISTORY_TABLE_ENTRY, * PUNWIND_HISTORY_TABLE_ENTRY;
	typedef struct _UNWIND_HISTORY_TABLE {
		ULONG Count;
		UCHAR LocalHint;
		UCHAR GlobalHint;
		UCHAR Search;
		UCHAR Once;
		ULONG_PTR LowAddress;
		ULONG_PTR HighAddress;
		UNWIND_HISTORY_TABLE_ENTRY Entry[UNWIND_HISTORY_TABLE_SIZE];
	} UNWIND_HISTORY_TABLE, * PUNWIND_HISTORY_TABLE;

	// https://doxygen.reactos.org/d5/df7/ndk_2rtltypes_8h.html#a7261fc01cbea64ed8c51ca805a82c31b
	typedef LONG(NTAPI* PVECTORED_EXCEPTION_HANDLER) (PEXCEPTION_POINTERS ExceptionPointers);

	// =============================== functions ===============================
	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSAPI NTSTATUS NTAPI NtContinue(
		_In_ PCONTEXT Context,
		_In_ BOOLEAN bTest);
	//ZwContinue

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSAPI NTSTATUS NTAPI NtContinueEx(
		_In_ PCONTEXT Context,
		_In_ BOOLEAN bTest);
	//ZwContinueEx

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSAPI NTSTATUS NTAPI NtRaiseException(
		_In_ PEXCEPTION_RECORD Record,
		_In_ PCONTEXT Context,
		_In_ BOOL SearchFrames);
	//ZwRaiseException

	// https://github.com/reactos/wine/blob/master/dlls/ntdll/exception.c
	NTSYSAPI PVOID NTAPI RtlAddVectoredContinueHandler(
		ULONG first,
		PVECTORED_EXCEPTION_HANDLER func);

	// https://github.com/reactos/wine/blob/master/dlls/ntdll/exception.c
	NTSYSAPI PVOID NTAPI /*DECLSPEC_HOTPATCH*/ RtlAddVectoredExceptionHandler(
		ULONG first,
		PVECTORED_EXCEPTION_HANDLER func);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntxcapi.h#L111
	_Analysis_noreturn_ NTSYSAPI __declspec(noreturn) VOID NTAPI RtlAssert(
		_In_ PVOID VoidFailedAssertion,
		_In_ PVOID VoidFileName,
		_In_ ULONG LineNumber,
		_In_opt_ PSTR MutableMessage);

	// https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntrtl.h#L3778C1-L3783C7
	NTSYSAPI LONG NTAPI RtlKnownExceptionFilter(
		_In_ PEXCEPTION_POINTERS ExceptionPointers);

	// https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-rtllookupfunctionentry
	NTSYSAPI PRUNTIME_FUNCTION RtlLookupFunctionEntry(
		_In_ DWORD64 ControlPc,
		_Out_ PDWORD64 ImageBase,
		_Out_ PUNWIND_HISTORY_TABLE HistoryTable);

	// https://learn.microsoft.com/fr-fr/windows/win32/api/rtlsupportapi/nf-rtlsupportapi-rtlraiseexception
	NTSYSAPI VOID NTAPI RtlRaiseException(
		_In_ PEXCEPTION_RECORD ExceptionRecord);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntxcapi.h#L36
	NTSYSAPI VOID NTAPI RtlRaiseExceptionForReturnAddressHijack(VOID);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntxcapi.h#L44
	_Analysis_noreturn_ NTSYSAPI __declspec(noreturn) VOID NTAPI RtlRaiseNoncontinuableException(
		_In_ PEXCEPTION_RECORD ExceptionRecord,
		_In_ PCONTEXT ContextRecord);

	// https://github.com/reactos/wine/blob/master/dlls/ntdll/exception.c
	NTSYSAPI VOID NTAPI RtlRaiseStatus(
		NTSTATUS status);

	// https://github.com/reactos/wine/blob/master/dlls/ntdll/exception.c
	NTSYSAPI ULONG NTAPI RtlRemoveVectoredContinueHandler(
		PVOID handler);

	// https://github.com/reactos/wine/blob/master/dlls/ntdll/exception.c
	NTSYSAPI ULONG NTAPI RtlRemoveVectoredExceptionHandler(
		PVOID handler);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI NTSTATUS NTAPI RtlReportException(
		_In_ PEXCEPTION_RECORD ExceptionRecord,
		_In_ PCONTEXT ContextRecord,
		_In_ ULONG Flags);

	// https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntrtl.h#L6568C1-L6576C7
	NTSYSAPI NTSTATUS NTAPI RtlReportExceptionEx(
		_In_ PEXCEPTION_RECORD ExceptionRecord,
		_In_ PCONTEXT ContextRecord,
		_In_ ULONG Flags,
		_In_ PLARGE_INTEGER Timeout);

	// https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-setunhandledexceptionfilter
	// From Kernel32, invoke api-ms-win-core-errorhandling-l1-1-0.dll::__imp_SetUnhandledExceptionFilter
	NTSYSAPI LPTOP_LEVEL_EXCEPTION_FILTER NTAPI RtlSetUnhandledExceptionFilter(
		_In_ LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter);

	// https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-unhandledexceptionfilter
	// From Kernel32, invoke api-ms-win-core-errorhandling-l1-1-0.dll::__imp_UnhandledExceptionFilter
	NTSYSAPI LONG NTAPI RtlUnhandledExceptionFilter(
		_In_ _EXCEPTION_POINTERS* ExceptionInfo);

	// https://doxygen.reactos.org/dc/d38/sdk_2lib_2rtl_2exception_8c.html
	NTSYSAPI LONG NTAPI RtlUnhandledExceptionFilter2(
		_In_ PEXCEPTION_POINTERS ExceptionInfo,
		_In_ ULONG Flags);

	//https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-rtlunwind
	NTSYSAPI VOID NTAPI RtlUnwind(
		_In_opt_ PVOID             TargetFrame,
		_In_opt_ PVOID             TargetIp,
		_In_opt_ PEXCEPTION_RECORD ExceptionRecord,
		_In_           PVOID             ReturnValue);

	// https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-rtlunwindex
	NTSYSAPI VOID NTAPI RtlUnwindEx(
		_In_opt_ PVOID                 TargetFrame,
		_In_opt_ PVOID                 TargetIp,
		_In_opt_ PEXCEPTION_RECORD     ExceptionRecord,
		_In_           PVOID                 ReturnValue,
		_In_           PCONTEXT              ContextRecord,
		_In_opt_ PUNWIND_HISTORY_TABLE HistoryTable);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI NTSTATUS NTAPI RtlWerpReportException(
		_In_ ULONG ProcessId,
		_In_ HANDLE CrashReportSharedMem,
		_In_ ULONG Flags,
		_Out_ PHANDLE CrashVerticalProcessHandle);

#ifdef __cplusplus
}
#endif

#endif // _NTEXCEPTIONS_
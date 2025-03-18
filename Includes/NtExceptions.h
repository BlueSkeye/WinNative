#pragma once

#ifndef _NTEXCEPTIONS_
#define _NTEXCEPTIONS_

#include "NtCommonDefs.h"

extern "C" {

	// UNRESOLVED FUNCTIONS
	//RtlKnownExceptionFilter
	//RtlReportExceptionEx
	//WerReportExceptionWorker
	// END OF UNRESOLVED FUNCTIONS

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtContinue(
		_In_ PCONTEXT Context,
		_In_ BOOLEAN bTest);
	//ZwContinue

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtContinueEx(
		_In_ PCONTEXT Context,
		_In_ BOOLEAN bTest);
	//ZwContinueEx

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtRaiseException(
		_In_ PEXCEPTION_RECORD Record,
		_In_ PCONTEXT Context,
		_In_ BOOL SearchFrames);
	//ZwRaiseException

	// https://github.com/reactos/wine/blob/master/dlls/ntdll/exception.c
	NTSYSAPI PVOID WINAPI RtlAddVectoredContinueHandler(
		ULONG first,
		PVECTORED_EXCEPTION_HANDLER func);

	// https://github.com/reactos/wine/blob/master/dlls/ntdll/exception.c
	NTSYSAPI PVOID WINAPI DECLSPEC_HOTPATCH RtlAddVectoredExceptionHandler(
		ULONG first,
		PVECTORED_EXCEPTION_HANDLER func);


	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntxcapi.h#L111
	_Analysis_noreturn_ NTSYSCALLAPI DECLSPEC_NORETURN VOID NTAPI RtlAssert(
		_In_ PVOID VoidFailedAssertion,
		_In_ PVOID VoidFileName,
		_In_ ULONG LineNumber,
		_In_opt_ PSTR MutableMessage);

	// https://learn.microsoft.com/fr-fr/windows/win32/api/rtlsupportapi/nf-rtlsupportapi-rtlraiseexception
	NTSYSAPI VOID NTAPI RtlRaiseException(
		_In_ PEXCEPTION_RECORD ExceptionRecord);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntxcapi.h#L36
	NTSYSAPI VOID NTAPI RtlRaiseExceptionForReturnAddressHijack(VOID);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntxcapi.h#L44
	_Analysis_noreturn_ NTSYSAPI DECLSPEC_NORETURN VOID NTAPI RtlRaiseNoncontinuableException(
		_In_ PEXCEPTION_RECORD ExceptionRecord,
		_In_ PCONTEXT ContextRecord);

	// https://github.com/reactos/wine/blob/master/dlls/ntdll/exception.c
	NTSYSAPI VOID WINAPI RtlRaiseStatus(
		NTSTATUS status);

	// https://github.com/reactos/wine/blob/master/dlls/ntdll/exception.c
	NTSYSAPI ULONG WINAPI RtlRemoveVectoredContinueHandler(
		PVOID handler);

	// https://github.com/reactos/wine/blob/master/dlls/ntdll/exception.c
	NTSYSAPI ULONG WINAPI RtlRemoveVectoredExceptionHandler(
		PVOID handler);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI NTSTATUS NTAPI RtlReportException(
		_In_ PEXCEPTION_RECORD ExceptionRecord,
		_In_ PCONTEXT ContextRecord,
		_In_ ULONG Flags);

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

}

#endif // _NTEXCEPTIONS_
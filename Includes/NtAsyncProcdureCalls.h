#pragma once

#ifndef _NTASYNCPROCCALLS_
#define _NTASYNCPROCCALLS_

#include "NtCommonDefs.h"

extern "C" {

	// NO UNRESOLVED FUNCTIONS

	// https://repnz.github.io/posts/apc/user-apc/
	// https://repnz.github.io/posts/apc/wow64-user-apc/

	//https://doxygen.reactos.org/d2/d15/dll_2ntdll_2dispatch_2dispatch_8c.html
	NTSYSAPI VOID NTAPI KiRaiseUserExceptionDispatcher(VOID);

	//http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FAPC%2FKiUserApcDispatcher.html
	NTSYSAPI VOID NTAPI KiUserApcDispatcher(
		IN PVOID Unused1,
		IN PVOID Unused2,
		IN PVOID Unused3,
		IN PVOID ContextStart,
		IN PVOID ContextBody);

	//https://doxygen.reactos.org/d2/d15/dll_2ntdll_2dispatch_2dispatch_8c.html
	NTSYSAPI VOID NTAPI KiUserCallbackDispatcher(
		ULONG Index,
		PVOID Argument,
		ULONG ArgumentLength);

	// https://doxygen.reactos.org/d2/d15/dll_2ntdll_2dispatch_2dispatch_8c.html
	NTSYSAPI VOID NTAPI KiUserExceptionDispatcher(
		PEXCEPTION_RECORD ExceptionRecord,
		PCONTEXT Context);

	// See RtlpInsertInvertedFunctionTableEntry for a use example.
	NTSYSAPI LPVOID KiUserInvertedFunctionTable;

    // https://processhacker.sourceforge.io/doc/ntzwapi_8h_source.html
    NTSYSCALLAPI NTSTATUS NTAPI NtAlertThread(
        _In_ HANDLE ThreadHandle);
    //ZwAlertThread

}

#endif // _NTASYNCPROCCALLS_
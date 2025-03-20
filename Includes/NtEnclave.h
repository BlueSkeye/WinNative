#pragma once

#ifndef _NTENCLAVE_
#define _NTENCLAVE_

#include "NtCommonDefs.h"

extern "C" {

	// UNREOLVED FUNCTIONS
	// RtlEnclaveCallDispatch
	// RtlEnclaveCallDispatchReturn
	// END OF UNRESOLVED FUNCTIONS

	// Enclave related functions have strict requirements which are summarized in :
	// https://learn.microsoft.com/en-us/windows/win32/trusted-execution/enclaves
	// Basically, they require some kind of strict electronic signature by Microsoft itself.
	// The following functions are identified as enclave related, are not really documented
	// and hence are not researched at current time.

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtCallEnclave(
		_In_ PVOID Function,
		_In_ PVOID Parameter,
		_In_ BOOLEAN WaitForThread,
		_Out_opt_ PVOID* Result);
	//ZwCallEnclave

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtTerminateEnclave(
		_In_ PVOID BaseAddress,
		_In_ BOOLEAN WaitForThread);
	//ZwTerminateEnclave

}

#endif // _NTENCLAVE_
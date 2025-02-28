#pragma once

#ifndef _NTATOMS_
#define _NTATOMS_

#include "NtCommonDefs.h"

extern "C" {

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtAddAtom(
		_In_ PWSTR AtomName,
		_In_ ULONG AtomNameLength,
		_Out_ PRTL_ATOM Atom);
	//ZwAddAtom

	//NtAddAtomEx
	NTSYSCALLAPI NTSTATUS NTAPI NtAddAtomEx(
		_In_ PWSTR AtomName,
		_In_ ULONG AtomNameLength,
		_Out_ PRTL_ATOM Atom,
		ULONG Scope);
	//ZwAddAtomEx

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtDeleteAtom(
		_In_ RTL_ATOM Atom);
	//ZwDeleteAtom

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtFindAtom(
		_In_ PWSTR AtomName,
		_In_ ULONG AtomNameLength,
		_Out_opt_ PRTL_ATOM Atom);
	//ZwFindAtom

	// https://processhacker.sourceforge.io/doc/ntzwapi_8h_source.html
	NTSYSCALLAPI NTSTATUS NTAPI NtQueryInformationAtom(
		_In_ RTL_ATOM Atom,
		_In_ ATOM_INFORMATION_CLASS AtomInformationClass,
		_Out_ PVOID AtomInformation,
		_In_ ULONG Length,
		_Out_opt_ PULONG ReturnLength);
	//ZwQueryInformationAtom

	//RtlAddAtomToAtomTable

	//RtlCreateAtomTable

	//RtlDeleteAtomFromAtomTable

	//RtlDestroyAtomTable

	//RtlEmptyAtomTable

	//RtlGetIntegerAtom

	//RtlInitializeAtomPackage

	//RtlLookupAtomInAtomTable

	//RtlPinAtomInAtomTable

	//RtlQueryAtomInAtomTable

}

#endif // _NTATOMS_
#pragma once

#ifndef _NTATOMS_
#define _NTATOMS_

#include "NtCommonDefs.h"

extern "C" {

	// NO UNRESOLVED FUNCTIONS

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

	// https://raw.githubusercontent.com/x64dbg/TitanEngine/refs/heads/x64dbg/TitanEngine/ntdll.h
	NTSYSAPI NTSTATUS NTAPI RtlAddAtomToAtomTable(
		_In_ PVOID AtomTableHandle,
		_In_ PWSTR AtomName,
		_Inout_opt_ PRTL_ATOM Atom);

	// https://raw.githubusercontent.com/x64dbg/TitanEngine/refs/heads/x64dbg/TitanEngine/ntdll.h
	NTSYSAPI NTSTATUS NTAPI RtlCreateAtomTable(
		_In_ ULONG NumberOfBuckets,
		_Out_ PVOID* AtomTableHandle);

	//https://raw.githubusercontent.com/x64dbg/TitanEngine/refs/heads/x64dbg/TitanEngine/ntdll.h
	NTSYSAPI NTSTATUS NTAPI RtlDeleteAtomFromAtomTable(
		_In_ PVOID AtomTableHandle,
		_In_ RTL_ATOM Atom);

	// https://doxygen.reactos.org/d7/d39/sdk_2lib_2rtl_2atom_8c.html
	NTSYSAPI NTSTATUS NTAPI RtlDestroyAtomTable(
		IN PRTL_ATOM_TABLE AtomTable);

	//https://raw.githubusercontent.com/x64dbg/TitanEngine/refs/heads/x64dbg/TitanEngine/ntdll.h
	NTSYSAPI NTSTATUS NTAPI RtlEmptyAtomTable(
		_In_ PVOID AtomTableHandle,
		_In_ BOOLEAN IncludePinnedAtoms);

	//https://ntdoc.m417z.com/rtlgetintegeratom
	NTSYSAPI BOOLEAN NTAPI RtlGetIntegerAtom(
		_In_ PCWSTR AtomName,
		_Out_opt_ PUSHORT IntegerAtom);

	//https://skanthak.hier-im-netz.de/download/NTDLL.H
	//https://www.cnblogs.com/ahuo/archive/2011/05/29/2062398.html
	//https://github.com/mic101/windows/blob/master/WRK-v1.2/base/ntos/rtl/atom.c
	NTSYSAPI NTSTATUS NTAPI RtlInitializeAtomPackage(
		IN ULONG AllocationTag);

	//https://raw.githubusercontent.com/x64dbg/TitanEngine/refs/heads/x64dbg/TitanEngine/ntdll.h
	NTSYSAPI NTSTATUS NTAPI RtlLookupAtomInAtomTable(
		_In_ PVOID AtomTableHandle,
		_In_ PWSTR AtomName,
		_Out_opt_ PRTL_ATOM Atom);

	// https://doxygen.reactos.org/d7/d39/sdk_2lib_2rtl_2atom_8c.html
	NTSYSAPI NTSTATUS NTAPI RtlPinAtomInAtomTable(
		IN PRTL_ATOM_TABLE AtomTable,
		IN RTL_ATOM Atom);

	//https://raw.githubusercontent.com/x64dbg/TitanEngine/refs/heads/x64dbg/TitanEngine/ntdll.h
	NTSYSAPI NTSTATUS NTAPI RtlQueryAtomInAtomTable(
		_In_ PVOID AtomTableHandle,
		_In_ RTL_ATOM Atom,
		_Out_opt_ PULONG AtomUsage,
		_Out_opt_ PULONG AtomFlags,
		_Inout_opt_ PWSTR AtomName,
		_Inout_opt_ PULONG AtomNameLength);

}

#endif // _NTATOMS_
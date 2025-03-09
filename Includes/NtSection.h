#pragma once

#ifndef _NTSECTION_
#define _NTSECTION_

#include "NtCommonDefs.h"

extern "C" {

	// NO UNRESOLVED FUNCTIONS

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntcreatesection
	NTSYSCALLAPI NTSTATUS NTAPI NtCreateSection(
		_Out_ PHANDLE SectionHandle,
		_In_ ACCESS_MASK DesiredAccess,
		_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
		_In_opt_ PLARGE_INTEGER MaximumSize,
		_In_ ULONG SectionPageProtection,
		_In_ ULONG AllocationAttributes,
		_In_opt_ HANDLE FileHandle);
	//ZwCreateSection

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntcreatesectionex
	NTSYSCALLAPI NTSTATUS NtCreateSectionEx(
		_Out_ PHANDLE SectionHandle,
		_Out_ ACCESS_MASK DesiredAccess,
		_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
		_In_opt_ PLARGE_INTEGER MaximumSize,
		_In_ ULONG SectionPageProtection,
		_In_ ULONG AllocationAttributes,
		_In_opt_ HANDLE FileHandle,
		_Inout_ PMEM_EXTENDED_PARAMETER ExtendedParameters,
		_In_ ULONG ExtendedParameterCount);
	//ZwCreateSectionEx

	NTSYSCALLAPI NTSTATUS NTAPI NtExtendSection(_In_ HANDLE SectionHandle,
		_Inout_ PLARGE_INTEGER NewSectionSize);
	//ZwExtendSection

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtGetNlsSectionPtr(
		_In_ ULONG SectionType,
		_In_ ULONG SectionData,
		_In_ PVOID ContextData,
		_Out_ PPVOID SectionPointer,
		_Out_ PULONG SectionSize);
	//ZwGetNlsSectionPtr

	// https://learn.microsoft.com/fr-fr/windows-hardware/drivers/ddi/wdm/nf-wdm-zwmapviewofsection
	NTSYSCALLAPI NTSTATUS NTAPI NtMapViewOfSection(
		_In_ HANDLE SectionHandle,
		_In_ HANDLE ProcessHandle,
		_Inout_ _At_(*BaseAddress, _Readable_bytes_(*ViewSize) _Writable_bytes_(*ViewSize) _Post_readable_byte_size_(*ViewSize)) PVOID* BaseAddress,
		_In_ ULONG_PTR ZeroBits,
		_In_ SIZE_T CommitSize,
		_Inout_opt_ PLARGE_INTEGER SectionOffset,
		_Inout_ PSIZE_T ViewSize,
		_In_ SECTION_INHERIT InheritDisposition,
		_In_ ULONG AllocationType,
		_In_ ULONG Win32Protect);
	//ZwMapViewOfSection

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwmapviewofsectionex
	NTSYSAPI NTSTATUS ZwMapViewOfSectionEx(
		[in]                HANDLE                  SectionHandle,
		[in]                HANDLE                  ProcessHandle,
		[in, out]           PVOID* BaseAddress,
		[in, out, optional] PLARGE_INTEGER          SectionOffset,
		[in, out]           PSIZE_T                 ViewSize,
		[in]                ULONG                   AllocationType,
		[in]                ULONG                   PageProtection,
		[in, out, optional] PMEM_EXTENDED_PARAMETER ExtendedParameters,
		[in]                ULONG                   ExtendedParameterCount);
	//ZwMapViewOfSectionEx

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtOpenSection(
		_Out_ PHANDLE SectionHandle,
		_In_ ACCESS_MASK DesiredAccess,
		_In_ POBJECT_ATTRIBUTES ObjectAttributes);
	//ZwOpenSection

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtQuerySection(
		_In_ HANDLE SectionHandle,
		_In_ SECTION_INFORMATION_CLASS SectionInformationClass,
		_Out_writes_bytes_(SectionInformationLength) PVOID SectionInformation, _In_ SIZE_T SectionInformationLength,
		_Out_opt_ PSIZE_T ReturnLength);
	//ZwQuerySection

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwunmapviewofsection
	NTSYSCALLAPI NTSTATUS NTAPI NtUnmapViewOfSection(
		_In_ HANDLE ProcessHandle,
		_In_opt_ PVOID BaseAddress);
	//ZwUnmapViewOfSection

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtUnmapViewOfSectionEx(
		_In_ HANDLE ProcessHandle,
		_In_opt_ PVOID BaseAddress,
		_In_ ULONG Flags);
	//ZwUnmapViewOfSectionEx

}

#endif //_NTSECTION_
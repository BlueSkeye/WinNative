#pragma once

#ifndef _NTSECTION_
#define _NTSECTION_

#include "NtCommonDefs.h"

#ifdef __cplusplus
extern "C" {
#endif

	// NO UNRESOLVED FUNCTIONS

#define MEM_EXTENDED_PARAMETER_TYPE_BITS    8
	// https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-mem_extended_parameter
	typedef struct MEM_EXTENDED_PARAMETER {
		struct {
			DWORD64 Type : MEM_EXTENDED_PARAMETER_TYPE_BITS;
			DWORD64 Reserved : 64 - MEM_EXTENDED_PARAMETER_TYPE_BITS;
		} DUMMYSTRUCTNAME;
		union {
			DWORD64 ULong64;
			PVOID Pointer;
			SIZE_T Size;
			HANDLE Handle;
			DWORD ULong;
		} DUMMYUNIONNAME;
	} MEM_EXTENDED_PARAMETER, * PMEM_EXTENDED_PARAMETER;

	// https://github.com/winsiderss/systeminformer/blob/cc931ddaf76f62e313cf7b9f5a81ef0c54590088/phnt/include/ntmmapi.h#L592C1-L600C29
	typedef enum _SECTION_INFORMATION_CLASS  {
		SectionBasicInformation, // q; SECTION_BASIC_INFORMATION
		SectionImageInformation, // q; SECTION_IMAGE_INFORMATION
		SectionRelocationInformation, // q; ULONG_PTR RelocationDelta // name:wow64:whNtQuerySection_SectionRelocationInformation // since WIN7
		SectionOriginalBaseInformation, // q; PVOID BaseAddress // since REDSTONE
		SectionInternalImageInformation, // SECTION_INTERNAL_IMAGE_INFORMATION // since REDSTONE2
		MaxSectionInfoClass
	} SECTION_INFORMATION_CLASS;

	// From wdm.h
	typedef enum _SECTION_INHERIT {
		ViewShare = 1,
		ViewUnmap = 2
	} SECTION_INHERIT;

	// ================================== functions ==================================
	
	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntcreatesection
	NTSYSAPI NTSTATUS NTAPI NtCreateSection(
		_Out_ PHANDLE SectionHandle,
		_In_ ACCESS_MASK DesiredAccess,
		_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
		_In_opt_ PLARGE_INTEGER MaximumSize,
		_In_ ULONG SectionPageProtection,
		_In_ ULONG AllocationAttributes,
		_In_opt_ HANDLE FileHandle);
	//ZwCreateSection

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntcreatesectionex
	NTSYSAPI NTSTATUS NtCreateSectionEx(
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

	NTSYSAPI NTSTATUS NTAPI NtExtendSection(
		_In_ HANDLE SectionHandle,
		_Inout_ PLARGE_INTEGER NewSectionSize);
	//ZwExtendSection

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSAPI NTSTATUS NTAPI NtGetNlsSectionPtr(
		_In_ ULONG SectionType,
		_In_ ULONG SectionData,
		_In_ PVOID ContextData,
		_Out_ PPVOID SectionPointer,
		_Out_ PULONG SectionSize);
	//ZwGetNlsSectionPtr

	// https://learn.microsoft.com/fr-fr/windows-hardware/drivers/ddi/wdm/nf-wdm-zwmapviewofsection
	NTSYSAPI NTSTATUS NTAPI NtMapViewOfSection(
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
	NTSYSAPI NTSTATUS NtMapViewOfSectionEx(
		_In_ HANDLE SectionHandle,
		_In_ HANDLE ProcessHandle,
		_Inout_ PVOID* BaseAddress,
		_Inout_opt_ PLARGE_INTEGER SectionOffset,
		_Inout_ PSIZE_T ViewSize,
		_In_ ULONG AllocationType,
		_In_ ULONG PageProtection,
		_Inout_opt_ PMEM_EXTENDED_PARAMETER ExtendedParameters,
		_In_ ULONG ExtendedParameterCount);
	//ZwMapViewOfSectionEx

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSAPI NTSTATUS NTAPI NtOpenSection(
		_Out_ PHANDLE SectionHandle,
		_In_ ACCESS_MASK DesiredAccess,
		_In_ POBJECT_ATTRIBUTES ObjectAttributes);
	//ZwOpenSection

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSAPI NTSTATUS NTAPI NtQuerySection(
		_In_ HANDLE SectionHandle,
		_In_ SECTION_INFORMATION_CLASS SectionInformationClass,
		_Out_writes_bytes_(SectionInformationLength) PVOID SectionInformation,
		_In_ SIZE_T SectionInformationLength,
		_Out_opt_ PSIZE_T ReturnLength);
	//ZwQuerySection

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwunmapviewofsection
	NTSYSAPI NTSTATUS NTAPI NtUnmapViewOfSection(
		_In_ HANDLE ProcessHandle,
		_In_opt_ PVOID BaseAddress);
	//ZwUnmapViewOfSection

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSAPI NTSTATUS NTAPI NtUnmapViewOfSectionEx(
		_In_ HANDLE ProcessHandle,
		_In_opt_ PVOID BaseAddress,
		_In_ ULONG Flags);
	//ZwUnmapViewOfSectionEx

#ifdef __cplusplus
}
#endif

#endif //_NTSECTION_
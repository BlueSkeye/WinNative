#pragma once

#ifndef _NTPARTITION_
#define _NTPARTITION_

#include "NtCommonDefs.h"

extern "C" {

	// https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/mm/partition/create.htm?ta=8.199996948242188&tx=91;90&ts=0,57
	NTSYSCALLAPI NTSTATUS NTAPI NtCreatePartition(
		_Out_ PHANDLE PartitionHandle,
		_In_ ACCESS_MASK DesiredAccess,
		_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
		_In_ ULONG PreferredNode);
	//ZwCreatePartition

	// https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/mm/partition/open.htm?tx=91;90&ts=0,57
	NTSYSCALLAPI NTSTATUS NTAPI NtOpenPartition(
		_Out_ PHANDLE PartitionHandle,
		_In_ ACCESS_MASK DesiredAccess,
		_In_ POBJECT_ATTRIBUTES ObjectAttributes);
	//ZwOpenPartition

	// https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/mm/partition/manage.htm?tx=91;90&ts=0,57
	NTSYSCALLAPI NTSTATUS NTAPI NtManagePartition(
		_In_ MEMORY_PARTITION_INFORMATION_CLASS PartitionInformationClass,
		_In_ PVOID PartitionInformation,
		_In_ ULONG PartitionInformationLength);
	//ZwManagePartition

}

#endif // _NTPARTITION_
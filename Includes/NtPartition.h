#pragma once

#ifndef _NTPARTITION_
#define _NTPARTITION_

#include "NtCommonDefs.h"

extern "C" {

	// NO UNRESOLVED FUNCTIONS

	typedef enum _PARTITION_INFORMATION_CLASS {
		SystemMemoryPartitionInformation, // q: MEMORY_PARTITION_CONFIGURATION_INFORMATION
		SystemMemoryPartitionMoveMemory, // s: MEMORY_PARTITION_TRANSFER_INFORMATION
		SystemMemoryPartitionAddPagefile, // s: MEMORY_PARTITION_PAGEFILE_INFORMATION
		SystemMemoryPartitionCombineMemory, // q; s: MEMORY_PARTITION_PAGE_COMBINE_INFORMATION
		SystemMemoryPartitionInitialAddMemory, // q; s: MEMORY_PARTITION_INITIAL_ADD_INFORMATION
		SystemMemoryPartitionGetMemoryEvents, // MEMORY_PARTITION_MEMORY_EVENTS_INFORMATION // since REDSTONE2
		SystemMemoryPartitionSetAttributes,
		SystemMemoryPartitionNodeInformation,
		SystemMemoryPartitionCreateLargePages,
		SystemMemoryPartitionDedicatedMemoryInformation,
		SystemMemoryPartitionOpenDedicatedMemory, // 10
		SystemMemoryPartitionMemoryChargeAttributes,
		SystemMemoryPartitionClearAttributes,
		SystemMemoryPartitionSetMemoryThresholds, // since WIN11
		SystemMemoryPartitionMemoryListCommand, // since 24H2
		SystemMemoryPartitionMax
	} PARTITION_INFORMATION_CLASS, * PPARTITION_INFORMATION_CLASS;

	// =============================== functions ===============================
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

	// https://github.com/winsiderss/systeminformer/blob/0b59400ca381a9c8681abb07a66d77cc55115e63/phnt/include/ntmmapi.h#L1357C1-L1366C7
	NTSYSCALLAPI NTSTATUS NTAPI NtManagePartition(
		_In_ HANDLE TargetHandle,
		_In_opt_ HANDLE SourceHandle,
		_In_ PARTITION_INFORMATION_CLASS PartitionInformationClass,
		_Inout_updates_bytes_(PartitionInformationLength) PVOID PartitionInformation,
		_In_ ULONG PartitionInformationLength);
	//ZwManagePartition

}

#endif // _NTPARTITION_
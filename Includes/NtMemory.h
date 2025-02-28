#pragma once

#ifndef _NTMEMORY_
#define _NTMEMORY_

#include "NtCommonDefs.h"

extern "C" {

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtAllocateUserPhysicalPages(
		_In_ HANDLE ProcessHandle,
		_Inout_ PULONG_PTR NumberOfPages,
		_Out_writes_(*NumberOfPages) PULONG_PTR UserPfnArray);
	//ZwAllocateUserPhysicalPages

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtAllocateUserPhysicalPagesEx(
		_In_     HANDLE hProcess,
		_Inout_  PULONG NumberOfPages,
		_Out_    PULONG UserPfnArray,
		_Inout_opt_  PVOID DataBuffer,
		_In_     ULONG DataCount);
	//ZwAllocateUserPhysicalPagesEx

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntallocatevirtualmemory
	NTSYSCALLAPI NTSTATUS NTAPI NtAllocateVirtualMemory(
		_In_ HANDLE ProcessHandle,
		_Inout_ _At_(*BaseAddress, _Readable_bytes_(*RegionSize) _Writable_bytes_(*RegionSize) _Post_readable_byte_size_(*RegionSize)) PVOID* BaseAddress,
		_In_ ULONG_PTR ZeroBits,
		_Inout_ PSIZE_T RegionSize,
		_In_ ULONG AllocationType,
		_In_ ULONG Protect);
	//ZwAllocateVirtualMemory

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtAllocateVirtualMemoryEx(
		_In_ HANDLE ProcessHandle,
		_Inout_ PPVOID lpAddress,
		_In_ ULONG_PTR ZeroBits,
		_Inout_ PSIZE_T pSize,
		_In_ ULONG flAllocationType,
		_Inout_opt_ PVOID DataBuffer,
		_In_ ULONG DataCount);
	//ZwAllocateVirtualMemoryEx

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtCreateEnclave(
		_In_ HANDLE ProcessHandle,
		_Inout_ PVOID* BaseAddress,
		_In_ ULONG_PTR ZeroBits,
		_In_ SIZE_T Size,
		_In_ SIZE_T InitialCommitment,
		_In_ ULONG EnclaveType,
		_In_ PVOID EnclaveInformation,
		_In_ ULONG EnclaveInformationLength,
		_Out_opt_ PULONG EnclaveError);
	//ZwCreateEnclave

	// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FFile%2FNtWriteFileGather.html
	// https://processhacker.sourceforge.io/doc/ntzwapi_8h_source.html
	NTSYSCALLAPI NTSTATUS NTAPI NtCreatePagingFile(
		_In_ PUNICODE_STRING PageFileName,
		_In_ PLARGE_INTEGER MinimumSize,
		_In_ PLARGE_INTEGER MaximumSize,
		_In_ ULONG Priority);
	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	// Defines last parameter as : _Out_opt_ PLARGE_INTEGER ActualSize
	//ZwCreatePagingFile

	// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FFile%2FNtWriteFileGather.html
	NTSYSCALLAPI NTSTATUS NTAPI NtFlushInstructionCache(
		_In_ HANDLE ProcessHandle,
		_In_opt_ PVOID BaseAddress,
		_In_ SIZE_T Length);
	//ZwFlushInstructionCache

	// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FFile%2FNtWriteFileGather.html
	NTSYSCALLAPI NTSTATUS NTAPI NtFlushProcessWriteBuffers();
	//ZwFlushProcessWriteBuffers

	//https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwflushvirtualmemory
	NTSYSAPI NTSTATUS NtFlushVirtualMemory(
		[in]      HANDLE           ProcessHandle,
		[in, out] PVOID* BaseAddress,
		[in, out] PSIZE_T          RegionSize,
		[out]     PIO_STATUS_BLOCK IoStatus);
	//ZwFlushVirtualMemory

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtFlushWriteBuffer(VOID);
	//ZwFlushWriteBuffer

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtFreeUserPhysicalPages(
		_In_ HANDLE ProcessHandle,
		_Inout_ PULONG_PTR NumberOfPages,
		_In_reads_(*NumberOfPages) PULONG_PTR UserPfnArray);
	//ZwFreeUserPhysicalPages

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntfreevirtualmemory
	NTSYSCALLAPI NTSTATUS NTAPI NtFreeVirtualMemory(
		_In_ HANDLE ProcessHandle,
		_Inout_ PVOID* BaseAddress,
		_Inout_ PSIZE_T RegionSize,
		_In_ ULONG FreeType);
	//ZwFreeVirtualMemory

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtGetWriteWatch(
		_In_ HANDLE ProcessHandle,
		_In_ ULONG Flags,
		_In_ PVOID BaseAddress,
		_In_ SIZE_T RegionSize,
		_Out_writes_(*EntriesInUserAddressArray) PVOID* UserAddressArray,
		_Inout_ PULONG_PTR EntriesInUserAddressArray,
		_Out_ PULONG Granularity);
	//ZwGetWriteWatch

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtInitializeEnclave(
		_In_ HANDLE ProcessHandle,
		_In_ PVOID BaseAddress,
		_In_ PVOID EnclaveInformation,
		_In_ ULONG EnclaveInformationLength,
		_Out_opt_ PULONG EnclaveError
		);
	//ZwInitializeEnclave

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtLoadEnclaveData(
		_In_ HANDLE ProcessHandle,
		_In_ PVOID BaseAddress,
		_In_ PVOID Buffer,
		_In_ SIZE_T BufferSize,
		_In_ ULONG Protect,
		_In_ PVOID PageInformation,
		_In_ ULONG PageInformationLength,
		_Out_opt_ PSIZE_T NumberOfBytesWritten,
		_Out_opt_ PULONG EnclaveError);
	//ZwLoadEnclaveData

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtLockVirtualMemory(
		_In_ HANDLE ProcessHandle,
		_Inout_ PVOID* BaseAddress,
		_Inout_ PSIZE_T RegionSize,
		_In_ ULONG MapType);
	//ZwLockVirtualMemory

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtMapUserPhysicalPages(
		_In_ PVOID VirtualAddress,
		_In_ ULONG_PTR NumberOfPages,
		_In_reads_opt_(NumberOfPages) PULONG_PTR UserPfnArray);
	//ZwMapUserPhysicalPages

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtMapUserPhysicalPagesScatter(
		_In_reads_(NumberOfPages) PVOID* VirtualAddresses,
		_In_ ULONG_PTR NumberOfPages,
		_In_reads_opt_(NumberOfPages) PULONG_PTR UserPfnArray);
	//ZwMapUserPhysicalPagesScatter

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtProtectVirtualMemory(
		_In_ HANDLE ProcessHandle,
		_Inout_ PVOID* BaseAddress,
		_Inout_ PSIZE_T RegionSize,
		_In_ ULONG NewProtect,
		_Out_ PULONG OldProtect);
	//ZwProtectVirtualMemory
	
	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtPssCaptureVaSpaceBulk(
		_In_ HANDLE ProcessHandle,
		_In_ PVOID BaseAddress,
		_In_ PVOID Buffer,
		_In_ SIZE_T Length,
		_Out_ PSIZE_T ReturnLength);
	//ZwPssCaptureVaSpaceBulk

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntqueryvirtualmemory
	NTSYSCALLAPI NTSTATUS NTAPI NtQueryVirtualMemory(
		_In_ HANDLE ProcessHandle,
		_In_ PVOID BaseAddress,
		_In_ MEMORY_INFORMATION_CLASS MemoryInformationClass,
		_Out_writes_bytes_(MemoryInformationLength) PVOID MemoryInformation,
		_In_ SIZE_T MemoryInformationLength,
		_Out_opt_ PSIZE_T ReturnLength);
	//ZwQueryVirtualMemory

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtReadVirtualMemory(
		_In_ HANDLE ProcessHandle,
		_In_opt_ PVOID BaseAddress,
		_Out_writes_bytes_(BufferSize) PVOID Buffer,
		_In_ SIZE_T BufferSize,
		_Out_opt_ PSIZE_T NumberOfBytesRead);
	//ZwReadVirtualMemory

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtResetWriteWatch(
		_In_ HANDLE ProcessHandle,
		_In_ PVOID BaseAddress,
		_In_ SIZE_T RegionSize);
	//ZwResetWriteWatch

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwsetinformationvirtualmemory
	NTSYSCALLAPI NTSTATUS NTAPI NtSetInformationVirtualMemory(
		_In_ HANDLE ProcessHandle,
		_In_ VIRTUAL_MEMORY_INFORMATION_CLASS VmInformationClass,
		_In_ ULONG_PTR NumberOfEntries,
		_In_reads_(NumberOfEntries) PMEMORY_RANGE_ENTRY VirtualAddresses,
		_In_reads_bytes_(VmInformationLength) PVOID VmInformation,
		_In_ ULONG VmInformationLength);
	//ZwSetInformationVirtualMemory

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtUnlockVirtualMemory(
		_In_ HANDLE ProcessHandle,
		_Inout_ PVOID* BaseAddress,
		_Inout_ PSIZE_T RegionSize,
		_In_ ULONG MapType);
	//ZwUnlockVirtualMemory

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtWriteVirtualMemory(
		_In_ HANDLE ProcessHandle,
		_In_opt_ PVOID BaseAddress,
		_In_reads_bytes_(BufferSize) PVOID Buffer,
		_In_ SIZE_T BufferSize,
		_Out_opt_ PSIZE_T NumberOfBytesWritten);
	//ZwWriteVirtualMemory

}

#endif // _NTMEMORY_
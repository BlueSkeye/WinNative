#pragma once

#ifndef _NTMEMORY_
#define _NTMEMORY_

#include "NtCommonDefs.h"

extern "C" {

	// NO UNRESOLVED FUNCTIONS
	// END OF UNRESOLVED FUNCTIONS

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
		_In_      HANDLE           ProcessHandle,
		[in, out] PVOID* BaseAddress,
		[in, out] PSIZE_T          RegionSize,
		_Out_     PIO_STATUS_BLOCK IoStatus);
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

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlallocateheap
	NTSYSAPI PVOID RtlAllocateHeap(
		_In_           PVOID  HeapHandle,
		_In_opt_ ULONG  Flags,
		_In_           SIZE_T Size);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html#a45d5646d40fe2acf29e8137ca6b93795
	NTSYSAPI NTSTATUS NTAPI RtlAllocateMemoryBlockLookaside(
		_In_ PVOID MemoryBlockLookaside,
		_In_ ULONG BlockSize,
		_Out_ PVOID* Block);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html#a45d5646d40fe2acf29e8137ca6b93795
	NTSYSAPI NTSTATUS NTAPI RtlAllocateMemoryZone(
		_In_ PVOID MemoryZone,
		_In_ SIZE_T BlockSize,
		_Out_ PVOID* Block);

	//https://github.com/winsiderss/systeminformer/blob/daf4737ce0399fa92d17df118bcb3aba5cdc794f/phnt/include/ntrtl.h#L5467
	NTSYSAPI SIZE_T NTAPI RtlCompactHeap(
		_In_ PVOID HeapHandle,
		_In_ ULONG Flags);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlcomparememory
	NTSYSAPI SIZE_T NTAPI RtlCompareMemory(
		_In_ const VOID* Source1,
		_In_ const VOID* Source2,
		_In_ SIZE_T     Length);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlcomparememoryulong
	NTSYSAPI SIZE_T NTAPI RtlCompareMemoryUlong(
		_In_ PVOID  Source,
		_In_ SIZE_T Length,
		_In_ ULONG  Pattern);

	// https://doxygen.reactos.org/da/dff/memstream_8c.html
	NTSYSAPI NTSTATUS NTAPI RtlCopyMappedMemory(
		_Out_writes_bytes_all_(Size) PVOID Destination,
		_In_reads_bytes_(Size) const VOID* Source,
		_In_ SIZE_T Size);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlcopymemory
	NTSYSAPI VOID NTAPI RtlCopyMemory(
		PVOID Destination,
		const PVOID Source,
		SIZE_T Length);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlcopymemorynontemporal
	NTSYSAPI VOID NTAPI RtlCopyMemoryNonTemporal(
		VOID* Destination,
		const VOID* Source,
		SIZE_T     Length);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlcreateheap
	NTSYSAPI PVOID NTAPI RtlCreateHeap(
		_In_           ULONG                Flags,
		_In_opt_ PVOID                HeapBase,
		_In_opt_ SIZE_T               ReserveSize,
		_In_opt_ SIZE_T               CommitSize,
		_In_opt_ PVOID                Lock,
		_In_opt_ PRTL_HEAP_PARAMETERS Parameters);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI NTSTATUS NTAPI RtlCreateMemoryBlockLookaside(
		_Out_ PVOID* MemoryBlockLookaside,
		_Reserved_ ULONG Flags,
		_In_ ULONG InitialSize,
		_In_ ULONG MinimumBlockSize,
		_In_ ULONG MaximumBlockSize);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI NTSTATUS NTAPI RtlCreateMemoryZone(
		_Out_ PVOID* MemoryZone,
		_In_ SIZE_T 	InitialSize,
		_Reserved_ ULONG 	Flags);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI ULONG NTAPI RtlCreateTagHeap(
		_In_ PVOID 	HeapHandle,
		_In_ ULONG 	Flags,
		_In_opt_ PWSTR 	TagPrefix,
		_In_ PWSTR 	TagNames);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtldestroyheap
	NTSYSAPI PVOID NTAPI RtlDestroyHeap(
		_In_ PVOID HeapHandle);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI NTSTATUS NTAPI RtlDestroyMemoryBlockLookaside(
		_In_ PVOID MemoryBlockLookaside);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI NTSTATUS NTAPI RtlDestroyMemoryZone(
		_In_ _Post_invalid_ PVOID 	MemoryZone);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI VOID NTAPI RtlDetectHeapLeaks(VOID);

	// https://learn.microsoft.com/en-us/windows/win32/devnotes/rtlsupportapi/nf-rtlsupportapi-rtldisownmoduleheapallocation
	NTSYSAPI NTSTATUS WINAPI RtlDisownModuleHeapAllocation(
		_In_ HANDLE HeapHandle,
		_In_ PVOID Allocation);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI NTSTATUS NTAPI RtlEnumProcessHeaps(
		_In_ PRTL_ENUM_HEAPS_ROUTINE EnumRoutine,
		_In_ PVOID 	Parameter);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI NTSTATUS NTAPI RtlExtendMemoryBlockLookaside(
		_In_ PVOID MemoryBlockLookaside,
		_In_ ULONG Increment);

	// Reversed
	typedef struct _RTL_MEMORY_ZONE {
		RTL_SRWLOCK Lock; // @ offset 0x20
		DWORD _28;
		PVOID _30;
	} RTL_MEMORY_ZONE, *PRTL_MEMORY_ZONE;
	NTSYSAPI NTSTATUS NTAPI RtlExtendMemoryZone(
		_In_ PRTL_MEMORY_ZONE MemoryZone,
		_In_ PVOID NewSize);

	// Reversed
#ifdef RtlFillMemory
#undef RtlFillMemory
#endif
	NTSYSAPI VOID NTAPI RtlFillMemory(
		_In_ PVOID Destination,
		_In_ SIZE_T Length,
		_In_ const UCHAR Fill);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlfillmemorynontemporal
	NTSYSAPI VOID NTAPI RtlFillMemoryNonTemporal(
		_In_ PVOID Destination,
		_In_ SIZE_T Length,
		_In_ const UCHAR Value);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlfillnonvolatilememory
	NTSYSAPI NTSTATUS NTAPI RtlFillNonVolatileMemory(
		_In_ PVOID NvToken,
		_In_ PVOID NvDestination,
		_In_ SIZE_T Size,
		_In_ const UCHAR Value,
		_In_ ULONG Flags);
	
	// https://github.com/winsiderss/systeminformer/blob/5d11186e6a48a7329cb30666131977365e78f591/phnt/include/ntrtl.h#L5883C1-L5888C7
	NTSYSAPI VOID NTAPI RtlFlushHeaps(VOID);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlflushnonvolatilememory
	NTSYSAPI NTSTATUS NTAPI RtlFlushNonVolatileMemory(
		_In_ PVOID NvToken,
		_In_ PVOID NvBuffer,
		_In_ SIZE_T Size,
		_In_ ULONG Flags);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlflushnonvolatilememoryranges
	NTSYSAPI NTSTATUS NTAPI RtlFlushNonVolatileMemoryRanges(
		_In_ PVOID NvToken,
		_In_ PNV_MEMORY_RANGE NvRanges,
		_In_ SIZE_T NumRanges,
		_In_ ULONG Flags);

	// https://github.com/winsiderss/systeminformer/blob/5d11186e6a48a7329cb30666131977365e78f591/phnt/include/ntrtl.h#L10832C1-L10838C7
	NTSYSAPI BOOLEAN NTAPI RtlFlushSecureMemoryCache(
		_In_ PVOID MemoryCache,
		_In_opt_ SIZE_T MemoryLength);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlfreeheap
	NTSYSAPI LOGICAL RtlFreeHeap(
		_In_           PVOID                 HeapHandle,
		_In_opt_ ULONG                 Flags,
		_Frees_ptr_opt_ PVOID BaseAddress);

	// https://github.com/winsiderss/systeminformer/blob/5d11186e6a48a7329cb30666131977365e78f591/phnt/include/ntrtl.h#L5991C1-L5997C7
	NTSYSAPI NTSTATUS NTAPI RtlFreeMemoryBlockLookaside(
		_In_ PVOID MemoryBlockLookaside,
		_In_ PVOID Block);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlfreenonvolatiletoken
	NTSYSAPI NTSTATUS NTAPI RtlFreeNonVolatileToken(
		_In_ PVOID NvToken);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlgetnonvolatiletoken
	NTSYSAPI NTSTATUS NTAPI RtlGetNonVolatileToken(
		_In_ PVOID NvBuffer,
		_In_ SIZE_T Size,
		_Out_ PVOID* NvToken);

	// https://github.com/winsiderss/systeminformer/blob/5d11186e6a48a7329cb30666131977365e78f591/phnt/include/ntrtl.h#L5491C1-L5497C7
	NTSYSAPI ULONG NTAPI RtlGetProcessHeaps(
		_In_ ULONG NumberOfHeaps,
		_Out_ PVOID* ProcessHeaps);

	// https://github.com/winsiderss/systeminformer/blob/5d11186e6a48a7329cb30666131977365e78f591/phnt/include/ntrtl.h#L5395C1-L5405C1
	NTSYSAPI BOOLEAN NTAPI RtlGetUserInfoHeap(
		_In_ PVOID HeapHandle,
		_In_ ULONG Flags,
		_In_ PVOID BaseAddress,
		_Out_opt_ PVOID* UserValue,
		_Out_opt_ PULONG UserFlags);

	// Reversed
	NTSYSAPI NTSTATUS NTAPI RtlHeapTrkInitialize(
		_In_ HANDLE SectionHandle);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtliszeromemory
	NTSYSAPI BOOLEAN RtlIsZeroMemory(
		PVOID  Buffer,
		SIZE_T Length);

	// https://github.com/winsiderss/systeminformer/blob/5d11186e6a48a7329cb30666131977365e78f591/phnt/include/ntrtl.h#L5363C1-L5368C7
	NTSYSAPI BOOLEAN NTAPI RtlLockHeap(
		_In_ PVOID HeapHandle);

	// https://github.com/winsiderss/systeminformer/blob/5d11186e6a48a7329cb30666131977365e78f591/phnt/include/ntrtl.h#L6014C1-L6019C7
	NTSYSAPI NTSTATUS NTAPI RtlLockMemoryBlockLookaside(
		_In_ PVOID MemoryBlockLookaside);

	// https://github.com/winsiderss/systeminformer/blob/5d11186e6a48a7329cb30666131977365e78f591/phnt/include/ntrtl.h#L5944C1-L5950C1
	NTSYSAPI NTSTATUS NTAPI RtlLockMemoryZone(
		_In_ PVOID MemoryZone);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlmovememory
	NTSYSAPI VOID NTAPI RtlMoveMemory(
		void* Destination,
		const void* Source,
		size_t      Length);

	// https://github.com/winsiderss/systeminformer/blob/5d11186e6a48a7329cb30666131977365e78f591/phnt/include/ntrtl.h#L5853C1-L5862C7
	NTSYSAPI ULONG NTAPI RtlMultipleAllocateHeap(
		_In_ PCVOID HeapHandle,
		_In_ ULONG Flags,
		_In_ SIZE_T Size,
		_In_ ULONG Count,
		_Out_ PVOID* Array);

	// https://github.com/winsiderss/systeminformer/blob/5d11186e6a48a7329cb30666131977365e78f591/phnt/include/ntrtl.h#L5864C1-L5872C7
	NTSYSAPI ULONG NTAPI RtlMultipleFreeHeap(
		_In_ PCVOID HeapHandle,
		_In_ ULONG Flags,
		_In_ ULONG Count,
		_In_ PVOID* Array);
	 
	// https://github.com/winsiderss/systeminformer/blob/5d11186e6a48a7329cb30666131977365e78f591/phnt/include/ntrtl.h#L5353C1-L5360C1
	NTSYSAPI VOID NTAPI RtlProtectHeap(
		_In_ PVOID HeapHandle,
		_In_ BOOLEAN MakeReadOnly);

	// https://github.com/winsiderss/systeminformer/blob/5d11186e6a48a7329cb30666131977365e78f591/phnt/include/ntrtl.h#L5832C1-L5841C7
	NTSYSAPI NTSTATUS NTAPI RtlQueryHeapInformation(
		_In_opt_ PVOID HeapHandle,
		_In_ HEAP_INFORMATION_CLASS HeapInformationClass,
		_Out_opt_ PVOID HeapInformation,
		_In_opt_ SIZE_T HeapInformationLength,
		_Out_opt_ PSIZE_T ReturnLength);

	// https://doxygen.reactos.org/d8/dc5/sdk_2lib_2rtl_2heap_8c.html
	NTSYSAPI NTSTATUS NTAPI RtlQueryProcessHeapInformation(
		IN struct _DEBUG_BUFFER* DebugBuffer);

	// https://github.com/winsiderss/systeminformer/blob/5d11186e6a48a7329cb30666131977365e78f591/phnt/include/ntrtl.h#L5446C1-L5455C7
	NTSYSAPI PWSTR NTAPI RtlQueryTagHeap(
		_In_ PVOID HeapHandle,
		_In_ ULONG Flags,
		_In_ USHORT TagIndex,
		_In_ BOOLEAN ResetCounters,
		_Out_opt_ PRTL_HEAP_TAG_INFO TagInfo);
	
	// https://github.com/winsiderss/systeminformer/blob/5d11186e6a48a7329cb30666131977365e78f591/phnt/include/ntrtl.h#L5377C1-L5393C7
	NTSYSAPI
		_Success_(return != 0)
		_Must_inspect_result_
		_Ret_maybenull_
		_Post_writable_byte_size_(Size)
		_When_(Size > 0, __drv_allocatesMem(Mem))
		DECLSPEC_ALLOCATOR
		DECLSPEC_NOALIAS
		DECLSPEC_RESTRICT PVOID NTAPI RtlReAllocateHeap(
			_In_ PVOID HeapHandle,
			_In_ ULONG Flags,
			_Frees_ptr_opt_ PVOID BaseAddress,
			_In_ SIZE_T Size);

	// https://github.com/winsiderss/systeminformer/blob/5d11186e6a48a7329cb30666131977365e78f591/phnt/include/ntrtl.h#L10817C1-L10822C7
	NTSYSAPI NTSTATUS NTAPI RtlRegisterSecureMemoryCacheCallback(
		_In_ PRTL_SECURE_MEMORY_CACHE_CALLBACK Callback);

	// https://github.com/winsiderss/systeminformer/blob/5d11186e6a48a7329cb30666131977365e78f591/phnt/include/ntrtl.h#L6007C1-L6012C7
	NTSYSAPI NTSTATUS NTAPI RtlResetMemoryBlockLookaside(
		_In_ PVOID MemoryBlockLookaside);

	// https://github.com/winsiderss/systeminformer/blob/5d11186e6a48a7329cb30666131977365e78f591/phnt/include/ntrtl.h#L5937C1-L5942C7
	NTSYSAPI NTSTATUS NTAPI RtlResetMemoryZone(
		_In_ PVOID MemoryZone);

	// https://github.com/winsiderss/systeminformer/blob/5d11186e6a48a7329cb30666131977365e78f591/phnt/include/ntrtl.h#L5843C1-L5851C7
	NTSYSAPI NTSTATUS NTAPI RtlSetHeapInformation(
		_In_opt_ PCVOID HeapHandle,
		_In_ HEAP_INFORMATION_CLASS HeapInformationClass,
		_In_opt_ PCVOID HeapInformation,
		_In_opt_ SIZE_T HeapInformationLength);

	// https://github.com/winsiderss/systeminformer/blob/5d11186e6a48a7329cb30666131977365e78f591/phnt/include/ntrtl.h#L5416C1-L5425C7
	NTSYSAPI BOOLEAN NTAPI RtlSetUserFlagsHeap(
		_In_ PVOID HeapHandle,
		_In_ ULONG Flags,
		_In_ PVOID BaseAddress,
		_In_ ULONG UserFlagsReset,
		_In_ ULONG UserFlagsSet);

	// https://github.com/winsiderss/systeminformer/blob/5d11186e6a48a7329cb30666131977365e78f591/phnt/include/ntrtl.h#L5406C1-L5415C1
	NTSYSAPI BOOLEAN NTAPI RtlSetUserValueHeap(
		_In_ PVOID HeapHandle,
		_In_ ULONG Flags,
		_In_ PVOID BaseAddress,
		_In_ PVOID UserValue);

	// https://github.com/winsiderss/systeminformer/blob/5d11186e6a48a7329cb30666131977365e78f591/phnt/include/ntrtl.h#L5336C1-L5343C7
	NTSYSAPI SIZE_T NTAPI RtlSizeHeap(
		_In_ PVOID HeapHandle,
		_In_ ULONG Flags,
		_In_ PVOID BaseAddress);

	// https://github.com/winsiderss/systeminformer/blob/5d11186e6a48a7329cb30666131977365e78f591/phnt/include/ntrtl.h#L5370C1-L5375C7
	NTSYSAPI BOOLEAN NTAPI RtlUnlockHeap(
		_In_ PVOID HeapHandle);

	// https://github.com/winsiderss/systeminformer/blob/5d11186e6a48a7329cb30666131977365e78f591/phnt/include/ntrtl.h#L6021C1-L6026C7
	NTSYSAPI NTSTATUS NTAPI RtlUnlockMemoryBlockLookaside(
		_In_ PVOID MemoryBlockLookaside);

	// https://github.com/winsiderss/systeminformer/blob/5d11186e6a48a7329cb30666131977365e78f591/phnt/include/ntrtl.h#L5951C1-L5956C7
	NTSYSAPI NTSTATUS NTAPI RtlUnlockMemoryZone(
		_In_ PVOID MemoryZone);

	// https://github.com/winsiderss/systeminformer/blob/5d11186e6a48a7329cb30666131977365e78f591/phnt/include/ntrtl.h#L5475C1-L5482C7
	NTSYSAPI BOOLEAN NTAPI RtlValidateHeap(
		_In_opt_ PVOID HeapHandle,
		_In_ ULONG Flags,
		_In_opt_ PVOID BaseAddress);

	// https://github.com/winsiderss/systeminformer/blob/5d11186e6a48a7329cb30666131977365e78f591/phnt/include/ntrtl.h#L5484C1-L5489C7
	NTSYSAPI BOOLEAN NTAPI RtlValidateProcessHeaps(VOID);

	// https://github.com/winsiderss/systeminformer/blob/5d11186e6a48a7329cb30666131977365e78f591/phnt/include/ntrtl.h#L5574C1-L5580C7
	NTSYSAPI NTSTATUS NTAPI RtlWalkHeap(
		_In_ PVOID HeapHandle,
		_Inout_ PRTL_HEAP_WALK_ENTRY Entry);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlwritenonvolatilememory
	NTSYSAPI NTSTATUS NTAPI RtlWriteNonVolatileMemory(
		PVOID      NvToken,
		PVOID NvDestination,
		const PVOID Source,
		SIZE_T     Size,
		ULONG      Flags);

	// https://github.com/winsiderss/systeminformer/blob/5d11186e6a48a7329cb30666131977365e78f591/phnt/include/ntrtl.h#L5345C1-L5351C7
	NTSYSAPI NTSTATUS NTAPI RtlZeroHeap(
		_In_ PVOID HeapHandle,
		_In_ ULONG Flags);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlzeromemory
	NTSYSAPI VOID NTAPI RtlZeroMemory(
		void* Destination,
		size_t Length);

}

#endif // _NTMEMORY_
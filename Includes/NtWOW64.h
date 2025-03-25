#pragma once

#ifndef _NTWOW64_
#define _NTWOW64_

#include "NtCommonDefs.h"

#ifdef __cplusplus
extern "C" {
#endif

	// https://github.com/wine-mirror/wine/blob/0927c5c3da7cda8cf476416260286bd299ad6319/include/winternl.h#L4291C1-L4297C42
	typedef struct _WOW64_CPURESERVED {
		USHORT Flags;
		USHORT Machine;
		/* CONTEXT context */
		/* CONTEXT_EX *context_ex */
	} WOW64_CPURESERVED, * PWOW64_CPURESERVED;

	// https://github.com/wine-mirror/wine/blob/0927c5c3da7cda8cf476416260286bd299ad6319/include/winternl.h#L4301C1-L4309C46
	typedef struct _WOW64_CPU_AREA_INFO {
		void* Context;
		void* ContextEx;
		void* ContextFlagsLocation;
		WOW64_CPURESERVED* CpuReserved;
		ULONG ContextFlag;
		USHORT Machine;
	} WOW64_CPU_AREA_INFO, * PWOW64_CPU_AREA_INFO;

	// https://github.com/wine-mirror/wine/blob/0927c5c3da7cda8cf476416260286bd299ad6319/include/winnt.h#L1132C1-L1143C81
#define I386_SIZE_OF_80387_REGISTERS 80
	typedef struct _I386_FLOATING_SAVE_AREA {
		DWORD ControlWord;
		DWORD StatusWord;
		DWORD TagWord;
		DWORD ErrorOffset;
		DWORD ErrorSelector;
		DWORD DataOffset;
		DWORD DataSelector;
		BYTE RegisterArea[I386_SIZE_OF_80387_REGISTERS];
		DWORD Cr0NpxState;
	} I386_FLOATING_SAVE_AREA, WOW64_FLOATING_SAVE_AREA, * PWOW64_FLOATING_SAVE_AREA;

	// https://github.com/wine-mirror/wine/blob/0927c5c3da7cda8cf476416260286bd299ad6319/include/winnt.h#L1148
#define I386_MAXIMUM_SUPPORTED_EXTENSION 512
	typedef struct _I386_CONTEXT {
		DWORD ContextFlags;  /* 000 */
		/* These are selected by CONTEXT_DEBUG_REGISTERS */
		DWORD Dr0;           /* 004 */
		DWORD Dr1;           /* 008 */
		DWORD Dr2;           /* 00c */
		DWORD Dr3;           /* 010 */
		DWORD Dr6;           /* 014 */
		DWORD Dr7;           /* 018 */
		/* These are selected by CONTEXT_FLOATING_POINT */
		I386_FLOATING_SAVE_AREA FloatSave; /* 01c */
		/* These are selected by CONTEXT_SEGMENTS */
		DWORD SegGs;         /* 08c */
		DWORD SegFs;         /* 090 */
		DWORD SegEs;         /* 094 */
		DWORD SegDs;         /* 098 */
		/* These are selected by CONTEXT_INTEGER */
		DWORD Edi;           /* 09c */
		DWORD Esi;           /* 0a0 */
		DWORD Ebx;           /* 0a4 */
		DWORD Edx;           /* 0a8 */
		DWORD Ecx;           /* 0ac */
		DWORD Eax;           /* 0b0 */
		/* These are selected by CONTEXT_CONTROL */
		DWORD Ebp;           /* 0b4 */
		DWORD Eip;           /* 0b8 */
		DWORD SegCs;         /* 0bc */
		DWORD EFlags;        /* 0c0 */
		DWORD Esp;           /* 0c4 */
		DWORD SegSs;         /* 0c8 */
		BYTE ExtendedRegisters[I386_MAXIMUM_SUPPORTED_EXTENSION];  /* 0xcc */
	} I386_CONTEXT, WOW64_CONTEXT, * PWOW64_CONTEXT;

	// https://github.com/wine-mirror/wine/blob/0927c5c3da7cda8cf476416260286bd299ad6319/include/winternl.h#L296C1-L304C1
	typedef struct {
		UINT next;
		UINT id;
		ULONGLONG addr;
		ULONGLONG size;
		UINT args[4];
	} CROSS_PROCESS_WORK_ENTRY;

	// https://github.com/wine-mirror/wine/blob/0927c5c3da7cda8cf476416260286bd299ad6319/include/winternl.h#L305C1-L313C26
	typedef union {
		struct {
			UINT first;
			UINT counter;
		} DUMMYSTRUCTNAME;
		volatile LONGLONG hdr;
	} CROSS_PROCESS_WORK_HDR;

	// https://github.com/wine-mirror/wine/blob/0927c5c3da7cda8cf476416260286bd299ad6319/include/winnt.h#L1221C1-L1244C62
	typedef struct _LDT_ENTRY {
		WORD LimitLow;
		WORD BaseLow;
		union {
			struct {
				BYTE BaseMid;
				BYTE Flags1;
				BYTE Flags2;
				BYTE BaseHi;
			} Bytes;
			struct {
				unsigned BaseMid : 8;
				unsigned Type : 5;
				unsigned Dpl : 2;
				unsigned Pres : 1;
				unsigned LimitHi : 4;
				unsigned Sys : 1;
				unsigned Reserved_0 : 1;
				unsigned Default_Big : 1;
				unsigned Granularity : 1;
				unsigned BaseHi : 8;
			} Bits;
		} HighWord;
	} LDT_ENTRY, * PLDT_ENTRY, WOW64_LDT_ENTRY, * PWOW64_LDT_ENTRY;

	typedef struct _THREAD_DESCRIPTOR_INFORMATION {
		DWORD Selector;
		LDT_ENTRY Entry;
	} THREAD_DESCRIPTOR_INFORMATION, * PTHREAD_DESCRIPTOR_INFORMATION;

	// ================================= functions

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/process.c
	NTSYSAPI NTSTATUS NTAPI RtlWow64EnableFsRedirection(
		BOOLEAN enable);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/process.c
	NTSYSAPI NTSTATUS NTAPI RtlWow64EnableFsRedirectionEx(
		ULONG disable,
		PULONG old_value);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/process.c
	NTSYSAPI NTSTATUS NTAPI RtlWow64GetCpuAreaInfo(
		WOW64_CPURESERVED* cpu,
		ULONG reserved,
		WOW64_CPU_AREA_INFO* info);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/process.c
	NTSYSAPI NTSTATUS NTAPI RtlWow64GetCurrentCpuArea(
		USHORT* machine,
		void** context,
		void** context_ex);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/process.c
	NTSYSAPI USHORT NTAPI RtlWow64GetCurrentMachine(VOID);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/process.c
	NTSYSAPI NTSTATUS NTAPI RtlWow64GetThreadContext(
		HANDLE handle,
		WOW64_CONTEXT* context);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/process.c
	NTSYSAPI NTSTATUS NTAPI RtlWow64GetThreadSelectorEntry(
		HANDLE handle,
		THREAD_DESCRIPTOR_INFORMATION* info,
		ULONG size, ULONG* retlen);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/process.c
	NTSYSAPI NTSTATUS NTAPI RtlWow64IsWowGuestMachineSupported(
		USHORT machine,
		BOOLEAN* supported);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/process.c
	NTSYSAPI CROSS_PROCESS_WORK_ENTRY* NTAPI RtlWow64PopAllCrossProcessWorkFromWorkList(
		CROSS_PROCESS_WORK_HDR* list,
		BOOLEAN* flush);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/process.c
	NTSYSAPI CROSS_PROCESS_WORK_ENTRY* NTAPI RtlWow64PopCrossProcessWorkFromFreeList(
		CROSS_PROCESS_WORK_HDR* list);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/process.c
	NTSYSAPI BOOLEAN NTAPI RtlWow64PushCrossProcessWorkOntoFreeList(
		CROSS_PROCESS_WORK_HDR* list,
		CROSS_PROCESS_WORK_ENTRY* entry);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/process.c
	NTSYSAPI BOOLEAN NTAPI RtlWow64PushCrossProcessWorkOntoWorkList(
		CROSS_PROCESS_WORK_HDR* list,
		CROSS_PROCESS_WORK_ENTRY* entry,
		void** unknown);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/process.c
	NTSYSAPI BOOLEAN NTAPI RtlWow64RequestCrossProcessHeavyFlush(
		CROSS_PROCESS_WORK_HDR* list);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/process.c
	NTSYSAPI NTSTATUS NTAPI RtlWow64SetThreadContext(
		HANDLE handle,
		const WOW64_CONTEXT* context);

#ifdef __cplusplus
}
#endif

#endif // _NTWOW64_
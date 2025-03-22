#pragma once

#ifndef _NTWOW64_
#define _NTWOW64_

#include "NtCommonDefs.h"

extern "C" {

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

}

#endif // _NTWOW64_
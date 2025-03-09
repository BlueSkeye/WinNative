#pragma once

#ifndef _NTCONTEXTS_
#define _NTCONTEXTS_

#include "NtCommonDefs.h"

extern "C" {

	// NO UNRESOLVED FUNCTIONS

	//https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/actctx.c
	NTSYSAPI NTSTATUS WINAPI RtlActivateActivationContext(
		_In_ ULONG Flags,
		_In_ HANDLE Handle,
		_Out_ PULONG_PTR Cookie);

	//https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/actctx.c
	NTSTATUS WINAPI RtlActivateActivationContextEx(
		_In_ ULONG Flags,
		_In_ TEB* Teb,
		_In_ HANDLE Handle,
		_Out_ PULONG_PTR Cookie);

	//https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/actctx.c
	NTSYSAPI void WINAPI RtlAddRefActivationContext(
		_In_ HANDLE handle);

	//https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/actctx.c
	NTSYSAPI NTSTATUS WINAPI RtlCreateActivationContext(
		PHANDLE handle,
		const PVOID ptr);

	//https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/actctx.c
	NTSYSAPI VOID WINAPI RtlDeactivateActivationContext(
		_In_ ULONG Flags,
		_In_ ULONG_PTR cookie);

	//https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/actctx.c
	NTSYSAPI NTSTATUS WINAPI RtlFindActivationContextSectionGuid(
		_In_ ULONG Flags,
		const PGUID extguid,
		ULONG section_kind,
		const PGUID guid,
		PVOID ptr);

	// https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/actctx.c
	NTSYSAPI NTSTATUS WINAPI RtlFindActivationContextSectionString(
		_In_ ULONG Flags,
		const PGUID guid,
		ULONG section_kind,
		const PUNICODE_STRING section_name,
		PVOID ptr);

	// https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/actctx.c
	NTSYSAPI VOID WINAPI RtlFreeActivationContextStack(
		_In_ PACTIVATION_CONTEXT_STACK actctx_stack);

	//https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/actctx.c
	NTSYSAPI void WINAPI RtlFreeThreadActivationContextStack(VOID);

	// https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/actctx.c
	NTSYSAPI NTSTATUS WINAPI RtlGetActiveActivationContext(
		_Out_ PHANDLE handle);

	// https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/actctx.c
	NTSYSAPI BOOLEAN WINAPI RtlIsActivationContextActive(
		_In_ HANDLE handle);

	//https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/actctx.c
	NTSYSAPI NTSTATUS WINAPI RtlQueryActivationContextApplicationSettings(
		DWORD Flags,
		HANDLE handle,
		const PWCHAR ns,
		const PWCHAR settings,
		PWCHAR buffer,
		SIZE_T size,
		_Out_ PSIZE_T written);

	//https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/actctx.c
	NTSYSAPI NTSTATUS WINAPI RtlQueryInformationActivationContext(
		_In_ ULONG Flags,
		_In_ HANDLE Handle,
		PVOID Subinst,
		_In_ ULONG Class,
		_In_ PVOID Buffer,
		_In_ SIZE_T Bufsize,
		_Out_ PSIZE_T retlen);

	//https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/actctx.c
	NTSYSAPI void WINAPI RtlReleaseActivationContext(
		_In_ HANDLE handle);

	// https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/actctx.c
	NTSYSAPI NTSTATUS WINAPI RtlZombifyActivationContext(
		_In_ HANDLE handle);

}

#endif // _NTCONTEXTS_
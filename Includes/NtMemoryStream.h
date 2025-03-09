#pragma once

#ifndef _NTMEMORYSTREAM_
#define _NTMEMORYSTREAM_

#include "NtCommonDefs.h"

extern "C" {

	// NO UNRESOLVED FUNCTIONS
	// On Windows 10 each of these functions either return ERROR_NOT_IMPLEMENTED or are empty placeholders.

	// Reversed. Empty function. Return ERROR_SUCCESS
	//https://doxygen.reactos.org/da/dff/memstream_8c.html
	NTSYSAPI ULONG NTAPI RtlAddRefMemoryStream(
		_In_ IStream* This);

	// NOT IMPLEMENTED
	// https://doxygen.reactos.org/da/dff/memstream_8c.html
	NTSYSAPI HRESULT NTAPI RtlCloneMemoryStream(
		_In_ IStream* This,
		_Outptr_ IStream** ResultStream);

	// NOT IMPLEMENTED
	// https://doxygen.reactos.org/da/dff/memstream_8c.html
	NTSYSAPI HRESULT NTAPI RtlCommitMemoryStream(
		_In_ IStream* This,
		_In_ ULONG CommitFlags);

	// NOT IMPLEMENTED
	// https://doxygen.reactos.org/da/dff/memstream_8c.html
	NTSYSAPI HRESULT NTAPI RtlCopyMemoryStreamTo(
		_In_ IStream* This,
		_In_ IStream* Target,
		_In_ ULARGE_INTEGER Length,
		_Out_opt_ PULARGE_INTEGER BytesRead,
		_Out_opt_ PULARGE_INTEGER BytesWritten);

	// NOT IMPLEMENTED
	//RtlCopyOutOfProcessMemoryStreamTo

	// Empty function
	// https://doxygen.reactos.org/da/dff/memstream_8c.html
	NTSYSAPI VOID NTAPI RtlFinalReleaseOutOfProcessMemoryStream(
		_In_ PRTL_MEMORY_STREAM Stream);

	// Reversed. Empty function.
	// https://doxygen.reactos.org/da/dff/memstream_8c.html
	NTSYSAPI VOID NTAPI RtlInitMemoryStream(
		_Out_ PRTL_MEMORY_STREAM Stream);

	// Empty function
	// https://doxygen.reactos.org/da/dff/memstream_8c.html
	NTSYSAPI VOID NTAPI RtlInitOutOfProcessMemoryStream(
		_Out_ PRTL_MEMORY_STREAM Stream);

	// NOT IMPLEMENTED
	// https://doxygen.reactos.org/da/dff/memstream_8c.html
	NTSYSAPI HRESULT NTAPI RtlLockMemoryStreamRegion(
		_In_ IStream* This,
		_In_ ULARGE_INTEGER Offset,
		_In_ ULARGE_INTEGER Length,
		_In_ ULONG LockType);

	// NOT IMPLEMENTED
	// https://doxygen.reactos.org/da/dff/memstream_8c.html
	NTSYSAPI HRESULT NTAPI RtlQueryInterfaceMemoryStream(
		_In_ IStream* This,
		_In_ REFIID RequestedIid,
		_Outptr_ PVOID* ResultObject);

	// NOT IMPLEMENTED
	// https://doxygen.reactos.org/da/dff/memstream_8c.html
	NTSYSAPI HRESULT NTAPI RtlReadMemoryStream(
		_In_ IStream* This,
		_Out_writes_bytes_(Length) PVOID Buffer,
		_In_ ULONG Length,
		_Out_opt_ PULONG BytesRead);

	// NOT IMPLEMENTED
	// https://doxygen.reactos.org/da/dff/memstream_8c.html
	NTSYSAPI HRESULT NTAPI RtlReadOutOfProcessMemoryStream(
		_In_ IStream* This,
		_Out_writes_bytes_(Length) PVOID Buffer,
		_In_ ULONG Length,
		_Out_opt_ PULONG BytesRead);

	// Returns ERROR_SUCESS
	// https://doxygen.reactos.org/da/dff/memstream_8c.html
	NTSYSAPI ULONG NTAPI RtlReleaseMemoryStream(
		_In_ IStream* This);

	// NOT IMPLEMENTED
	// https://doxygen.reactos.org/da/dff/memstream_8c.html
	NTSYSAPI HRESULT NTAPI RtlRevertMemoryStream(
		_In_ IStream* This);

	// NOT IMPLEMENTED
	// https://doxygen.reactos.org/da/dff/memstream_8c.html
	NTSYSAPI HRESULT NTAPI RtlSeekMemoryStream(
		_In_ IStream* This,
		_In_ LARGE_INTEGER RelativeOffset,
		_In_ ULONG Origin,
		_Out_opt_ PULARGE_INTEGER ResultOffset);

	// NOT IMPLEMENTED
	// https://doxygen.reactos.org/da/dff/memstream_8c.html
	NTSYSAPI HRESULT NTAPI RtlSetMemoryStreamSize(
		_In_ IStream* This,
		_In_ ULARGE_INTEGER NewSize);

	// NOT IMPLEMENTED
	// https://doxygen.reactos.org/da/dff/memstream_8c.html
	NTSYSAPI HRESULT NTAPI RtlStatMemoryStream(
		_In_ IStream* This,
		_Out_ STATSTG* Stats,
		_In_ ULONG Flags);

	// NOT IMPLEMENTED
	// https://doxygen.reactos.org/da/dff/memstream_8c.html
	NTSYSAPI HRESULT NTAPI RtlUnlockMemoryStreamRegion(
		_In_ IStream* This,
		_In_ ULARGE_INTEGER Offset,
		_In_ ULARGE_INTEGER Length,
		_In_ ULONG LockType);

	// NOT IMPLEMENTED
	// https://doxygen.reactos.org/da/dff/memstream_8c.html
	NTSYSAPI HRESULT NTAPI RtlWriteMemoryStream(
		_In_ IStream* This,
		_In_reads_bytes_(Length) CONST VOID* Buffer,
		_In_ ULONG Length,
		_Out_opt_ PULONG BytesWritten);
}

#endif // _NTMEMORYSTREAM_
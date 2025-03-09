#pragma once

#ifndef _NTCLIENTSERVER_
#define _NTCLIENTSERVER_

#include "NtCommonDefs.h"

extern "C" {

	// NO UNDEFINED FUNCTIONS

	//https://www.geoffchappell.com/studies/windows/win32/ntdll/api/csrutil/allocatecapturebuffer.htm
	NTSYSAPI PVOID WINAPI CsrAllocateCaptureBuffer(
		ULONG MaxMessagePointers,
		ULONG Size);

	//https://www.geoffchappell.com/studies/windows/win32/ntdll/api/csrutil/allocatemessagepointer.htm
	NTSYSAPI ULONG WINAPI CsrAllocateMessagePointer(
		PVOID CaptureBuffer,
		ULONG Size,
		PVOID* Pointer);

	//https://www.geoffchappell.com/studies/windows/win32/ntdll/api/csrutil/capturemessagebuffer.htm
	NTSYSAPI ULONG WINAPI CsrCaptureMessageBuffer(
		PVOID CaptureBuffer,
		PVOID Data,
		ULONG Size,
		PVOID* Pointer);

	// https://doxygen.reactos.org/d6/dad/sdk_2include_2reactos_2subsys_2csr_2csr_8h.html
	NTSYSAPI NTSTATUS NTAPI CsrCaptureMessageMultiUnicodeStringsInPlace(
		_Inout_ PCSR_CAPTURE_BUFFER* CaptureBuffer,
		_In_ ULONG StringsCount,
		_In_ PUNICODE_STRING* MessageStrings);

	// https://doxygen.reactos.org/d6/dad/sdk_2include_2reactos_2subsys_2csr_2csr_8h.html
	NTSYSAPI VOID NTAPI CsrCaptureMessageString(
		_Inout_ PCSR_CAPTURE_BUFFER CaptureBuffer,
		_In_opt_ PCSTR 	String,
		_In_ ULONG 	StringLength,
		_In_ ULONG 	MaximumLength,
		_Out_ PSTRING 	CapturedString);

	// https://doxygen.reactos.org/d6/dad/sdk_2include_2reactos_2subsys_2csr_2csr_8h.html
	NTSYSAPI PLARGE_INTEGER NTAPI CsrCaptureTimeout(
		_In_ ULONG 	Milliseconds,
		_Out_ PLARGE_INTEGER Timeout);

	//https://www.geoffchappell.com/studies/windows/win32/ntdll/api/csrutil/clientcallserver.htm
	NTSYSAPI NTSTATUS WINAPI CsrClientCallServer(
		CSR_API_MSG* ApiMsg,
		PVOID CaptureBuffer,
		ULONG ApiNumber,
		LONG ApiMessageDataSize);

	//https://doxygen.reactos.org/d6/dad/sdk_2include_2reactos_2subsys_2csr_2csr_8h.html
	NTSYSAPI NTSTATUS NTAPI CsrClientConnectToServer(
		_In_ PCWSTR ObjectDirectory,
		_In_ ULONG ServerId,
		_In_ PVOID ConnectionInfo,
		_Inout_ PULONG 	ConnectionInfoSize,
		_Out_ PBOOLEAN 	ServerToServerCall);

	//https://doxygen.reactos.org/d6/dad/sdk_2include_2reactos_2subsys_2csr_2csr_8h.html
	NTSYSAPI VOID NTAPI CsrFreeCaptureBuffer(
		_In_ _Frees_ptr_ PCSR_CAPTURE_BUFFER CaptureBuffer);

	//https://doxygen.reactos.org/d6/dad/sdk_2include_2reactos_2subsys_2csr_2csr_8h.html
	NTSYSAPI HANDLE NTAPI CsrGetProcessId(VOID);

	//https://doxygen.reactos.org/d6/dad/sdk_2include_2reactos_2subsys_2csr_2csr_8h.html
	NTSYSAPI NTSTATUS NTAPI CsrIdentifyAlertableThread(VOID);

	//https://doxygen.reactos.org/d6/dad/sdk_2include_2reactos_2subsys_2csr_2csr_8h.html
	NTSYSAPI NTSTATUS NTAPI CsrSetPriorityClass(
		_In_ HANDLE 	Process,
		_Inout_ PULONG PriorityClass);

	//Reversed
	NTSYSAPI BOOL NTAPI CsrVerifyRegion(
		_In_ HANDLE RegionBase,
		_In_ DWORD RegionSize);

}

#endif // _NTCLIENTSERVER_
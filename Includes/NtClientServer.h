#pragma once

#ifndef _NTCLIENTSERVER_
#define _NTCLIENTSERVER_

#include "NtCommonDefs.h"

extern "C" {

	// See : https://www.ivanlef0u.tuxfamily.org/?p=188
	// See : https://www.geoffchappell.com/studies/windows/win32/csrsrv/api/apireqst/api_msg.htm

	// NO UNDEFINED FUNCTIONS

	typedef struct _CSR_API_CONNECTINFO CSR_API_CONNECTINFO;
	typedef struct _CSR_API_MSG CSR_API_MSG, * PCSR_API_MSG;
	// https://doxygen.reactos.org/d4/de1/csrmsg_8h.html#adcbe9d8d973f321880e9fc4696439d4d
	typedef ULONG CSR_API_NUMBER;
	typedef struct _CSR_CAPTURE_BUFFER CSR_CAPTURE_BUFFER,* PCSR_CAPTURE_BUFFER;
	typedef struct _CSR_CLIENT_CONNECT CSR_CLIENT_CONNECT;

	// https://doxygen.reactos.org/d2/db8/struct__PORT__MESSAGE__HEADER.html
	typedef struct _PORT_MESSAGE_HEADER {
		USHORT DataSize;
		USHORT MessageSize;
		USHORT MessageType;
		USHORT VirtualRangesOffset;
		CLIENT_ID ClientId;
		ULONG MessageId;
		ULONG SectionSize;
	} PORT_MESSAGE_HEADER;

	// https://doxygen.reactos.org/da/d28/struct__CSR__API__CONNECTINFO.html
	struct _CSR_API_CONNECTINFO {
		HANDLE ObjectDirectory;
		PVOID SharedSectionBase;
		PVOID SharedStaticServerData;
		PVOID SharedSectionHeap;
		ULONG DebugFlags;
		ULONG SizeOfPebData;
		ULONG SizeOfTebData;
		ULONG NumberOfServerDllNames;
		HANDLE ServerProcessId;
	};

	// https://doxygen.reactos.org/db/d40/struct__CSR__CLIENT__CONNECT.html
	struct _CSR_CLIENT_CONNECT {
		ULONG ServerId;
		PVOID ConnectionInfo;
		ULONG ConnectionInfoSize;
	};

	// https://www.geoffchappell.com/studies/windows/win32/csrsrv/api/apireqst/api_msg.htm
	// Expected size from 6.0 to 10.0 is 0x01B0
	// https://doxygen.reactos.org/da/db7/struct__CSR__API__MESSAGE.html
	struct _CSR_API_MSG {
		PORT_MESSAGE_HEADER Header;
		union {
			CSR_API_CONNECTINFO ConnectionInfo;
			struct {
				PCSR_CAPTURE_BUFFER CsrCaptureData;
				CSR_API_NUMBER ApiNumber;
				NTSTATUS Status;
				ULONG Reserved;
				union {
					CSR_CLIENT_CONNECT CsrClientConnect;
					ULONG_PTR ApiMessageData[39];
				} Data;
			} DUMMYSTRUCTNAME;
		} DUMMYUNIONNAME;
	};

	struct _CSR_CAPTURE_BUFFER {
		ULONG Size;
		struct _CSR_CAPTURE_BUFFER* PreviousCaptureBuffer;
		ULONG PointerCount;
		PVOID BufferEnd;
		ULONG_PTR PointerOffsetsArray[ANYSIZE_ARRAY];
	};

	// ======================== functions ========================
	//https://www.geoffchappell.com/studies/windows/win32/ntdll/api/csrutil/allocatecapturebuffer.htm
	NTSYSAPI PVOID NTAPI CsrAllocateCaptureBuffer(
		ULONG MaxMessagePointers,
		ULONG Size);

	//https://www.geoffchappell.com/studies/windows/win32/ntdll/api/csrutil/allocatemessagepointer.htm
	NTSYSAPI ULONG NTAPI CsrAllocateMessagePointer(
		PVOID CaptureBuffer,
		ULONG Size,
		PVOID* Pointer);

	//https://www.geoffchappell.com/studies/windows/win32/ntdll/api/csrutil/capturemessagebuffer.htm
	NTSYSAPI ULONG NTAPI CsrCaptureMessageBuffer(
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
		_In_opt_ PCSTR String,
		_In_ ULONG StringLength,
		_In_ ULONG MaximumLength,
		_Out_ PSTRING CapturedString);

	// https://doxygen.reactos.org/d6/dad/sdk_2include_2reactos_2subsys_2csr_2csr_8h.html
	NTSYSAPI PLARGE_INTEGER NTAPI CsrCaptureTimeout(
		_In_ ULONG 	Milliseconds,
		_Out_ PLARGE_INTEGER Timeout);

	// https://www.geoffchappell.com/studies/windows/win32/ntdll/api/csrutil/clientcallserver.htm
	NTSYSAPI NTSTATUS NTAPI CsrClientCallServer(
		PCSR_API_MSG ApiMsg,
		PVOID CaptureBuffer,
		ULONG ApiNumber,
		LONG ApiMessageDataSize);

	//https://doxygen.reactos.org/d6/dad/sdk_2include_2reactos_2subsys_2csr_2csr_8h.html
	NTSYSAPI NTSTATUS NTAPI CsrClientConnectToServer(
		_In_ PCWSTR ObjectDirectory,
		_In_ ULONG ServerId,
		_In_ PVOID ConnectionInfo,
		_Inout_ PULONG ConnectionInfoSize,
		_Out_ PBOOLEAN ServerToServerCall);

	//https://doxygen.reactos.org/d6/dad/sdk_2include_2reactos_2subsys_2csr_2csr_8h.html
	NTSYSAPI VOID NTAPI CsrFreeCaptureBuffer(
		_In_ _Frees_ptr_ PCSR_CAPTURE_BUFFER CaptureBuffer);

	//https://doxygen.reactos.org/d6/dad/sdk_2include_2reactos_2subsys_2csr_2csr_8h.html
	NTSYSAPI HANDLE NTAPI CsrGetProcessId(VOID);

	//https://doxygen.reactos.org/d6/dad/sdk_2include_2reactos_2subsys_2csr_2csr_8h.html
	NTSYSAPI NTSTATUS NTAPI CsrIdentifyAlertableThread(VOID);

	//https://doxygen.reactos.org/d6/dad/sdk_2include_2reactos_2subsys_2csr_2csr_8h.html
	NTSYSAPI NTSTATUS NTAPI CsrSetPriorityClass(
		_In_ HANDLE Process,
		_Inout_ PULONG PriorityClass);

	//Reversed
	NTSYSAPI BOOL NTAPI CsrVerifyRegion(
		_In_ HANDLE RegionBase,
		_In_ DWORD RegionSize);

}

#endif // _NTCLIENTSERVER_
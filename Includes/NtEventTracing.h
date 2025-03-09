#pragma once

#ifndef _NTEVTTRACING_
#define _NTEVTTRACING_

#include "NtCommonDefs.h"

extern "C" {

	// UNRESOLVED FUNCTIONS

	//EtwDeliverDataBlock
	// Invoked from :
	//   |- EtwpNotificationThread
	//   |- EtwpSendSessionNotification
	//      |- EtwpStartUmLogger
	//         |- EtwProcessPrivateLoggerRequest
	//            |- EtwProcessNotification
	//               |- DeliverDataBlock (LOOPING)
	//      |- EtwpLogger
	//         |- EtwpStartUmLogger (SEE ABOVE)
	//      |- EtwpStopLoggerInstance
	//         |- EtwpStopUmLogger
	//            |-EtwpStopUmLogger
	//              |- EtwProcessPrivateLoggerRequest (EXPORTED)
	//              |- EtwpShutdownPrivateLoggers
	//                 |- RtlExitUserProcess (EXPORTED)
	//            |- EtwpLogger (LOOPING SEE ABOVE)
	//      |- EtwpFlushActiveBuffers
	//         |- EtwpLogger (LOOPING SEE ABOVE)

	// EtwProcessPrivateLoggerRequest
	// (SECHOST) |- unsigned int __stdcall __high EtwpSendUmLogRequest(enum ETWTRACECONTROLCODE, struct _WMI_LOGGER_INFORMATION *, unsigned int, struct _EVENT_FILTER_DESCRIPTOR *)

	// END OF UNRESOLVED FUNCTIONS

	// https://docs.rs/phnt/latest/phnt/ffi/fn.EtwCheckCoverage.html
	//EtwCheckCoverage
	NTSYSAPI BOOL NTAPI EtwCheckCoverage(
		PTELEMETRY_COVERAGE_POINT);

	//https://learn.microsoft.com/fr-fr/windows/win32/api/evntrace/nf-evntrace-createtraceinstanceid
	// Forwarded from Advapi32:CreateTraceInstanceId
	NTSYSAPI ULONG WMIAPI EtwCreateTraceInstanceId(
		[in]  HANDLE               RegHandle,
		[out] PEVENT_INSTANCE_INFO InstInfo);

	// https://ntdoc.m417z.com/etwenumerateprocessregguids
	// https://docs.rs/phnt/latest/phnt/ffi/fn.EtwEnumerateProcessRegGuids.html
	NTSYSAPI ULONG NTAPI EtwEnumerateProcessRegGuids(
		_Out_writes_bytes_opt_(OutBufferSize) PVOID OutBuffer,
		_In_ ULONG OutBufferSize,
		_Out_ PULONG ReturnLength);

	// https://learn.microsoft.com/fr-fr/windows/win32/api/evntrace/nf-evntrace-gettraceenableflags
	// Forwarded from Advapi32:GetTraceEnableFlags
	NTSYSAPI ULONG NTAPI EtwGetTraceEnableFlags(
		[in] TRACELOGGER_HANDLE TraceHandle);

	// https://learn.microsoft.com/fr-fr/windows/win32/api/evntrace/nf-evntrace-gettraceenablelevel
	// Forwarded from Advapi32:GetTraceEnableLevel
	NTSYSAPI UCHAR NTAPI EtwGetTraceEnableLevel(
		[in] TRACEHANDLE TraceHandle);

	// https://learn.microsoft.com/fr-fr/windows/win32/api/evntrace/nf-evntrace-gettraceloggerhandle
	// Forwarded from Advapi32:GetTraceLoggerHandle
	NTSYSAPI TRACEHANDLE NTAPI EtwGetTraceLoggerHandle(
		[in] PVOID Buffer);

	// https://learn.microsoft.com/en-us/windows/win32/devnotes/etwlogtraceevent
	NTSYSAPI ULONG NTAPI EtwLogTraceEvent(
		_In_ TRACEHANDLE LoggerHandle,
		_In_ PEVENT_TRACE_HEADER EventTrace);

	// https://docs.rs/phnt/latest/phnt/ffi/fn.EtwNotificationRegister.html
	// See also : https://www.geoffchappell.com/studies/windows/win32/ntdll/api/etw/etweventregister.htm
	NTSYSAPI ULONG NTAPI EtwNotificationRegister(
		LPCGUID Guid,
		ULONG Type,
		PETW_NOTIFICATION_CALLBACK Callback,
		PVOID Context,
		PREGHANDLE RegHandle);

	//https://github.com/winsiderss/systeminformer/blob/b0526bc41f7536bb9e71ecdc5d74f05572d703a5/phnt/include/ntwmi.h#L5854
	NTSYSAPI ULONG NTAPI EtwNotificationUnregister(
		_In_ REGHANDLE RegHandle,
		_Out_opt_ PVOID* Context);
	
	// https://www.geoffchappell.com/studies/windows/win32/ntdll/api/etw/registersecurityprovider.htm
	NTSYSAPI ULONG NTAPI EtwRegisterSecurityProvider(VOID);

	// https://learn.microsoft.com/fr-fr/windows/win32/api/evntrace/nf-evntrace-registertraceguidsa
	NTSYSAPI ULONG NTAPI EtwRegisterTraceGuidsA(
		[in]      WMIDPREQUEST             RequestAddress,
		[in]      PVOID                    RequestContext,
		[in]      LPCGUID                  ControlGuid,
		[in]      ULONG                    GuidCount,
		[in, out] PTRACE_GUID_REGISTRATION TraceGuidReg,
		[in]      LPCSTR                   MofImagePath,
		[in]      LPCSTR                   MofResourceName,
		[out]     TRACEGUID_HANDLE* RegistrationHandle);

	// https://learn.microsoft.com/fr-fr/windows/win32/api/evntrace/nf-evntrace-registertraceguidsw
	NTSYSAPI ULONG NTAPI EtwRegisterTraceGuidsW(
		[in]      WMIDPREQUEST             RequestAddress,
		[in]      PVOID                    RequestContext,
		[in]      LPCGUID                  ControlGuid,
		[in]      ULONG                    GuidCount,
		[in, out] PTRACE_GUID_REGISTRATION TraceGuidReg,
		[in]      LPCWSTR                  MofImagePath,
		[in]      LPCWSTR                  MofResourceName,
		[out]     PTRACEHANDLE             RegistrationHandle);

	//https://ntdoc.m417z.com/etwreplynotification
	NTSYSAPI ULONG NTAPI EtwReplyNotification(
		_In_ PETW_NOTIFICATION_HEADER Notification);

	//https://github.com/winsiderss/systeminformer/blob/b0526bc41f7536bb9e71ecdc5d74f05572d703a5/phnt/include/ntwmi.h#L5862
	NTSYSAPI ULONG NTAPI EtwSendNotification(
		_In_ PETW_NOTIFICATION_HEADER DataBlock,
		_In_ ULONG ReceiveDataBlockSize,
		_Inout_ PVOID ReceiveDataBlock,
		_Out_ PULONG ReplyReceived,
		_Out_ PULONG ReplySizeNeeded);

	// https://ntdoc.m417z.com/etwsetmark
	NTSYSAPI ULONG NTAPI EtwSetMark(
		_In_opt_ TRACEHANDLE TraceHandle,
		_In_ PETW_SET_MARK_INFORMATION MarkInfo,
		_In_ ULONG Size);

	// https://learn.microsoft.com/fr-fr/windows/win32/api/evntrace/nf-evntrace-traceeventinstance
	// Forwarded from Advapi32:TraceEventInstance
	NTSYSAPI ULONG NTAPI EtwTraceEventInstance(
		[in] TRACEHANDLE            TraceHandle,
		[in] PEVENT_INSTANCE_HEADER EventTrace,
		[in] PEVENT_INSTANCE_INFO   InstInfo,
		[in] PEVENT_INSTANCE_INFO   ParentInstInfo);

	// https://learn.microsoft.com/fr-fr/windows/win32/api/evntrace/nf-evntrace-tracemessage
	// Forwarded from Advapi32:TraceMessage
	NTSYSAPI ULONG NTAPI EtwTraceMessage(
		[in] TRACEHANDLE LoggerHandle,
		[in] ULONG       MessageFlags,
		[in] LPCGUID     MessageGuid,
		[in] USHORT      MessageNumber,
		...);

	// https://learn.microsoft.com/fr-fr/windows/win32/api/evntrace/nf-evntrace-tracemessageva
	// Forwarded from Advapi32:TraceMessageVa
	NTSYSAPI ULONG NTAPI EtwTraceMessageVa(
		[in] TRACEHANDLE LoggerHandle,
		[in] ULONG       MessageFlags,
		[in] LPCGUID     MessageGuid,
		[in] USHORT      MessageNumber,
		[in] va_list     MessageArgList);

	// https://learn.microsoft.com/fr-fr/windows/win32/api/evntrace/nf-evntrace-unregistertraceguids
	// Forwarded from Advapi32:UnregisterTraceGuids
	NTSYSAPI ULONG NTAPI EtwUnregisterTraceGuids(
		[in] TRACEGUID_HANDLE RegistrationHandle);

	// https://jsecurity101.medium.com/uncovering-window-security-events-ab72e1ec745c
	// https://www.geoffchappell.com/studies/windows/win32/ntdll/api/etw/writeumsecurityevent.htm
	NTSYSAPI ULONG NTAPI EtwWriteUMSecurityEvent(
		PCEVENT_DESCRIPTOR EventDescriptor,
		USHORT EventProperty,
		ULONG UserDataCount,
		PEVENT_DATA_DESCRIPTOR UserData);

	// https://www.mdpi.com/2624-800X/1/3/21
	// https://gist.github.com/Nexact/a67f5eefa47eb6e01983694b5f6dd154
	// https://b1n.io/posts/rust-shellcode/#etwp_create_etw_thread
	NTSYSAPI intptr_t NTAPI EtwpCreateEtwThread(
		PVOID entryPoint,
		PVOID undefined);

	// Reverse engineered. Result in Mhz.
	NTSYSAPI NTSTATUS NTAPI EtwpGetCpuSpeed(
		_Out_ PDWORD pResult);

}

#endif // _NTEVTTRACING_
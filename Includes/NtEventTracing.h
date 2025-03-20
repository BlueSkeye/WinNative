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

	typedef ULONG64 TRACEHANDLE, * PTRACEHANDLE;
	typedef ULONG64 TRACELOGGER_HANDLE;
	typedef ULONG64 TRACEGUID_HANDLE;

	// https://learn.microsoft.com/fr-fr/windows/win32/api/evntrace/ns-evntrace-event_instance_info
	typedef struct EVENT_INSTANCE_INFO {
		HANDLE RegHandle;
		ULONG  InstanceId;
	} EVENT_INSTANCE_INFO, * PEVENT_INSTANCE_INFO;

	// https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_header
	typedef struct _EVENT_TRACE_HEADER {
		USHORT        Size;
		union {
			USHORT FieldTypeFlags;
			struct {
				UCHAR HeaderType;
				UCHAR MarkerFlags;
			} DUMMYSTRUCTNAME;
		} DUMMYUNIONNAME;
		union {
			ULONG Version;
			struct {
				UCHAR  Type;
				UCHAR  Level;
				USHORT Version;
			} Class;
		} DUMMYUNIONNAME2;
		ULONG         ThreadId;
		ULONG         ProcessId;
		LARGE_INTEGER TimeStamp;
		union {
			GUID      Guid;
			ULONGLONG GuidPtr;
		} DUMMYUNIONNAME3;
		union {
			struct {
				ULONG KernelTime;
				ULONG UserTime;
			} DUMMYSTRUCTNAME;
			ULONG64 ProcessorTime;
			struct {
				ULONG ClientContext;
				ULONG Flags;
			} DUMMYSTRUCTNAME2;
		} DUMMYUNIONNAME4;
	} EVENT_TRACE_HEADER, * PEVENT_TRACE_HEADER;

	// https://learn.microsoft.com/fr-fr/windows/win32/api/evntrace/ns-evntrace-event_instance_header
	typedef struct _EVENT_INSTANCE_HEADER {
		USHORT        Size;
		union {
			USHORT FieldTypeFlags;
			struct {
				UCHAR HeaderType;
				UCHAR MarkerFlags;
			} DUMMYSTRUCTNAME;
		} DUMMYUNIONNAME;
		union {
			ULONG Version;
			struct {
				UCHAR  Type;
				UCHAR  Level;
				USHORT Version;
			} Class;
		} DUMMYUNIONNAME2;
		ULONG         ThreadId;
		ULONG         ProcessId;
		LARGE_INTEGER TimeStamp;
		ULONGLONG     RegHandle;
		ULONG         InstanceId;
		ULONG         ParentInstanceId;
		union {
			struct {
				ULONG KernelTime;
				ULONG UserTime;
			} DUMMYSTRUCTNAME;
			ULONG64 ProcessorTime;
			struct {
				ULONG EventId;
				ULONG Flags;
			} DUMMYSTRUCTNAME2;
		} DUMMYUNIONNAME3;
		ULONGLONG     ParentRegHandle;
	} EVENT_INSTANCE_HEADER, * PEVENT_INSTANCE_HEADER;

	// https://docs.rs/phnt/latest/phnt/ffi/struct._TELEMETRY_COVERAGE_POINT.html
	typedef struct _TELEMETRY_COVERAGE_POINT {
		PWSTR Name;
		ULONG Hash;
		ULONG LastCoveredRound;
		ULONG Flags;
	} TELEMETRY_COVERAGE_POINT, *PTELEMETRY_COVERAGE_POINT;

	typedef enum _ETW_NOTIFICATION_TYPE {
		EtwNotificationTypeNoReply = 1,
		EtwNotificationTypeLegacyEnable = 2,
		EtwNotificationTypeEnable = 3,
		EtwNotificationTypePrivateLogger = 4,
		EtwNotificationTypePerflib = 5,
		EtwNotificationTypeAudio = 6,
		EtwNotificationTypeSession = 7,
		EtwNotificationTypeReserved = 8,
		EtwNotificationTypeCredentialUI = 9,
		EtwNotificationTypeInProcSession = 10,
		EtwNotificationTypeMax = 11,
	} ETW_NOTIFICATION_TYPE;

	// https://docs.rs/phnt/latest/phnt/ffi/struct._ETW_NOTIFICATION_HEADER.html
	typedef struct _ETW_NOTIFICATION_HEADER {
		ETW_NOTIFICATION_TYPE NotificationType;
		ULONG NotificationSize;
		ULONG Offset;
		BOOLEAN ReplyRequested;
		ULONG Timeout;
		union {
			ULONG ReplyCount;
			ULONG NotifyeeCount;
		} DUMMYUNIONNAME;
		ULONGLONG Reserved2;
		ULONG TargetPID;
		ULONG SourcePID;
		GUID DestinationGuid;
		GUID SourceGuid;
	} ETW_NOTIFICATION_HEADER, *PETW_NOTIFICATION_HEADER;

	// https://docs.rs/phnt/latest/phnt/ffi/type.PETW_NOTIFICATION_CALLBACK.html
	typedef ULONG(NTAPI* PETW_NOTIFICATION_CALLBACK)(
		PETW_NOTIFICATION_HEADER NotificationHeader,
		PVOID Context);

	// From Wmistr.h
	typedef enum {
		WMI_GET_ALL_DATA = 0,
		WMI_GET_SINGLE_INSTANCE = 1,
		WMI_SET_SINGLE_INSTANCE = 2,
		WMI_SET_SINGLE_ITEM = 3,
		WMI_ENABLE_EVENTS = 4,
		WMI_DISABLE_EVENTS = 5,
		WMI_ENABLE_COLLECTION = 6,
		WMI_DISABLE_COLLECTION = 7,
		WMI_REGINFO = 8,
		WMI_EXECUTE_METHOD = 9,
		WMI_CAPTURE_STATE = 10
	} WMIDPREQUESTCODE;

	// From evntrace.h
	typedef ULONG(NTAPI* WMIDPREQUEST)(
		_In_ WMIDPREQUESTCODE RequestCode,
		_In_ PVOID RequestContext,
		_Inout_ PULONG BufferSize,
		_Inout_ PVOID Buffer);

	// https://learn.microsoft.com/fr-fr/windows/win32/api/evntrace/ns-evntrace-trace_guid_registration
	typedef struct _TRACE_GUID_REGISTRATION {
		LPCGUID Guid;
		HANDLE RegHandle;
	} TRACE_GUID_REGISTRATION, * PTRACE_GUID_REGISTRATION;

	// https://github.com/winsiderss/systeminformer/blob/dd76af8d5f64ca6c5436d6fc86890f2ab90e17d7/phnt/include/ntwmi.h#L5592C1-L5596C56
	typedef struct _ETW_SET_MARK_INFORMATION {
		ULONG Flag;
		WCHAR Mark[1];
	} ETW_SET_MARK_INFORMATION, * PETW_SET_MARK_INFORMATION;

	// =============================== functions ===============================

	// https://docs.rs/phnt/latest/phnt/ffi/fn.EtwCheckCoverage.html
	//EtwCheckCoverage
	NTSYSAPI BOOL NTAPI EtwCheckCoverage(
		PTELEMETRY_COVERAGE_POINT);

	// https://learn.microsoft.com/fr-fr/windows/win32/api/evntrace/nf-evntrace-createtraceinstanceid
	// Forwarded from Advapi32:CreateTraceInstanceId
	NTSYSAPI ULONG NTAPI EtwCreateTraceInstanceId(
		_In_ HANDLE RegHandle,
		_Out_ PEVENT_INSTANCE_INFO InstInfo);

	// https://ntdoc.m417z.com/etwenumerateprocessregguids
	// https://docs.rs/phnt/latest/phnt/ffi/fn.EtwEnumerateProcessRegGuids.html
	NTSYSAPI ULONG NTAPI EtwEnumerateProcessRegGuids(
		_Out_writes_bytes_opt_(OutBufferSize) PVOID OutBuffer,
		_In_ ULONG OutBufferSize,
		_Out_ PULONG ReturnLength);

	// https://learn.microsoft.com/fr-fr/windows/win32/api/evntrace/nf-evntrace-gettraceenableflags
	// Forwarded from Advapi32:GetTraceEnableFlags
	NTSYSAPI ULONG NTAPI EtwGetTraceEnableFlags(
		_In_ TRACELOGGER_HANDLE TraceHandle);

	// https://learn.microsoft.com/fr-fr/windows/win32/api/evntrace/nf-evntrace-gettraceenablelevel
	// Forwarded from Advapi32:GetTraceEnableLevel
	NTSYSAPI UCHAR NTAPI EtwGetTraceEnableLevel(
		_In_ TRACEHANDLE TraceHandle);

	// https://learn.microsoft.com/fr-fr/windows/win32/api/evntrace/nf-evntrace-gettraceloggerhandle
	// Forwarded from Advapi32:GetTraceLoggerHandle
	NTSYSAPI TRACEHANDLE NTAPI EtwGetTraceLoggerHandle(
		_In_ PVOID Buffer);

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
		_In_ WMIDPREQUEST RequestAddress,
		_In_ PVOID RequestContext,
		_In_ LPCGUID ControlGuid,
		_In_ ULONG GuidCount,
		_Inout_ PTRACE_GUID_REGISTRATION TraceGuidReg,
		_In_ LPCSTR MofImagePath,
		_In_ LPCSTR MofResourceName,
		_Out_ TRACEGUID_HANDLE* RegistrationHandle);

	// https://learn.microsoft.com/fr-fr/windows/win32/api/evntrace/nf-evntrace-registertraceguidsw
	NTSYSAPI ULONG NTAPI EtwRegisterTraceGuidsW(
		_In_      WMIDPREQUEST             RequestAddress,
		_In_      PVOID                    RequestContext,
		_In_      LPCGUID                  ControlGuid,
		_In_      ULONG                    GuidCount,
		_Inout_ PTRACE_GUID_REGISTRATION TraceGuidReg,
		_In_      LPCWSTR                  MofImagePath,
		_In_      LPCWSTR                  MofResourceName,
		_Out_     PTRACEHANDLE             RegistrationHandle);

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

	// https://github.com/winsiderss/systeminformer/blob/dd76af8d5f64ca6c5436d6fc86890f2ab90e17d7/phnt/include/ntwmi.h#L5678
	NTSYSAPI ULONG NTAPI EtwSetMark(
		_In_opt_ TRACEHANDLE TraceHandle,
		_In_ PETW_SET_MARK_INFORMATION MarkInfo,
		_In_ ULONG Size);

	// https://learn.microsoft.com/fr-fr/windows/win32/api/evntrace/nf-evntrace-traceeventinstance
	// Forwarded from Advapi32:TraceEventInstance
	NTSYSAPI ULONG NTAPI EtwTraceEventInstance(
		_In_ TRACEHANDLE            TraceHandle,
		_In_ PEVENT_INSTANCE_HEADER EventTrace,
		_In_ PEVENT_INSTANCE_INFO   InstInfo,
		_In_ PEVENT_INSTANCE_INFO   ParentInstInfo);

	// https://learn.microsoft.com/fr-fr/windows/win32/api/evntrace/nf-evntrace-tracemessage
	// Forwarded from Advapi32:TraceMessage
	NTSYSAPI ULONG NTAPI EtwTraceMessage(
		_In_ TRACEHANDLE LoggerHandle,
		_In_ ULONG       MessageFlags,
		_In_ LPCGUID     MessageGuid,
		_In_ USHORT      MessageNumber,
		...);

	// https://learn.microsoft.com/fr-fr/windows/win32/api/evntrace/nf-evntrace-tracemessageva
	// Forwarded from Advapi32:TraceMessageVa
	NTSYSAPI ULONG NTAPI EtwTraceMessageVa(
		_In_ TRACEHANDLE LoggerHandle,
		_In_ ULONG       MessageFlags,
		_In_ LPCGUID     MessageGuid,
		_In_ USHORT      MessageNumber,
		_In_ va_list     MessageArgList);

	// https://learn.microsoft.com/fr-fr/windows/win32/api/evntrace/nf-evntrace-unregistertraceguids
	// Forwarded from Advapi32:UnregisterTraceGuids
	NTSYSAPI ULONG NTAPI EtwUnregisterTraceGuids(
		_In_ TRACEGUID_HANDLE RegistrationHandle);

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
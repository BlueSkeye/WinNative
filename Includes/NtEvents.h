#pragma once

#ifndef _NTEVENTS_
#define _NTEVENTS_

#include "NtCommonDefs.h"
#include "NtAccessRights.h"

#ifdef __cplusplus
extern "C" {
#endif

	// UNRESOLVED FUNCTIONS
	// EvtIntReportEventAndSourceAsync // invoked by several DLLs
	// END OF UNRESOLVED FUNCTIONS

	typedef struct _EVENT_DESCRIPTOR {
		USHORT    Id;
		UCHAR     Version;
		UCHAR     Channel;
		UCHAR     Level;
		UCHAR     Opcode;
		USHORT    Task;
		ULONGLONG Keyword;
	} EVENT_DESCRIPTOR, * PEVENT_DESCRIPTOR;
	typedef const EVENT_DESCRIPTOR* PCEVENT_DESCRIPTOR;

	// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FEvent%2FNtQueryEvent.html
	typedef enum _EVENT_INFORMATION_CLASS {
		EventBasicInformation
	} EVENT_INFORMATION_CLASS, * PEVENT_INFORMATION_CLASS;

	// https://learn.microsoft.com/en-us/windows/win32/api/evntprov/ns-evntprov-event_filter_descriptor
	typedef struct _EVENT_FILTER_DESCRIPTOR {
		ULONGLONG Ptr;
		ULONG     Size;
		ULONG     Type;
	} EVENT_FILTER_DESCRIPTOR, * PEVENT_FILTER_DESCRIPTOR;

	// https://learn.microsoft.com/en-us/windows/win32/api/evntprov/nc-evntprov-penablecallback
	typedef void (NTAPI* PENABLECALLBACK)(
		_In_ LPCGUID SourceId,
		_In_ ULONG IsEnabled,
		_In_ UCHAR Level,
		_In_ ULONGLONG MatchAnyKeyword,
		ULONGLONG MatchAllKeyword,
		_In_opt_ PEVENT_FILTER_DESCRIPTOR FilterData,
		_In_opt_ PVOID CallbackContext);

	// https://learn.microsoft.com/en-us/windows/win32/api/evntprov/ne-evntprov-event_info_class
	typedef enum _EVENT_INFO_CLASS {
		EventProviderBinaryTrackInfo,
		EventProviderSetReserved1,
		EventProviderSetTraits,
		EventProviderUseDescriptorType,
		MaxEventInfo
	} EVENT_INFO_CLASS;

	// https://learn.microsoft.com/en-us/windows/win32/api/evntprov/ns-evntprov-event_data_descriptor
	typedef struct _EVENT_DATA_DESCRIPTOR {
		ULONGLONG Ptr;
		ULONG     Size;
		union {
			ULONG Reserved;
			struct {
				UCHAR  Type;
				UCHAR  Reserved1;
				USHORT Reserved2;
			} DUMMYSTRUCTNAME;
		} DUMMYUNIONNAME;
	} EVENT_DATA_DESCRIPTOR, * PEVENT_DATA_DESCRIPTOR;

	// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FMutant%2FNtQueryMutant.html
	typedef enum _MUTANT_INFORMATION_CLASS {
		MutantBasicInformation
	} MUTANT_INFORMATION_CLASS, * PMUTANT_INFORMATION_CLASS;

	// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FType%20independed%2FOBJECT_WAIT_TYPE.html
	typedef enum _OBJECT_WAIT_TYPE {
		WaitAllObject,
		WaitAnyObject
	} OBJECT_WAIT_TYPE, * POBJECT_WAIT_TYPE;

	// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FSemaphore%2FNtQuerySemaphore.html
	typedef enum _SEMAPHORE_INFORMATION_CLASS {
		SemaphoreBasicInformation
	} SEMAPHORE_INFORMATION_CLASS, * PSEMAPHORE_INFORMATION_CLASS;

	// https://doxygen.reactos.org/db/dd9/ntdef_8template_8h.html#a698d786b10840dc1198b09bb957b00f5
	typedef enum _WAIT_TYPE {
		WaitAll,
		WaitAny
	} WAIT_TYPE;

	// =============================== functions ===============================

	//https://learn.microsoft.com/en-us/windows/win32/api/evntprov/nf-evntprov-eventactivityidcontrol
	// Forwarded from advapi32.dll:EventActivityIdControl
	NTSYSAPI ULONG NTAPI EtwEventActivityIdControl(
		_In_ ULONG  ControlCode,
		_Inout_ LPGUID ActivityId);

	// https://learn.microsoft.com/en-us/windows/win32/api/evntprov/nf-evntprov-eventenabled
	// Forwarded from advapi32.dll:EventEnabled
	NTSYSAPI BOOLEAN NTAPI EtwEventEnabled(
		_In_ REGHANDLE          RegHandle,
		_In_ PCEVENT_DESCRIPTOR EventDescriptor);

	//https://learn.microsoft.com/en-us/windows/win32/api/evntprov/nf-evntprov-eventproviderenabled
	// Forwarded from advapi32.dll:EventProviderEnabled
	NTSYSAPI BOOLEAN NTAPI EtwEventProviderEnabled(
		_In_ REGHANDLE RegHandle,
		_In_ UCHAR     Level,
		_In_ ULONGLONG Keyword);

	// https://learn.microsoft.com/en-us/windows/win32/api/evntprov/nf-evntprov-eventregister
	// Forwarded from advapi32.dll:EventRegister
	NTSYSAPI ULONG NTAPI EtwEventRegister(
		_In_ LPCGUID ProviderId,
		_In_opt_ PENABLECALLBACK EnableCallback,
		_In_opt_ PVOID CallbackContext,
		_Out_ PREGHANDLE RegHandle);

	// https://learn.microsoft.com/en-us/windows/win32/api/evntprov/nf-evntprov-eventsetinformation
	// Forwarded from advapi32.dll:EventSetInformation
	NTSYSAPI ULONG NTAPI EtwEventSetInformation(
		_In_ REGHANDLE        RegHandle,
		_In_ EVENT_INFO_CLASS InformationClass,
		_In_ PVOID            EventInformation,
		_In_ ULONG            InformationLength);

	//https://learn.microsoft.com/en-us/windows/win32/api/evntprov/nf-evntprov-eventunregister
	// Forwarded from advapi32.dll:EventUnregister
	NTSYSAPI ULONG NTAPI EtwEventUnregister(
		_In_ REGHANDLE RegHandle);

	// https://learn.microsoft.com/en-us/windows/win32/api/evntprov/nf-evntprov-eventwrite
	// Forwarded from advapi32.dll:EventWrite
	NTSYSAPI ULONG NTAPI EtwEventWrite(
		_In_ REGHANDLE              RegHandle,
		_In_ PCEVENT_DESCRIPTOR     EventDescriptor,
		_In_ ULONG                  UserDataCount,
		_In_opt_ PEVENT_DATA_DESCRIPTOR UserData);

	//https://learn.microsoft.com/en-us/windows/win32/api/evntprov/nf-evntprov-eventwriteex
	// Forwarded from advapi32.dll:EventWriteEx
	NTSYSAPI ULONG NTAPI EtwEventWriteEx(
		_In_           REGHANDLE              RegHandle,
		_In_           PCEVENT_DESCRIPTOR     EventDescriptor,
		_In_           ULONG64                Filter,
		_In_           ULONG                  Flags,
		_In_opt_ LPCGUID                ActivityId,
		_In_opt_ LPCGUID                RelatedActivityId,
		_In_           ULONG                  UserDataCount,
		_In_opt_ PEVENT_DATA_DESCRIPTOR UserData);

	//https://skanthak.hier-im-netz.de/download/NTDLL.H
	// Forwarded from advapi32.dll:EventWriteEndScenario
	NTSYSAPI DWORD NTAPI EtwEventWriteEndScenario(
		REGHANDLE             RegHandle,
		EVENT_DESCRIPTOR* EventDescriptor,
		DWORD                 UserDataCount,
		EVENT_DATA_DESCRIPTOR* UserData);

	//https://learn.microsoft.com/en-us/windows/win32/devnotes/etweventwritefull
	NTSYSAPI ULONG NTAPI EtwEventWriteFull(
		__in REGHANDLE RegHandle,
		__in PCEVENT_DESCRIPTOR EventDescriptor,
		__in USHORT EventProperty,
		__in_opt LPCGUID ActivityId,
		__in_opt LPCGUID RelatedActivityId,
		__in ULONG UserDataCount,
		__in_ecount_opt(UserDataCount) PEVENT_DATA_DESCRIPTOR UserData);

	//https://www.geoffchappell.com/studies/windows/win32/ntdll/api/etw/evntapi/writenoregistration.htm
	NTSYSAPI ULONG NTAPI EtwEventWriteNoRegistration(
		GUID const* ProviderId,
		EVENT_DESCRIPTOR const* EventDescriptor,
		ULONG UserDataCount,
		EVENT_DATA_DESCRIPTOR* UserData);

	//https://skanthak.hier-im-netz.de/download/NTDLL.H
	// Forwarded from advapi32.dll:EventWriteStartScenario
	NTSYSAPI DWORD NTAPI EtwEventWriteStartScenario(
		REGHANDLE             RegHandle,
		EVENT_DESCRIPTOR* EventDescriptor,
		DWORD                 UserDataCount,
		EVENT_DATA_DESCRIPTOR* UserData);

	//https://learn.microsoft.com/en-us/windows/win32/api/evntprov/nf-evntprov-eventwritestring
	// Forwarded from advapi32.dll:EventWriteString
	NTSYSAPI ULONG NTAPI EtwEventWriteString(
		_In_ REGHANDLE RegHandle,
		_In_ UCHAR     Level,
		_In_ ULONGLONG Keyword,
		_In_ PCWSTR    String);

	//https://learn.microsoft.com/en-us/windows/win32/api/evntprov/nf-evntprov-eventwritetransfer
	// Forwarded from advapi32.dll:EventWriteTransfer
	NTSYSAPI ULONG NTAPI EtwEventWriteTransfer(
		_In_           REGHANDLE              RegHandle,
		_In_           PCEVENT_DESCRIPTOR     EventDescriptor,
		_In_opt_ LPCGUID                ActivityId,
		_In_opt_ LPCGUID                RelatedActivityId,
		_In_           ULONG                  UserDataCount,
		_In_opt_ PEVENT_DATA_DESCRIPTOR UserData);

	// Reversed
	// invoked by lsasrv.dll
	NTSYSAPI NTSTATUS NTAPI EvtIntReportAuthzEventAndSourceAsync(
		__int64 argRCX,
		__int64 argRDX,
		__int64 argR8,
		__int64 argR9,
		DWORD arg4,
		__int64 arg5,
		WORD arg6,
		DWORD arg7,
		__int64 arg8,
		__int64 arg9);

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSAPI  NTSTATUS NTAPI NtAcquireCrossVmMutant(
		_In_ HANDLE EventHandle,
		_In_ PULONGLONG Unknown);
	//ZwAcquireCrossVmMutant


	// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FFile%2FNtWriteFileGather.html
	NTSYSAPI NTSTATUS NTAPI NtClearEvent(
		_In_ HANDLE               EventHandle);
	//ZwClearEvent

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSAPI  NTSTATUS NTAPI NtCreateCrossVmEvent(
		_Out_ PHANDLE EventHandle,
		_In_ EVENT_ACCESS_MASK DesiredAccess,
		_In_ POBJECT_ATTRIBUTES ObjectAttributes,
		ULONG Unknown1,
		PVOID Unknown2,
		_In_ PGUID Guid);
	//ZwCreateCrossVmEvent

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSAPI NTSTATUS NTAPI NtCreateCrossVmMutant(
		_Out_ PHANDLE EventHandle,
		_In_ MUTANT_ACCESS_MASK DesiredAccess,
		_In_ POBJECT_ATTRIBUTES ObjectAttributes,
		ULONG Unknown1,
		PVOID Unknown2,
		_In_ PGUID Guid);
	//ZwCreateCrossVmMutant

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwcreateevent
	NTSYSAPI NTSTATUS NtCreateEvent(
		_Out_ PHANDLE EventHandle,
		_In_ ACCESS_MASK DesiredAccess,
		_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
		_In_ EVENT_TYPE EventType,
		_In_ BOOLEAN InitialState);
	//ZwCreateEvent

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FFile%2FNtWriteFileGather.html
	NTSYSAPI NTSTATUS NTAPI NtCreateEventPair(
		_Out_ PHANDLE EventPairHandle,
		_In_ ACCESS_MASK DesiredAccess,
		_In_opt_ POBJECT_ATTRIBUTES   ObjectAttributes);
	//ZwCreateEventPair

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FFile%2FNtWriteFileGather.html
	NTSYSAPI NTSTATUS NTAPI NtCreateKeyedEvent(
		_Out_ PHANDLE KeyedEventHandle,
		_In_ ACCESS_MASK DesiredAccess,
		_In_opt_ POBJECT_ATTRIBUTES   ObjectAttributes,
		_In_ ULONG Reserved);
	//ZwCreateKeyedEvent

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSAPI NTSTATUS NTAPI NtCreateMutant(
		_Out_ PHANDLE MutantHandle,
		_In_ MUTANT_ACCESS_MASK DesiredAccess,
		_In_ POBJECT_ATTRIBUTES ObjectAttributes,
		_In_ BOOLEAN InitialOwner);
	//ZwCreateMutant

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSAPI  NTSTATUS NTAPI NtCreateSemaphore(
		_Out_ PHANDLE SemaphoreHandle,
		_In_ SEMAPHORE_ACCESS_MASK DesiredAccess,
		_In_ POBJECT_ATTRIBUTES ObjectAttributes,
		_In_ LONG InitialCount,
		_In_ LONG MaxCount);
	//ZwCreateSemaphore

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwopenevent
	NTSYSAPI  NTSTATUS NtOpenEvent(
		_Out_ PHANDLE EventHandle,
		_In_  ACCESS_MASK DesiredAccess,
		_In_  POBJECT_ATTRIBUTES ObjectAttributes);
	//ZwOpenEvent

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FFile%2FNtWriteFileGather.html
	NTSYSAPI NTSTATUS NTAPI NtOpenEventPair(
		_Out_ PHANDLE EventPairHandle,
		_In_ ACCESS_MASK DesiredAccess,
		_In_ POBJECT_ATTRIBUTES ObjectAttributes);
	//ZwOpenEventPair

	// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FFile%2FNtWriteFileGather.html
	NTSYSAPI NTSTATUS NTAPI NtOpenKeyedEvent(
		_Out_ PHANDLE KeyedEventHandle,
		_In_ ACCESS_MASK DesiredAccess,
		_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes);
	//ZwOpenKeyedEvent

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSAPI NTSTATUS NTAPI NtOpenMutant(
		_Out_ PHANDLE MutantHandle,
		_In_ MUTANT_ACCESS_MASK DesiredAccess,
		_In_ POBJECT_ATTRIBUTES ObjectAttributes);
	//ZwOpenMutant

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSAPI NTSTATUS NTAPI NtOpenSemaphore(
		_Out_ PHANDLE SemaphoreHandle,
		_In_ SEMAPHORE_ACCESS_MASK DesiredAccess,
		_In_ POBJECT_ATTRIBUTES ObjectAttributes);
	//ZwOpenSemaphore

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FFile%2FNtWriteFileGather.html
	NTSYSAPI NTSTATUS NTAPI NtPulseEvent(
		_In_ HANDLE EventHandle,
		_Out_opt_ PLONG PreviousState);
	//ZwPulseEvent

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FFile%2FNtWriteFileGather.html
	NTSYSAPI NTSTATUS NTAPI NtQueryEvent(
		_In_ HANDLE EventHandle,
		_In_ EVENT_INFORMATION_CLASS EventInformationClass,
		_Out_ PVOID EventInformation,
		_In_ ULONG EventInformationLength,
		_Out_opt_ PULONG ReturnLength);
	//ZwQueryEvent

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSAPI NTSTATUS NTAPI NtQueryMutant(
		_In_ HANDLE MutantHandle,
		_In_ MUTANT_INFORMATION_CLASS MutantInformationClass,
		_Out_ PVOID MutantInformation,
		_In_ ULONG Length,
		_Out_opt_ PULONG ReturnLength);
	//ZwQueryMutant

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSAPI NTSTATUS NTAPI NtQuerySemaphore(
		_In_ HANDLE SemaphoreHandle,
		_In_ SEMAPHORE_INFORMATION_CLASS SemaphoreInformationClass,
		_Out_ PVOID SemaphoreInformation,
		_In_ ULONG Length,
		_Out_opt_ PULONG ReturnLength);
	//ZwQuerySemaphore

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FFile%2FNtWriteFileGather.html
	NTSYSAPI NTSTATUS NTAPI NtReleaseKeyedEvent(
		_In_ HANDLE KeyedEventHandle,
		_In_ PVOID Key,
		_In_ BOOLEAN Alertable,
		_In_opt_ PLARGE_INTEGER Timeout);
	//ZwReleaseKeyedEvent

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSAPI NTSTATUS NTAPI NtReleaseMutant(
		_In_ HANDLE MutantHandle,
		_Out_opt_ PULONG PreviousCount);
	//ZwReleaseMutant

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSAPI NTSTATUS NTAPI NtReleaseSemaphore(
		_In_ HANDLE SemaphoreHandle,
		_In_ ULONG Count,
		_Out_opt_ PULONG PreviousCount);
	//ZwReleaseSemaphore

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FFile%2FNtWriteFileGather.html
	NTSYSAPI NTSTATUS NTAPI NtResetEvent(
		_In_ HANDLE EventHandle,
		_Out_opt_ PLONG PreviousState);
	//ZwResetEvent

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwsetevent
	NTSYSAPI NTSTATUS NtSetEvent(
		_In_ HANDLE EventHandle,
		_Out_opt_ PLONG PreviousState);
	//ZwSetEvent

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FFile%2FNtWriteFileGather.html
	NTSYSAPI NTSTATUS NTAPI NtSetEventBoostPriority(
		_In_ HANDLE EventHandle);
	//ZwSetEventBoostPriority

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FFile%2FNtWriteFileGather.html
	NTSYSAPI NTSTATUS NTAPI NtSetHighEventPair(
		_In_ HANDLE EventPairHandle);
	//ZwSetHighEventPair

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FFile%2FNtWriteFileGather.html
	NTSYSAPI NTSTATUS NTAPI NtSetHighWaitLowEventPair(
		_In_ HANDLE EventPairHandle);
	//ZwSetHighWaitLowEventPair

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FFile%2FNtWriteFileGather.html
	NTSYSAPI NTSTATUS NTAPI NtSetLowEventPair(
		_In_ HANDLE EventPairHandle);
	//ZwSetLowEventPair

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FFile%2FNtWriteFileGather.html
	NTSYSAPI NTSTATUS NTAPI NtSetLowWaitHighEventPair(
		_In_ HANDLE EventPairHandle);
	//ZwSetLowWaitHighEventPair

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FFile%2FNtWriteFileGather.html
	NTSYSAPI NTSTATUS NTAPI NtSignalAndWaitForSingleObject(
		_In_ HANDLE ObjectToSignal,
		_In_ HANDLE WaitableObject,
		_In_ BOOLEAN Alertable,
		_In_opt_ PLARGE_INTEGER Time);
	//ZwSignalAndWaitForSingleObject

	// https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/etw/traceapi/control/index.htm?ta=7.839996337890625&tx=27,29,32,41&ts=0,160
	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSAPI  NTSTATUS NTAPI NtTraceControl(
		_In_ ULONG CtrlCode,
		_In_ PVOID InputBuffer,
		_In_ ULONG InputBufferLength,
		_Out_ PVOID OutputBuffer,
		_In_ ULONG OutputBufferLength,
		_Out_ PULONG ReturnLength);
	//ZwTraceControl

	// https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/etw/traceapi/event/index.htm?tx=27,29,32,41&ts=0,160
	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSAPI NTSTATUS NTAPI NtTraceEvent(
		_In_ HANDLE TraceHandle,
		_In_ ULONG Flags,
		_In_ ULONG FieldSize,
		_In_ PVOID Fields);
	//ZwTraceEvent

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FFile%2FNtWriteFileGather.html
	NTSYSAPI NTSTATUS NTAPI NtWaitForKeyedEvent(
		_In_ HANDLE KeyedEventHandle,
		_In_ PVOID Key,
		_In_ BOOLEAN Alertable,
		_In_opt_ PLARGE_INTEGER Timeout);
	//ZwWaitForKeyedEvent

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FFile%2FNtWriteFileGather.html
	NTSYSAPI NTSTATUS NTAPI NtWaitForMultipleObjects(
		_In_ ULONG ObjectCount,
		_In_ PHANDLE ObjectsArray,
		_In_ OBJECT_WAIT_TYPE WaitType,
		_In_ BOOLEAN Alertable,
		_In_opt_ PLARGE_INTEGER TimeOut);
	//ZwWaitForMultipleObjects

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSAPI NTSTATUS NTAPI NtWaitForMultipleObjects32(
		_In_ ULONG ObjectCount,
		_In_ PHANDLE Handles,
		_In_ WAIT_TYPE WaitType,
		_In_ BOOLEAN Alertable,
		_In_opt_ PLARGE_INTEGER Timeout);
	//ZwWaitForMultipleObjects32

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwwaitforsingleobject
	// See winternl.h
	// https://processhacker.sourceforge.io/doc/ntzwapi_8h_source.html
	NTSYSAPI  NTSTATUS NTAPI ZwWaitForSingleObject(
		_In_ HANDLE Handle,
		_In_ BOOLEAN Alertable,
		_In_opt_ PLARGE_INTEGER Timeout);
	//ZwWaitForSingleObject

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FFile%2FNtWriteFileGather.html
	NTSYSAPI NTSTATUS NTAPI NtWaitHighEventPair(
		_In_ HANDLE EventPairHandle);
	//ZwWaitHighEventPair

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FFile%2FNtWriteFileGather.html
	NTSYSAPI NTSTATUS NTAPI NtWaitLowEventPair(
		_In_ HANDLE EventPairHandle);
	//ZwWaitLowEventPair

#ifdef __cplusplus
}
#endif

#endif // _NTEVENTS_
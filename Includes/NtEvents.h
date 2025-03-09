#pragma once

#ifndef _NTEVENTS_
#define _NTEVENTS_

#include "NtCommonDefs.h"

extern "C" {

	// UNRESOLVED FUNCTIONS
//EvtIntReportAuthzEventAndSourceAsync
//EvtIntReportEventAndSourceAsync
	// END OF UNRESOLVED FUNCTIONS

	//https://learn.microsoft.com/en-us/windows/win32/api/evntprov/nf-evntprov-eventactivityidcontrol
	// Forwarded from advapi32.dll:EventActivityIdControl
	NTSYSAPI ULONG NTAPI EtwEventActivityIdControl(
		[in]      ULONG  ControlCode,
		[in, out] LPGUID ActivityId);

	//https://learn.microsoft.com/en-us/windows/win32/api/evntprov/nf-evntprov-eventenabled
	// Forwarded from advapi32.dll:EventEnabled
	NTSYSAPI BOOLEAN NTAPI EtwEventEnabled(
		[in] REGHANDLE          RegHandle,
		[in] PCEVENT_DESCRIPTOR EventDescriptor);

	//https://learn.microsoft.com/en-us/windows/win32/api/evntprov/nf-evntprov-eventproviderenabled
	// Forwarded from advapi32.dll:EventProviderEnabled
	NTSYSAPI BOOLEAN NTAPI EtwEventProviderEnabled(
		[in] REGHANDLE RegHandle,
		[in] UCHAR     Level,
		[in] ULONGLONG Keyword);

	//https://learn.microsoft.com/en-us/windows/win32/api/evntprov/nf-evntprov-eventregister
	// Forwarded from advapi32.dll:EventRegister
	NTSYSAPI ULONG NTAPI EtwEventRegister(
		[in]           LPCGUID         ProviderId,
		[in, optional] PENABLECALLBACK EnableCallback,
		[in, optional] PVOID           CallbackContext,
		[out]          PREGHANDLE      RegHandle);

	//https://learn.microsoft.com/en-us/windows/win32/api/evntprov/nf-evntprov-eventsetinformation
	// Forwarded from advapi32.dll:EventSetInformation
	NTSYSAPI ULONG NTAPI EtwEventSetInformation(
		[in] REGHANDLE        RegHandle,
		[in] EVENT_INFO_CLASS InformationClass,
		[in] PVOID            EventInformation,
		[in] ULONG            InformationLength);

	//https://learn.microsoft.com/en-us/windows/win32/api/evntprov/nf-evntprov-eventunregister
	// Forwarded from advapi32.dll:EventUnregister
	NTSYSAPI ULONG NTAPI EtwEventUnregister(
		[in] REGHANDLE RegHandle);

	//https://learn.microsoft.com/en-us/windows/win32/api/evntprov/nf-evntprov-eventwrite
	// Forwarded from advapi32.dll:EventWrite
	NTSYSAPI ULONG NTAPI EtwEventWrite(
		[in]           REGHANDLE              RegHandle,
		[in]           PCEVENT_DESCRIPTOR     EventDescriptor,
		[in]           ULONG                  UserDataCount,
		[in, optional] PEVENT_DATA_DESCRIPTOR UserData);

	//https://learn.microsoft.com/en-us/windows/win32/api/evntprov/nf-evntprov-eventwriteex
	// Forwarded from advapi32.dll:EventWriteEx
	NTSYSAPI ULONG NTAPI EtwEventWriteEx(
		[in]           REGHANDLE              RegHandle,
		[in]           PCEVENT_DESCRIPTOR     EventDescriptor,
		[in]           ULONG64                Filter,
		[in]           ULONG                  Flags,
		[in, optional] LPCGUID                ActivityId,
		[in, optional] LPCGUID                RelatedActivityId,
		[in]           ULONG                  UserDataCount,
		[in, optional] PEVENT_DATA_DESCRIPTOR UserData);

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
		[in] REGHANDLE RegHandle,
		[in] UCHAR     Level,
		[in] ULONGLONG Keyword,
		[in] PCWSTR    String);

	//https://learn.microsoft.com/en-us/windows/win32/api/evntprov/nf-evntprov-eventwritetransfer
	// Forwarded from advapi32.dll:EventWriteTransfer
	NTSYSAPI ULONG NTAPI EtwEventWriteTransfer(
		[in]           REGHANDLE              RegHandle,
		[in]           PCEVENT_DESCRIPTOR     EventDescriptor,
		[in, optional] LPCGUID                ActivityId,
		[in, optional] LPCGUID                RelatedActivityId,
		[in]           ULONG                  UserDataCount,
		[in, optional] PEVENT_DATA_DESCRIPTOR UserData);

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtAcquireCrossVmMutant(
		_In_ HANDLE EventHandle,
		_In_ PULONGLONG Unknown);
	//ZwAcquireCrossVmMutant


	// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FFile%2FNtWriteFileGather.html
	NTSYSAPI NTSTATUS NTAPI NtClearEvent(
		IN HANDLE               EventHandle);
	//ZwClearEvent

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtCreateCrossVmEvent(
		_Out_ PHANDLE EventHandle,
		_In_ EVENT_ACCESS_MASK DesiredAccess,
		_In_ POBJECT_ATTRIBUTES ObjectAttributes,
		ULONG Unknown,
		PVOID Unknown,
		_In_ PGUID Guid);
	//ZwCreateCrossVmEvent

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtCreateCrossVmMutant(
		_Out_ PHANDLE EventHandle,
		_In_ MUTANT_ACCESS_MASK DesiredAccess,
		_In_ POBJECT_ATTRIBUTES ObjectAttributes,
		ULONG Unknown,
		PVOID Unknown,
		_In_ PGUID Guid);
	//ZwCreateCrossVmMutant

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwcreateevent
	NTSYSCALLAPI NTSYSAPI NTSTATUS NtCreateEvent(
		[out]          PHANDLE            EventHandle,
		[in]           ACCESS_MASK        DesiredAccess,
		[in, optional] POBJECT_ATTRIBUTES ObjectAttributes,
		[in]           EVENT_TYPE         EventType,
		[in]           BOOLEAN            InitialState);
	//ZwCreateEvent

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FFile%2FNtWriteFileGather.html
	NTSYSCALLAPI NTSYSAPI NTSTATUS NTAPI NtCreateEventPair(
		OUT PHANDLE             EventPairHandle,
		IN ACCESS_MASK          DesiredAccess,
		IN POBJECT_ATTRIBUTES   ObjectAttributes OPTIONAL);
	//ZwCreateEventPair

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FFile%2FNtWriteFileGather.html
	NTSYSCALLAPI NTSYSAPI NTSTATUS NTAPI NtCreateKeyedEvent(
		OUT PHANDLE             KeyedEventHandle,
		IN ACCESS_MASK          DesiredAccess,
		_In_opt_ POBJECT_ATTRIBUTES   ObjectAttributes,
		IN ULONG                Reserved);
	//ZwCreateKeyedEvent

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtCreateMutant(
		_Out_ PHANDLE MutantHandle,
		_In_ MUTANT_ACCESS_MASK DesiredAccess,
		_In_ POBJECT_ATTRIBUTES ObjectAttributes,
		_In_ BOOLEAN InitialOwner);
	//ZwCreateMutant

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtCreateSemaphore(
		_Out_ PHANDLE SemaphoreHandle,
		_In_ SEMAPHORE_ACCESS_MASK DesiredAccess,
		_In_ POBJECT_ATTRIBUTES ObjectAttributes,
		_In_ LONG InitialCount,
		_In_ LONG MaxCount);
	//ZwCreateSemaphore

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwopenevent
	NTSYSCALLAPI NTSTATUS NtOpenEvent(
		[out] PHANDLE            EventHandle,
		[in]  ACCESS_MASK        DesiredAccess,
		[in]  POBJECT_ATTRIBUTES ObjectAttributes);
	//ZwOpenEvent

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FFile%2FNtWriteFileGather.html
	NTSYSAPI NTSTATUS NTAPI NtOpenEventPair(
		OUT PHANDLE             EventPairHandle,
		IN ACCESS_MASK          DesiredAccess,
		IN POBJECT_ATTRIBUTES   ObjectAttributes);
	//ZwOpenEventPair

	// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FFile%2FNtWriteFileGather.html
	NTSYSAPI NTSTATUS NTAPI NtOpenKeyedEvent(
		OUT PHANDLE             KeyedEventHandle,
		IN ACCESS_MASK          DesiredAccess,
		IN POBJECT_ATTRIBUTES   ObjectAttributes OPTIONAL);
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
		IN HANDLE               EventHandle,
		OUT PLONG               PreviousState OPTIONAL);
	//ZwPulseEvent

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FFile%2FNtWriteFileGather.html
	NTSYSAPI NTSTATUS NTAPI NtQueryEvent(
		IN HANDLE               EventHandle,
		IN EVENT_INFORMATION_CLASS EventInformationClass,
		OUT PVOID               EventInformation,
		IN ULONG                EventInformationLength,
		OUT PULONG              ReturnLength OPTIONAL);
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
		IN HANDLE               KeyedEventHandle,
		IN PVOID                Key,
		IN BOOLEAN              Alertable,
		IN PLARGE_INTEGER       Timeout OPTIONAL);
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
		IN HANDLE               EventHandle,
		OUT PLONG               PreviousState OPTIONAL);
	//ZwResetEvent

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwsetevent
	NTSYSAPI NTSTATUS NtSetEvent(
		[in]            HANDLE EventHandle,
		[out, optional] PLONG  PreviousState);
	//ZwSetEvent

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FFile%2FNtWriteFileGather.html
	NTSYSAPI NTSTATUS NTAPI NtSetEventBoostPriority(
		IN HANDLE               EventHandle);
	//ZwSetEventBoostPriority

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FFile%2FNtWriteFileGather.html
	NTSYSAPI NTSTATUS NTAPI NtSetHighEventPair(
		IN HANDLE               EventPairHandle);
	//ZwSetHighEventPair

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FFile%2FNtWriteFileGather.html
	NTSYSAPI NTSTATUS NTAPI NtSetHighWaitLowEventPair(
		IN HANDLE               EventPairHandle);
	//ZwSetHighWaitLowEventPair

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FFile%2FNtWriteFileGather.html
	NTSYSAPI NTSTATUS NTAPI NtSetLowEventPair(
		IN HANDLE               EventPairHandle);
	//ZwSetLowEventPair

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FFile%2FNtWriteFileGather.html
	NTSYSAPI NTSTATUS NTAPI NtSetLowWaitHighEventPair(
		IN HANDLE               EventPairHandle);
	//ZwSetLowWaitHighEventPair

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FFile%2FNtWriteFileGather.html
	NTSYSAPI NTSTATUS NTAPI NtSignalAndWaitForSingleObject(
		IN HANDLE               ObjectToSignal,
		IN HANDLE               WaitableObject,
		IN BOOLEAN              Alertable,
		IN PLARGE_INTEGER       Time OPTIONAL);
	//ZwSignalAndWaitForSingleObject

	// https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/etw/traceapi/control/index.htm?ta=7.839996337890625&tx=27,29,32,41&ts=0,160
	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtTraceControl(
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
		IN HANDLE               KeyedEventHandle,
		IN PVOID                Key,
		IN BOOLEAN              Alertable,
		IN PLARGE_INTEGER       Timeout OPTIONAL);
	//ZwWaitForKeyedEvent

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FFile%2FNtWriteFileGather.html
	NTSYSAPI NTSTATUS NTAPI NtWaitForMultipleObjects(
		IN ULONG                ObjectCount,
		IN PHANDLE              ObjectsArray,
		IN OBJECT_WAIT_TYPE     WaitType,
		IN BOOLEAN              Alertable,
		IN PLARGE_INTEGER       TimeOut OPTIONAL);
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
	NTSYSCALLAPI NTSTATUS NTAPI ZwWaitForSingleObject(
		_In_ HANDLE Handle,
		_In_ BOOLEAN Alertable,
		_In_opt_ PLARGE_INTEGER Timeout);
	//ZwWaitForSingleObject

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FFile%2FNtWriteFileGather.html
	NTSYSAPI NTSTATUS NTAPI NtWaitHighEventPair(
		IN HANDLE               EventPairHandle);
	//ZwWaitHighEventPair

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FFile%2FNtWriteFileGather.html
	NTSYSAPI NTSTATUS NTAPI NtWaitLowEventPair(
		IN HANDLE               EventPairHandle);
	//ZwWaitLowEventPair

}

#endif // _NTEVENTS_
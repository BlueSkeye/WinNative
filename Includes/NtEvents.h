#pragma once

#ifndef _NTEVENTS_
#define _NTEVENTS_

#include "NtCommonDefs.h"

extern "C" {

//EtwEventActivityIdControl
//EtwEventEnabled
//EtwEventProviderEnabled
//EtwEventRegister
//EtwEventSetInformation
//EtwEventUnregister
//EtwEventWrite
//EtwEventWriteEndScenario
//EtwEventWriteEx
//EtwEventWriteFull
//EtwEventWriteNoRegistration
//EtwEventWriteStartScenario
//EtwEventWriteString
//EtwEventWriteTransfer

	// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FFile%2FNtWriteFileGather.html
	NTSYSAPI NTSTATUS NTAPI NtClearEvent(
		IN HANDLE               EventHandle);
	//ZwClearEvent

	//NtCreateCrossVmEvent
	//ZwCreateCrossVmEvent

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwcreateevent
	NTSYSCALLAPI NTSYSAPI NTSTATUS NtCreateEvent(
		[out]          PHANDLE            EventHandle,
		[in]           ACCESS_MASK        DesiredAccess,
		[in, optional] POBJECT_ATTRIBUTES ObjectAttributes,
		[in]           EVENT_TYPE         EventType,
		[in]           BOOLEAN            InitialState);
	//ZwCreateEvent

	// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FFile%2FNtWriteFileGather.html
	NTSYSCALLAPI NTSYSAPI NTSTATUS NTAPI NtCreateEventPair(
		OUT PHANDLE             EventPairHandle,
		IN ACCESS_MASK          DesiredAccess,
		IN POBJECT_ATTRIBUTES   ObjectAttributes OPTIONAL);
	//ZwCreateEventPair

	// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FFile%2FNtWriteFileGather.html
	NTSYSCALLAPI NTSYSAPI NTSTATUS NTAPI NtCreateKeyedEvent(
		OUT PHANDLE             KeyedEventHandle,
		IN ACCESS_MASK          DesiredAccess,
		IN POBJECT_ATTRIBUTES   ObjectAttributes OPTIONAL,
		IN ULONG                Reserved);
	//ZwCreateKeyedEvent

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwopenevent
	NTSYSCALLAPI NTSTATUS NtOpenEvent(
		[out] PHANDLE            EventHandle,
		[in]  ACCESS_MASK        DesiredAccess,
		[in]  POBJECT_ATTRIBUTES ObjectAttributes);
	//ZwOpenEvent

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

	// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FFile%2FNtWriteFileGather.html
	NTSYSAPI NTSTATUS NTAPI NtPulseEvent(
		IN HANDLE               EventHandle,
		OUT PLONG               PreviousState OPTIONAL);
	//ZwPulseEvent

	// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FFile%2FNtWriteFileGather.html
	NTSYSAPI NTSTATUS NTAPI NtQueryEvent(
		IN HANDLE               EventHandle,
		IN EVENT_INFORMATION_CLASS EventInformationClass,
		OUT PVOID               EventInformation,
		IN ULONG                EventInformationLength,
		OUT PULONG              ReturnLength OPTIONAL);
	//ZwQueryEvent

	// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FFile%2FNtWriteFileGather.html
	NTSYSAPI NTSTATUS NTAPI NtReleaseKeyedEvent(
		IN HANDLE               KeyedEventHandle,
		IN PVOID                Key,
		IN BOOLEAN              Alertable,
		IN PLARGE_INTEGER       Timeout OPTIONAL);
	//ZwReleaseKeyedEvent

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

	// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FFile%2FNtWriteFileGather.html
	NTSYSAPI NTSTATUS NTAPI NtSetEventBoostPriority(
		IN HANDLE               EventHandle);
	//ZwSetEventBoostPriority

	// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FFile%2FNtWriteFileGather.html
	NTSYSAPI NTSTATUS NTAPI NtSetHighEventPair(
		IN HANDLE               EventPairHandle);
	//ZwSetHighEventPair

	// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FFile%2FNtWriteFileGather.html
	NTSYSAPI NTSTATUS NTAPI NtSetHighWaitLowEventPair(
		IN HANDLE               EventPairHandle);
	//ZwSetHighWaitLowEventPair

	// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FFile%2FNtWriteFileGather.html
	NTSYSAPI NTSTATUS NTAPI NtSetLowEventPair(
		IN HANDLE               EventPairHandle);
	//ZwSetLowEventPair

	// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FFile%2FNtWriteFileGather.html
	NTSYSAPI NTSTATUS NTAPI NtSetLowWaitHighEventPair(
		IN HANDLE               EventPairHandle);
	//ZwSetLowWaitHighEventPair

	// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FFile%2FNtWriteFileGather.html
	NTSYSAPI NTSTATUS NTAPI NtWaitForKeyedEvent(
		IN HANDLE               KeyedEventHandle,
		IN PVOID                Key,
		IN BOOLEAN              Alertable,
		IN PLARGE_INTEGER       Timeout OPTIONAL);
	//ZwWaitForKeyedEvent

	// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FFile%2FNtWriteFileGather.html
	NTSYSAPI NTSTATUS NTAPI NtWaitHighEventPair(
		IN HANDLE               EventPairHandle);
	//ZwWaitHighEventPair

	// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FFile%2FNtWriteFileGather.html
	NTSYSAPI NTSTATUS NTAPI NtWaitLowEventPair(
		IN HANDLE               EventPairHandle);
	//ZwWaitLowEventPair

}

#endif // _NTEVENTS_
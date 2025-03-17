#pragma once

#ifndef _NTNOTIFICATION_
#define _NTNOTIFICATION_

#include "NtCommonDefs.h"

extern "C" {

    // NO UNRESOLVED FUNCTIONS

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntcommitcomplete
    NTSYSCALLAPI NTSTATUS NTAPI NtCreateWnfStateName(
        _Out_ PCWNF_STATE_NAME StateName,
        _In_ ULONG Lifetime,
        _In_ ULONG DataScope,
        _In_ BOOLEAN PersistData,
        _In_opt_ PVOID TypeId,
        _In_ ULONG MaximumStateSize,
        _In_ PSECURITY_DESCRIPTOR SecurityDescriptor);
    //ZwCreateWnfStateName

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntcommitcomplete
    NTSYSCALLAPI NTSTATUS NTAPI NtDeleteWnfStateData(
        _In_ PCWNF_STATE_NAME StateName,
        _In_opt_ PVOID ExplicitScope);
    //ZwDeleteWnfStateData

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntcommitcomplete
    NTSYSCALLAPI NTSTATUS NTAPI NtDeleteWnfStateName(
        _In_ PCWNF_STATE_NAME StateName);
    //ZwDeleteWnfStateName

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntcommitcomplete
    NTSYSCALLAPI NTSTATUS NTAPI NtGetCompleteWnfStateSubscription(
        _In_opt_ PWNF_STATE_NAME OldDescriptorStateName,
        _In_opt_ PULONG OldSubscriptionId,
        _In_opt_ ULONG OldDescriptorEventMask,
        _In_opt_ ULONG OldDescriptorStatus,
        _Out_ PVOID NewDeliveryDescriptor,
        _In_ ULONG DescriptorSize);
    //ZwGetCompleteWnfStateSubscription

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntcommitcomplete
    NTSYSCALLAPI NTSTATUS NTAPI NtQueryWnfStateData(
        _In_ PCWNF_STATE_NAME StateName,
        _In_opt_ PVOID TypeId,
        _In_opt_ const PVOID ExplicitScope,
        _Out_ PULONG ChangeStamp,
        _Out_ PVOID Buffer,
        _Inout_ PULONG BufferSize);
    //ZwQueryWnfStateData

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntcommitcomplete
    NTSYSCALLAPI NTSTATUS NTAPI NtQueryWnfStateNameInformation(
        _In_ PCWNF_STATE_NAME StateName,
        _In_ ULONG NameInfoClass,
        _In_opt_ PVOID ExplicitScope,
        _Out_ PVOID InfoBuffer,
        _In_ ULONG InfoBufferSize);
    //ZwQueryWnfStateNameInformation

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntcommitcomplete
    NTSYSCALLAPI NTSTATUS NTAPI NtSetWnfProcessNotificationEvent(
        _In_ HANDLE NotificationEvent);
    //ZwSetWnfProcessNotificationEvent

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntcommitcomplete
    NTSYSCALLAPI NTSTATUS NTAPI NtSubscribeWnfStateChange(
        _In_ PCWNF_STATE_NAME StateName,
        _In_opt_ ULONG ChangeStamp,
        _In_ ULONG EventMask,
        _Out_opt_ PULONG SubscriptionId);
    //ZwSubscribeWnfStateChange

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntcommitcomplete
    NTSYSCALLAPI NTSTATUS NTAPI NtUnsubscribeWnfStateChange(
        _In_ PCWNF_STATE_NAME StateName);
    //ZwUnsubscribeWnfStateChange

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntcommitcomplete
    NTSYSCALLAPI NTSTATUS NTAPI NtUpdateWnfStateData(
        _In_ PCWNF_STATE_NAME StateName,
        _In_ PVOID Buffer,
        _In_opt_ ULONG Length,
        _In_opt_ PULONG TypeId,
        _In_opt_ PVOID ExplicitScope,
        _In_ ULONG MatchingChangeStamp,
        _In_ ULONG CheckStamp);
    //ZwUpdateWnfStateData

    // Reversed
    NTSYSAPI NTSTATUS NTAPI RtlWaitForWnfMetaNotification(
        _In_ PCWNF_STATE_NAME StateName,
        _In_ DWORD Unknown1,
        _In_ DWORD Unknown2,
        _In_ __int64 Unused,
        _Out_ PVOID Unknown4);

}

#endif // _NTNOTIFICATION_
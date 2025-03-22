#pragma once

#ifndef _NTNOTIFICATION_
#define _NTNOTIFICATION_

#include "NtCommonDefs.h"

extern "C" {

    // NO UNRESOLVED FUNCTIONS

    typedef struct _WNF_STATE_NAME {
        ULONG Data[2];
    } WNF_STATE_NAME, * PWNF_STATE_NAME;
    typedef const struct _WNF_STATE_NAME* PCWNF_STATE_NAME;

    typedef ULONG WNF_CHANGE_STAMP, * PWNF_CHANGE_STAMP;

    // https://github.com/winsiderss/systeminformer/blob/21b740464f0d1f738d49542e13d68e6dbb7f76d2/phnt/include/ntexapi.h#L1365C1-L1370C42
    typedef struct _WNF_TYPE_ID {
        GUID TypeId;
    } WNF_TYPE_ID, * PWNF_TYPE_ID;
    typedef const WNF_TYPE_ID* PCWNF_TYPE_ID;

    // https://github.com/sbousseaden/injection-1/blob/ed54f267471df1261b08731fca5f0c2010c2c848/wnf/wnf.h#L95
    typedef struct _WNF_DELIVERY_DESCRIPTOR {
        ULONG64 SubscriptionId;
        WNF_STATE_NAME StateName;
        WNF_CHANGE_STAMP ChangeStamp;
        ULONG StateDataSize;
        ULONG EventMask;
        WNF_TYPE_ID TypeId;
        ULONG StateDataOffset;
    } WNF_DELIVERY_DESCRIPTOR, * PWNF_DELIVERY_DESCRIPTOR;

    _Always_(_Post_satisfies_(return == STATUS_NO_MEMORY || return == STATUS_RETRY || return == STATUS_SUCCESS))
        typedef NTSTATUS (NTAPI* PWNF_USER_CALLBACK)(
            _In_ WNF_STATE_NAME StateName,
            _In_ WNF_CHANGE_STAMP ChangeStamp,
            _In_opt_ PWNF_TYPE_ID TypeId,
            _In_opt_ PVOID CallbackContext,
            _In_reads_bytes_opt_(Length) const VOID* Buffer,
            _In_ ULONG Length);

    // =========================== functions ===========================

    // https://github.com/sbousseaden/injection-1/blob/ed54f267471df1261b08731fca5f0c2010c2c848/wnf/wnf.h#L170
    NTSYSCALLAPI NTSTATUS NTAPI NtCreateWnfStateName(
        _Out_ PCWNF_STATE_NAME StateName,
        _In_ ULONG Lifetime,
        _In_ ULONG DataScope,
        _In_ BOOLEAN PersistData,
        _In_opt_ PVOID TypeId,
        _In_ ULONG MaximumStateSize,
        _In_ PSECURITY_DESCRIPTOR SecurityDescriptor);
    //ZwCreateWnfStateName

    // https://github.com/sbousseaden/injection-1/blob/ed54f267471df1261b08731fca5f0c2010c2c848/wnf/wnf.h#L203
    NTSYSCALLAPI NTSTATUS NTAPI NtDeleteWnfStateData(
        _In_ PCWNF_STATE_NAME StateName,
        _In_opt_ PVOID ExplicitScope);
    //ZwDeleteWnfStateData

    // https://github.com/sbousseaden/injection-1/blob/ed54f267471df1261b08731fca5f0c2010c2c848/wnf/wnf.h#L183
    NTSYSCALLAPI NTSTATUS NTAPI NtDeleteWnfStateName(
        _In_ PCWNF_STATE_NAME StateName);
    //ZwDeleteWnfStateName

    // https://github.com/sbousseaden/injection-1/blob/ed54f267471df1261b08731fca5f0c2010c2c848/wnf/wnf.h#L251
    NTSYSCALLAPI NTSTATUS NTAPI NtGetCompleteWnfStateSubscription(
        _In_opt_ PWNF_STATE_NAME OldDescriptorStateName,
        _In_opt_ PULONG OldSubscriptionId,
        _In_opt_ ULONG OldDescriptorEventMask,
        _In_opt_ ULONG OldDescriptorStatus,
        _Out_writes_bytes_(DescriptorSize) PWNF_DELIVERY_DESCRIPTOR NewDeliveryDescriptor,
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

    // https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L11330C1-L11339C7
    NTSYSAPI NTSTATUS NTAPI RtlPublishWnfStateData(
        _In_ WNF_STATE_NAME StateName,
        _In_opt_ PCWNF_TYPE_ID TypeId,
        _In_reads_bytes_opt_(Length) const PVOID Buffer,
        _In_opt_ ULONG Length,
        _In_opt_ const VOID* ExplicitScope);

    // https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L11355C1-L11360C7
    NTSYSAPI NTSTATUS NTAPI RtlUnsubscribeWnfStateChangeNotification(
        _In_ PWNF_USER_CALLBACK Callback);

    // Reversed
    NTSYSAPI NTSTATUS NTAPI RtlWaitForWnfMetaNotification(
        _In_ PCWNF_STATE_NAME StateName,
        _In_ DWORD Unknown1,
        _In_ DWORD Unknown2,
        _In_ __int64 Unused,
        _Out_ PVOID Unknown4);

}

#endif // _NTNOTIFICATION_
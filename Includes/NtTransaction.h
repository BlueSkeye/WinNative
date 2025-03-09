#pragma once

#ifndef _NTTRANSACTION_
#define _NTTRANSACTION_

#include "NtCommonDefs.h"

extern "C" {

    // NO UNRESOLVED FUNCTIONS

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntcommitcomplete
    NTSYSCALLAPI NTSTATUS NtCommitComplete(
        [in]           HANDLE         EnlistmentHandle,
        [in, optional] PLARGE_INTEGER TmVirtualClock);
    //ZwCommitComplete

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntcommitenlistment
    NTSYSCALLAPI NTSTATUS NtCommitEnlistment(
        [in]           HANDLE         EnlistmentHandle,
        [in, optional] PLARGE_INTEGER TmVirtualClock);
    //ZwCommitEnlistment

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntcommittransaction
    NTSYSCALLAPI NTSTATUS NtCommitTransaction(
        [in] HANDLE  TransactionHandle,
        [in] BOOLEAN Wait);
    //ZwCommitTransaction

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntcreateenlistment
    NTSYSCALLAPI NTSTATUS NtCreateEnlistment(
        [out]          PHANDLE            EnlistmentHandle,
        [in]           ACCESS_MASK        DesiredAccess,
        [in]           HANDLE             ResourceManagerHandle,
        [in]           HANDLE             TransactionHandle,
        [in, optional] POBJECT_ATTRIBUTES ObjectAttributes,
        [in, optional] ULONG              CreateOptions,
        [in]           NOTIFICATION_MASK  NotificationMask,
        [in, optional] PVOID              EnlistmentKey);
    //ZwCreateEnlistment

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntcreateresourcemanager
    NTSYSCALLAPI NTSTATUS NtCreateResourceManager(
        [out]          PHANDLE            ResourceManagerHandle,
        [in]           ACCESS_MASK        DesiredAccess,
        [in]           HANDLE             TmHandle,
        [in]           LPGUID             RmGuid,
        [in, optional] POBJECT_ATTRIBUTES ObjectAttributes,
        [in, optional] ULONG              CreateOptions,
        [in, optional] PUNICODE_STRING    Description);
    //ZwCreateResourceManager

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntcreatetransaction
    NTSYSCALLAPI NTSTATUS NtCreateTransaction(
        [out]          PHANDLE            TransactionHandle,
        [in]           ACCESS_MASK        DesiredAccess,
        [in, optional] POBJECT_ATTRIBUTES ObjectAttributes,
        [in, optional] LPGUID             Uow,
        [in, optional] HANDLE             TmHandle,
        [in, optional] ULONG              CreateOptions,
        [in, optional] ULONG              IsolationLevel,
        [in, optional] ULONG              IsolationFlags,
        [in, optional] PLARGE_INTEGER     Timeout,
        [in, optional] PUNICODE_STRING    Description);
    //ZwCreateTransaction

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntcreatetransactionmanager
    NTSYSCALLAPI NTSTATUS NtCreateTransactionManager(
        [out]          PHANDLE            TmHandle,
        [in]           ACCESS_MASK        DesiredAccess,
        [in, optional] POBJECT_ATTRIBUTES ObjectAttributes,
        [in, optional] PUNICODE_STRING    LogFileName,
        [in, optional] ULONG              CreateOptions,
        [in, optional] ULONG              CommitStrength);
    //ZwCreateTransactionManager

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntenumeratetransactionobject
    NTSYSCALLAPI NTSTATUS NtEnumerateTransactionObject(
        [in, optional] HANDLE            RootObjectHandle,
        [in]           KTMOBJECT_TYPE    QueryType,
        [in, out]      PKTMOBJECT_CURSOR ObjectCursor,
        [in]           ULONG             ObjectCursorLength,
        [out]          PULONG            ReturnLength);
    //ZwEnumerateTransactionObject

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtFreezeTransactions(
        _In_ PLARGE_INTEGER FreezeTimeout,
        _In_ PLARGE_INTEGER ThawTimeout);
    //ZwFreezeTransactions

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntgetnotificationresourcemanager
    NTSYSCALLAPI NTSTATUS NtGetNotificationResourceManager(
        [in]            HANDLE                    ResourceManagerHandle,
        [out]           PTRANSACTION_NOTIFICATION TransactionNotification,
        [in]            ULONG                     NotificationLength,
        [in]            PLARGE_INTEGER            Timeout,
        [out, optional] PULONG                    ReturnLength,
        [in]            ULONG                     Asynchronous,
        [in, optional]  ULONG_PTR                 AsynchronousContext);
    //ZwGetNotificationResourceManager

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntopenenlistment
    NTSYSCALLAPI NTSTATUS NtOpenEnlistment(
        [out]          PHANDLE            EnlistmentHandle,
        [in]           ACCESS_MASK        DesiredAccess,
        [in]           HANDLE             ResourceManagerHandle,
        [in]           LPGUID             EnlistmentGuid,
        [in, optional] POBJECT_ATTRIBUTES ObjectAttributes);
    //ZwOpenEnlistment

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntopenresourcemanager
    NTSYSCALLAPI NTSTATUS NtOpenResourceManager(
        [out]          PHANDLE            ResourceManagerHandle,
        [in]           ACCESS_MASK        DesiredAccess,
        [in]           HANDLE             TmHandle,
        [in]           LPGUID             ResourceManagerGuid,
        [in, optional] POBJECT_ATTRIBUTES ObjectAttributes);
    //ZwOpenResourceManager

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntopentransaction
    NTSYSCALLAPI NTSTATUS NtOpenTransaction(
        [out]          PHANDLE            TransactionHandle,
        [in]           ACCESS_MASK        DesiredAccess,
        [in, optional] POBJECT_ATTRIBUTES ObjectAttributes,
        [in]           LPGUID             Uow,
        [in, optional] HANDLE             TmHandle);
    //ZwOpenTransaction

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntopentransactionmanager
    NTSYSCALLAPI NTSTATUS NtOpenTransactionManager(
        [out]          PHANDLE            TmHandle,
        [in]           ACCESS_MASK        DesiredAccess,
        [in, optional] POBJECT_ATTRIBUTES ObjectAttributes,
        [in, optional] PUNICODE_STRING    LogFileName,
        [in, optional] LPGUID             TmIdentity,
        [in, optional] ULONG              OpenOptions);
    //ZwOpenTransactionManager

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntprepreparecomplete
    NTSYSCALLAPI NTSTATUS NtPrePrepareComplete(
        [in]           HANDLE         EnlistmentHandle,
        [in, optional] PLARGE_INTEGER TmVirtualClock);
    //ZwPrePrepareComplete

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntpreprepareenlistment
    NTSYSCALLAPI NTSTATUS NtPrePrepareEnlistment(
        [in]           HANDLE         EnlistmentHandle,
        [in, optional] PLARGE_INTEGER TmVirtualClock);
    //ZwPrePrepareEnlistment

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntpreparecomplete
    NTSYSCALLAPI NTSTATUS NtPrepareComplete(
        [in]           HANDLE         EnlistmentHandle,
        [in, optional] PLARGE_INTEGER TmVirtualClock);
    //ZwPrepareComplete

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntprepareenlistment
    NTSYSCALLAPI NTSTATUS NtPrepareEnlistment(
        [in]           HANDLE         EnlistmentHandle,
        [in, optional] PLARGE_INTEGER TmVirtualClock);
    //ZwPrepareEnlistment

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntprepareenlistment
    NTSYSCALLAPI NTSTATUS NTAPI NtPropagationComplete(
        _In_ HANDLE ResourceManagerHandle,
        _In_ ULONG RequestCookie,
        _In_ ULONG BufferLength,
        _In_ PVOID Buffer);
    //ZwPropagationComplete

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntprepareenlistment
    NTSYSCALLAPI NTSTATUS NTAPI NtPropagationFailed(
        _In_ HANDLE ResourceManagerHandle,
        _In_ ULONG RequestCookie,
        _In_ NTSTATUS PropStatus);
    //ZwPropagationFailed

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntqueryinformationenlistment
    NTSYSCALLAPI NTSTATUS NtQueryInformationEnlistment(
        [in]            HANDLE                       EnlistmentHandle,
        [in]            ENLISTMENT_INFORMATION_CLASS EnlistmentInformationClass,
        [out]           PVOID                        EnlistmentInformation,
        [in]            ULONG                        EnlistmentInformationLength,
        [out, optional] PULONG                       ReturnLength);
    //ZwQueryInformationEnlistment

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntqueryinformationresourcemanager
    NTSYSCALLAPI NTSTATUS NtQueryInformationResourceManager(
        [in]            HANDLE                            ResourceManagerHandle,
        [in]            RESOURCEMANAGER_INFORMATION_CLASS ResourceManagerInformationClass,
        [out]           PVOID                             ResourceManagerInformation,
        [in]            ULONG                             ResourceManagerInformationLength,
        [out, optional] PULONG                            ReturnLength);
    //ZwQueryInformationResourceManager

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntqueryinformationtransaction
    NTSYSCALLAPI NTSTATUS NtQueryInformationTransaction(
        [in]            HANDLE                        TransactionHandle,
        [in]            TRANSACTION_INFORMATION_CLASS TransactionInformationClass,
        [out]           PVOID                         TransactionInformation,
        [in]            ULONG                         TransactionInformationLength,
        [out, optional] PULONG                        ReturnLength);
    //ZwQueryInformationTransaction

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntqueryinformationtransactionmanager
    NTSYSCALLAPI NTSTATUS NtQueryInformationTransactionManager(
        [in]            HANDLE                               TransactionManagerHandle,
        [in]            TRANSACTIONMANAGER_INFORMATION_CLASS TransactionManagerInformationClass,
        [out]           PVOID                                TransactionManagerInformation,
        [in]            ULONG                                TransactionManagerInformationLength,
        [out, optional] PULONG                               ReturnLength);
    //ZwQueryInformationTransactionManager

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntreadonlyenlistment
    NTSYSCALLAPI NTSTATUS NtReadOnlyEnlistment(
        [in]           HANDLE         EnlistmentHandle,
        [in, optional] PLARGE_INTEGER TmVirtualClock);
    //ZwReadOnlyEnlistment

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntrecoverenlistment
    NTSYSCALLAPI NTSTATUS NtRecoverEnlistment(
        [in]           HANDLE EnlistmentHandle,
        [in, optional] PVOID  EnlistmentKey);
    //ZwRecoverEnlistment

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntrecoverresourcemanager
    NTSYSCALLAPI NTSTATUS NtRecoverResourceManager(
        [in] HANDLE ResourceManagerHandle);
    //ZwRecoverResourceManager

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntrecovertransactionmanager
    NTSYSCALLAPI NTSTATUS NtRecoverTransactionManager(
        [in] HANDLE TransactionManagerHandle);
    //ZwRecoverTransactionManager

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSAPI NTSTATUS NTAPI NtRegisterProtocolAddressInformation(
        _In_ HANDLE ResourceManager,
        _In_ PGUID ProtocolId,
        _In_ ULONG ProtocolInformationSize,
        _In_ PVOID ProtocolInformation,
        _In_ ULONG CreateOptions);
    //ZwRegisterProtocolAddressInformation

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntrenametransactionmanager
    NTSYSCALLAPI NTSTATUS NtRenameTransactionManager(
        [in] PUNICODE_STRING LogFileName,
        [in] LPGUID          ExistingTransactionManagerGuid);
    //ZwRenameTransactionManager

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntrollbackcomplete
    NTSYSCALLAPI NTSTATUS NtRollbackComplete(
        [in]           HANDLE         EnlistmentHandle,
        [in, optional] PLARGE_INTEGER TmVirtualClock);
    //ZwRollbackComplete

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntrollbackenlistment
    NTSYSCALLAPI NTSTATUS NtRollbackEnlistment(
        [in]           HANDLE         EnlistmentHandle,
        [in, optional] PLARGE_INTEGER TmVirtualClock);
    //ZwRollbackEnlistment

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntrollbacktransaction
    NTSYSCALLAPI NTSTATUS NtRollbackTransaction(
        [in] HANDLE  TransactionHandle,
        [in] BOOLEAN Wait);
    //ZwRollbackTransaction

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntrollforwardtransactionmanager
    NTSYSCALLAPI NTSTATUS NtRollforwardTransactionManager(
        [in]           HANDLE         TransactionManagerHandle,
        [in, optional] PLARGE_INTEGER TmVirtualClock);
    //ZwRollforwardTransactionManager

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntsetinformationenlistment
    NTSYSCALLAPI NTSTATUS NtSetInformationEnlistment(
        [in] HANDLE                       EnlistmentHandle,
        [in] ENLISTMENT_INFORMATION_CLASS EnlistmentInformationClass,
        [in] PVOID                        EnlistmentInformation,
        [in] ULONG                        EnlistmentInformationLength);
    //ZwSetInformationEnlistment

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntsetinformationresourcemanager
    NTSYSCALLAPI NTSTATUS NtSetInformationResourceManager(
        HANDLE                            ResourceManagerHandle,
        RESOURCEMANAGER_INFORMATION_CLASS ResourceManagerInformationClass,
        PVOID                             ResourceManagerInformation,
        ULONG                             ResourceManagerInformationLength);
    //ZwSetInformationResourceManager

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntsetinformationtransaction
    NTSYSCALLAPI NTSTATUS NtSetInformationTransaction(
        [in] HANDLE                        TransactionHandle,
        [in] TRANSACTION_INFORMATION_CLASS TransactionInformationClass,
        [in] PVOID                         TransactionInformation,
        [in] ULONG                         TransactionInformationLength);
    //ZwSetInformationTransaction

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntsetinformationtransactionmanager
    NTSYSCALLAPI NTSTATUS NtSetInformationTransactionManager(
        [in, optional] HANDLE                               TmHandle,
        [in]           TRANSACTIONMANAGER_INFORMATION_CLASS TransactionManagerInformationClass,
        [in]           PVOID                                TransactionManagerInformation,
        [in]           ULONG                                TransactionManagerInformationLength);
    //ZwSetInformationTransactionManager

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntsinglephasereject
    NTSYSCALLAPI NTSTATUS NtSinglePhaseReject(
        [in]           HANDLE         EnlistmentHandle,
        [in, optional] PLARGE_INTEGER TmVirtualClock);
    //ZwSinglePhaseReject

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSAPI NTSTATUS NTAPI NtThawTransactions();
    //ZwThawTransactions

}

#endif // _NTTRANSACTION_
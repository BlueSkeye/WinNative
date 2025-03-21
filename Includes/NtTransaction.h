#pragma once

#ifndef _NTTRANSACTION_
#define _NTTRANSACTION_

#include "NtCommonDefs.h"
#include "NtAccessRights.h"

extern "C" {

    // NO UNRESOLVED FUNCTIONS

    typedef enum _ENLISTMENT_INFORMATION_CLASS {
        EnlistmentBasicInformation,
        EnlistmentRecoveryInformation,
        EnlistmentCrmInformation
    } ENLISTMENT_INFORMATION_CLASS;

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ne-wdm-_ktmobject_type
    typedef enum _KTMOBJECT_TYPE {
        KTMOBJECT_TRANSACTION,
        KTMOBJECT_TRANSACTION_MANAGER,
        KTMOBJECT_RESOURCE_MANAGER,
        KTMOBJECT_ENLISTMENT,
        KTMOBJECT_INVALID
    } KTMOBJECT_TYPE, * PKTMOBJECT_TYPE;

    // From ktmtypes.h
    typedef enum _TRANSACTION_NOTIFICATION_TYPES {
        TRANSACTION_NOTIFY_MASK = 0x3FFFFFFF,
        TRANSACTION_NOTIFY_PREPREPARE = 0x00000001,
        TRANSACTION_NOTIFY_PREPARE = 0x00000002,
        TRANSACTION_NOTIFY_COMMIT = 0x00000004,
        TRANSACTION_NOTIFY_ROLLBACK = 0x00000008,
        TRANSACTION_NOTIFY_PREPREPARE_COMPLETE = 0x00000010,
        TRANSACTION_NOTIFY_PREPARE_COMPLETE = 0x00000020,
        TRANSACTION_NOTIFY_COMMIT_COMPLETE = 0x00000040,
        TRANSACTION_NOTIFY_ROLLBACK_COMPLETE = 0x00000080,
        TRANSACTION_NOTIFY_RECOVER = 0x00000100,
        TRANSACTION_NOTIFY_SINGLE_PHASE_COMMIT = 0x00000200,
        TRANSACTION_NOTIFY_DELEGATE_COMMIT = 0x00000400,
        TRANSACTION_NOTIFY_RECOVER_QUERY = 0x00000800,
        TRANSACTION_NOTIFY_ENLIST_PREPREPARE = 0x00001000,
        TRANSACTION_NOTIFY_LAST_RECOVER = 0x00002000,
        TRANSACTION_NOTIFY_INDOUBT = 0x00004000,
        TRANSACTION_NOTIFY_PROPAGATE_PULL = 0x00008000,
        TRANSACTION_NOTIFY_PROPAGATE_PUSH = 0x00010000,
        TRANSACTION_NOTIFY_MARSHAL = 0x00020000,
        TRANSACTION_NOTIFY_ENLIST_MASK = 0x00040000,
        TRANSACTION_NOTIFY_RM_DISCONNECTED = 0x01000000,
        TRANSACTION_NOTIFY_TM_ONLINE = 0x02000000,
        TRANSACTION_NOTIFY_COMMIT_REQUEST = 0x04000000,
        TRANSACTION_NOTIFY_PROMOTE = 0x08000000,
        TRANSACTION_NOTIFY_PROMOTE_NEW = 0x10000000,
        TRANSACTION_NOTIFY_REQUEST_OUTCOME = 0x20000000
    } TRANSACTION_NOTIFICATION_TYPES;

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_ktmobject_cursor
    typedef struct _KTMOBJECT_CURSOR {
        GUID  LastQuery;
        ULONG ObjectIdCount;
        GUID  ObjectIds[1];
    } KTMOBJECT_CURSOR, * PKTMOBJECT_CURSOR;

    // https://learn.microsoft.com/en-us/previous-versions/windows/hardware/kernel/ff564813(v=vs.85)
    typedef struct _TRANSACTION_NOTIFICATION {
        PVOID TransactionKey;
        ULONG TransactionNotification;
        LARGE_INTEGER TmVirtualClock;
        ULONG ArgumentLength;
    } TRANSACTION_NOTIFICATION, * PTRANSACTION_NOTIFICATION;

    typedef enum _RESOURCEMANAGER_INFORMATION_CLASS {
        ResourceManagerBasicInformation,
        ResourceManagerCompletionInformation
    } RESOURCEMANAGER_INFORMATION_CLASS;

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ne-wdm-_transactionmanager_information_class
    typedef enum _TRANSACTIONMANAGER_INFORMATION_CLASS {
        TransactionManagerBasicInformation,
        TransactionManagerLogInformation,
        TransactionManagerLogPathInformation,
        TransactionManagerRecoveryInformation
    } TRANSACTIONMANAGER_INFORMATION_CLASS;

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ne-wdm-_transaction_information_class
    typedef enum _TRANSACTION_INFORMATION_CLASS {
        TransactionBasicInformation,
        TransactionPropertiesInformation,
        TransactionEnlistmentInformation,
        TransactionSuperiorEnlistmentInformation
    } TRANSACTION_INFORMATION_CLASS;

    // ============================ functions ============================

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntcommitcomplete
    NTSYSCALLAPI NTSTATUS NtCommitComplete(
        _In_           HANDLE         EnlistmentHandle,
        _In_opt_ PLARGE_INTEGER TmVirtualClock);
    //ZwCommitComplete

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntcommitenlistment
    NTSYSCALLAPI NTSTATUS NtCommitEnlistment(
        _In_           HANDLE         EnlistmentHandle,
        _In_opt_ PLARGE_INTEGER TmVirtualClock);
    //ZwCommitEnlistment

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntcommittransaction
    NTSYSCALLAPI NTSTATUS NtCommitTransaction(
        _In_ HANDLE  TransactionHandle,
        _In_ BOOLEAN Wait);
    //ZwCommitTransaction

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntcreateenlistment
    NTSYSCALLAPI NTSTATUS NtCreateEnlistment(
        _Out_ PHANDLE EnlistmentHandle,
        _In_ ENLISTMENT_ACCESS_MASK DesiredAccess,
        _In_ HANDLE ResourceManagerHandle,
        _In_ HANDLE TransactionHandle,
        _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
        _In_opt_ ULONG CreateOptions,
        _In_ TRANSACTION_NOTIFICATION_TYPES NotificationMask,
        _In_opt_ PVOID EnlistmentKey);
    //ZwCreateEnlistment

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntcreateresourcemanager
    NTSYSCALLAPI NTSTATUS NtCreateResourceManager(
        _Out_ PHANDLE ResourceManagerHandle,
        _In_ ACCESS_MASK DesiredAccess,
        _In_ HANDLE TmHandle,
        _In_ LPGUID RmGuid,
        _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
        _In_opt_ ULONG CreateOptions,
        _In_opt_ PUNICODE_STRING Description);
    //ZwCreateResourceManager

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntcreatetransaction
    NTSYSCALLAPI NTSTATUS NtCreateTransaction(
        _Out_ PHANDLE            TransactionHandle,
        _In_ ACCESS_MASK        DesiredAccess,
        _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
        _In_opt_ LPGUID             Uow,
        _In_opt_ HANDLE             TmHandle,
        _In_opt_ ULONG              CreateOptions,
        _In_opt_ ULONG              IsolationLevel,
        _In_opt_ ULONG              IsolationFlags,
        _In_opt_ PLARGE_INTEGER     Timeout,
        _In_opt_ PUNICODE_STRING    Description);
    //ZwCreateTransaction

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntcreatetransactionmanager
    NTSYSCALLAPI NTSTATUS NtCreateTransactionManager(
        _Out_ PHANDLE TmHandle,
        _In_ ACCESS_MASK DesiredAccess,
        _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
        _In_opt_ PUNICODE_STRING LogFileName,
        _In_opt_ ULONG CreateOptions,
        _In_opt_ ULONG CommitStrength);
    //ZwCreateTransactionManager

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntenumeratetransactionobject
    NTSYSCALLAPI NTSTATUS NtEnumerateTransactionObject(
        _In_opt_ HANDLE RootObjectHandle,
        _In_ KTMOBJECT_TYPE QueryType,
        _Inout_ PKTMOBJECT_CURSOR ObjectCursor,
        _In_ ULONG ObjectCursorLength,
        _Out_ PULONG ReturnLength);
    //ZwEnumerateTransactionObject

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtFreezeTransactions(
        _In_ PLARGE_INTEGER FreezeTimeout,
        _In_ PLARGE_INTEGER ThawTimeout);
    //ZwFreezeTransactions

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntgetnotificationresourcemanager
    NTSYSCALLAPI NTSTATUS NtGetNotificationResourceManager(
        _In_ HANDLE ResourceManagerHandle,
        _Out_ PTRANSACTION_NOTIFICATION TransactionNotification,
        _In_ ULONG NotificationLength,
        _In_ PLARGE_INTEGER Timeout,
        _Out_opt_ PULONG ReturnLength,
        _In_ ULONG Asynchronous,
        _In_opt_ ULONG_PTR AsynchronousContext);
    //ZwGetNotificationResourceManager

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntopenenlistment
    NTSYSCALLAPI NTSTATUS NtOpenEnlistment(
        _Out_          PHANDLE            EnlistmentHandle,
        _In_           ACCESS_MASK        DesiredAccess,
        _In_           HANDLE             ResourceManagerHandle,
        _In_           LPGUID             EnlistmentGuid,
        _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes);
    //ZwOpenEnlistment

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntopenresourcemanager
    NTSYSCALLAPI NTSTATUS NtOpenResourceManager(
        _Out_          PHANDLE            ResourceManagerHandle,
        _In_           ACCESS_MASK        DesiredAccess,
        _In_           HANDLE             TmHandle,
        _In_           LPGUID             ResourceManagerGuid,
        _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes);
    //ZwOpenResourceManager

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntopentransaction
    NTSYSCALLAPI NTSTATUS NtOpenTransaction(
        _Out_          PHANDLE            TransactionHandle,
        _In_           ACCESS_MASK        DesiredAccess,
        _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
        _In_           LPGUID             Uow,
        _In_opt_ HANDLE             TmHandle);
    //ZwOpenTransaction

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntopentransactionmanager
    NTSYSCALLAPI NTSTATUS NtOpenTransactionManager(
        _Out_          PHANDLE            TmHandle,
        _In_           ACCESS_MASK        DesiredAccess,
        _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
        _In_opt_ PUNICODE_STRING    LogFileName,
        _In_opt_ LPGUID             TmIdentity,
        _In_opt_ ULONG              OpenOptions);
    //ZwOpenTransactionManager

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntprepreparecomplete
    NTSYSCALLAPI NTSTATUS NtPrePrepareComplete(
        _In_           HANDLE         EnlistmentHandle,
        _In_opt_ PLARGE_INTEGER TmVirtualClock);
    //ZwPrePrepareComplete

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntpreprepareenlistment
    NTSYSCALLAPI NTSTATUS NtPrePrepareEnlistment(
        _In_           HANDLE         EnlistmentHandle,
        _In_opt_ PLARGE_INTEGER TmVirtualClock);
    //ZwPrePrepareEnlistment

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntpreparecomplete
    NTSYSCALLAPI NTSTATUS NtPrepareComplete(
        _In_           HANDLE         EnlistmentHandle,
        _In_opt_ PLARGE_INTEGER TmVirtualClock);
    //ZwPrepareComplete

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntprepareenlistment
    NTSYSCALLAPI NTSTATUS NtPrepareEnlistment(
        _In_           HANDLE         EnlistmentHandle,
        _In_opt_ PLARGE_INTEGER TmVirtualClock);
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
    // https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/nttmapi.h#L211
    NTSYSCALLAPI NTSTATUS NtQueryInformationEnlistment(
        _In_ HANDLE EnlistmentHandle,
        _In_ ENLISTMENT_INFORMATION_CLASS EnlistmentInformationClass,
        _Out_ PVOID EnlistmentInformation,
        _In_ ULONG EnlistmentInformationLength,
        _Out_opt_ PULONG ReturnLength);
    //ZwQueryInformationEnlistment

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntqueryinformationresourcemanager
    NTSYSCALLAPI NTSTATUS NtQueryInformationResourceManager(
        _In_ HANDLE ResourceManagerHandle,
        _In_ RESOURCEMANAGER_INFORMATION_CLASS ResourceManagerInformationClass,
        _Out_ PVOID ResourceManagerInformation,
        _In_ ULONG ResourceManagerInformationLength,
        _Out_opt_ PULONG ReturnLength);
    //ZwQueryInformationResourceManager

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntqueryinformationtransaction
    NTSYSCALLAPI NTSTATUS NtQueryInformationTransaction(
        _In_ HANDLE TransactionHandle,
        _In_ TRANSACTION_INFORMATION_CLASS TransactionInformationClass,
        _Out_ PVOID TransactionInformation,
        _In_ ULONG TransactionInformationLength,
        _Out_opt_ PULONG ReturnLength);
    //ZwQueryInformationTransaction

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntqueryinformationtransactionmanager
    NTSYSCALLAPI NTSTATUS NtQueryInformationTransactionManager(
        _In_ HANDLE TransactionManagerHandle,
        _In_ TRANSACTIONMANAGER_INFORMATION_CLASS TransactionManagerInformationClass,
        _Out_ PVOID TransactionManagerInformation,
        _In_ ULONG TransactionManagerInformationLength,
        _Out_opt_ PULONG ReturnLength);
    //ZwQueryInformationTransactionManager

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntreadonlyenlistment
    NTSYSCALLAPI NTSTATUS NtReadOnlyEnlistment(
        _In_           HANDLE         EnlistmentHandle,
        _In_opt_ PLARGE_INTEGER TmVirtualClock);
    //ZwReadOnlyEnlistment

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntrecoverenlistment
    NTSYSCALLAPI NTSTATUS NtRecoverEnlistment(
        _In_           HANDLE EnlistmentHandle,
        _In_opt_ PVOID  EnlistmentKey);
    //ZwRecoverEnlistment

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntrecoverresourcemanager
    NTSYSCALLAPI NTSTATUS NtRecoverResourceManager(
        _In_ HANDLE ResourceManagerHandle);
    //ZwRecoverResourceManager

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntrecovertransactionmanager
    NTSYSCALLAPI NTSTATUS NtRecoverTransactionManager(
        _In_ HANDLE TransactionManagerHandle);
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
        _In_ PUNICODE_STRING LogFileName,
        _In_ LPGUID          ExistingTransactionManagerGuid);
    //ZwRenameTransactionManager

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntrollbackcomplete
    NTSYSCALLAPI NTSTATUS NtRollbackComplete(
        _In_           HANDLE         EnlistmentHandle,
        _In_opt_ PLARGE_INTEGER TmVirtualClock);
    //ZwRollbackComplete

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntrollbackenlistment
    NTSYSCALLAPI NTSTATUS NtRollbackEnlistment(
        _In_           HANDLE         EnlistmentHandle,
        _In_opt_ PLARGE_INTEGER TmVirtualClock);
    //ZwRollbackEnlistment

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntrollbacktransaction
    NTSYSCALLAPI NTSTATUS NtRollbackTransaction(
        _In_ HANDLE  TransactionHandle,
        _In_ BOOLEAN Wait);
    //ZwRollbackTransaction

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntrollforwardtransactionmanager
    NTSYSCALLAPI NTSTATUS NtRollforwardTransactionManager(
        _In_           HANDLE         TransactionManagerHandle,
        _In_opt_ PLARGE_INTEGER TmVirtualClock);
    //ZwRollforwardTransactionManager

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntsetinformationenlistment
    NTSYSCALLAPI NTSTATUS NtSetInformationEnlistment(
        _In_ HANDLE                       EnlistmentHandle,
        _In_ ENLISTMENT_INFORMATION_CLASS EnlistmentInformationClass,
        _In_ PVOID                        EnlistmentInformation,
        _In_ ULONG                        EnlistmentInformationLength);
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
        _In_ HANDLE                        TransactionHandle,
        _In_ TRANSACTION_INFORMATION_CLASS TransactionInformationClass,
        _In_ PVOID                         TransactionInformation,
        _In_ ULONG                         TransactionInformationLength);
    //ZwSetInformationTransaction

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntsetinformationtransactionmanager
    NTSYSCALLAPI NTSTATUS NtSetInformationTransactionManager(
        _In_opt_ HANDLE                               TmHandle,
        _In_           TRANSACTIONMANAGER_INFORMATION_CLASS TransactionManagerInformationClass,
        _In_           PVOID                                TransactionManagerInformation,
        _In_           ULONG                                TransactionManagerInformationLength);
    //ZwSetInformationTransactionManager

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntsinglephasereject
    NTSYSCALLAPI NTSTATUS NtSinglePhaseReject(
        _In_           HANDLE         EnlistmentHandle,
        _In_opt_ PLARGE_INTEGER TmVirtualClock);
    //ZwSinglePhaseReject

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSAPI NTSTATUS NTAPI NtThawTransactions();
    //ZwThawTransactions

}

#endif // _NTTRANSACTION_
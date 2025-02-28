#pragma once

#ifndef _NTREGISTRY_
#define _NTREGISTRY_

#include "NtCommonDefs.h"

extern "C" {

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtCommitRegistryTransaction(
        HANDLE RegistryHandle,
        BOOL Wait);
    //ZwCommitRegistryTransaction

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtCompactKeys(
        _In_ ULONG NumberOfKeys,
        _In_ PVOID KeyHandles);
    //ZwCompactKeys

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtCompressKey(
        _In_ HANDLE KeyHandle);
    //ZwCompressKey

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwcreatekey
    NTSYSAPI NTSTATUS NtCreateKey(
        [out]           PHANDLE            KeyHandle,
        [in]            ACCESS_MASK        DesiredAccess,
        [in]            POBJECT_ATTRIBUTES ObjectAttributes,
        ULONG              TitleIndex,
        [in, optional]  PUNICODE_STRING    Class,
        [in]            ULONG              CreateOptions,
        [out, optional] PULONG             Disposition);
    //ZwCreateKey

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwcreatekeytransacted
    NTSYSAPI NTSTATUS NtCreateKeyTransacted(
        [out]           PHANDLE            KeyHandle,
        [in]            ACCESS_MASK        DesiredAccess,
        [in]            POBJECT_ATTRIBUTES ObjectAttributes,
        ULONG              TitleIndex,
        [in, optional]  PUNICODE_STRING    Class,
        [in]            ULONG              CreateOptions,
        [in]            HANDLE             TransactionHandle,
        [out, optional] PULONG             Disposition);
    //ZwCreateKeyTransacted

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwcreatekeytransacted
    NTSYSAPI NTSTATUS NTAPI NtCreateRegistryTransaction(
        _Out_ PHANDLE RegistryHandle,
        _In_ KEY_ACCESS_MASK DesiredAccess,
        _In_ POBJECT_ATTRIBUTES ObjectAttributes,
        _In_ ULONG Flags);
    //ZwCreateRegistryTransaction

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwdeletekey
    NTSYSAPI NTSTATUS NtDeleteKey(
        [in] HANDLE KeyHandle);
    //ZwDeleteKey

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwdeletevaluekey
    NTSYSAPI NTSTATUS NtDeleteValueKey(
        [in] HANDLE          KeyHandle,
        [in] PUNICODE_STRING ValueName);
    //ZwDeleteValueKey

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwenumeratekey
    NTSYSAPI NTSTATUS NtEnumerateKey(
        [in]            HANDLE                KeyHandle,
        [in]            ULONG                 Index,
        [in]            KEY_INFORMATION_CLASS KeyInformationClass,
        [out, optional] PVOID                 KeyInformation,
        [in]            ULONG                 Length,
        [out]           PULONG                ResultLength);
    //ZwEnumerateKey

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwenumeratevaluekey
    NTSYSAPI NTSTATUS NtEnumerateValueKey(
        [in]            HANDLE                      KeyHandle,
        [in]            ULONG                       Index,
        [in]            KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
        [out, optional] PVOID                       KeyValueInformation,
        [in]            ULONG                       Length,
        [out]           PULONG                      ResultLength);
    //ZwEnumerateValueKey

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwflushkey
    NTSYSAPI NTSTATUS NtFlushKey(
        [in] HANDLE KeyHandle);
    //ZwFlushKey

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtFreezeRegistry(
        _In_ ULONG TimeOutInSeconds);
    //ZwFreezeRegistry

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtInitializeRegistry(
        _In_ ULONG Options);
    //ZwInitializeRegistry

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtLoadKey(
        _In_ POBJECT_ATTRIBUTES KeyObjectAttributes,
        _In_ POBJECT_ATTRIBUTES FileObjectAttributes);
    //ZwLoadKey

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtLoadKey2(
        _In_ POBJECT_ATTRIBUTES KeyObjectAttributes,
        _In_ POBJECT_ATTRIBUTES FileObjectAttributes,
        _In_ ULONG Flags);
    //ZwLoadKey2

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtLoadKey3(
        _In_ POBJECT_ATTRIBUTES KeyObjectAttributes,
        _In_ POBJECT_ATTRIBUTES FileObjectAttributes,
        _In_ ULONG Flags,
        _In_ PVOID LoadArguments,
        _In_ ULONG LoadArgumentCount,
        _In_ KEY_ACCESS_MASK DesiredAccess,
        _In_ HANDLE KeyHandle,
        _In_ ULONG Unkown);
    //ZwLoadKey3

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtLoadKeyEx(
        _In_ POBJECT_ATTRIBUTES TargetKey,
        _In_ POBJECT_ATTRIBUTES SourceFile,
        _In_ ULONG Flags,
        _In_opt_ HANDLE TrustClassKey,
        _In_ PVOID Reserved,
        _In_ PVOID ObjectContext,
        _In_ PVOID CallbackReserved,
        _Out_ PIO_STATUS_BLOCK IoStatusBlock);
    //ZwLoadKeyEx

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtLockRegistryKey(
        _In_ HANDLE KeyHandle);
    //ZwLockRegistryKey

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwnotifychangekey
    NTSYSAPI NTSTATUS NtNotifyChangeKey(
        [in]            HANDLE           KeyHandle,
        [in, optional]  HANDLE           Event,
        [in, optional]  PIO_APC_ROUTINE  ApcRoutine,
        [in, optional]  PVOID            ApcContext,
        [out]           PIO_STATUS_BLOCK IoStatusBlock,
        [in]            ULONG            CompletionFilter,
        [in]            BOOLEAN          WatchTree,
        [out, optional] PVOID            Buffer,
        [in]            ULONG            BufferSize,
        [in]            BOOLEAN          Asynchronous);
    //ZwNotifyChangeKey

    // https://learn.microsoft.com/en-us/windows/win32/api/Winternl/nf-winternl-ntnotifychangemultiplekeys
    // See winternl.h
    // https://processhacker.sourceforge.io/doc/ntzwapi_8h_source.html
    NTSYSCALLAPI NTSTATUS NTAPI ZwNotifyChangeMultipleKeys(
        _In_ HANDLE MasterKeyHandle,
        _In_opt_ ULONG Count,
        _In_reads_opt_(Count) OBJECT_ATTRIBUTES SubordinateObjects[],
        _In_opt_ HANDLE Event,
        _In_opt_ PIO_APC_ROUTINE ApcRoutine,
        _In_opt_ PVOID ApcContext,
        _Out_ PIO_STATUS_BLOCK IoStatusBlock,
        _In_ ULONG CompletionFilter,
        _In_ BOOLEAN WatchTree,
        _Out_writes_bytes_opt_(BufferSize) PVOID Buffer,
        _In_ ULONG BufferSize,
        _In_ BOOLEAN Asynchronous);
    //ZwNotifyChangeMultipleKeys

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwopenkey
    NTSYSAPI NTSTATUS NtOpenKey(
        [out] PHANDLE            KeyHandle,
        [in]  ACCESS_MASK        DesiredAccess,
        [in]  POBJECT_ATTRIBUTES ObjectAttributes);
    //ZwOpenKey

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwopenkeyex
    NTSYSAPI NTSTATUS NtOpenKeyEx(
        [out] PHANDLE            KeyHandle,
        [in]  ACCESS_MASK        DesiredAccess,
        [in]  POBJECT_ATTRIBUTES ObjectAttributes,
        [in]  ULONG              OpenOptions);
    //ZwOpenKeyEx

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwopenkeytransacted
    NTSYSAPI NTSTATUS NtOpenKeyTransacted(
        [out] PHANDLE            KeyHandle,
        [in]  ACCESS_MASK        DesiredAccess,
        [in]  POBJECT_ATTRIBUTES ObjectAttributes,
        [in]  HANDLE             TransactionHandle);
    //ZwOpenKeyTransacted

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwopenkeytransactedex
    NTSYSAPI NTSTATUS NtOpenKeyTransactedEx(
        [out] PHANDLE            KeyHandle,
        [in]  ACCESS_MASK        DesiredAccess,
        [in]  POBJECT_ATTRIBUTES ObjectAttributes,
        [in]  ULONG              OpenOptions,
        [in]  HANDLE             TransactionHandle);
    //ZwOpenKeyTransactedEx

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwopenkeytransactedex
    NTSYSAPI NTSTATUS NTAPI NtOpenRegistryTransaction(
        _Out_ PHANDLE RegistryHandle,
        _In_ KEY_ACCESS_MASK DesiredAccess,
        _In_ POBJECT_ATTRIBUTES ObjectAttributes);
    //ZwOpenRegistryTransaction

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwopenkeytransactedex
    NTSYSAPI NTSTATUS NTAPI NtQueryKey(
        _In_ HANDLE KeyHandle,
        _In_ KEY_INFORMATION_CLASS KeyInformationClass,
        _Out_ PVOID KeyInformation,
        _In_ ULONG Length,
        _Out_ PULONG ResultLength);

    // See winternl.h
    // https://processhacker.sourceforge.io/doc/ntzwapi_8h_source.html
    NTSYSCALLAPI NTSTATUS NTAPI ZwQueryMultipleValueKey(
        _In_ HANDLE KeyHandle,
        _Inout_updates_(EntryCount) PKEY_VALUE_ENTRY ValueEntries,
        _In_ ULONG EntryCount,
        _Out_writes_bytes_(*BufferLength) PVOID ValueBuffer,
        _Inout_ PULONG BufferLength,
        _Out_opt_ PULONG RequiredBufferLength);
    //ZwQueryMultipleValueKey

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwopenkeytransactedex
    NTSYSAPI NTSTATUS NTAPI NtQueryOpenSubKeys(
        _In_ POBJECT_ATTRIBUTES TargetKey,
        _Out_ PULONG HandleCount);
    //ZwQueryOpenSubKeys

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwopenkeytransactedex
    NTSYSAPI NTSTATUS NTAPI NtQueryOpenSubKeysEx(
        _In_ POBJECT_ATTRIBUTES TargetKey,
        _In_ ULONG BufferLength,
        _Out_ PVOID Buffer,
        _Out_ PULONG ResultLength);
    //ZwQueryOpenSubKeysEx

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwopenkeytransactedex
    NTSYSAPI NTSTATUS NTAPI NtQueryValueKey(
        _In_ HANDLE KeyHandle,
        _In_ PUNICODE_STRING ValueName,
        _In_ KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
        _Out_ PVOID KeyValueInformation,
        _In_ ULONG Length,
        _Out_ PULONG ResultLength);
    //ZwQueryValueKey
    
    //RtlpNtQueryValueKey

    // See winternl.h
    // https://processhacker.sourceforge.io/doc/ntzwapi_8h_source.html
    NTSYSCALLAPI NTSTATUS NTAPI ZwRenameKey(
        _In_ HANDLE KeyHandle,
        _In_ PUNICODE_STRING NewName);
    //ZwRenameKey

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwopenkeytransactedex
    NTSYSAPI NTSTATUS NTAPI NtReplaceKey(
        _In_ POBJECT_ATTRIBUTES ObjectAttributes,
        _In_ HANDLE Key,
        _In_ POBJECT_ATTRIBUTES ReplacedObjectAttributes);
    //ZwReplaceKey

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwopenkeytransactedex
    NTSYSAPI NTSTATUS NTAPI NtRestoreKey(
        _In_ HANDLE KeyHandle,
        _In_ HANDLE FileHandle,
        _In_ ULONG RestoreFlags);
    //ZwRestoreKey

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwopenkeytransactedex
    NTSYSAPI NTSTATUS NTAPI NtRollbackRegistryTransaction(
        HANDLE RegistryHandle,
        BOOL Wait);
    //ZwRollbackRegistryTransaction

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwopenkeytransactedex
    NTSYSAPI NTSTATUS NTAPI NtSaveKey(
        _In_ HANDLE KeyHandle,
        _In_ HANDLE FileHandle);
    //ZwSaveKey

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwopenkeytransactedex
    NTSYSAPI NTSTATUS NTAPI NtSaveKeyEx(
        _In_ HANDLE KeyHandle,
        _In_ HANDLE FileHandle,
        _In_ ULONG Flags);
    //ZwSaveKeyEx

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwopenkeytransactedex
    NTSYSAPI NTSTATUS NTAPI NtSaveMergedKeys(
        _In_ HANDLE HighPrecedenceKeyHandle,
        _In_ HANDLE LowPrecedenceKeyHandle,
        _In_ HANDLE FileHandle);
    //ZwSaveMergedKeys

    // See winternl.h
    // NtSetInformationKey

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwopenkeytransactedex
    NTSYSAPI NTSTATUS NTAPI NtSetValueKey(
        _In_ HANDLE KeyHandle,
        _In_ PUNICODE_STRING ValueName,
        _In_opt_ ULONG TitleIndex,
        _In_ ULONG Type,
        _In_ PVOID Data,
        _In_ ULONG DataSize);
    //ZwSetValueKey

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwopenkeytransactedex
    NTSYSAPI NTSTATUS NTAPI NtThawRegistry();
    //ZwThawRegistry

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwopenkeytransactedex
    NTSYSAPI NTSTATUS NTAPI NtUnloadKey(
        _In_ POBJECT_ATTRIBUTES TargetKey);
    //ZwUnloadKey

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwopenkeytransactedex
    NTSYSAPI NTSTATUS NTAPI NtUnloadKey2(
        _In_ POBJECT_ATTRIBUTES TargetKey,
        _In_ ULONG Flags);
    //ZwUnloadKey2

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwopenkeytransactedex
    NTSYSAPI NTSTATUS NTAPI NtUnloadKeyEx(
        _In_ POBJECT_ATTRIBUTES TargetKey,
        _In_ HANDLE Event);
    //ZwUnloadKeyEx

}

#endif // _NTREGISTRY_
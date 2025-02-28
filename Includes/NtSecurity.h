#pragma once

#ifndef _NTSECURITY_
#define _NTSECURITY_

#include "NtCommonDefs.h"

extern "C" {

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtAccessCheck(
        _In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
        _In_ HANDLE ClientToken,
        _In_ TOKEN_ACCESS_MASK DesiredAccess,
        _In_ PGENERIC_MAPPING GenericMapping,
        _Out_ PPRIVILEGE_SET PrivilegeSet,
        _Out_ PULONG ReturnLength,
        _Out_ PACCESS_MASK GrantedAccess,
        _Out_ PNTSTATUS AccessStatus);
    //ZwAccessCheck

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtAccessCheckAndAuditAlarm(
        _In_opt_ PUNICODE_STRING SubsystemName,
        _In_opt_ HANDLE ObjectHandle,
        _In_opt_ PUNICODE_STRING ObjectTypeName,
        _In_opt_ PUNICODE_STRING ObjectName,
        _In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
        _In_ ACCESS_MASK DesiredAccess,
        _In_ PGENERIC_MAPPING GenericMapping,
        _In_ BOOLEAN ObjectCreation,
        _Out_ PACCESS_MASK GrantedAccess,
        _Out_ PNTSTATUS AccessStatus,
        _Out_ PBOOLEAN GenerateOnClose);
    //ZwAccessCheckAndAuditAlarm

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtAccessCheckByType(
        _In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
        _In_ PSID PrincipalSelfSid,
        _In_ HANDLE ClientToken,
        _In_ TOKEN_ACCESS_MASK DesiredAccess,
        _In_ POBJECT_TYPE_LIST ObjectTypeList,
        _In_ ULONG ObjectTypeListLength,
        _In_ PGENERIC_MAPPING GenericMapping,
        _Out_ PPRIVILEGE_SET PrivilegeSet,
        _Out_ PULONG ReturnedLength,
        _Out_ PACCESS_MASK GrantedAccess,
        _Out_ PNTSTATUS AccessStatus);
    //ZwAccessCheckByType

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtAccessCheckByTypeAndAuditAlarm(
        _In_ PUNICODE_STRING SubsystemName,
        _In_ PVOID HandleId,
        _In_ PUNICODE_STRING ObjectTypeName,
        _In_ PUNICODE_STRING ObjectName,
        _In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
        _In_ PSID PrincipalSelfSid,
        _In_ TOKEN_ACCESS_MASK DesiredAccess,
        _In_ ULONG AuditType,
        _In_ ULONG Flags,
        _In_ POBJECT_TYPE_LIST ObjectTypeList,
        _In_ ULONG ObjectTypeListLength,
        _In_ PGENERIC_MAPPING GenericMapping,
        _In_ BOOLEAN ObjectCreation,
        _Out_ PACCESS_MASK GrantedAccess,
        _Out_ PULONG AccessStatus,
        _Out_ PBOOLEAN GenerateOnClose);
    //ZwAccessCheckByTypeAndAuditAlarm

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtAccessCheckByTypeResultList(
        _In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
        _In_ PSID PrincipalSelfSid,
        _In_ HANDLE TokenHandle,
        _In_ TOKEN_ACCESS_MASK DesiredAccess,
        _In_ POBJECT_TYPE_LIST ObjectTypeList,
        _In_ ULONG ObjectTypeListLength,
        _In_ PGENERIC_MAPPING GenericMapping,
        _In_ PPRIVILEGE_SET PrivilegeSet,
        _In_ ULONG PrivilegeSetLength,
        _Out_ PACCESS_MASK GrantedAccessList,
        _Out_ PNTSTATUS AccessStatusList);
    //ZwAccessCheckByTypeResultList

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtAccessCheckByTypeResultListAndAuditAlarm(
        _In_ PUNICODE_STRING SubsystemName,
        _In_ PVOID HandleId,
        _In_ PUNICODE_STRING ObjectTypeName,
        _In_ PUNICODE_STRING ObjectName,
        _In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
        _In_ PSID PrincipalSelfSid,
        _In_ TOKEN_ACCESS_MASK DesiredAccess,
        _In_ ULONG AuditType,
        _In_ ULONG Flags,
        _In_ POBJECT_TYPE_LIST ObjectTypeList,
        _In_ ULONG ObjectTypeListLength,
        _In_ PVOID GenericMapping,
        _In_ BOOLEAN ObjectCreation,
        _Out_ PACCESS_MASK GrantedAccessList,
        _Out_ PNTSTATUS AccessStatusList,
        _Out_ PULONG GenerateOnClose);
    //ZwAccessCheckByTypeResultListAndAuditAlarm

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtAccessCheckByTypeResultListAndAuditAlarmByHandle(
        _In_ PUNICODE_STRING SubsystemName,
        _In_ PVOID HandleId,
        _In_ HANDLE TokenHandle,
        _In_ PUNICODE_STRING ObjectTypeName,
        _In_ PUNICODE_STRING ObjectName,
        _In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
        _In_ PSID PrincipalSelfSid,
        _In_ TOKEN_ACCESS_MASK DesiredAccess,
        _In_ AUDIT_EVENT_TYPE AuditType,
        _In_ ULONG Flags,
        _In_ POBJECT_TYPE_LIST ObjectTypeList,
        _In_ ULONG ObjectTypeListLength,
        _In_ PGENERIC_MAPPING GenericMapping,
        _In_ BOOLEAN ObjectCreation,
        _Out_ PACCESS_MASK GrantedAccessList,
        _Out_ PNTSTATUS AccessStatusList,
        _Out_ PULONG GenerateOnClose);
    //ZwAccessCheckByTypeResultListAndAuditAlarmByHandle

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtAdjustGroupsToken(
        _In_ HANDLE TokenHandle,
        _In_ BOOLEAN ResetToDefault,
        _In_ PTOKEN_GROUPS NewTokenGroups,
        _In_ ULONG TokenGroupsLength,
        _Out_ PTOKEN_GROUPS PrevTokenGroups,
        _Out_opt_ PULONG ReturnedLength);
    //ZwAdjustGroupsToken

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtAdjustPrivilegesToken(
        _In_ HANDLE TokenHandle,
        _In_ BOOLEAN DisableAllPrivileges,
        _In_ PTOKEN_PRIVILEGES NewState,
        _In_ ULONG BufferLength,
        _Out_opt_ PTOKEN_PRIVILEGES PreviousState,
        _Out_ PULONG ReturnLength);
    //ZwAdjustPrivilegesToken

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtAdjustTokenClaimsAndDeviceGroups(
        _In_ HANDLE TokenHandle,
        _In_ BOOLEAN UserResetToDefault,
        _In_ BOOLEAN DeviceResetToDefault,
        _In_ BOOLEAN DeviceGroupsResetToDefault,
        _In_opt_ PTOKEN_SECURITY_ATTRIBUTES_INFORMATION NewUserState,
        _In_opt_ PTOKEN_SECURITY_ATTRIBUTES_INFORMATION NewDeviceState,
        _In_opt_ PTOKEN_GROUPS NewDeviceGroupsState,
        _In_ ULONG UserBufferLength,
        _Out_ PTOKEN_SECURITY_ATTRIBUTES_INFORMATION PreviousUserState,
        _In_ ULONG DeviceBufferLength,
        _Out_ PTOKEN_SECURITY_ATTRIBUTES_INFORMATION PreviousDeviceState,
        _In_ ULONG DeviceGroupsBufferLength,
        _Out_ PTOKEN_GROUPS PreviousDeviceGroups,
        _Out_opt_ PULONG UserReturnLength,
        _Out_opt_ PULONG DeviceReturnLength,
        _Out_opt_ PULONG DeviceGroupsReturnBufferLength);
    //ZwAdjustTokenClaimsAndDeviceGroups

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtCloseObjectAuditAlarm(
        _In_ PUNICODE_STRING SubsystemName,
        _In_opt_ HANDLE ObjectHandle,
        _In_ BOOLEAN OnClose);
    //ZwCloseObjectAuditAlarm

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtCompareSigningLevels(
        BYTE SigningLevel,
        BYTE RequiredLevel);
    //ZwCompareSigningLevels

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtCompareTokens(
        _In_ HANDLE FirstTokenHandle,
        _In_ HANDLE SecondTokenHandle,
        _Out_ PBOOLEAN Equal);
    //ZwCompareTokens

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtCreateLowBoxToken(
        _Out_ PHANDLE LowBoxToken,
        _In_ HANDLE hOrgToken,
        _In_ TOKEN_ACCESS_MASK DesiredAccess,
        _In_ POBJECT_ATTRIBUTES ObjectAttributes,
        _In_ PSID AppContainerSid,
        _In_ DWORD CapabilityCount,
        _In_ PSID_AND_ATTRIBUTES Capabilities,
        _In_ DWORD LowBoxCount,
        _In_ PVOID LowBoxStruct);
    //ZwCreateLowBoxToken

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtCreateToken(
        _Out_ PHANDLE TokenHandle,
        _In_ TOKEN_ACCESS_MASK    DesiredAccess,
        _In_ POBJECT_ATTRIBUTES   ObjectAttributes,
        _In_ TOKEN_TYPE           TokenType,
        _In_ PLUID                AuthenticationId,
        _In_ PLARGE_INTEGER       ExpirationTime,
        _In_ PTOKEN_USER          TokenUser,
        _In_ PTOKEN_GROUPS        TokenGroups,
        _In_ PTOKEN_PRIVILEGES    TokenPrivileges,
        _In_ PTOKEN_OWNER         TokenOwner,
        _In_ PTOKEN_PRIMARY_GROUP TokenPrimaryGroup,
        _In_ PTOKEN_DEFAULT_DACL  TokenDefaultDacl,
        _In_ PTOKEN_SOURCE        TokenSource);
    //ZwCreateToken

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtCreateTokenEx(
        _Out_ PHANDLE TokenHandle,
        _In_ TOKEN_ACCESS_MASK DesiredAccess,
        _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
        _In_ TOKEN_TYPE TokenType,
        _In_ PLUID AuthenticationId,
        _In_ PLARGE_INTEGER ExpirationTime,
        _In_ PTOKEN_USER User,
        _In_ PTOKEN_GROUPS Groups,
        _In_ PTOKEN_PRIVILEGES Privileges,
        _In_opt_ PTOKEN_SECURITY_ATTRIBUTES_INFORMATION UserAttributes,
        _In_opt_ PTOKEN_SECURITY_ATTRIBUTES_INFORMATION DeviceAttributes,
        _In_opt_ PTOKEN_GROUPS DeviceGroups,
        _In_opt_ PTOKEN_MANDATORY_POLICY TokenMandatoryPolicy,
        _In_opt_ PTOKEN_OWNER Owner,
        _In_ PTOKEN_PRIMARY_GROUP PrimaryGroup,
        _In_opt_ PTOKEN_DEFAULT_DACL DefaultDacl,
        _In_ PTOKEN_SOURCE TokenSource);
    //ZwCreateTokenEx

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtDeleteObjectAuditAlarm(
        _In_ PUNICODE_STRING SubsystemName,
        _In_opt_ HANDLE ObjectHandle,
        _In_ BOOLEAN OnClose);
    //ZwDeleteObjectAuditAlarm

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntduplicatetoken
    NTSYSCALLAPI NTSTATUS NtDuplicateToken(
        _In_ HANDLE ExistingTokenHandle,
        _In_ ACCESS_MASK DesiredAccess,
        _In_ POBJECT_ATTRIBUTES ObjectAttributes,
        _In_ BOOLEAN EffectiveOnly,
        _In_ TOKEN_TYPE TokenType,
        _Out_ PHANDLE NewTokenHandle);
    //ZwDuplicateToken

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtFilterBootOption(
        _In_ ULONG FilterOperation,
        _In_ ULONG ObjectType,
        _In_ ULONG ElementType,
        _In_ PVOID Data,
        _In_ ULONG DataSize);
    //ZwFilterBootOption

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtFilterToken(
        _In_ HANDLE ExistingTokenHandle,
        _In_ ULONG Flags,
        _In_opt_ PTOKEN_GROUPS SidsToDisable,
        _In_opt_ PTOKEN_PRIVILEGES PrivilegesToDelete,
        _In_opt_ PTOKEN_GROUPS RestrictedSids,
        _Out_ PHANDLE NewTokenHandle);
    //ZwFilterToken

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtFilterTokenEx(
        _In_ HANDLE TokenHandle,
        _In_ ULONG  Flags,
        _In_opt_ PTOKEN_GROUPS  SidsToDisable,
        _In_opt_ PTOKEN_PRIVILEGES  PrivilegesToDelete,
        _In_opt_ PTOKEN_GROUPS  RestrictedSids,
        _In_ ULONG  DisableUserClaimsCount,
        _In_opt_ PUNICODE_STRING  UserClaimsToDisable,
        _In_ ULONG  DisableDeviceClaimsCount,
        _In_opt_ PUNICODE_STRING  DeviceClaimsToDisable,
        _In_opt_ PTOKEN_GROUPS  DeviceGroupsToDisable,
        _In_opt_ PTOKEN_SECURITY_ATTRIBUTES_INFORMATION  RestrictedUserAttributes,
        _In_opt_ PTOKEN_SECURITY_ATTRIBUTES_INFORMATION  RestrictedDeviceAttributes,
        _In_opt_ PTOKEN_GROUPS  RestrictedDeviceGroups,
        _Out_ PHANDLE  NewTokenHandle);
    //ZwFilterTokenEx

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtGetCachedSigningLevel(
        _In_ HANDLE File,
        _Out_ PULONG Flags,
        _Out_ PBYTE SigningLevel,
        _Out_ PUCHAR Thumbprint,
        _Inout_opt_ PULONG ThumbprintSize,
        _Out_opt_ PULONG ThumbprintAlgorithm);
    //ZwGetCachedSigningLevel

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtImpersonateAnonymousToken(
        _In_ HANDLE THreadHandle);
    //ZwImpersonateAnonymousToken

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtImpersonateThread(
        _In_ HANDLE ThreadHandle,
        _In_ HANDLE ThreadToImpersonate,
        _In_ PULONG SecurityQualityOfService);
    //ZwImpersonateThread

    // https://processhacker.sourceforge.io/doc/ntzwapi_8h_source.html
    NTSYSCALLAPI NTSTATUS NTAPI ZwOpenJobObjectToken(
        _In_ HANDLE JobHandle,
        _In_ ACCESS_MASK DesiredAccess,
        _Out_ PHANDLE TokenHandle);

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntopenprocesstoken
    NTSYSCALLAPI NTSTATUS NtOpenProcessToken(
        _In_ HANDLE ProcessHandle,
        _In_ ACCESS_MASK DesiredAccess,
        _Out_ PHANDLE TokenHandle);
    //ZwOpenProcessToken

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntopenprocesstokenex
    NTSYSCALLAPI NTSTATUS NtOpenProcessTokenEx(
        _In_ HANDLE ProcessHandle,
        _In_ ACCESS_MASK DesiredAccess,
        _In_ ULONG HandleAttributes,
        _Out_ PHANDLE TokenHandle);
    //ZwOpenProcessTokenEx

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntopenthreadtoken
    NTSYSCALLAPI NTSTATUS NtOpenThreadToken(
        _In_ HANDLE ThreadHandle,
        _In_ ACCESS_MASK DesiredAccess,
        _In_ BOOLEAN OpenAsSelf,
        _Out_ PHANDLE TokenHandle);
    //ZwOpenThreadToken

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntopenthreadtokenex
    NTSYSCALLAPI NTSTATUS NtOpenThreadTokenEx(
        _In_ HANDLE      ThreadHandle,
        _In_ ACCESS_MASK DesiredAccess,
        _In_ BOOLEAN     OpenAsSelf,
        _In_ ULONG       HandleAttributes,
        _Out_ PHANDLE     TokenHandle);
    //ZwOpenThreadTokenEx

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntprivilegecheck
    NTSYSCALLAPI NTSTATUS NtPrivilegeCheck(
        _In_ HANDLE ClientToken,
        _Inout_ PPRIVILEGE_SET RequiredPrivileges,
        _Out_ PBOOLEAN Result);
    //ZwPrivilegeCheck

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntprivilegecheck
    NTSYSCALLAPI NTSTATUS NTAPI NtPrivilegeObjectAuditAlarm(
        _In_ PUNICODE_STRING SubsystemName,
        _In_ PVOID HandleId,
        _In_ HANDLE TokenHandle,
        _In_ TOKEN_ACCESS_MASK DesiredAccess,
        _In_ PPRIVILEGE_SET PrivilegeSet,
        _In_ BOOLEAN AccessGranted);
    //ZwPrivilegeObjectAuditAlarm

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntprivilegecheck
    NTSYSCALLAPI NTSTATUS NTAPI NtPrivilegedServiceAuditAlarm(
        _In_ PUNICODE_STRING SubsystemName,
        _In_ PUNICODE_STRING ServiceName,
        _In_ HANDLE TokenHandle,
        _In_ PPRIVILEGE_SET PrivilegeSet,
        _In_ BOOLEAN AccessGranted);
    //ZwPrivilegedServiceAuditAlarm

    //https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntqueryinformationtoken
    NTSYSCALLAPI NTSTATUS NtQueryInformationToken(
        [in]  HANDLE                  TokenHandle,
        [in]  TOKEN_INFORMATION_CLASS TokenInformationClass,
        [out] PVOID                   TokenInformation,
        [in]  ULONG                   TokenInformationLength,
        [out] PULONG                  ReturnLength);
    //ZwQueryInformationToken

    //https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntqueryinformationtoken
    NTSYSCALLAPI NTSTATUS NTAPI NtQuerySecurityAttributesToken(
        _In_ HANDLE TokenHandle,
        _In_ PUNICODE_STRING Attributes,
        _In_ ULONG NumberOfAttributes,
        _Out_ PVOID Buffer,
        _In_ ULONG Length,
        _Out_ PULONG ReturnLength);
    //ZwQuerySecurityAttributesToken

    //https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntquerysecurityobject
    NTSYSCALLAPI NTSTATUS NtQuerySecurityObject(
        [in]  HANDLE               Handle,
        [in]  SECURITY_INFORMATION SecurityInformation,
        [out] PSECURITY_DESCRIPTOR SecurityDescriptor,
        [in]  ULONG                Length,
        [out] PULONG               LengthNeeded);
    //ZwQuerySecurityObject

    //https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntquerysecurityobject
    NTSYSCALLAPI NTSTATUS NTAPI NtQuerySecurityPolicy(
        _In_ PUNICODE_STRING Category,
        _In_ PUNICODE_STRING SubCategory,
        _In_ PUNICODE_STRING Policy,
        _Inout_ PULONG Unknown,
        _Out_ PBOOLEAN Enabled,
        _In_ PULONG Subsystem);
    //ZwQuerySecurityPolicy

    //https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntquerysecurityobject
    NTSYSCALLAPI NTSTATUS NTAPI NtSetCachedSigningLevel(
        _In_ ULONG Flags,
        _In_ BYTE InputSigningLevel,
        _In_ PHANDLE SourceFiles,
        _In_ ULONG SourceFileCount,
        _In_opt_ HANDLE TargetFile);
    //ZwSetCachedSigningLevel

    //https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntquerysecurityobject
    NTSYSCALLAPI NTSTATUS NTAPI NtSetCachedSigningLevel2(
        _In_ ULONG Flags,
        _In_ BYTE InputSigningLevel,
        _In_ PHANDLE SourceFiles,
        _In_ ULONG SourceFileCount,
        _In_opt_ HANDLE TargetFile,
        _In_opt_ PVOID LevelInformation);
    //ZwSetCachedSigningLevel2

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntsetinformationtoken
    NTSYSCALLAPI NTSTATUS NtSetInformationToken(
        [in] HANDLE                  TokenHandle,
        [in] TOKEN_INFORMATION_CLASS TokenInformationClass,
        [in] PVOID                   TokenInformation,
        [in] ULONG                   TokenInformationLength);
    //ZwSetInformationToken

    //https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntsetsecurityobject
    NTSYSCALLAPI NTSTATUS NtSetSecurityObject(
        [in] HANDLE               Handle,
        [in] SECURITY_INFORMATION SecurityInformation,
        [in] PSECURITY_DESCRIPTOR SecurityDescriptor);
    // ZwSetSecurityObject

}

#endif // _NTSECURITY_
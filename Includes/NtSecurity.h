#pragma once

#ifndef _NTSECURITY_
#define _NTSECURITY_

#include "NtCommonDefs.h"

extern "C" {

    // NO UNRESOLVED FUNCTIONS

    typedef struct _OBJECT_BOUNDARY_DESCRIPTOR {
        ULONG Version;
        ULONG Items;
        ULONG TotalSize;
        union {
            ULONG Flags;
            struct {
                ULONG AddAppContainerSid : 1;
                ULONG Reserved : 31;
            } DUMMYSTRUCTNAME;
        } DUMMYUNIONNAME;
        //OBJECT_BOUNDARY_ENTRY Entries[1];
    } OBJECT_BOUNDARY_DESCRIPTOR, * POBJECT_BOUNDARY_DESCRIPTOR;

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_generic_mapping
    typedef struct _GENERIC_MAPPING {
        ACCESS_MASK GenericRead;
        ACCESS_MASK GenericWrite;
        ACCESS_MASK GenericExecute;
        ACCESS_MASK GenericAll;
    } GENERIC_MAPPING, *PGENERIC_MAPPING;

    // From WTypeBase.h
    typedef struct _SID_AND_ATTRIBUTES {
        SID* Sid;
        DWORD Attributes;
    } SID_AND_ATTRIBUTES, * PSID_AND_ATTRIBUTES;

    // From Winnt.h
#define SID_HASH_SIZE 32
    typedef ULONG_PTR SID_HASH_ENTRY, * PSID_HASH_ENTRY;
    typedef struct _SID_AND_ATTRIBUTES_HASH {
        DWORD SidCount;
        PSID_AND_ATTRIBUTES SidAttr;
        SID_HASH_ENTRY Hash[SID_HASH_SIZE];
    } SID_AND_ATTRIBUTES_HASH, * PSID_AND_ATTRIBUTES_HASH;

    // https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntpsapi.h#L1166C1-L1181C34
    /* The PS_PROTECTION structure is used to define the protection level of a process. */
    typedef struct _PS_PROTECTION {
        union {
            UCHAR Level;
            struct {
                UCHAR Type : 3;
                UCHAR Audit : 1;
                UCHAR Signer : 4;
            } DUMMYSTRUCTNAME;
        } DUMMYUNIONNAME;
    } PS_PROTECTION, * PPS_PROTECTION;

    typedef enum _SECURITY_INFORMATION {
        OWNER_SECURITY_INFORMATION = 0x00000001L,
        GROUP_SECURITY_INFORMATION = 0x00000002L,
        DACL_SECURITY_INFORMATION = 0x00000004L,
        SACL_SECURITY_INFORMATION = 0x00000008L,
        LABEL_SECURITY_INFORMATION = 0x00000010L,
        ATTRIBUTE_SECURITY_INFORMATION = 0x00000020L,
        SCOPE_SECURITY_INFORMATION = 0x00000040L,
        PROCESS_TRUST_LABEL_SECURITY_INFORMATION = 0x00000080L,
        ACCESS_FILTER_SECURITY_INFORMATION = 0x00000100L,
        BACKUP_SECURITY_INFORMATION = 0x00010000L,

        PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000L,
        PROTECTED_SACL_SECURITY_INFORMATION = 0x40000000L,
        UNPROTECTED_DACL_SECURITY_INFORMATION = 0x20000000L,
        UNPROTECTED_SACL_SECURITY_INFORMATION = 0x10000000L
    } SECURITY_INFORMATION;

    // https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-control
    typedef enum _SECURITY_DESCRIPTOR_CONTROL {
        // Indicates a required security descriptor in which the discretionary access control
        // list(DACL) is set up to support automatic propagation of inheritable access control
        // entries(ACEs) to existing child objects. For access control lists(ACLs) that support
        // auto inheritance, this bit is always set.Protected servers can call the
        // ConvertToAutoInheritPrivateObjectSecurity function to convert a security descriptor
        // and set this flag.
        SE_DACL_AUTO_INHERIT_REQ = 0x0100,
        // Indicates a security descriptor in which the discretionary access control list(DACL)
        // is set up to support automatic propagation of inheritable access control entries(ACEs)
        // to existing child objects. For access control lists(ACLs) that support auto inheritance,
        // this bit is always set. Protected servers can call the
        // ConvertToAutoInheritPrivateObjectSecurity function to convert a security descriptor
        // and set this flag.
        SE_DACL_AUTO_INHERITED = 0x0400,
        // Indicates a security descriptor with a default DACL.For example, if the creator an
        // object does not specify a DACL, the object receives the default DACL from the access
        // token of the creator. This flag can affect how the system treats the DACL with respect
        // to ACE inheritance.The system ignores this flag if the SE_DACL_PRESENT flag is not set.
        // This flag is used to determine how the final DACL on the object is to be computed and
        // is not stored physically in the security descriptor control of the securable object.
        // To set this flag, use the SetSecurityDescriptorDacl function.
        SE_DACL_DEFAULTED = 0x0008,
        // Indicates a security descriptor that has a DACL.If this flag is not set, or if this
        // flag is set and the DACL is NULL, the security descriptor allows full access to everyone.
        // This flag is used to hold the security information specified by a caller until the
        // security descriptor is associated with a securable object.After the security descriptor
        // is associated with a securable object, the SE_DACL_PRESENT flag is always set in the
        // security descriptor control. To set this flag, use the SetSecurityDescriptorDacl function.
        SE_DACL_PRESENT = 0x0004,
        // Prevents the DACL of the security descriptor from being modified by inheritable ACEs.
        // To set this flag, use the SetSecurityDescriptorControl function.
        SE_DACL_PROTECTED = 0x1000,
        // Indicates that the security identifier(SID) of the security descriptor group was provided
        // by a default mechanism. This flag can be used by a resource manager to identify objects
        // whose security descriptor group was set by a default mechanism. To set this flag, use
        // the SetSecurityDescriptorGroup function.
        SE_GROUP_DEFAULTED = 0x0002,
        // Indicates that the SID of the owner of the security descriptor was provided by a default
        // mechanism. This flag can be used by a resource manager to identify objects whose owner
        // was set by a default mechanism. To set this flag, use the SetSecurityDescriptorOwner
        // function.
        SE_OWNER_DEFAULTED = 0x0001,
        // Indicates that the resource manager control is valid.
        SE_RM_CONTROL_VALID = 0x4000,
        // Indicates a required security descriptor in which the system access control list(SACL)
        // is set up to support automatic propagation of inheritable ACEs to existing child objects.
        // The system sets this bit when it performs the automatic inheritance algorithm for the
        // object and its existing child objects. To convert a security descriptor and set this
        // flag, protected servers can call the ConvertToAutoInheritPrivateObjectSecurity function.
        SE_SACL_AUTO_INHERIT_REQ = 0x0200,
        // Indicates a security descriptor in which the system access control list(SACL) is set
        // up to support automatic propagation of inheritable ACEs to existing child objects.
        // The system sets this bit when it performs the automatic inheritance algorithm for the
        // object and its existing child objects.To convert a security descriptor and set this
        // flag, protected servers can call the ConvertToAutoInheritPrivateObjectSecurity function.
        SE_SACL_AUTO_INHERITED = 0x0800,
        // A default mechanism, rather than the original provider of the security descriptor,
        // provided the SACL. This flag can affect how the system treats the SACL, with respect
        // to ACE inheritance.The system ignores this flag if the SE_SACL_PRESENT flag is not set.
        // To set this flag, use the SetSecurityDescriptorSacl function.
        SE_SACL_DEFAULTED = 0x0020,
        // Indicates a security descriptor that has a SACL.To set this flag, use the
        // SetSecurityDescriptorSacl function.
        SE_SACL_PRESENT = 0x0010,
        // Prevents the SACL of the security descriptor from being modified by inheritable ACEs.
        // To set this flag, use the SetSecurityDescriptorControl function.
        SE_SACL_PROTECTED = 0x2000,
        // Indicates a self - relative security descriptor. If this flag is not set, the security
        // descriptor is in absolute format. For more information, see Absolute and Self - Relative
        // Security Descriptors.
        SE_SELF_RELATIVE = 0x8000
    } SECURITY_DESCRIPTOR_CONTROL, *PSECURITY_DESCRIPTOR_CONTROL;

    // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-acl_information_class
    typedef enum _ACL_INFORMATION_CLASS {
        AclRevisionInformation = 1,
        AclSizeInformation
    } ACL_INFORMATION_CLASS;

    // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-audit_event_type
    typedef enum _AUDIT_EVENT_TYPE {
        AuditEventObjectAccess,
        AuditEventDirectoryServiceAccess
    } AUDIT_EVENT_TYPE, * PAUDIT_EVENT_TYPE;

    // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-object_type_list
    typedef struct _OBJECT_TYPE_LIST {
        WORD Level;
        WORD Sbz;
        GUID* ObjectType;
    } OBJECT_TYPE_LIST, * POBJECT_TYPE_LIST;

    // https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntrtl.h#L10285C1-L10292C50
    typedef enum _APPCONTAINER_SID_TYPE {
        NotAppContainerSidType,
        ChildAppContainerSidType,
        ParentAppContainerSidType,
        InvalidAppContainerSidType,
        MaxAppContainerSidType
    } APPCONTAINER_SID_TYPE, * PAPPCONTAINER_SID_TYPE;

    // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_type
    typedef enum _TOKEN_TYPE {
        TokenPrimary = 1,
        TokenImpersonation
    } TOKEN_TYPE;

    // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_user
    typedef struct _TOKEN_USER {
        SID_AND_ATTRIBUTES User;
    } TOKEN_USER, * PTOKEN_USER;

    // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_groups
    typedef struct _TOKEN_GROUPS {
        DWORD              GroupCount;
        SID_AND_ATTRIBUTES Groups[ANYSIZE_ARRAY];
    } TOKEN_GROUPS, * PTOKEN_GROUPS;

    // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_privileges
    typedef struct _TOKEN_PRIVILEGES {
        DWORD               PrivilegeCount;
        LUID_AND_ATTRIBUTES Privileges[ANYSIZE_ARRAY];
    } TOKEN_PRIVILEGES, * PTOKEN_PRIVILEGES;

    // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_owner
    typedef struct _TOKEN_OWNER {
        PSID Owner;
    } TOKEN_OWNER, * PTOKEN_OWNER;

    // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-claim_security_attribute_fqbn_value
    typedef struct _CLAIM_SECURITY_ATTRIBUTE_FQBN_VALUE {
        DWORD64 Version;
        PWSTR   Name;
    } CLAIM_SECURITY_ATTRIBUTE_FQBN_VALUE, * PCLAIM_SECURITY_ATTRIBUTE_FQBN_VALUE;

    // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-claim_security_attribute_octet_string_value
    typedef struct _CLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE {
        PVOID pValue;
        DWORD ValueLength;
    } CLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE, * PCLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE;

    // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-claim_security_attribute_v1
    typedef enum _CLAIM_SECURITY_ATTRIBUTE_TYPE {
        // The Values member refers to an array of LONG64 values.
        CLAIM_SECURITY_ATTRIBUTE_TYPE_INT64 = 0x0001,
        // The Values member refers to an array of ULONG64 values
        CLAIM_SECURITY_ATTRIBUTE_TYPE_UINT64 = 0x0002,
        // The Values member refers to an array of pointers to Unicode string values
        CLAIM_SECURITY_ATTRIBUTE_TYPE_STRING = 0x0003,
        // The Values member refers to an array of CLAIM_SECURITY_ATTRIBUTE_FQBN_VALUE values
        CLAIM_SECURITY_ATTRIBUTE_TYPE_FQBN = 0x0004,
        // The Values member refers to an array of CLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE
        // values where the pValue member of each CLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE
        // is a PSID.
        CLAIM_SECURITY_ATTRIBUTE_TYPE_SID = 0x0005,
        // The Values member refers to an array of ULONG64 values where each element indicates
        // a Boolean value.The value 1 indicates TRUE and the value 0 indicates FALSE
        CLAIM_SECURITY_ATTRIBUTE_TYPE_BOOLEAN = 0x0006,
        // The Values member refers to an array of CLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE
        // values.
        CLAIM_SECURITY_ATTRIBUTE_TYPE_OCTET_STRING = 0x0010
    } CLAIM_SECURITY_ATTRIBUTE_TYPE;

    // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-claim_security_attribute_v1
    typedef enum _CLAIM_SECURITY_ATTRIBUTE_FLAGS {
        // This attribute is ignored by the operating system.This claim security attribute is
        // not inherited across processes.
        CLAIM_SECURITY_ATTRIBUTE_VALUE_CASE_SENSITIVE = 0x0001,
        // The value of the claim security attribute is case sensitive.This flag is valid for
        // values that contain string types
        CLAIM_SECURITY_ATTRIBUTE_NON_INHERITABLE = 0x0002,
        // The claim security attribute is considered only for deny access control entries(ACEs).
        CLAIM_SECURITY_ATTRIBUTE_USE_FOR_DENY_ONLY = 0x0004,
        // The claim security attribute is disabled by default.
        CLAIM_SECURITY_ATTRIBUTE_DISABLED_BY_DEFAULT = 0x0008,
        // The claim security attribute is disabled and will not be applied by the AccessCheck
        // function.
        CLAIM_SECURITY_ATTRIBUTE_DISABLED = 0x0010,
        // The claim security attribute is mandatory.
        CLAIM_SECURITY_ATTRIBUTE_MANDATORY = 0x0020
    } CLAIM_SECURITY_ATTRIBUTE_FLAGS;

    // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-claim_security_attribute_v1
    typedef struct _CLAIM_SECURITY_ATTRIBUTE_V1 {
        PWSTR Name;
        CLAIM_SECURITY_ATTRIBUTE_TYPE ValueType;
        WORD  Reserved;
        CLAIM_SECURITY_ATTRIBUTE_FLAGS Flags;
        DWORD ValueCount;
        union {
            PLONG64 pInt64;
            PDWORD64 pUint64;
            PWSTR* ppString;
            PCLAIM_SECURITY_ATTRIBUTE_FQBN_VALUE pFqbn;
            PCLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE pOctetString;
        } Values;
    } CLAIM_SECURITY_ATTRIBUTE_V1, * PCLAIM_SECURITY_ATTRIBUTE_V1;

    //https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-claim_security_attributes_information
    typedef struct _CLAIM_SECURITY_ATTRIBUTES_INFORMATION {
        WORD  Version;
        WORD  Reserved;
        DWORD AttributeCount;
        union {
            PCLAIM_SECURITY_ATTRIBUTE_V1 pAttributeV1;
        } Attribute;
    } CLAIM_SECURITY_ATTRIBUTES_INFORMATION, * PCLAIM_SECURITY_ATTRIBUTES_INFORMATION;

    typedef enum _TOKEN_INFORMATION_CLASS {
        TokenUser = 1, // q: TOKEN_USER, SE_TOKEN_USER
        TokenGroups, // q: TOKEN_GROUPS
        TokenPrivileges, // q: TOKEN_PRIVILEGES
        TokenOwner, // q; s: TOKEN_OWNER
        TokenPrimaryGroup, // q; s: TOKEN_PRIMARY_GROUP
        TokenDefaultDacl, // q; s: TOKEN_DEFAULT_DACL
        TokenSource, // q: TOKEN_SOURCE
        TokenType, // q: TOKEN_TYPE
        TokenImpersonationLevel, // q: SECURITY_IMPERSONATION_LEVEL
        TokenStatistics, // q: TOKEN_STATISTICS // 10
        TokenRestrictedSids, // q: TOKEN_GROUPS
        TokenSessionId, // q; s: ULONG (requires SeTcbPrivilege)
        TokenGroupsAndPrivileges, // q: TOKEN_GROUPS_AND_PRIVILEGES
        TokenSessionReference, // s: ULONG (requires SeTcbPrivilege)
        TokenSandBoxInert, // q: ULONG
        TokenAuditPolicy, // q; s: TOKEN_AUDIT_POLICY (requires SeSecurityPrivilege/SeTcbPrivilege)
        TokenOrigin, // q; s: TOKEN_ORIGIN (requires SeTcbPrivilege)
        TokenElevationType, // q: TOKEN_ELEVATION_TYPE
        TokenLinkedToken, // q; s: TOKEN_LINKED_TOKEN (requires SeCreateTokenPrivilege)
        TokenElevation, // q: TOKEN_ELEVATION // 20
        TokenHasRestrictions, // q: ULONG
        TokenAccessInformation, // q: TOKEN_ACCESS_INFORMATION
        TokenVirtualizationAllowed, // q; s: ULONG (requires SeCreateTokenPrivilege)
        TokenVirtualizationEnabled, // q; s: ULONG
        TokenIntegrityLevel, // q; s: TOKEN_MANDATORY_LABEL
        TokenUIAccess, // q; s: ULONG (requires SeTcbPrivilege)
        TokenMandatoryPolicy, // q; s: TOKEN_MANDATORY_POLICY (requires SeTcbPrivilege)
        TokenLogonSid, // q: TOKEN_GROUPS
        TokenIsAppContainer, // q: ULONG // since WIN8
        TokenCapabilities, // q: TOKEN_GROUPS // 30
        TokenAppContainerSid, // q: TOKEN_APPCONTAINER_INFORMATION
        TokenAppContainerNumber, // q: ULONG
        TokenUserClaimAttributes, // q: CLAIM_SECURITY_ATTRIBUTES_INFORMATION
        TokenDeviceClaimAttributes, // q: CLAIM_SECURITY_ATTRIBUTES_INFORMATION
        TokenRestrictedUserClaimAttributes, // q: CLAIM_SECURITY_ATTRIBUTES_INFORMATION
        TokenRestrictedDeviceClaimAttributes, // q: CLAIM_SECURITY_ATTRIBUTES_INFORMATION
        TokenDeviceGroups, // q: TOKEN_GROUPS
        TokenRestrictedDeviceGroups, // q: TOKEN_GROUPS
        TokenSecurityAttributes, // q; s: TOKEN_SECURITY_ATTRIBUTES_[AND_OPERATION_]INFORMATION (requires SeTcbPrivilege)
        TokenIsRestricted, // q: ULONG // 40
        TokenProcessTrustLevel, // q: TOKEN_PROCESS_TRUST_LEVEL // since WINBLUE
        TokenPrivateNameSpace, // q; s: ULONG (requires SeTcbPrivilege) // since THRESHOLD
        TokenSingletonAttributes, // q: TOKEN_SECURITY_ATTRIBUTES_INFORMATION // since REDSTONE
        TokenBnoIsolation, // q: TOKEN_BNO_ISOLATION_INFORMATION // since REDSTONE2
        TokenChildProcessFlags, // s: ULONG  (requires SeTcbPrivilege) // since REDSTONE3
        TokenIsLessPrivilegedAppContainer, // q: ULONG // since REDSTONE5
        TokenIsSandboxed, // q: ULONG // since 19H1
        TokenIsAppSilo, // q: ULONG // since WIN11 22H2 // previously TokenOriginatingProcessTrustLevel // q: TOKEN_PROCESS_TRUST_LEVEL
        TokenLoggingInformation, // TOKEN_LOGGING_INFORMATION // since 24H2
        MaxTokenInfoClass
    } TOKEN_INFORMATION_CLASS, * PTOKEN_INFORMATION_CLASS;

    // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_primary_group
    typedef struct _TOKEN_PRIMARY_GROUP {
        PSID PrimaryGroup;
    } TOKEN_PRIMARY_GROUP, * PTOKEN_PRIMARY_GROUP;

    // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_mandatory_policy
    typedef struct _TOKEN_MANDATORY_POLICY {
        DWORD Policy;
    } TOKEN_MANDATORY_POLICY, * PTOKEN_MANDATORY_POLICY;

    // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_default_dacl
    typedef struct _TOKEN_DEFAULT_DACL {
        PACL DefaultDacl;
    } TOKEN_DEFAULT_DACL, * PTOKEN_DEFAULT_DACL;

    // From winnt.h
#define TOKEN_SOURCE_LENGTH 8
    // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_source
    typedef struct _TOKEN_SOURCE {
        CHAR SourceName[TOKEN_SOURCE_LENGTH];
        LUID SourceIdentifier;
    } TOKEN_SOURCE, * PTOKEN_SOURCE;

    // ============================= functions 
    
    // https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntseapi.h#L668
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

    // https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-accesscheckbytyperesultlistandauditalarmbyhandlea
    // https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntseapi.h#L853
    NTSYSCALLAPI NTSTATUS NTAPI NtAccessCheckByTypeResultListAndAuditAlarmByHandle(
        _In_ PUNICODE_STRING SubsystemName,
        _In_opt_ PVOID HandleId,
        _In_ HANDLE TokenHandle,
        _In_ PUNICODE_STRING ObjectTypeName,
        _In_ PUNICODE_STRING ObjectName,
        _In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
        _In_opt_ PSID PrincipalSelfSid,
        _In_ TOKEN_ACCESS_MASK DesiredAccess,
        _In_ AUDIT_EVENT_TYPE AuditType,
        _In_ ULONG Flags,
        _In_reads_opt_(ObjectTypeListLength) POBJECT_TYPE_LIST ObjectTypeList,
        _In_ ULONG ObjectTypeListLength,
        _In_ PGENERIC_MAPPING GenericMapping,
        _In_ BOOLEAN ObjectCreation,
        _Out_writes_(ObjectTypeListLength) PACCESS_MASK GrantedAccessList,
        _Out_writes_(ObjectTypeListLength) PNTSTATUS AccessStatusList,
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
        _In_opt_ PCLAIM_SECURITY_ATTRIBUTE_V1 NewUserState,
        _In_opt_ PCLAIM_SECURITY_ATTRIBUTE_V1 NewDeviceState,
        _In_opt_ PTOKEN_GROUPS NewDeviceGroupsState,
        _In_ ULONG UserBufferLength,
        _Out_ PCLAIM_SECURITY_ATTRIBUTE_V1 PreviousUserState,
        _In_ ULONG DeviceBufferLength,
        _Out_ PCLAIM_SECURITY_ATTRIBUTE_V1 PreviousDeviceState,
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

    // https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntseapi.h#L323
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
        _In_opt_ PCLAIM_SECURITY_ATTRIBUTE_V1 UserAttributes,
        _In_opt_ PCLAIM_SECURITY_ATTRIBUTE_V1 DeviceAttributes,
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
        _In_opt_ PCLAIM_SECURITY_ATTRIBUTE_V1 RestrictedUserAttributes,
        _In_opt_ PCLAIM_SECURITY_ATTRIBUTE_V1 RestrictedDeviceAttributes,
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
        _In_  HANDLE                  TokenHandle,
        _In_  TOKEN_INFORMATION_CLASS TokenInformationClass,
        _Out_ PVOID                   TokenInformation,
        _In_  ULONG                   TokenInformationLength,
        _Out_ PULONG                  ReturnLength);
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
        _In_  HANDLE               Handle,
        _In_  SECURITY_INFORMATION SecurityInformation,
        _Out_ PSECURITY_DESCRIPTOR SecurityDescriptor,
        _In_  ULONG                Length,
        _Out_ PULONG               LengthNeeded);
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
        _In_ HANDLE                  TokenHandle,
        _In_ TOKEN_INFORMATION_CLASS TokenInformationClass,
        _In_ PVOID                   TokenInformation,
        _In_ ULONG                   TokenInformationLength);
    //ZwSetInformationToken

    //https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntsetsecurityobject
    NTSYSCALLAPI NTSTATUS NtSetSecurityObject(
        _In_ HANDLE               Handle,
        _In_ SECURITY_INFORMATION SecurityInformation,
        _In_ PSECURITY_DESCRIPTOR SecurityDescriptor);
    // ZwSetSecurityObject

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlabsolutetoselfrelativesd
    NTSYSAPI NTSTATUS RtlAbsoluteToSelfRelativeSD(
        _In_      PSECURITY_DESCRIPTOR AbsoluteSecurityDescriptor,
        _Out_     PSECURITY_DESCRIPTOR SelfRelativeSecurityDescriptor,
        _Inout_ PULONG               BufferLength);

    // https://github.com/mirror/reactos/blob/master/reactos/lib/rtl/priv.c
    NTSYSAPI NTSTATUS NTAPI RtlAcquirePrivilege(
        _In_ PULONG Privilege,
        _In_ ULONG NumPriv,
        _In_ ULONG Flags,
        _Out_ PVOID* ReturnedState);

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtladdaccessallowedace
    NTSYSAPI NTSTATUS RtlAddAccessAllowedAce(
        _Inout_ PACL        Acl,
        _In_      ULONG       AceRevision,
        _In_      ACCESS_MASK AccessMask,
        _In_      PSID        Sid);

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtladdaccessallowedaceex
    NTSYSAPI NTSTATUS RtlAddAccessAllowedAceEx(
        _Inout_ PACL        Acl,
        _In_      ULONG       AceRevision,
        _In_      ULONG       AceFlags,
        _In_      ACCESS_MASK AccessMask,
        _In_      PSID        Sid);

    //https://doxygen.reactos.org/dc/de0/sdk_2lib_2rtl_2acl_8c.html
    NTSYSAPI NTSTATUS NTAPI RtlAddAccessAllowedObjectAce(
        _Inout_ PACL Acl,
        _In_ ULONG Revision,
        _In_ ULONG Flags,
        _In_ ACCESS_MASK AccessMask,
        _In_opt_ PGUID ObjectTypeGuid,
        _In_opt_ PGUID InheritedObjectTypeGuid,
        _In_ PSID Sid);

    //https://doxygen.reactos.org/dc/de0/sdk_2lib_2rtl_2acl_8c.html
    NTSYSAPI NTSTATUS NTAPI RtlAddAccessDeniedAce(
        _In_ PACL Acl,
        _In_ ULONG Revision,
        _In_ ACCESS_MASK AccessMask,
        _In_ PSID Sid);

    //https://doxygen.reactos.org/dc/de0/sdk_2lib_2rtl_2acl_8c.html
    NTSYSAPI NTSTATUS NTAPI RtlAddAccessDeniedAceEx(
        _Inout_ PACL Acl,
        _In_ ULONG Revision,
        _In_ ULONG Flags,
        _In_ ACCESS_MASK AccessMask,
        _In_ PSID Sid);

    //https://doxygen.reactos.org/dc/de0/sdk_2lib_2rtl_2acl_8c.html
    NTSYSAPI NTSTATUS NTAPI RtlAddAccessDeniedObjectAce(
        _Inout_ PACL Acl,
        _In_ ULONG Revision,
        _In_ ULONG Flags,
        _In_ ACCESS_MASK AccessMask,
        _In_opt_ PGUID ObjectTypeGuid,
        _In_opt_ PGUID InheritedObjectTypeGuid,
        _In_ PSID Sid);

    //Guessed prototype. Unreliable.
    NTSYSAPI __int64 /*__usercall*/ RtlAddAccessFilterAce(
        PACL Acl,
        char,
        int,
        void* Src,
        __int16);

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtladdace
    NTSYSAPI NTSTATUS NTAPI RtlAddAce(
        _Inout_ PACL  Acl,
        _In_ ULONG AceRevision,
        _In_ ULONG StartingAceIndex,
        _In_ PVOID AceList,
        _In_ ULONG AceListLength);

    // https://doxygen.reactos.org/dc/de0/sdk_2lib_2rtl_2acl_8c.html
    NTSYSAPI NTSTATUS NTAPI RtlAddAuditAccessAce(
        _In_ PACL Acl,
        _In_ ULONG Revision,
        _In_ ACCESS_MASK AccessMask,
        _In_ PSID Sid,
        _In_ BOOLEAN Success,
        _In_ BOOLEAN Failure);

    // https://doxygen.reactos.org/dc/de0/sdk_2lib_2rtl_2acl_8c.html
    NTSYSAPI NTSTATUS NTAPI RtlAddAuditAccessAceEx(
        _In_ PACL Acl,
        _In_ ULONG Revision,
        _In_ ULONG Flags,
        _In_ ACCESS_MASK AccessMask,
        _In_ PSID Sid,
        _In_ BOOLEAN Success,
        _In_ BOOLEAN Failure);

    // https://doxygen.reactos.org/dc/de0/sdk_2lib_2rtl_2acl_8c.html
    NTSYSAPI NTSTATUS NTAPI RtlAddAuditAccessObjectAce(
        _In_ PACL Acl,
        _In_ ULONG Revision,
        _In_ ULONG Flags,
        _In_ ACCESS_MASK AccessMask,
        _In_opt_ GUID* ObjectTypeGuid,
        _In_opt_ GUID* InheritedObjectTypeGuid,
        _In_ PSID Sid,
        _In_ BOOLEAN Success,
        _In_ BOOLEAN Failure);

    // https://raw.githubusercontent.com/mic101/windows/refs/heads/master/WRK-v1.2/base/ntos/rtl/acledit.c
    NTSYSAPI NTSTATUS NTAPI RtlAddCompoundAce(
        _In_ PACL Acl,
        _In_ ULONG AceRevision,
        _In_ UCHAR CompoundAceType,
        _In_ ACCESS_MASK AccessMask,
        _In_ PSID ServerSid,
        _In_ PSID ClientSid);

    // https://processhacker.sourceforge.io/doc/ntrtl_8h.html
    NTSYSAPI NTSTATUS NTAPI RtlAddIntegrityLabelToBoundaryDescriptor(
        _Inout_ PVOID* BoundaryDescriptor,
        _In_ PSID IntegrityLabel);

    //https://processhacker.sourceforge.io/doc/ntrtl_8h.html
    NTSYSAPI NTSTATUS NTAPI RtlAddMandatoryAce(
        _Inout_ PACL 	Acl,
        _In_ ULONG 	AceRevision,
        _In_ ULONG 	AceFlags,
        _In_ PSID 	Sid,
        _In_ UCHAR 	AceType,
        _In_ ACCESS_MASK 	AccessMask);

    // https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/sec.c
    NTSYSAPI NTSTATUS NTAPI RtlAddProcessTrustLabelAce(
        PACL acl,
        DWORD revision,
        DWORD flags,
        PSID sid,
        DWORD type,
        DWORD mask);

    // https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntrtl.h#L8550
    NTSYSAPI NTSTATUS NTAPI RtlAddResourceAttributeAce(
        _Inout_ PACL Acl,
        _In_ ULONG AceRevision,
        _In_ ULONG AceFlags,
        _In_ ULONG AccessMask,
        _In_ PSID Sid,
        _In_ PCLAIM_SECURITY_ATTRIBUTES_INFORMATION AttributeInfo,
        _Out_ PULONG ReturnLength);

    // https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntrtl.h#L8883
    NTSYSAPI NTSTATUS NTAPI RtlAddSIDToBoundaryDescriptor(
        _Inout_ POBJECT_BOUNDARY_DESCRIPTOR* BoundaryDescriptor,
        _In_ PSID RequiredSid);

    // https://github.com/winsiderss/phnt/blob/master/ntrtl.h
    NTSYSAPI NTSTATUS NTAPI RtlAddScopedPolicyIDAce(
        _Inout_ PACL Acl,
        _In_ ULONG AceRevision,
        _In_ ULONG AceFlags,
        _In_ ULONG AccessMask,
        _In_ PSID Sid);

    // https://github.com/Uri3n/Thread-Pool-Injection-PoC/blob/main/include/FunctionPtrs.hpp
    NTSYSAPI NTSTATUS NTAPI RtlAdjustPrivilege(
        _In_ ULONG Privilege,
        _In_ BOOLEAN Enable,
        _In_ BOOLEAN Client,
        _Out_ PBOOLEAN WasEnabled);

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlallocateandinitializesid
    NTSYSAPI NTSTATUS RtlAllocateAndInitializeSid(
        PSID_IDENTIFIER_AUTHORITY IdentifierAuthority,
        UCHAR SubAuthorityCount,
        ULONG SubAuthority0,
        ULONG SubAuthority1,
        ULONG SubAuthority2,
        ULONG SubAuthority3,
        ULONG SubAuthority4,
        ULONG SubAuthority5,
        ULONG SubAuthority6,
        ULONG SubAuthority7,
        PSID* Sid);

    // https://github.com/winsiderss/phnt/blob/master/ntrtl.h
    _Must_inspect_result_ NTSYSAPI NTSTATUS NTAPI RtlAllocateAndInitializeSidEx(
        _In_ PSID_IDENTIFIER_AUTHORITY IdentifierAuthority,
        _In_ UCHAR SubAuthorityCount,
        _In_reads_(SubAuthorityCount) PULONG SubAuthorities,
        _Outptr_ PSID* Sid);

    // https://processhacker.sourceforge.io/doc/ntrtl_8h.html
    NTSYSAPI BOOLEAN NTAPI RtlAreAllAccessesGranted(
        _In_ ACCESS_MASK GrantedAccess,
        _In_ ACCESS_MASK DesiredAccess);

    // https://processhacker.sourceforge.io/doc/ntrtl_8h.html
    NTSYSAPI BOOLEAN NTAPI RtlAreAnyAccessesGranted(
        _In_ ACCESS_MASK GrantedAccess,
        _In_ ACCESS_MASK DesiredAccess);

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlconvertsidtounicodestring
    // See winterl.h
    NTSYSAPI NTSTATUS NTAPI RtlConvertSidToUnicodeString(
        _Inout_ PUNICODE_STRING UnicodeString,
        _In_      PSID            Sid,
        _In_      BOOLEAN         AllocateDestinationString);

    // https://processhacker.sourceforge.io/doc/ntrtl_8h.html
    NTSYSAPI NTSTATUS NTAPI RtlConvertToAutoInheritSecurityObject(
        _In_opt_ PSECURITY_DESCRIPTOR ParentDescriptor,
        _In_ PSECURITY_DESCRIPTOR CurrentSecurityDescriptor,
        _Out_ PSECURITY_DESCRIPTOR* NewSecurityDescriptor,
        _In_opt_ GUID* ObjectType,
        _In_ BOOLEAN IsDirectoryObject,
        _In_ PGENERIC_MAPPING GenericMapping);
    
    // https://processhacker.sourceforge.io/doc/ntrtl_8h.html
    NTSYSAPI NTSTATUS NTAPI RtlCopySecurityDescriptor(
        _In_ PSECURITY_DESCRIPTOR InputSecurityDescriptor,
        _Out_ PSECURITY_DESCRIPTOR* OutputSecurityDescriptor);

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlcopysid
    NTSYSAPI NTSTATUS RtlCopySid(
        _In_ ULONG DestinationSidLength,
        _In_ PSID  DestinationSid,
        _In_ PSID  SourceSid);

    // https://doxygen.reactos.org/dd/da4/sdk_2lib_2rtl_2sid_8c_source.html
    NTSTATUS NTAPI RtlCopySidAndAttributesArray(_In_ ULONG Count,
        _In_ PSID_AND_ATTRIBUTES Src,
        _In_ ULONG SidAreaSize,
        _In_ PSID_AND_ATTRIBUTES Dest,
        _In_ PSID SidArea,
        _Out_ PSID* RemainingSidArea,
        _Out_ PULONG RemainingSidAreaSize);

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlcreateacl
    NTSYSAPI NTSTATUS RtlCreateAcl(
        _Out_ PACL  Acl,
        _In_  ULONG AclLength,
        ULONG AclRevision);

    // https://github.com/mirror/reactos/blob/master/reactos/lib/rtl/security.c
    NTSTATUS NTAPI RtlCreateAndSetSD(
        _In_ PVOID AceData,
        _In_ ULONG AceCount,
        _In_opt_ PSID OwnerSid,
        _In_opt_ PSID GroupSid,
        _Out_ PSECURITY_DESCRIPTOR* NewDescriptor);

    // https://processhacker.sourceforge.io/doc/ntrtl_8h.html
    NTSYSAPI PVOID NTAPI RtlCreateBoundaryDescriptor(
        _In_ PUNICODE_STRING Name,
        _In_ ULONG Flags);

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlcreatesecuritydescriptor
    NTSYSAPI NTSTATUS RtlCreateSecurityDescriptor(
        _Out_ PSECURITY_DESCRIPTOR SecurityDescriptor,
        _In_  ULONG                Revision);

    // https://processhacker.sourceforge.io/doc/ntrtl_8h.html
    NTSYSAPI NTSTATUS NTAPI RtlCreateServiceSid(
        _In_ PUNICODE_STRING ServiceName,
        _Out_writes_bytes_opt_(*ServiceSidLength) PSID ServiceSid,
        _Inout_ PULONG ServiceSidLength);
        
    // https://processhacker.sourceforge.io/doc/ntrtl_8h.html
    NTSYSAPI NTSTATUS NTAPI RtlCreateVirtualAccountSid(
        _In_ PUNICODE_STRING Name,
        _In_ ULONG BaseSubAuthority,
        _Out_writes_bytes_(*SidLength) PSID Sid,
        _Inout_ PULONG SidLength);

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtldeleteace
    NTSYSAPI NTSTATUS RtlDeleteAce(
        _Inout_ PACL  Acl,
        _In_      ULONG AceIndex);

    // https://processhacker.sourceforge.io/doc/ntrtl_8h.html
    NTSYSAPI VOID NTAPI RtlDeleteBoundaryDescriptor(
        _In_ PVOID BoundaryDescriptor);

    // https://github.com/winsiderss/phnt/blob/master/ntrtl.h
    NTSYSAPI NTSTATUS NTAPI RtlDeleteSecurityObject(
        _Inout_ PSECURITY_DESCRIPTOR* ObjectDescriptor);

    // https://ntdoc.m417z.com/rtlderivecapabilitysidsfromname
    NTSYSAPI NTSTATUS NTAPI RtlDeriveCapabilitySidsFromName(
        _Inout_ PUNICODE_STRING UnicodeString,
        _Out_ PSID CapabilityGroupSid,
        _Out_ PSID CapabilitySid);

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlequalprefixsid
    NTSYSAPI BOOLEAN RtlEqualPrefixSid(
        _In_ PSID Sid1,
        _In_ PSID Sid2);

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlequalsid
    NTSYSAPI BOOLEAN RtlEqualSid(
        _In_ PSID Sid1,
        _In_ PSID Sid2);

    // https://github.com/winsiderss/phnt/blob/master/ntrtl.h
    NTSYSAPI PVOID NTAPI RtlFindAceByType(
        _In_ PACL Acl,
        _In_ UCHAR AceType,
        _Out_opt_ PULONG Index);

    // https://github.com/winsiderss/phnt/blob/master/ntrtl.h
    NTSYSAPI BOOLEAN NTAPI RtlFirstFreeAce(
        _In_ PACL Acl,
        _Out_ PVOID* FirstFree);

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlfreesid
    NTSYSAPI PVOID RtlFreeSid(
        PSID Sid);

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlgetace
    NTSYSAPI NTSTATUS RtlGetAce(
        _In_  PACL  Acl,
        _In_  ULONG AceIndex,
        _Out_ PVOID* Ace);

    // https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntrtl.h#L10296
    NTSYSAPI NTSTATUS NTAPI RtlGetAppContainerSidType(
        _In_ PSID AppContainerSid,
        _Out_ PAPPCONTAINER_SID_TYPE AppContainerSidType);

    // Reversed
    NTSYSAPI __int64 NTAPI RtlGetConsoleSessionForegroundProcessId(VOID);

    // https://processhacker.sourceforge.io/doc/ntrtl_8h.html
    NTSYSAPI NTSTATUS NTAPI RtlGetControlSecurityDescriptor(
        _In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
        _Out_ PSECURITY_DESCRIPTOR_CONTROL Control,
        _Out_ PULONG Revision);

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlgetdaclsecuritydescriptor
    NTSYSAPI NTSTATUS RtlGetDaclSecurityDescriptor(
        _In_  PSECURITY_DESCRIPTOR SecurityDescriptor,
        _Out_ PBOOLEAN             DaclPresent,
        _Out_ PACL* Dacl,
        _Out_ PBOOLEAN             DaclDefaulted);

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlgetgroupsecuritydescriptor
    NTSYSAPI NTSTATUS RtlGetGroupSecurityDescriptor(
        _In_  PSECURITY_DESCRIPTOR SecurityDescriptor,
        _Out_ PSID* Group,
        _Out_ PBOOLEAN             GroupDefaulted);

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlgetownersecuritydescriptor
    NTSYSAPI NTSTATUS RtlGetOwnerSecurityDescriptor(
        _In_  PSECURITY_DESCRIPTOR SecurityDescriptor,
        _Out_ PSID* Owner,
        _Out_ PBOOLEAN             OwnerDefaulted);

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlgetsaclsecuritydescriptor
    NTSYSAPI NTSTATUS RtlGetSaclSecurityDescriptor(
        _In_  PSECURITY_DESCRIPTOR SecurityDescriptor,
        _Out_ PBOOLEAN             SaclPresent,
        _Out_ PACL* Sacl,
        _Out_ PBOOLEAN             SaclDefaulted);

    // https://processhacker.sourceforge.io/doc/ntrtl_8h.html
    NTSYSAPI BOOLEAN NTAPI RtlGetSecurityDescriptorRMControl(
        _In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
        _Out_ PUCHAR RMControl);

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlidentifierauthoritysid
    NTSYSAPI PSID_IDENTIFIER_AUTHORITY RtlIdentifierAuthoritySid(
        PSID Sid);

    // https://processhacker.sourceforge.io/doc/ntrtl_8h.html
    NTSYSAPI NTSTATUS NTAPI RtlImpersonateSelf(
        _In_ SECURITY_IMPERSONATION_LEVEL ImpersonationLevel);

    // https://processhacker.sourceforge.io/doc/ntrtl_8h.html
    NTSYSAPI NTSTATUS NTAPI RtlImpersonateSelfEx(
        _In_ SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
        _In_opt_ ACCESS_MASK AdditionalAccess,
        _Out_opt_ PHANDLE ThreadToken);

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlinitializesid
    NTSYSAPI NTSTATUS RtlInitializeSid(
        _Out_ PSID                      Sid,
        _In_  PSID_IDENTIFIER_AUTHORITY IdentifierAuthority,
        _In_  UCHAR                     SubAuthorityCount);

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlinitializesidex
    NTSYSAPI NTSTATUS RtlInitializeSidEx(
        _Out_ PSID                      Sid,
        _In_  PSID_IDENTIFIER_AUTHORITY IdentifierAuthority,
        _In_  UCHAR                     SubAuthorityCount,
        ...);

    // https://ntdoc.m417z.com/rtliscapabilitysid
    NTSYSAPI BOOLEAN NTAPI RtlIsCapabilitySid(
        _In_ PSID Sid);

    // https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L3403
    NTSYSAPI BOOLEAN NTAPI RtlIsElevatedRid(
        _In_ PSID_AND_ATTRIBUTES SidAttr);

    // https://github.com/winsiderss/systeminformer/blob/daf4737ce0399fa92d17df118bcb3aba5cdc794f/phnt/include/ntrtl.h#L10189
    NTSYSAPI BOOLEAN NTAPI RtlIsPackageSid(
        _In_ PSID Sid);

    // https://processhacker.sourceforge.io/doc/ntrtl_8h.html
    NTSYSAPI NTSTATUS NTAPI RtlIsUntrustedObject(
        _In_opt_ HANDLE Handle,
        _In_opt_ PVOID Object,
        _Out_ PBOOLEAN UntrustedObject);

    // https://github.com/winsiderss/systeminformer/blob/daf4737ce0399fa92d17df118bcb3aba5cdc794f/phnt/include/ntrtl.h#L10199
    NTSYSAPI BOOLEAN NTAPI RtlIsValidProcessTrustLabelSid(
        _In_ PSID Sid);

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtllengthrequiredsid
    NTSYSAPI ULONG RtlLengthRequiredSid(
        _In_ ULONG SubAuthorityCount);

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtllengthsecuritydescriptor
    NTSYSAPI ULONG RtlLengthSecurityDescriptor(
        _In_ PSECURITY_DESCRIPTOR SecurityDescriptor);

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtllengthsid
    NTSYSAPI ULONG RtlLengthSid(
        _In_ PSID Sid);

    // https://github.com/winsiderss/systeminformer/blob/daf4737ce0399fa92d17df118bcb3aba5cdc794f/phnt/include/ntrtl.h#L7783
    NTSYSAPI NTSTATUS NTAPI RtlLengthSidAsUnicodeString(
        _In_ PSID Sid,
        _Out_ PULONG StringLength);

    // https://processhacker.sourceforge.io/doc/ntrtl_8h.html
    NTSYSAPI NTSTATUS NTAPI RtlMakeSelfRelativeSD(
        _In_ PSECURITY_DESCRIPTOR AbsoluteSecurityDescriptor,
        _Out_writes_bytes_(*BufferLength) PSECURITY_DESCRIPTOR SelfRelativeSecurityDescriptor,
        _Inout_ PULONG BufferLength);

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlmapgenericmask
    NTSYSAPI VOID RtlMapGenericMask(
        _Inout_ PACCESS_MASK AccessMask,
        _In_ const GENERIC_MAPPING* GenericMapping);

    // https://processhacker.sourceforge.io/doc/ntrtl_8h.html
    NTSYSAPI NTSTATUS NTAPI RtlNewInstanceSecurityObject(
        _In_ BOOLEAN ParentDescriptorChanged,
        _In_ BOOLEAN CreatorDescriptorChanged,
        _In_ PLUID OldClientTokenModifiedId,
        _Out_ PLUID NewClientTokenModifiedId,
        _In_opt_ PSECURITY_DESCRIPTOR ParentDescriptor,
        _In_opt_ PSECURITY_DESCRIPTOR CreatorDescriptor,
        _Out_ PSECURITY_DESCRIPTOR* NewDescriptor,
        _In_ BOOLEAN IsDirectoryObject,
        _In_ HANDLE Token,
        _In_ PGENERIC_MAPPING GenericMapping);

    // https://doxygen.reactos.org/da/d08/sdk_2lib_2rtl_2security_8c.html
    NTSYSAPI NTSTATUS NTAPI RtlNewSecurityGrantedAccess(
        _In_ ACCESS_MASK DesiredAccess,
        _Out_ PPRIVILEGE_SET Privileges,
        _In_ _Out_ PULONG Length,
        _In_ HANDLE Token,
        _In_ PGENERIC_MAPPING GenericMapping,
        _Out_ PACCESS_MASK RemainingDesiredAccess);

    // https://processhacker.sourceforge.io/doc/ntrtl_8h.html
    NTSYSAPI NTSTATUS NTAPI RtlNewSecurityObject(
        _In_opt_ PSECURITY_DESCRIPTOR ParentDescriptor,
        _In_opt_ PSECURITY_DESCRIPTOR CreatorDescriptor,
        _Out_ PSECURITY_DESCRIPTOR* NewDescriptor,
        _In_ BOOLEAN IsDirectoryObject,
        _In_opt_ HANDLE Token,
        _In_ PGENERIC_MAPPING GenericMapping);

    // https://processhacker.sourceforge.io/doc/ntrtl_8h.html
    NTSYSAPI NTSTATUS NTAPI RtlNewSecurityObjectEx(
        _In_opt_ PSECURITY_DESCRIPTOR ParentDescriptor,
        _In_opt_ PSECURITY_DESCRIPTOR CreatorDescriptor,
        _Out_ PSECURITY_DESCRIPTOR* NewDescriptor,
        _In_opt_ GUID* ObjectType,
        _In_ BOOLEAN IsDirectoryObject,
        _In_ ULONG AutoInheritFlags,
        _In_opt_ HANDLE Token,
        _In_ PGENERIC_MAPPING GenericMapping);

    // https://processhacker.sourceforge.io/doc/ntrtl_8h.html
    NTSYSAPI NTSTATUS NTAPI RtlNewSecurityObjectWithMultipleInheritance(
        _In_opt_ PSECURITY_DESCRIPTOR ParentDescriptor,
        _In_opt_ PSECURITY_DESCRIPTOR CreatorDescriptor,
        _Out_ PSECURITY_DESCRIPTOR* NewDescriptor,
        _In_opt_ GUID** ObjectType,
        _In_ ULONG GuidCount,
        _In_ BOOLEAN IsDirectoryObject,
        _In_ ULONG AutoInheritFlags,
        _In_opt_ HANDLE Token,
        _In_ PGENERIC_MAPPING GenericMapping);

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlnormalizesecuritydescriptor
    NTSYSAPI BOOLEAN RtlNormalizeSecurityDescriptor(
        PSECURITY_DESCRIPTOR* SecurityDescriptor,
        ULONG                SecurityDescriptorLength,
        PSECURITY_DESCRIPTOR* NewSecurityDescriptor,
        PULONG               NewSecurityDescriptorLength,
        BOOLEAN              CheckOnly);

    // https://github.com/winsiderss/phnt/blob/master/ntrtl.h
    NTSYSAPI BOOLEAN NTAPI RtlOwnerAcesPresent(
        _In_ PACL pAcl);

    // https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntrtl.h#L7970C1-L7980C15
    /* The RtlValidRelativeSecurityDescriptor routine checks the validity of a self-relative
    * security descriptor.
    * \param SecurityDescriptorInput A pointer to the buffer that contains the security
    * descriptor in self-relative format.
    * The buffer must begin with a SECURITY_DESCRIPTOR structure, which is followed by the rest
    * of the security descriptor data.
    * \param SecurityDescriptorLength The size of the SecurityDescriptorInput structure.
    * \param RequiredInformation A SECURITY_INFORMATION value that specifies the information
    * that is required to be contained in the security descriptor.
    * @return RtlValidRelativeSecurityDescriptor returns TRUE if the security descriptor is
    * valid and includes the information that the RequiredInformation parameter specifies.
    * Otherwise, this routine returns FALSE.
    * @see https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlvalidrelativesecuritydescriptor*/
    _Check_return_ NTSYSAPI NTSTATUS NTAPI RtlQueryInformationAcl(
        _In_ PACL Acl,
        _Out_writes_bytes_(AclInformationLength) PVOID AclInformation,
        _In_ ULONG AclInformationLength,
        _In_ SECURITY_INFORMATION AclInformationClass);

    // https://processhacker.sourceforge.io/doc/ntrtl_8h.html
    NTSYSAPI NTSTATUS NTAPI RtlQuerySecurityObject(
        _In_ PSECURITY_DESCRIPTOR ObjectDescriptor,
        _In_ SECURITY_INFORMATION SecurityInformation,
        _Out_opt_ PSECURITY_DESCRIPTOR ResultantDescriptor,
        _In_ ULONG DescriptorLength,
        _Out_ PULONG ReturnLength);

    // https://processhacker.sourceforge.io/doc/ntrtl_8h.html
    NTSYSAPI ULONG NTAPI RtlQueryValidationRunlevel(
        _In_opt_ PCUNICODE_STRING ComponentName);

    // https://processhacker.sourceforge.io/doc/ntrtl_8h.html
    NTSYSAPI VOID NTAPI RtlReleasePrivilege(
        _In_ PVOID StatePointer);

    // https://processhacker.sourceforge.io/doc/ntrtl_8h.html
    NTSYSAPI NTSTATUS NTAPI RtlRemovePrivileges(
        _In_ HANDLE hToken,
        _In_ PULONG PrivilegesToKeep,
        _In_ ULONG PrivilegeCount);

    // https://processhacker.sourceforge.io/doc/ntrtl_8h.html
    NTSYSAPI NTSTATUS NTAPI RtlSidDominates(
        _In_ PSID Sid1,
        _In_ PSID Sid2,
        _Out_ PBOOLEAN pbDominate);

    // https://processhacker.sourceforge.io/doc/ntrtl_8h.html
    NTSYSAPI NTSTATUS NTAPI RtlReplaceSidInSd(
        _Inout_ PSECURITY_DESCRIPTOR SecurityDescriptor,
        _In_ PSID OldSid,
        _In_ PSID NewSid,
        _Out_ ULONG* NumChanges);

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlselfrelativetoabsolutesd
    NTSYSAPI NTSTATUS RtlSelfRelativeToAbsoluteSD(
        _In_ PSECURITY_DESCRIPTOR SelfRelativeSecurityDescriptor,
        _Out_ PSECURITY_DESCRIPTOR AbsoluteSecurityDescriptor,
        _Inout_ PULONG               AbsoluteSecurityDescriptorSize,
        _Out_ PACL                 Dacl,
        _Inout_ PULONG               DaclSize,
        _Out_ PACL                 Sacl,
        _Inout_ PULONG               SaclSize,
        _Out_ PSID                 Owner,
        _Inout_ PULONG               OwnerSize,
        _Out_ PSID                 PrimaryGroup,
        _Inout_ PULONG               PrimaryGroupSize);

    // https://processhacker.sourceforge.io/doc/ntrtl_8h.html
    NTSYSAPI NTSTATUS NTAPI RtlSelfRelativeToAbsoluteSD2(
        _Inout_ PSECURITY_DESCRIPTOR pSelfRelativeSecurityDescriptor,
        _Inout_ PULONG pBufferSize);

    // https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntrtl.h#L8008
    NTSYSAPI NTSTATUS NTAPI RtlSetAttributesSecurityDescriptor(
        _Inout_ PSECURITY_DESCRIPTOR SecurityDescriptor,
        _In_ SECURITY_DESCRIPTOR_CONTROL Control,
        _Out_ PULONG Revision);

    // https://processhacker.sourceforge.io/doc/ntrtl_8h.html
    NTSYSAPI NTSTATUS NTAPI RtlSetControlSecurityDescriptor(
        _Inout_ PSECURITY_DESCRIPTOR SecurityDescriptor,
        _In_ SECURITY_DESCRIPTOR_CONTROL ControlBitsOfInterest,
        _In_ SECURITY_DESCRIPTOR_CONTROL ControlBitsToSet);

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlsetdaclsecuritydescriptor
    NTSYSAPI NTSTATUS RtlSetDaclSecurityDescriptor(
        _Inout_      PSECURITY_DESCRIPTOR SecurityDescriptor,
        _In_           BOOLEAN              DaclPresent,
        _In_opt_ PACL                 Dacl,
        _In_opt_ BOOLEAN              DaclDefaulted);

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlsetgroupsecuritydescriptor
    NTSYSAPI NTSTATUS RtlSetGroupSecurityDescriptor(
        _Inout_      PSECURITY_DESCRIPTOR SecurityDescriptor,
        _In_opt_ PSID                 Group,
        _In_opt_ BOOLEAN              GroupDefaulted);

    //RtlSetInformationAcl
    NTSYSAPI NTSTATUS NTAPI RtlSetInformationAcl(
        _Inout_ PACL Acl,
        _In_reads_bytes_(AclInformationLength) PVOID AclInformation,
        _In_ ULONG AclInformationLength,
        _In_ ACL_INFORMATION_CLASS AclInformationClass);

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlsetownersecuritydescriptor
    NTSYSAPI NTSTATUS RtlSetOwnerSecurityDescriptor(
        _Inout_ PSECURITY_DESCRIPTOR SecurityDescriptor,
        _In_opt_ PSID Owner,
        _In_opt_ BOOLEAN OwnerDefaulted);

    // https://github.com/winsiderss/systeminformer/blob/daf4737ce0399fa92d17df118bcb3aba5cdc794f/phnt/include/ntrtl.h#L10787
    NTSYSAPI ULONG NTAPI RtlSetProxiedProcessId(
        _In_ ULONG ProxiedProcessId);

    // https://processhacker.sourceforge.io/doc/ntrtl_8h.html
    NTSYSAPI NTSTATUS NTAPI RtlSetSaclSecurityDescriptor(
        _Inout_ PSECURITY_DESCRIPTOR SecurityDescriptor,
        _In_ BOOLEAN SaclPresent,
        _In_opt_ PACL Sacl,
        _In_opt_ BOOLEAN SaclDefaulted);

    // https://processhacker.sourceforge.io/doc/ntrtl_8h.html
    NTSYSAPI VOID NTAPI RtlSetSecurityDescriptorRMControl(
        _Inout_ PSECURITY_DESCRIPTOR SecurityDescriptor,
        _In_opt_ PUCHAR RMControl);

    // https://processhacker.sourceforge.io/doc/ntrtl_8h.html
    NTSYSAPI NTSTATUS NTAPI RtlSetSecurityObject(
        _In_ SECURITY_INFORMATION SecurityInformation,
        _In_ PSECURITY_DESCRIPTOR ModificationDescriptor,
        _Inout_ PSECURITY_DESCRIPTOR* ObjectsSecurityDescriptor,
        _In_ PGENERIC_MAPPING GenericMapping,
        _In_opt_ HANDLE Token);
    
    // https://processhacker.sourceforge.io/doc/ntrtl_8h.html
    NTSYSAPI NTSTATUS NTAPI RtlSetSecurityObjectEx(
        _In_ SECURITY_INFORMATION SecurityInformation,
        _In_ PSECURITY_DESCRIPTOR ModificationDescriptor,
        _Inout_ PSECURITY_DESCRIPTOR* ObjectsSecurityDescriptor,
        _In_ ULONG AutoInheritFlags,
        _In_ PGENERIC_MAPPING GenericMapping,
        _In_opt_ HANDLE Token);
    
    // https://github.com/winsiderss/systeminformer/blob/daf4737ce0399fa92d17df118bcb3aba5cdc794f/phnt/include/ntrtl.h#L7724
    NTSYSAPI NTSTATUS NTAPI RtlSidDominatesForTrust(
        _In_ PSID Sid1,
        _In_ PSID Sid2,
        _Out_ PBOOLEAN DominatesTrust); // TokenProcessTrustLevel

    // https://processhacker.sourceforge.io/doc/ntrtl_8h.html
    NTSYSAPI NTSTATUS NTAPI RtlSidEqualLevel(
        _In_ PSID Sid1,
        _In_ PSID Sid2,
        _Out_ PBOOLEAN pbEqual);

    //https://processhacker.sourceforge.io/doc/ntrtl_8h.html
    NTSYSAPI NTSTATUS NTAPI RtlSidHashInitialize(
        _In_reads_(SidCount) PSID_AND_ATTRIBUTES SidAttr,
        _In_ ULONG SidCount,
        _Out_ PSID_AND_ATTRIBUTES_HASH SidAttrHash);

    // https://processhacker.sourceforge.io/doc/ntrtl_8h.html
    NTSYSAPI PSID_AND_ATTRIBUTES NTAPI RtlSidHashLookup(
        _In_ PSID_AND_ATTRIBUTES_HASH SidAttrHash,
        _In_ PSID Sid);

    // https://processhacker.sourceforge.io/doc/ntrtl_8h.html
    NTSYSAPI NTSTATUS NTAPI RtlSidIsHigherLevel(
        _In_ PSID Sid1,
        _In_ PSID Sid2,
        _Out_ PBOOLEAN pbHigher);

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlsubauthoritycountsid
    NTSYSAPI PUCHAR RtlSubAuthorityCountSid(
        PSID Sid);

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlsubauthoritysid
    NTSYSAPI PULONG RtlSubAuthoritySid(
        _In_ PSID  Sid,
        ULONG SubAuthority);

    // https://processhacker.sourceforge.io/doc/ntrtl_8h.html
    NTSYSAPI BOOLEAN NTAPI RtlValidAcl(
        _In_ PACL Acl);

    // https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntrtl.h#L3345
    NTSYSAPI BOOLEAN NTAPI RtlValidProcessProtection(
        _In_ PS_PROTECTION ProcessProtection);

    // https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntrtl.h#L7970C1-L7979C4
    /* The RtlValidRelativeSecurityDescriptor routine checks the validity of a self-relative
    * security descriptor.
    * \param SecurityDescriptorInput A pointer to the buffer that contains the security
    * descriptor in self-relative format.
    * The buffer must begin with a SECURITY_DESCRIPTOR structure, which is followed by
    * the rest of the security descriptor data.
    * \param SecurityDescriptorLength The size of the SecurityDescriptorInput structure.
    * \param RequiredInformation A SECURITY_INFORMATION value that specifies the information
    * that is required to be contained in the security descriptor.
    * @return RtlValidRelativeSecurityDescriptor returns TRUE if the security descriptor
    * is valid and includes the information that the RequiredInformation parameter specifies. Otherwise, this routine returns FALSE.
    * @see https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlvalidrelativesecuritydescriptor*/
    _Check_return_ NTSYSAPI BOOLEAN NTAPI RtlValidRelativeSecurityDescriptor(
        _In_reads_bytes_(SecurityDescriptorLength) PSECURITY_DESCRIPTOR SecurityDescriptorInput,
        _In_ ULONG SecurityDescriptorLength,
        _In_ SECURITY_INFORMATION RequiredInformation);

    // https://processhacker.sourceforge.io/doc/ntrtl_8h.html
    _Check_return_ NTSYSAPI BOOLEAN NTAPI RtlValidSecurityDescriptor(
        _In_ PSECURITY_DESCRIPTOR SecurityDescriptor);

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlvalidsid
    NTSYSAPI BOOLEAN RtlValidSid(
        _In_ PSID Sid);

}

#endif // _NTSECURITY_
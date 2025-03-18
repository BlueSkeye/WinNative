#pragma once

#ifndef _NTOBJECTS_
#define _NTOBJECTS_

#include "NtCommonDefs.h"

extern "C" {

    // NO UNRESOLVED FUNCTIONS

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtAllocateReserveObject(
        _Out_ PHANDLE MemoryReserveHandle,
        _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
        _In_ ULONG Type);
    //ZwAllocateReserveObject

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtCompareObjects(
        _In_ HANDLE Object1,
        _In_ HANDLE Object2);
    //ZwCompareObjects

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtCreateDebugObject(
        _Out_ PHANDLE DebugHandle,
        _In_ ACCESS_MASK DesiredAccess,
        _In_ POBJECT_ATTRIBUTES ObjectAttributes,
        // Flags = BOOLEAN KillProcessOnExit according to
        // http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FFile%2FNtWriteFileGather.html
        _In_ ULONG Flags);
    //ZwCreateDebugObject

    // http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FFile%2FNtWriteFileGather.html
    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwcreatedirectoryobject
    NTSYSAPI NTSTATUS NTAPI NtCreateDirectoryObject(
        _Out_ PHANDLE DirectoryHandle,
        _In_ DIRECTORY_ACCESS_MASK DesiredAccess,
        _In_ POBJECT_ATTRIBUTES ObjectAttributes);
    //ZwCreateDirectoryObject

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtCreateDirectoryObjectEx(
        _Out_ PHANDLE DirectoryHandle,
        _In_ DIRECTORY_ACCESS_MASK DesiredAccess,
        _In_ POBJECT_ATTRIBUTES ObjectAttributes,
        _In_ HANDLE ShadowDirectoryHandle,
        _In_ ULONG Flags);
    //ZwCreateDirectoryObjectEx

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtCreatePrivateNamespace(
        _Out_ PHANDLE NamespaceHandle,
        _In_opt_ PSECURITY_ATTRIBUTES Attributes,
        _In_ PVOID BoundaryDescriptor,
        _In_ PUNICODE_STRING AliasPrefix);
    //ZwCreatePrivateNamespace

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtCreateSymbolicLinkObject(
        _Out_ PHANDLE LinkHandle,
        _In_ ACCESS_MASK DesiredAccess,
        _In_ POBJECT_ATTRIBUTES ObjectAttributes,
        _In_ PUNICODE_STRING SymbolicLink);
    //ZwCreateSymbolicLinkObject

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtDeletePrivateNamespace(
        _In_ HANDLE NamespaceHandle);
    //ZwDeletePrivateNamespace

    //https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwduplicateobject
    NTSYSAPI NTSTATUS NtDuplicateObject(
        _In_            HANDLE      SourceProcessHandle,
        _In_            HANDLE      SourceHandle,
        _In_opt_  HANDLE      TargetProcessHandle,
        [out, optional] PHANDLE     TargetHandle,
        _In_            ACCESS_MASK DesiredAccess,
        _In_            ULONG       HandleAttributes,
        _In_            ULONG       Options);
    //ZwDuplicateObject

    //https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwduplicateobject
    NTSYSAPI NTSTATUS NTAPI NtMakePermanentObject(
        _In_ HANDLE Object);
    //ZwMakePermanentObject

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwmaketemporaryobject
    NTSYSAPI NTSTATUS NtMakeTemporaryObject(
        _In_ HANDLE Handle);
    //ZwMakeTemporaryObject

    // https://learn.microsoft.com/en-us/windows/win32/devnotes/ntopendirectoryobject
    NTSYSCALLAPI NTSTATUS WINAPI NtOpenDirectoryObject(
        _Out_ PHANDLE            DirectoryHandle,
        _In_  ACCESS_MASK        DesiredAccess,
        _In_  POBJECT_ATTRIBUTES ObjectAttributes
    );
    //ZwOpenDirectoryObject

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtOpenObjectAuditAlarm(
        _In_ PUNICODE_STRING SubsystemName,
        _In_ PHANDLE HandleId,
        _In_ PUNICODE_STRING ObjectTypeName,
        _In_ PUNICODE_STRING ObjectName,
        _In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
        _In_ HANDLE ClientToken,
        _In_ ACCESS_MASK DesiredAccess,
        _In_ ACCESS_MASK GrantedAccess,
        _In_ PPRIVILEGE_SET PrivilegeSet,
        _In_ BOOLEAN ObjectCreation,
        _In_ BOOLEAN AccessGranted,
        _Out_ PBOOLEAN OnClose);
    //ZwOpenObjectAuditAlarm

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtOpenPrivateNamespace(
        _Out_ PHANDLE NamespaceHandle,
        _In_ ACCESS_MASK DesiredAccess,
        _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
        _In_ PVOID Buffer);
    //ZwOpenPrivateNamespace

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwopensymboliclinkobject
    NTSYSAPI NTSTATUS NtOpenSymbolicLinkObject(
        _Out_ PHANDLE            LinkHandle,
        _In_  ACCESS_MASK        DesiredAccess,
        _In_  POBJECT_ATTRIBUTES ObjectAttributes);
    //ZwOpenSymbolicLinkObject

    // https://learn.microsoft.com/en-us/windows/win32/devnotes/ntquerydirectoryobject
    NTSTATUS WINAPI NtQueryDirectoryObject(
        _In_      HANDLE  DirectoryHandle,
        _Out_opt_ PVOID   Buffer,
        _In_      ULONG   Length,
        _In_      BOOLEAN ReturnSingleEntry,
        _In_      BOOLEAN RestartScan,
        _Inout_   PULONG  Context,
        _Out_opt_ PULONG  ReturnLength);
    //ZwQueryDirectoryObject

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntqueryobject
    // See winternl.h
    // https://processhacker.sourceforge.io/doc/ntzwapi_8h_source.html
    NTSYSCALLAPI NTSTATUS NTAPI ZwQueryObject(
        _In_ HANDLE Handle,
        _In_ OBJECT_INFORMATION_CLASS ObjectInformationClass,
        _Out_writes_bytes_opt_(ObjectInformationLength) PVOID ObjectInformation,
        _In_ ULONG ObjectInformationLength,
        _Out_opt_ PULONG ReturnLength);
    // ZwQueryObject

    // https://learn.microsoft.com/en-us/windows/win32/devnotes/ntquerysymboliclinkobject
    NTSTATUS WINAPI NtQuerySymbolicLinkObject(
        _In_      HANDLE          LinkHandle,
        _Inout_   PUNICODE_STRING LinkTarget,
        _Out_opt_ PULONG          ReturnedLength);
    //ZwQuerySymbolicLinkObject

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    // http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FFile%2FNtWriteFileGather.html
    NTSYSCALLAPI NTSTATUS NTAPI NtSetInformationObject(
        _In_ HANDLE Handle,
        _In_ OBJECT_INFORMATION_CLASS Class,
        _In_ PVOID Buffer,
        _In_ ULONG BufferLength);
    //ZwSetInformationObject

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtSetInformationSymbolicLink(
        _In_ HANDLE Handle,
        _In_ ULONG Class,
        _In_ PVOID Buffer,
        _In_ ULONG BufferLength);
    //ZwSetInformationSymbolicLink

}

#endif // _NTOBJECTS_
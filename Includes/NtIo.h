#pragma once

#ifndef _NTIO_
#define _NTIO_

#include "NtCommonDefs.h"

extern "C" {

    // NO UNRESOLVED FUNCTIONS

    typedef ACCESS_MASK JOB_ACCESS_MASK;

    // https://doxygen.reactos.org/d3/d61/include_2ndk_2pstypes_8h.html#aaf395c83558f6c49fd454c4b70d4e7ce
    // Also _JOBOBJECTINFOCLASS
    typedef enum _JOB_INFORMATION_CLASS {
        JobObjectBasicAccountingInformation = 1,
        JobObjectBasicLimitInformation,
        JobObjectBasicProcessIdList,
        JobObjectBasicUIRestrictions,
        JobObjectSecurityLimitInformation,
        JobObjectEndOfJobTimeInformation,
        JobObjectAssociateCompletionPortInformation,
        JobObjectBasicAndIoAccountingInformation,
        JobObjectExtendedLimitInformation,
        JobObjectJobSetInformation,
        MaxJobObjectInfoClass
    } JOB_INFORMATION_CLASS;

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtAssignProcessToJobObject(
        _In_ HANDLE JobHandle,
        _In_ HANDLE ProcessHandle);
    //ZwAssignProcessToJobObject

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtCreateJobObject(
        _Out_ PHANDLE JobHandle,
        _In_ JOB_ACCESS_MASK DesiredAccess,
        _In_ POBJECT_ATTRIBUTES ObjectAttributes);
    //ZwCreateJobObject

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtCreateJobSet(
        _In_ ULONG JobNumber,
        _In_ PVOID UserJobSet,
        _In_ ULONG Flags);
    //ZwCreateJobSet

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtIsProcessInJob(
        _In_ HANDLE hProcess,
        _In_opt_ HANDLE hJob);
    //ZwIsProcessInJob
    
    // https://doxygen.reactos.org/d0/dbc/ntoskrnl_2ps_2job_8c.html
    NTSYSCALLAPI NTSTATUS NTAPI NtOpenJobObject(
        _Out_ PHANDLE JobHandle,
        _In_ ACCESS_MASK DesiredAccess,
        _In_ POBJECT_ATTRIBUTES ObjectAttributes);
    //ZwOpenJobObject

    // https://doxygen.reactos.org/d0/dbc/ntoskrnl_2ps_2job_8c.html
    NTSYSCALLAPI NTSTATUS NTAPI NtQueryInformationJobObject(
        _In_ HANDLE JobHandle,
        _In_ JOB_INFORMATION_CLASS JobInformationClass,
        _Out_ PVOID JobInformation,
        _In_ ULONG Length,
        _Out_opt_ PULONG ReturnLength);
    //ZwQueryInformationJobObject

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtSetInformationJobObject(
        _In_ HANDLE Handle,
        _In_ JOB_INFORMATION_CLASS Class,
        _In_ PVOID Buffer,
        _In_ ULONG BufferLength);
    //ZwSetInformationJobObject

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtTerminateJobObject(
        _In_ HANDLE JobHandle,
        _In_ NTSTATUS ExitStatus);
    //ZwTerminateJobObject

}

#endif // _NTIO_
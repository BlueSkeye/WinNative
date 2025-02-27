#pragma once

#ifndef _NTDEBUGGING_
#define _NTDEBUGGING_

#include "NtCommonDefs.h"

extern "C" {

    //https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtCreateProfile(
        _Out_ PHANDLE ProfileHandle,
        _In_ HANDLE Process,
        _In_ PVOID ProfileBase,
        _In_ ULONG ProfileSize,
        _In_ ULONG BucketSize,
        _In_ PULONG Buffer,
        _In_ ULONG BufferSize,
        _In_ KPROFILE_SOURCE ProfileSource,
        _In_ KAFFINITY Affinity);
    //ZwCreateProfile
	
    //https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtCreateProfileEx(
        _Out_ PHANDLE ProfileHandle,
        _In_opt_ HANDLE Process,
        _In_ PVOID ProfileBase,
        _In_ ULONG ProfileSize,
        _In_ ULONG BucketSize,
        _In_ PULONG Buffer,
        _In_ ULONG BufferSize,
        _In_ ULONG ProfileSource,
        _In_ ULONG GroupAffinityCount,
        _In_opt_ PGROUP_AFFINITY GroupAffinity);
    //ZwCreateProfileEx

    // http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FFile%2FNtWriteFileGather.html
    NTSYSCALLAPI NTSYSAPI NTSTATUS NTAPI NtDebugActiveProcess(
        IN HANDLE               ProcessHandle,
        IN HANDLE               DebugObjectHandle);
    //ZwDebugActiveProcess

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtDebugContinue(
        _In_ HANDLE DebugHandle,
        _In_ PCLIENT_ID ClientId,
        _In_ NTSTATUS Status);
    //ZwDebugContinue

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtQueryDebugFilterState(
        _In_ ULONG Component,
        _In_ ULONG Level);
    //ZwQueryDebugFilterState

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtQueryIntervalProfile(
        _In_ KPROFILE_SOURCE Source,
        _Out_ PULONG Interval);
    //ZwQueryIntervalProfile

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtQueryPerformanceCounter(
        _Out_ PLARGE_INTEGER Counter,
        _Out_opt_ PLARGE_INTEGER Freq);
    //ZwQueryPerformanceCounter

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtRegisterThreadTerminatePort(
        _In_ HANDLE PortHandle);
    //ZwRegisterThreadTerminatePort

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    // http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FFile%2FNtWriteFileGather.html
    NTSYSCALLAPI NTSTATUS NTAPI NtRemoveProcessDebug(
        _In_ HANDLE ProcessHandle,
        _In_ HANDLE DebugHandle);
    //ZwRemoveProcessDebug

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtSetDebugFilterState(
        _In_ ULONG Component,
        _In_ ULONG Level,
        _In_ BOOLEAN State);
    //ZwSetDebugFilterState

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtSetInformationDebugObject(
        _In_ HANDLE DebugHandle,
        _In_ DEBUGOBJECTINFOCLASS Class,
        _In_ PVOID Buffer,
        _In_ ULONG Length,
        _Out_opt_ PULONG ReturnLength);
    //ZwSetInformationDebugObject

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtSetIntervalProfile(
        _In_ ULONG Interval,
        _In_ KPROFILE_SOURCE Source);
    //ZwSetIntervalProfile

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtStartProfile(
        _In_ HANDLE ProfileHandle);
    //ZwStartProfile

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtStopProfile(
        _In_ HANDLE ProfileHandle);
    //ZwStopProfile

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtSystemDebugControl(
        _In_ SYSDBG_COMMAND Command,
        _In_ PVOID InputBuffer,
        _In_ ULONG InputBufferLength,
        _Out_ PVOID OutputBuffer,
        _In_ ULONG OutputBufferLength,
        _Out_ PULONG ReturnLength);
    //ZwSystemDebugControl

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtTraceControl(
        _In_ ULONG CtrlCode,
        _In_ PVOID InputBuffer,
        _In_ ULONG InputBufferLength,
        _Out_ PVOID OutputBuffer,
        _In_ ULONG OutputBufferLength,
        _Out_ PULONG ReturnLength);
    //ZwTraceControl

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtWaitForDebugEvent(
        _In_ HANDLE DebugHandle,
        _In_ BOOLEAN Alertable,
        _In_opt_ PLARGE_INTEGER Timeout,
        _Out_ PULONG Result);
    //ZwWaitForDebugEvent
}

#endif // _NTDEBUGGING_
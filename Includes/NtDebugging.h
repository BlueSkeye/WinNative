#pragma once

#ifndef _NTDEBUGGING_
#define _NTDEBUGGING_

#include "NtCommonDefs.h"

extern "C" {

    // UNRESOLVED FUNCTIONS
    //RtlGetInterruptTimePrecise
    //RtlGetMultiTimePrecise
    //RtlGetSystemTimeAndBias
    //RtlGetSystemTimePrecise
    // RtlLocalTimeToSystemTime
    //RtlQueryDynamicTimeZoneInformation
    //RtlQueryTimeZoneInformation
    //RtlQueryUnbiasedInterruptTime
    //RtlSetDynamicTimeZoneInformation
    //RtlSetTimeZoneInformation
    //RtlSystemTimeToLocalTime
    //RtlTimeToElapsedTimeFields
    //RtlpCheckDynamicTimeZoneInformation
    //RtlpFreezeTimeBias
    //RtlpTimeFieldsToTime
    //RtlpTimeToTimeFields
    // END OF UNRESOLVED FUNCTIONS

    // https://learn.microsoft.com/fr-fr/windows-hardware/drivers/ddi/wdm/nf-wdm-dbgbreakpoint
    NTSYSAPI VOID DbgBreakPoint();

    // https://learn.microsoft.com/fr-fr/windows-hardware/drivers/ddi/wdm/nf-wdm-dbgprint
    NTSYSAPI ULONG DbgPrint(
        PCSTR Format,
        ...);

    //https://learn.microsoft.com/fr-fr/windows-hardware/drivers/ddi/wdm/nf-wdm-dbgprintex
    NTSYSAPI ULONG DbgPrintEx(
        [in] ULONG ComponentId,
        [in] ULONG Level,
        [in] PCSTR Format,
        ...);

    //https://doxygen.reactos.org/d6/dc3/xdk_2kdfuncs_8h.html
    NTSYSAPI ULONG __cdecl DbgPrintReturnControlC(
        _In_z_ _Printf_format_string_ PCCH Format,
        ...);

    //https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-dbgprompt
    NTSYSAPI ULONG DbgPrompt(
        [in]  PCCH  Prompt,
        [out] PCH   Response,
        ULONG Length);

    //https://doxygen.reactos.org/d6/dc3/xdk_2kdfuncs_8h.html
    NTSYSAPI ULONG __cdecl DbgPrintReturnControlC(
        _In_z_ _Printf_format_string_ PCCH Format,
        ...);

    //https://doxygen.reactos.org/d6/dc3/xdk_2kdfuncs_8h.html
    NTSYSAPI NTSTATUS NTAPI DbgSetDebugFilterState(
        _In_ ULONG ComponentId,
        _In_ ULONG Level,
        _In_ BOOLEAN State);

    // https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/process.c
    NTSYSCALLAPI NTSTATUS NTAPI DbgUiConnectToDbg(void);

    // https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/process.c
    NTSYSCALLAPI NTSTATUS NTAPI DbgUiContinue(
        CLIENT_ID* client,
        NTSTATUS status);

    // https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/process.c
    NTSYSCALLAPI NTSTATUS NTAPI DbgUiConvertStateChangeStructure(
        DBGUI_WAIT_STATE_CHANGE* state,
        DEBUG_EVENT* event);

    //DbgUiConvertStateChangeStructureEx
    //https://unprotect.it/media/archive/2022/06/22/NtSetDebugFilterState.pdf
    NTSYSCALLAPI NTSTATUS NTAPI DbgSetDebugFilterState(
        ULONG ComponentId,
        ULONG Level,
        BOOLEAN State);

    // https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/process.c
    NTSYSCALLAPI NTSTATUS WINAPI DbgUiDebugActiveProcess(
        HANDLE process);

    // https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/process.c
    NTSYSCALLAPI HANDLE WINAPI DbgUiGetThreadDebugObject(void);

    // https://processhacker.sourceforge.io/doc/ntdbg_8h.html#a6206168ba05b85ebb0cec355eca0e6d3
    NTSYSAPI NTSTATUS NTAPI DbgUiIssueRemoteBreakin(
        _In_ HANDLE Process);

    // https://processhacker.sourceforge.io/doc/ntdbg_8h.html#a6206168ba05b85ebb0cec355eca0e6d3
    NTSYSAPI VOID NTAPI DbgUiRemoteBreakin(
        _In_ PVOID Context);

    // https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/process.c
    NTSYSCALLAPI void WINAPI DbgUiSetThreadDebugObject(
        HANDLE handle);

    // https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/process.c
    NTSYSCALLAPI NTSTATUS WINAPI DbgUiStopDebugging(
        HANDLE process);

    // https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/process.c
    NTSYSCALLAPI NTSTATUS WINAPI DbgUiWaitStateChange(
        DBGUI_WAIT_STATE_CHANGE* state,
        LARGE_INTEGER* timeout);

    //https://processhacker.sourceforge.io/doc/ntrtl_8h.html
    NTSYSAPI VOID NTAPI DbgUserBreakPoint(VOID);

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
    NTSYSCALLAPI NTSTATUS NTAPI NtWaitForDebugEvent(
        _In_ HANDLE DebugHandle,
        _In_ BOOLEAN Alertable,
        _In_opt_ PLARGE_INTEGER Timeout,
        _Out_ PULONG Result);
    //ZwWaitForDebugEvent

    // Reversed. Empty function always returning 0. Arguments unknown may not be VOID.
    NTSYSAPI NTSTATUS NTAPI RtlDebugPrintTimes(VOID);

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlsecondssince1970totime
    NTSYSAPI VOID RtlSecondsSince1970ToTime(
        [in]  ULONG          ElapsedSeconds,
        [out] PLARGE_INTEGER Time);

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlsecondssince1980totime
    NTSYSAPI VOID RtlSecondsSince1980ToTime(
        [in]  ULONG          ElapsedSeconds,
        [out] PLARGE_INTEGER Time);

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtltimefieldstotime
    NTSYSAPI BOOLEAN RtlTimeFieldsToTime(
        [in]  PTIME_FIELDS   TimeFields,
        [out] PLARGE_INTEGER Time);

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtltimetosecondssince1970
    // See winternl.h
    // RtlTimeToSecondsSince1970

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtltimetosecondssince1980
    NTSYSAPI BOOLEAN RtlTimeToSecondsSince1980(
        [in]  PLARGE_INTEGER Time,
        [out] PULONG         ElapsedSeconds);

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtltimetotimefields
    NTSYSAPI VOID RtlTimeToTimeFields(
        [in]  PLARGE_INTEGER Time,
        [out] PTIME_FIELDS   TimeFields);

}

#endif // _NTDEBUGGING_
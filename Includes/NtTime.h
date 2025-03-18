#pragma once

#ifndef _NTTIME_
#define _NTTIME_

#include "NtCommonDefs.h"

extern "C" {

    // UNRESOLVED FUNCTIONS
    //RtlCreateTimer
    //RtlCreateTimerQueue
    //RtlCutoverTimeToSystemTime
    //RtlDeleteTimer
    //RtlDeleteTimerQueueEx
    //RtlUpdateTimer
    // END OF UNRESOLVED FUNCTIONS

    // http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FTimer%2FNtQueryTimer.html
    typedef enum _TIMER_INFORMATION_CLASS {
        TimerBasicInformation
    } TIMER_INFORMATION_CLASS, * PTIMER_INFORMATION_CLASS;

    typedef enum _TIMER_TYPE {
        NotificationTimer,
        SynchronizationTimer
    } TIMER_TYPE;

    // ====================== functions ====================
    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtCancelTimer(
        _In_ HANDLE TimerHandle,
        _Out_opt_ PBOOLEAN CurrentState);
    //ZwCancelTimer

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtCancelTimer2(
        _In_ HANDLE TimerHandle,
        _Out_opt_ PBOOLEAN State);
    //ZwCancelTimer2

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtConvertBetweenAuxiliaryCounterAndPerformanceCounter(
        BOOL InputIsAuxiliary,
        PULONGLONG lpInputCounterValue,
        PULONGLONG lpOutputCounterValue,
        PULONGLONG lpConversionError);
    //ZwConvertBetweenAuxiliaryCounterAndPerformanceCounter

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtCreateIRTimer(
        _Out_ PHANDLE TimerHandle,
        _In_ TIMER_ACCESS_MASK DesiredAccess);
    //ZwCreateIRTimer

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtCreateTimer(
        _Out_ PHANDLE TimerHandle,
        _In_ TIMER_ACCESS_MASK DesiredAccess,
        _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
        _In_ TIMER_TYPE TimerType);
    //ZwCreateTimer

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtCreateTimer2(
        _Out_ PHANDLE TimerHandle,
        _In_opt_ PVOID Unknown1,
        _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
        _In_ ULONG Attributes,
        _In_ TIMER_ACCESS_MASK DesiredAccess);
    //ZwCreateTimer2

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtOpenTimer(
        _Out_ PHANDLE TimerHandle,
        _In_ TIMER_ACCESS_MASK DesiredAccess,
        _In_ POBJECT_ATTRIBUTES ObjectAttributes);
    //ZwOpenTimer

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtQueryAuxiliaryCounterFrequency(
        _Out_ PULONGLONG lpAuxiliaryCounterFrequency
        );
    //ZwQueryAuxiliaryCounterFrequency

    // See winternl.h
    // https://processhacker.sourceforge.io/doc/ntzwapi_8h_source.html
    NTSYSCALLAPI NTSTATUS NTAPI ZwQuerySystemTime(
        _Out_ PLARGE_INTEGER SystemTime);
    //ZwQuerySystemTime

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtQueryTimer(
        _In_ HANDLE TimerHandle,
        _In_ TIMER_INFORMATION_CLASS TimerInformationClass,
        _Out_ PVOID TimerInformation,
        _In_ ULONG Length,
        _Out_opt_ PULONG ReturnLength);
    //ZwQueryTimer

    // See winternl.h
    NTSYSAPI NTSTATUS NTAPI NtQueryTimerResolution(
        _Out_ PULONG MinimumResolution,
        _Out_ PULONG MaximumResolution,
        _Out_ PULONG CurrentResolution);
    //ZwQueryTimerResolution

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtSetIRTimer(
        _In_ HANDLE TimerHandle,
        _In_opt_ PLARGE_INTEGER Time);
    //ZwSetIRTimer

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtSetSystemTime(
        _In_ PLARGE_INTEGER SystemTime,
        _Out_opt_ PLARGE_INTEGER PrevSystemTime);
    //ZwSetSystemTime

    // http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FTimer%2FNtSetTimer.html
    typedef void (NTAPI *PTIMER_APC_ROUTINE)(
        _In_ PVOID TimerContext,
        _In_ ULONG TimerLowValue,
        _In_ LONG TimerHighValue);

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtSetTimer(
        _In_ HANDLE TimerHandle,
        _In_ PLARGE_INTEGER DueTime,
        _In_opt_ PTIMER_APC_ROUTINE TimerApcRoutine,
        _In_opt_ PVOID TimerContext,
        _In_ BOOLEAN WakeTimer,
        _In_opt_ LONG Period,
        _Out_opt_ PBOOLEAN PreviousState);
    //ZwSetTimer

    // https://github.com/Uri3n/Thread-Pool-Injection-PoC/blob/main/include/FunctionPtrs.hpp
    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtSetTimer2(
        _In_ HANDLE TimerHandle,
        _In_ PLARGE_INTEGER DueTime,
        _In_opt_ PLARGE_INTEGER Period,
        _In_ PVOID Parameters);
    //ZwSetTimer2

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtSetTimerEx(
        _In_ HANDLE TimerHandle,
        _In_ TIMER_INFORMATION_CLASS TimerSetInformationClass,
        _Inout_ PVOID TimerSetInformation,
        _In_ ULONG Length);
    //ZwSetTimerEx

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtSetTimerResolution(
        _In_ ULONG DesiredTime,
        _In_ BOOLEAN SetResolution,
        _Out_ PULONG ActualTime);
    //ZwSetTimerResolution

    // https://doxygen.reactos.org/dd/d63/sdk_2lib_2rtl_2timerqueue_8c.html
    NTSYSAPI NTSTATUS NTAPI RtlCancelTimer(
        HANDLE TimerQueue,
        HANDLE Timer);

    // https://doxygen.reactos.org/dd/d63/sdk_2lib_2rtl_2timerqueue_8c.html
    NTSYSAPI NTSTATUS NTAPI RtlDeleteTimerQueue(
        HANDLE TimerQueue);

    // https://doxygen.reactos.org/dd/d63/sdk_2lib_2rtl_2timerqueue_8c.html
    // https://doxygen.reactos.org/d5/df7/ndk_2rtltypes_8h.html#a7015455ab806eacbc4cab1fa2a0c085d
    typedef VOID(NTAPI* WAITORTIMERCALLBACKFUNC)(
        PVOID pvContext,
        BOOLEAN fTimerOrWaitFired);
    NTSYSAPI NTSTATUS NTAPI RtlSetTimer(
        HANDLE TimerQueue,
        PHANDLE NewTimer,
        WAITORTIMERCALLBACKFUNC Callback,
        PVOID Parameter,
        DWORD DueTime,
        DWORD Period,
        ULONG Flags);

}

#endif // _NTTIME_
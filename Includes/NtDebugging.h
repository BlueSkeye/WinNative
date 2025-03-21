#pragma once

#ifndef _NTDEBUGGING_
#define _NTDEBUGGING_

#include "NtCommonDefs.h"
#include "NtExceptionRecord.h"

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

    typedef enum _DBG_STATE {
        DbgIdle,
        DbgReplyPending,
        DbgCreateThreadStateChange,
        DbgCreateProcessStateChange,
        DbgExitThreadStateChange,
        DbgExitProcessStateChange,
        DbgExceptionStateChange,
        DbgBreakpointStateChange,
        DbgSingleStepStateChange,
        DbgLoadDllStateChange,
        DbgUnloadDllStateChange
    } DBG_STATE, *PDBG_STATE;

    // https://processhacker.sourceforge.io/doc/struct___d_b_g_k_m___e_x_c_e_p_t_i_o_n.html
    typedef struct _DBGKM_EXCEPTION {
        EXCEPTION_RECORD ExceptionRecord;
        ULONG FirstChance;
    } DBGKM_EXCEPTION, *PDBGKM_EXCEPTION;

    // https://processhacker.sourceforge.io/doc/struct___d_b_g_k_m___c_r_e_a_t_e___t_h_r_e_a_d.html
    typedef struct _DBGKM_CREATE_THREAD {
        ULONG SubSystemKey;
        PVOID StartAddress;
    } DBGKM_CREATE_THREAD;

    // https://processhacker.sourceforge.io/doc/struct___d_b_g_u_i___c_r_e_a_t_e___t_h_r_e_a_d.html
    typedef struct _DBGUI_CREATE_THREAD {
        HANDLE HandleToThread;
        DBGKM_CREATE_THREAD NewThread;
    } DBGUI_CREATE_THREAD;

    // https://processhacker.sourceforge.io/doc/struct___d_b_g_u_i___c_r_e_a_t_e___p_r_o_c_e_s_s.html
    typedef struct _DBGUI_CREATE_PROCESS {
        HANDLE HandleToProcess;
        HANDLE HandleToThread;
    } DBGUI_CREATE_PROCESS;

    // https://processhacker.sourceforge.io/doc/struct___d_b_g_k_m___e_x_i_t___p_r_o_c_e_s_s.html
    typedef struct _DBGKM_EXIT_PROCESS {
        NTSTATUS ExitStatus;
    } DBGKM_EXIT_PROCESS;

    // https://processhacker.sourceforge.io/doc/struct___d_b_g_k_m___e_x_i_t___t_h_r_e_a_d.html
    typedef struct _DBGKM_EXIT_THREAD {
        NTSTATUS ExitStatus;
    } DBGKM_EXIT_THREAD;

    typedef struct _DBGKM_LOAD_DLL {
        HANDLE FileHandle;
        PVOID BaseOfDll;
        ULONG DebugInfoFileOffset;
        ULONG DebugInfoSize;
        PVOID NamePointer;
    } DBGKM_LOAD_DLL;

    // https://processhacker.sourceforge.io/doc/struct___d_b_g_k_m___u_n_l_o_a_d___d_l_l.html
    typedef struct _DBGKM_UNLOAD_DLL {
        PVOID BaseAddress;
    } DBGKM_UNLOAD_DLL;

    // https://processhacker.sourceforge.io/doc/struct___d_b_g_u_i___w_a_i_t___s_t_a_t_e___c_h_a_n_g_e.html
    typedef struct _DBGUI_WAIT_STATE_CHANGE {
        DBG_STATE NewState;
        CLIENT_ID AppClientId;
        union {
            DBGKM_EXCEPTION Exception;
            DBGUI_CREATE_THREAD CreateThread;
            DBGUI_CREATE_PROCESS CreateProcessInfo;
            DBGKM_EXIT_THREAD ExitThread;
            DBGKM_EXIT_PROCESS ExitProcess;
            DBGKM_LOAD_DLL LoadDll;
            DBGKM_UNLOAD_DLL UnloadDll;
        } StateInfo;
    } DBGUI_WAIT_STATE_CHANGE,*PDBGUI_WAIT_STATE_CHANGE;

    // http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FProfile%2FKPROFILE_SOURCE.html
    typedef enum _KPROFILE_SOURCE {
        ProfileTime,
        ProfileAlignmentFixup,
        ProfileTotalIssues,
        ProfilePipelineDry,
        ProfileLoadInstructions,
        ProfilePipelineFrozen,
        ProfileBranchInstructions,
        ProfileTotalNonissues,
        ProfileDcacheMisses,
        ProfileIcacheMisses,
        ProfileCacheMisses,
        ProfileBranchMispredictions,
        ProfileStoreInstructions,
        ProfileFpInstructions,
        ProfileIntegerInstructions,
        Profile2Issue,
        Profile3Issue,
        Profile4Issue,
        ProfileSpecialInstructions,
        ProfileTotalCycles,
        ProfileIcacheIssues,
        ProfileDcacheAccesses,
        ProfileMemoryBarrierCycles,
        ProfileLoadLinkedIssues,
        ProfileMaximum
    } KPROFILE_SOURCE, * PKPROFILE_SOURCE;

    // https://processhacker.sourceforge.io/doc/ntdbg_8h.html#a60e21afaf5b5e7f2d9ec440747f63443
    typedef enum _DEBUGOBJECTINFOCLASS {
        DebugObjectFlags,
        MaxDebugObjectInfoClass
    } DEBUGOBJECTINFOCLASS;

    typedef ULONG_PTR KAFFINITY;

    // http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FDebug%2FNtSystemDebugControl.html
    typedef enum _SYSDBG_COMMAND {
        SysDbgQueryModuleInformation = 1,
        SysDbgQueryTraceInformation,
        SysDbgSetTracepoint,
        SysDbgSetSpecialCall,
        SysDbgClearSpecialCalls,
        SysDbgQuerySpecialCalls
    } SYSDBG_COMMAND, * PSYSDBG_COMMAND;

    typedef struct _TIME_FIELDS {
        CSHORT Year;
        CSHORT Month;
        CSHORT Day;
        CSHORT Hour;
        CSHORT Minute;
        CSHORT Second;
        CSHORT Milliseconds;
        CSHORT Weekday;
    } TIME_FIELDS, *PTIME_FIELDS;

    // ============================== functions ==============================

    // https://learn.microsoft.com/fr-fr/windows-hardware/drivers/ddi/wdm/nf-wdm-dbgbreakpoint
    NTSYSAPI VOID DbgBreakPoint();

    // https://learn.microsoft.com/fr-fr/windows-hardware/drivers/ddi/wdm/nf-wdm-dbgprint
    NTSYSAPI ULONG DbgPrint(
        PCSTR Format,
        ...);

    //https://learn.microsoft.com/fr-fr/windows-hardware/drivers/ddi/wdm/nf-wdm-dbgprintex
    NTSYSAPI ULONG DbgPrintEx(
        _In_ ULONG ComponentId,
        _In_ ULONG Level,
        _In_ PCSTR Format,
        ...);

    //https://doxygen.reactos.org/d6/dc3/xdk_2kdfuncs_8h.html
    NTSYSAPI ULONG __cdecl DbgPrintReturnControlC(
        _In_z_ _Printf_format_string_ PCCH Format,
        ...);

    //https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-dbgprompt
    NTSYSAPI ULONG DbgPrompt(
        _In_  PCCH  Prompt,
        _Out_ PCH   Response,
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
    NTSYSAPI NTSTATUS NTAPI DbgUiConvertStateChangeStructure(
        _In_ PDBGUI_WAIT_STATE_CHANGE StateChange,
        _Out_ struct _DEBUG_EVENT* DebugEvent);

    //DbgUiConvertStateChangeStructureEx
    //https://unprotect.it/media/archive/2022/06/22/NtSetDebugFilterState.pdf
    NTSYSCALLAPI NTSTATUS NTAPI DbgSetDebugFilterState(
        ULONG ComponentId,
        ULONG Level,
        BOOLEAN State);

    // https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/process.c
    NTSYSCALLAPI NTSTATUS NTAPI DbgUiDebugActiveProcess(
        HANDLE process);

    // https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/process.c
    NTSYSCALLAPI HANDLE NTAPI DbgUiGetThreadDebugObject(void);

    // https://processhacker.sourceforge.io/doc/ntdbg_8h.html#a6206168ba05b85ebb0cec355eca0e6d3
    NTSYSAPI NTSTATUS NTAPI DbgUiIssueRemoteBreakin(
        _In_ HANDLE Process);

    // https://processhacker.sourceforge.io/doc/ntdbg_8h.html#a6206168ba05b85ebb0cec355eca0e6d3
    NTSYSAPI VOID NTAPI DbgUiRemoteBreakin(
        _In_ PVOID Context);

    // https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/process.c
    NTSYSCALLAPI void NTAPI DbgUiSetThreadDebugObject(
        HANDLE handle);

    // https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/process.c
    NTSYSCALLAPI NTSTATUS NTAPI DbgUiStopDebugging(
        HANDLE process);

    // https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/process.c
    NTSYSCALLAPI NTSTATUS NTAPI DbgUiWaitStateChange(
        DBGUI_WAIT_STATE_CHANGE* state,
        LARGE_INTEGER* timeout);

    //https://processhacker.sourceforge.io/doc/ntrtl_8h.html
    NTSYSAPI VOID NTAPI DbgUserBreakPoint(VOID);

    // http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FProfile%2FNtCreateProfile.html
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
    NTSYSAPI NTSTATUS NTAPI NtDebugActiveProcess(
        _In_ HANDLE ProcessHandle,
        _In_ HANDLE DebugObjectHandle);
    //ZwDebugActiveProcess

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSAPI NTSTATUS NTAPI NtDebugContinue(
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

    // http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FDebug%2FNtSystemDebugControl.html
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
        _In_  ULONG          ElapsedSeconds,
        _Out_ PLARGE_INTEGER Time);

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlsecondssince1980totime
    NTSYSAPI VOID RtlSecondsSince1980ToTime(
        _In_  ULONG          ElapsedSeconds,
        _Out_ PLARGE_INTEGER Time);

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtltimefieldstotime
    NTSYSAPI BOOLEAN RtlTimeFieldsToTime(
        _In_  PTIME_FIELDS   TimeFields,
        _Out_ PLARGE_INTEGER Time);

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtltimetosecondssince1970
    // See winternl.h
    // RtlTimeToSecondsSince1970

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtltimetosecondssince1980
    NTSYSAPI BOOLEAN RtlTimeToSecondsSince1980(
        _In_  PLARGE_INTEGER Time,
        _Out_ PULONG         ElapsedSeconds);

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtltimetotimefields
    NTSYSAPI VOID RtlTimeToTimeFields(
        _In_  PLARGE_INTEGER Time,
        _Out_ PTIME_FIELDS   TimeFields);

}

#endif // _NTDEBUGGING_
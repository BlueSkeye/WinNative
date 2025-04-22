#pragma once

#ifndef _NTDEBUGGING_
#define _NTDEBUGGING_

#include "NtCommonDefs.h"
#include "NtExceptionRecord.h"

#ifdef __cplusplus
extern "C" {
#endif

    // UNRESOLVED FUNCTIONS
    //RtlGetMultiTimePrecise
    //RtlSetDynamicTimeZoneInformation
    //RtlpCheckDynamicTimeZoneInformation
    //RtlpFreezeTimeBias

    //RtlpTimeToTimeFields
    // END OF UNRESOLVED FUNCTIONS

    typedef struct _CREATE_PROCESS_DEBUG_INFO
        CREATE_PROCESS_DEBUG_INFO, * LPCREATE_PROCESS_DEBUG_INFO;
    typedef struct _CREATE_THREAD_DEBUG_INFO CREATE_THREAD_DEBUG_INFO, * LPCREATE_THREAD_DEBUG_INFO;
    typedef enum _DBG_STATE DBG_STATE, * PDBG_STATE;
    typedef struct _DBGKM_CREATE_PROCESS DBGKM_CREATE_PROCESS, * PDBGKM_CREATE_PROCESS;
    typedef struct _DBGKM_CREATE_THREAD DBGKM_CREATE_THREAD, * PDBGKM_CREATE_THREAD;
    typedef struct _DBGKM_EXCEPTION DBGKM_EXCEPTION, * PDBGKM_EXCEPTION;
    typedef struct _DBGKM_EXIT_PROCESS DBGKM_EXIT_PROCESS, * PDBGKM_EXIT_PROCESS;
    typedef struct _DBGKM_EXIT_THREAD DBGKM_EXIT_THREAD, * PDBGKM_EXIT_THREAD;
    typedef struct _DBGKM_LOAD_DLL DBGKM_LOAD_DLL, * PDBGKM_LOAD_DLL;
    typedef struct _DBGKM_UNLOAD_DLL DBGKM_UNLOAD_DLL, * PDBGKM_UNLOAD_DLL;
    typedef struct _DBGUI_CREATE_PROCESS DBGUI_CREATE_PROCESS, * PDBGUI_CREATE_PROCESS;
    typedef struct _DBGUI_CREATE_THREAD DBGUI_CREATE_THREAD, * PDBGUI_CREATE_THREAD;
    typedef struct _DBGUI_WAIT_STATE_CHANGE DBGUI_WAIT_STATE_CHANGE, * PDBGUI_WAIT_STATE_CHANGE;
    typedef struct _DEBUG_EVENT DEBUG_EVENT, * LPDEBUG_EVENT;
    typedef struct _EXCEPTION_DEBUG_INFO EXCEPTION_DEBUG_INFO, * LPEXCEPTION_DEBUG_INFO;
    typedef struct _EXIT_PROCESS_DEBUG_INFO EXIT_PROCESS_DEBUG_INFO, * LPEXIT_PROCESS_DEBUG_INFO;
    typedef struct _EXIT_THREAD_DEBUG_INFO EXIT_THREAD_DEBUG_INFO, * LPEXIT_THREAD_DEBUG_INFO;
    typedef struct _LOAD_DLL_DEBUG_INFO LOAD_DLL_DEBUG_INFO, * LPLOAD_DLL_DEBUG_INFO;
    typedef struct _OUTPUT_DEBUG_STRING_INFO OUTPUT_DEBUG_STRING_INFO, * LPOUTPUT_DEBUG_STRING_INFO;
    typedef struct _RIP_INFO RIP_INFO, * LPRIP_INFO;
    typedef struct _UNLOAD_DLL_DEBUG_INFO UNLOAD_DLL_DEBUG_INFO, * LPUNLOAD_DLL_DEBUG_INFO;
    // https://learn.microsoft.com/en-us/dotnet/framework/unmanaged-api/hosting/lpthread-start-routine-function-pointer
    typedef DWORD(__stdcall* LPTHREAD_START_ROUTINE) (
        _In_ LPVOID lpThreadParameter);

    // https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-create_process_debug_info
    struct _CREATE_PROCESS_DEBUG_INFO {
        HANDLE hFile;
        HANDLE hProcess;
        HANDLE hThread;
        LPVOID lpBaseOfImage;
        DWORD dwDebugInfoFileOffset;
        DWORD nDebugInfoSize;
        LPVOID lpThreadLocalBase;
        LPTHREAD_START_ROUTINE lpStartAddress;
        LPVOID lpImageName;
        WORD fUnicode;
    };

    // https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-create_thread_debug_info
    struct _CREATE_THREAD_DEBUG_INFO {
        HANDLE hThread;
        LPVOID lpThreadLocalBase;
        LPTHREAD_START_ROUTINE lpStartAddress;
    };

    // https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntdbg.h#L162
    enum _DBG_STATE {
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
    };

    // https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntdbg.h#L116C1-L120C38
    struct _DBGKM_EXCEPTION {
        EXCEPTION_RECORD ExceptionRecord;
        ULONG FirstChance;
    };

    // https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntdbg.h#L177C1-L181C46
    struct _DBGKM_CREATE_THREAD {
        ULONG SubSystemKey;
        PVOID StartAddress;
    };

    // https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntdbg.h#L128C1-L136C48
    struct _DBGKM_CREATE_PROCESS {
        ULONG SubSystemKey;
        HANDLE FileHandle;
        PVOID BaseOfImage;
        ULONG DebugInfoFileOffset;
        ULONG DebugInfoSize;
        DBGKM_CREATE_THREAD InitialThread;
    };

    // https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntdbg.h#L138C1-L141C42
    struct _DBGKM_EXIT_THREAD {
        NTSTATUS ExitStatus;
    };

    // https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntdbg.h#L143C1-L146C44
    struct _DBGKM_EXIT_PROCESS {
        NTSTATUS ExitStatus;
    };

    // https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntdbg.h#L148
    struct _DBGKM_LOAD_DLL {
        HANDLE FileHandle;
        PVOID BaseOfDll;
        ULONG DebugInfoFileOffset;
        ULONG DebugInfoSize;
        PVOID NamePointer;
    };

    // https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntdbg.h#L157
    struct _DBGKM_UNLOAD_DLL {
        PVOID BaseAddress;
    };

    // https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntdbg.h#L183C1-L188C48
    struct _DBGUI_CREATE_PROCESS {
        HANDLE HandleToProcess;
        HANDLE HandleToThread;
        DBGKM_CREATE_PROCESS NewProcess;
    };

    // https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntdbg.h#L177C1-L181C46
    struct _DBGUI_CREATE_THREAD {
        HANDLE HandleToThread;
        DBGKM_CREATE_THREAD NewThread;
    };

    // https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntdbg.h#L190C1-L204C54
    struct _DBGUI_WAIT_STATE_CHANGE  {
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
    };

    // https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-exception_debug_info
    struct _EXCEPTION_DEBUG_INFO {
        EXCEPTION_RECORD ExceptionRecord;
        DWORD dwFirstChance;
    };

    // https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-load_dll_debug_info
    struct _LOAD_DLL_DEBUG_INFO {
        HANDLE hFile;
        LPVOID lpBaseOfDll;
        DWORD  dwDebugInfoFileOffset;
        DWORD  nDebugInfoSize;
        LPVOID lpImageName;
        WORD   fUnicode;
    };

    // https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-unload_dll_debug_info
    struct _UNLOAD_DLL_DEBUG_INFO {
        LPVOID lpBaseOfDll;
    };

    // https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-output_debug_string_info
    struct _OUTPUT_DEBUG_STRING_INFO {
        LPSTR lpDebugStringData;
        WORD  fUnicode;
        WORD  nDebugStringLength;
    };

    // https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-exit_process_debug_info
    struct _EXIT_PROCESS_DEBUG_INFO {
        DWORD dwExitCode;
    };

    // https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-exit_thread_debug_info
    struct _EXIT_THREAD_DEBUG_INFO {
        DWORD dwExitCode;
    };

    // https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-rip_info
    struct _RIP_INFO {
        DWORD dwError;
        DWORD dwType;
    };

    // https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-debug_event
    struct _DEBUG_EVENT {
        DWORD dwDebugEventCode;
        DWORD dwProcessId;
        DWORD dwThreadId;
        union {
            EXCEPTION_DEBUG_INFO Exception;
            CREATE_THREAD_DEBUG_INFO CreateThread;
            CREATE_PROCESS_DEBUG_INFO CreateProcessInfo;
            EXIT_THREAD_DEBUG_INFO ExitThread;
            EXIT_PROCESS_DEBUG_INFO ExitProcess;
            LOAD_DLL_DEBUG_INFO LoadDll;
            UNLOAD_DLL_DEBUG_INFO UnloadDll;
            OUTPUT_DEBUG_STRING_INFO DebugString;
            RIP_INFO RipInfo;
        } u;
    };

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

    typedef struct _RTL_TIME_ZONE_INFORMATION {
        LONG Bias;
        WCHAR StandardName[32];
        TIME_FIELDS StandardStart;
        LONG StandardBias;
        WCHAR DaylightName[32];
        TIME_FIELDS DaylightStart;
        LONG DaylightBias;
    } RTL_TIME_ZONE_INFORMATION, * PRTL_TIME_ZONE_INFORMATION;

    // https://github.com/wine-mirror/wine/blob/0927c5c3da7cda8cf476416260286bd299ad6319/include/winternl.h#L84C1-L101C38
    /* RTL_SYSTEM_TIME and RTL_TIME_ZONE_INFORMATION are the same as
     * the SYSTEMTIME and TIME_ZONE_INFORMATION structures defined
     * in winbase.h, however we need to define them separately so
     * winternl.h doesn't depend on winbase.h.  They are used by
     * RtlQueryTimeZoneInformation and RtlSetTimeZoneInformation.
     * The names are guessed; if anybody knows the real names, let me know.*/
    typedef struct _RTL_SYSTEM_TIME {
        WORD wYear;
        WORD wMonth;
        WORD wDayOfWeek;
        WORD wDay;
        WORD wHour;
        WORD wMinute;
        WORD wSecond;
        WORD wMilliseconds;
    } RTL_SYSTEM_TIME, * PRTL_SYSTEM_TIME;

    // https://github.com/wine-mirror/wine/blob/0927c5c3da7cda8cf476416260286bd299ad6319/include/winternl.h#L113
    typedef struct _RTL_TIME_DYNAMIC_ZONE_INFORMATION {
        LONG Bias;
        WCHAR StandardName[32];
        RTL_SYSTEM_TIME StandardDate;
        LONG StandardBias;
        WCHAR DaylightName[32];
        RTL_SYSTEM_TIME DaylightDate;
        LONG DaylightBias;
        WCHAR TimeZoneKeyName[128];
        BOOLEAN DynamicDaylightTimeDisabled;
    } RTL_DYNAMIC_TIME_ZONE_INFORMATION, * PRTL_DYNAMIC_TIME_ZONE_INFORMATION;

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

    // https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntdbg.h#L283C1-L288C7
    NTSYSAPI NTSTATUS NTAPI DbgUiConnectToDbg(VOID);

    // https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntdbg.h#L312C1-L318C7
    NTSYSAPI NTSTATUS NTAPI DbgUiContinue(
        _In_ PCLIENT_ID AppClientId,
        _In_ NTSTATUS ContinueStatus);

    // https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntdbg.h#L348C1-L354C7
    NTSYSAPI NTSTATUS NTAPI DbgUiConvertStateChangeStructure(
        _In_ PDBGUI_WAIT_STATE_CHANGE StateChange,
        _Out_ LPDEBUG_EVENT DebugEvent);

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

    // https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntrtl.h#L6977C1-L6982C7
    NTSYSAPI ULONGLONG NTAPI RtlGetInterruptTimePrecise(
        _Out_ PLARGE_INTEGER PerformanceCounter);

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlsecondssince1970totime
    NTSYSAPI VOID RtlSecondsSince1970ToTime(
        _In_  ULONG          ElapsedSeconds,
        _Out_ PLARGE_INTEGER Time);

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlsecondssince1980totime
    NTSYSAPI VOID RtlSecondsSince1980ToTime(
        _In_  ULONG          ElapsedSeconds,
        _Out_ PLARGE_INTEGER Time);
    
    // https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntrtl.h#L6966C1-L6973C7
    NTSYSAPI KSYSTEM_TIME NTAPI RtlGetSystemTimeAndBias(
        _Out_ KSYSTEM_TIME TimeZoneBias,
        _Out_opt_ PLARGE_INTEGER TimeZoneBiasEffectiveStart,
        _Out_opt_ PLARGE_INTEGER TimeZoneBiasEffectiveEnd);

    // https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntrtl.h#L6957C1-L6962C7
    NTSYSAPI ULONGLONG NTAPI RtlGetSystemTimePrecise(VOID);

    // https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntrtl.h#L6889C1-L6896C1
    NTSYSAPI NTSTATUS NTAPI RtlLocalTimeToSystemTime(
        _In_ PLARGE_INTEGER LocalTime,
        _Out_ PLARGE_INTEGER SystemTime);

    NTSYSAPI NTSTATUS NTAPI RtlQueryDynamicTimeZoneInformation(
        PRTL_DYNAMIC_TIME_ZONE_INFORMATION ret);

    // https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntrtl.h#L7026C1-L7031C7
    NTSYSAPI NTSTATUS NTAPI RtlQueryTimeZoneInformation(
        _Out_ PRTL_TIME_ZONE_INFORMATION TimeZoneInformation);

    // https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntrtl.h#L6986C1-L6991C7
    NTSYSAPI BOOLEAN NTAPI RtlQueryUnbiasedInterruptTime(
        _Out_ PLARGE_INTEGER InterruptTime);
    
    // https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntrtl.h#L7033C1-L7038C7
    NTSYSAPI NTSTATUS NTAPI RtlSetTimeZoneInformation(
        _In_ PRTL_TIME_ZONE_INFORMATION TimeZoneInformation);

    // https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntrtl.h#L6881C1-L6887C7
    NTSYSAPI NTSTATUS NTAPI RtlSystemTimeToLocalTime(
        _In_ PLARGE_INTEGER SystemTime,
        _Out_ PLARGE_INTEGER LocalTime);

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtltimefieldstotime
    NTSYSAPI BOOLEAN RtlTimeFieldsToTime(
        _In_  PTIME_FIELDS   TimeFields,
        _Out_ PLARGE_INTEGER Time);

    // https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntrtl.h#L6897C1-L6903C7
    NTSYSAPI VOID NTAPI RtlTimeToElapsedTimeFields(
        _In_ PLARGE_INTEGER Time,
        _Out_ PTIME_FIELDS TimeFields);

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtltimetosecondssince1970
    NTSYSAPI BOOLEAN RtlTimeToSecondsSince1970(
        _In_  PLARGE_INTEGER Time,
        _Out_ PULONG ElapsedSeconds);

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtltimetosecondssince1980
    NTSYSAPI BOOLEAN RtlTimeToSecondsSince1980(
        _In_ PLARGE_INTEGER Time,
        _Out_ PULONG ElapsedSeconds);

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtltimetotimefields
    NTSYSAPI VOID RtlTimeToTimeFields(
        _In_ PLARGE_INTEGER Time,
        _Out_ PTIME_FIELDS TimeFields);

    // https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/pebteb/peb/index.htm
    // Reversed
    NTSYSAPI BOOLEAN NTAPI RtlpTimeFieldsToTime(VOID);

#ifdef __cplusplus
}
#endif

#endif // _NTDEBUGGING_

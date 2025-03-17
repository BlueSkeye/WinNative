#pragma once

#ifndef _NTPROCESSES_
#define _NTPROCESSES_

#include "NtCommonDefs.h"

extern "C" {

    // UNRESOLVED FUNCTIONS
//RtlCloneUserProcess
//RtlCompleteProcessCloning
//RtlCreateProcessParameters
//RtlCreateProcessParametersEx
//RtlCreateProcessParametersWithTemplate
//RtlCreateProcessReflection
//RtlCreateUserProcessEx
//RtlDeNormalizeProcessParams
//RtlDestroyProcessParameters
//RtlExitUserProcess
//RtlExitUserThread
//RtlGetCurrentProcessorNumber
//RtlGetProcessPreferredUILanguages
//RtlNormalizeProcessParams
//RtlPrepareForProcessCloning
//RtlQueryProcessBackTraceInformation
//RtlQueryProcessDebugInformation
//RtlQueryProcessLockInformation
//RtlReportSilentProcessExit
//RtlSetProcessDebugInformation
//RtlSetProcessIsCritical
//RtlSetProcessPreferredUILanguages
//RtlWow64SuspendProcess
//RtlpCreateProcessRegistryInfo
//RtlpQueryProcessDebugInformationFromWow64
//RtlpQueryProcessDebugInformationRemote
    // END OF UNRESOLVED FUNCTIONS
    // Also see remark for PssWalkSnapshot

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtAcquireProcessActivityReference(
		_Out_ PHANDLE pHandle,
		_In_ HANDLE hProcess,
		ULONG Unknown);
	//ZwAcquireProcessActivityReference

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtAlertResumeThread(
		_In_ HANDLE ThreadHandle,
		_Out_ PULONG pSuspendCount);
	//ZwAlertResumeThread

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtAlertThreadByThreadId(
		_In_ ULONG ThreadId);
	//ZwAlertThreadByThreadId

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtApphelpCacheControl(
		_In_ ULONG ServiceClass,
		_In_ PUNICODE_STRING ServiceData);
	//ZwApphelpCacheControl

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtCreateProcess(
		_Out_ PHANDLE ProcessHandle,
		_In_ PROCESS_ACCESS_MASK DesiredAccess,
		_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
		_In_ HANDLE ParentProcessHandle,
		_In_ BOOL Inherit,
		_In_opt_ HANDLE SectionHandle,
		_In_opt_ HANDLE DebugPort,
		_In_opt_ HANDLE ExceptionPort);
	//ZwCreateProcess

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtCreateProcessEx(
		_Out_ PHANDLE ProcessHandle,
		_In_ PROCESS_ACCESS_MASK DesiredAccess,
		_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
		_In_ HANDLE ParentProcessHandle,
		_In_ BOOL Inherit,
		_In_opt_ HANDLE SectionHandle,
		_In_opt_ HANDLE DebugPort,
		_In_opt_ HANDLE ExceptionPort,
		_In_ BOOLEAN InJob);
	//ZwCreateProcessEx

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtCreateThread(
		_Out_ PHANDLE ThreadHandle,
		_In_ THREAD_ACCESS_MASK DesiredAccess,
		_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
		_In_ HANDLE ProcessHandle,
		_Out_ PCLIENT_ID ClientId,
		_In_ PCONTEXT ThreadContext,
		_In_ PVOID UserStack,
		_In_ BOOLEAN CreateSuspended);
	//ZwCreateThread

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtCreateThreadEx(
		_Out_ PHANDLE ThreadHandle,
		_In_ THREAD_ACCESS_MASK DesiredAccess,
		_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
		_In_ HANDLE ProcessHandle,
		_In_ PVOID StartRoutine,
		_In_opt_ PVOID Argument,
		_In_ ULONG CreateFlags,
		_In_opt_ ULONG ZeroBits,
		_In_opt_ ULONG StackSize,
		_In_opt_ ULONG MaximumStackSize,
		_In_opt_ PVOID AttributeList);
	//ZwCreateThreadEx

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtCreateUserProcess(
		_Out_ PHANDLE ProcessHandle,
		_Out_ PHANDLE ThreadHandle,
		_In_ PROCESS_ACCESS_MASK ProcessDesiredAccess,
		_In_ ACCESS_MASK ThreadDesiredAccess,
		_In_opt_ POBJECT_ATTRIBUTES ProcessObjectAttributes,
		_In_opt_ POBJECT_ATTRIBUTES ThreadObjectAttributes,
		_In_ ULONG ProcessFlags,
		_In_ ULONG ThreadFlags,
		_In_opt_ PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
		_Inout_ PVOID CreateInfo,
		_In_opt_ PVOID AttributeList);
	//ZwCreateUserProcess

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtCreateWorkerFactory(
		_Out_ PHANDLE WorkerFactoryHandleReturn,
		_In_ ACCESS_MASK DesiredAccess,
		_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
		_In_ HANDLE CompletionPortHandle,
		_In_ HANDLE WorkerProcessHandle,
		_In_ PVOID StartRoutine,
		_In_opt_ PVOID StartParameter,
		_In_opt_ ULONG MaxThreadCount,
		_In_opt_ ULONG StackReserve,
		_In_opt_ ULONG StackCommit);
	//ZwCreateWorkerFactory

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtDelayExecution(
		_In_ BOOLEAN Alertable,
		_In_ PLARGE_INTEGER DelayInterval);
	//ZwDelayExecution

    // https://processhacker.sourceforge.io/doc/ntzwapi_8h_source.html
    NTSYSCALLAPI NTSTATUS NTAPI ZwGetContextThread(
        _In_ HANDLE ThreadHandle,
        _Inout_ PCONTEXT ThreadContext);
    //ZwGetContextThread

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtGetNextProcess(
        HANDLE ProcessHandle,
        PROCESS_ACCESS_MASK DesiredAccess,
        ULONG HandleAttributes,
        ULONG Flags,
        PHANDLE NewProcessHandle);
    //ZwGetNextProcess

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtGetNextThread(
        HANDLE ProcessHandle,
        HANDLE ThreadHandle,
        THREAD_ACCESS_MASK DesiredAccess,
        ULONG HandleAttributes,
        ULONG Flags,
        PHANDLE NewThreadHandle);
    //ZwGetNextThread

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-ntopenprocess
    NTSYSCALLAPI NTSTATUS NtOpenProcess(
        [out]          PHANDLE            ProcessHandle,
        [in]           ACCESS_MASK        DesiredAccess,
        [in]           POBJECT_ATTRIBUTES ObjectAttributes,
        [in, optional] PCLIENT_ID         ClientId);
    //ZwOpenProcess

    // https://learn.microsoft.com/en-us/windows/win32/devnotes/ntopenthread
    NTSYSCALLAPI NTSTATUS NtOpenThread(
        _Out_ PHANDLE            ThreadHandle,
        _In_  ACCESS_MASK        DesiredAccess,
        _In_  POBJECT_ATTRIBUTES ObjectAttributes,
        _In_  PCLIENT_ID         ClientId);
    //ZwOpenThread

    // See winternl.h
    // https://processhacker.sourceforge.io/doc/ntzwapi_8h_source.html
    NTSYSCALLAPI NTSTATUS NTAPI ZwQueryInformationProcess(
        _In_ HANDLE ProcessHandle,
        _In_ PROCESSINFOCLASS ProcessInformationClass,
        _Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
        _In_ ULONG ProcessInformationLength,
        _Out_opt_ PULONG ReturnLength);
    //ZwQueryInformationProcess

    // See winternl.h
    // https://processhacker.sourceforge.io/doc/ntzwapi_8h_source.html
    NTSYSCALLAPI NTSTATUS NTAPI ZwQueryInformationThread(
        _In_ HANDLE ThreadHandle,
        _In_ THREADINFOCLASS ThreadInformationClass,
        _Out_writes_bytes_(ThreadInformationLength) PVOID ThreadInformation,
        _In_ ULONG ThreadInformationLength,
        _Out_opt_ PULONG ReturnLength);
    //ZwQueryInformationThread

    // https://github.com/Uri3n/Thread-Pool-Injection-PoC/blob/main/include/FunctionPtrs.hpp
    // https://urien.gitbook.io/diago-lima/a-deep-dive-into-exploiting-windows-thread-pools/attacking-worker-factories
    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtQueryInformationWorkerFactory(
        _In_ HANDLE WorkerFactoryHandle,
        _In_ WORKERFACTORYINFOCLASS WorkerFactoryInformationClass,
        _Out_ PVOID Buffer,
        _In_ ULONG BufferLength,
        _Out_opt_ PULONG ReturnLength);
    //ZwQueryInformationWorkerFactory

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtQueueApcThread(
        _In_ HANDLE ThreadHandle,
        _In_ PVOID ApcRoutine,
        _In_ PVOID Context,
        _In_ PVOID Argument1,
        _In_ PVOID Argument2);
    //ZwQueueApcThread

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtQueueApcThreadEx(
        _In_ HANDLE ThreadHandle,
        _In_ HANDLE ApcReserve,
        _In_ PVOID ApcRoutine,
        _In_ PVOID Context,
        _In_ PVOID Argument1,
        _In_ PVOID Argument2);
    //ZwQueueApcThreadEx

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtQueueApcThreadEx2(
        _In_ HANDLE ThreadHandle,
        _In_ HANDLE ApcReserve,
        _In_ QUEUE_USER_APC_FLAGS QueueUserApcFlags,
        _In_ PPS_APC_ROUTINE ApcRoutine,
        _In_opt_ PVOID SystemArgument1,
        _In_opt_ PVOID SystemArgument2,
        _In_opt_ PVOID SystemArgument3);
    //ZwQueueApcThreadEx2

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtRaiseHardError(
        _In_ NTSTATUS ErrorStatus,
        _In_ ULONG NumberOfParameters,
        _In_ ULONG ParameterMask,
        _In_ PULONG_PTR Parameters,
        _In_ HARDERROR_RESPONSE_OPTION ResponseOptions,
        _Out_ PULONG Response);
    //ZwRaiseHardError

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtReleaseWorkerFactoryWorker(
        _In_ HANDLE WorkerFactoryHandle);
    //ZwReleaseWorkerFactoryWorker

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtResumeProcess(
        _In_ HANDLE hProcess);
    //ZwResumeProcess

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtResumeThread(
        _In_ HANDLE ThreadHandle,
        _Out_ PULONG SuspendCount);
    //ZwResumeThread

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtSetContextThread(
        _In_ HANDLE ThreadHandle,
        _In_ PCONTEXT pContext);
    //ZwSetContextThread

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtSetDefaultHardErrorPort(
        _In_ HANDLE Port);
    //ZwSetDefaultHardErrorPort

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtSetInformationProcess(
        _In_ HANDLE ProcessHandle,
        _In_ PROCESSINFOCLASS ProcessInformationClass,
        _In_ PVOID ProcessInformation,
        _In_ ULONG Length);
    //ZwSetInformationProcess

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntsetinformationthread
    // See winternl.h
    // https://processhacker.sourceforge.io/doc/ntzwapi_8h_source.html
    NTSYSCALLAPI NTSTATUS NTAPI ZwSetInformationThread(
        _In_ HANDLE ThreadHandle,
        _In_ THREADINFOCLASS ThreadInformationClass,
        _In_reads_bytes_(ThreadInformationLength) PVOID ThreadInformation,
        _In_ ULONG ThreadInformationLength);
    // ZwSetInformationThread

    // https://urien.gitbook.io/diago-lima/a-deep-dive-into-exploiting-windows-thread-pools/attacking-worker-factories
    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtSetInformationWorkerFactory(
        _In_ HANDLE WorkerFactoryHandle,
        _In_ WORKERFACTORYINFOCLASS InformationClass,
        _In_ PVOID Buffer,
        _In_ ULONG BufferLength);
    //ZwSetInformationWorkerFactory

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtShutdownWorkerFactory(
        _In_ HANDLE WorkerFactoryHandle,
        _Inout_ PULONG PendingWorkerCount);
    //ZwShutdownWorkerFactory

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtSuspendProcess(
        _In_ HANDLE ProcessHandle);
    //ZwSuspendProcess

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtSuspendThread(
        _In_ HANDLE ThreadHandle,
        _Out_opt_ PULONG PreviousSuspendCount);
    //ZwSuspendThread

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtTerminateProcess(
        _In_ HANDLE ProcessHandle,
        _In_ NTSTATUS ExitStatus);
    //ZwTerminateProcess

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtTerminateThread(
        _In_ HANDLE ThreadHandle,
        _In_ NTSTATUS ExitStatus);
    //ZwTerminateThread

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtTestAlert();
    //ZwTestAlert

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtUmsThreadYield(
        _In_ PVOID SchedulerParam);
    //ZwUmsThreadYield

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtWaitForAlertByThreadId(
        _In_ HANDLE Handle,
        _In_opt_ PLARGE_INTEGER Timeout);
    //ZwWaitForAlertByThreadId

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtWaitForWorkViaWorkerFactory(
        _In_ HANDLE WorkerFactoryHandle,
        _Out_ PVOID MiniPacket);
    //ZwWaitForWorkViaWorkerFactory

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtWorkerFactoryWorkerReady(
        _In_ HANDLE WorkerFactoryHandle);
    //ZwWorkerFactoryWorkerReady

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtYieldExecution();
    //ZwYieldExecution

    //https://github.com/fortra/nanodump/blob/main/include/handle.h
    NTSYSAPI NTSTATUS NTAPI PssNtCaptureSnapshot(
        PHANDLE SnapshotHandle,
        HANDLE ProcessHandle,
        DWORD CaptureFlags,
        DWORD ThreadContextFlags);

    //https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntpsapi.h
    NTSYSAPI NTSTATUS NTAPI PssNtDuplicateSnapshot(
        _In_ HANDLE SourceProcessHandle,
        _In_ HANDLE SnapshotHandle,
        _In_ HANDLE TargetProcessHandle,
        _Out_ PHANDLE TargetSnapshotHandle,
        _In_opt_ PSSNT_DUPLICATE_FLAGS Flags);

    //https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntpsapi.h
    NTSYSAPI NTSTATUS NTAPI PssNtFreeRemoteSnapshot(
        _In_ HANDLE ProcessHandle,
        _In_ HANDLE SnapshotHandle);

    //https://github.com/fortra/nanodump/blob/main/include/handle.h
    NTSYSAPI NTSTATUS NTAPI PssNtFreeSnapshot(
        _In_ HANDLE SnapshotHandle);
    
    // Reversed
    typedef struct _WALKMARKER {
        PVOID BaseAddress;
        PVOID Unknown;
    } WALKMARKER, *PWALKMARKER;
    NTSYSAPI NTSTATUS PssNtFreeWalkMarker(
        _In_ PWALKMARKER pMarker);

    //https://github.com/fortra/nanodump/blob/main/include/handle.h
    NTSYSAPI NTSTATUS PssNtQuerySnapshot(
        _In_ HANDLE SnapshotHandle,
        _In_ DWORD InformationClass,
        _In_ PVOID Buffer,
        _In_ DWORD BufferLength);
    
    // Reversed
    NTSYSAPI NTSTATUS NTAPI PssNtValidateDescriptor(
        _In_ HANDLE SnapshotHandle,
        // What are we missing here ? The RDX register is the callers caller return address.
        _In_ PVOID Unknown);
    
    // https://learn.microsoft.com/en-us/windows/win32/api/processsnapshot/nf-processsnapshot-psswalksnapshot
    // This is the definition from kernel32 which directly forwards (jump) to 
    // api-ms-win-core-processsnapshot-l1-1-0.dll:__imp_PssWalkSnapshot
    // See this article for name resolution
    // https://stackoverflow.com/questions/47529106/what-are-api-ms-win-lx-x-x-dll-umbrella-libraries
    // TODO : Resolve virtual DLL name and make sure the implementation is the one provided by
    // NTDLL.DLL
    NTSYSAPI NTSTATUS NTAPI PssWalkSnapshot(
        [in]  HPSS                       SnapshotHandle,
        [in]  PSS_WALK_INFORMATION_CLASS InformationClass,
        [in]  HPSSWALK                   WalkMarkerHandle,
        [out] void* Buffer,
        [in]  DWORD                      BufferLength);

    // https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/process.c
    NTSTATUS WINAPI RtlCreateUserProcess(UNICODE_STRING* path, ULONG attributes,
        RTL_USER_PROCESS_PARAMETERS* params,
        SECURITY_DESCRIPTOR* process_descr,
        SECURITY_DESCRIPTOR* thread_descr,
        HANDLE parent, BOOLEAN inherit, HANDLE debug, HANDLE token,
        RTL_USER_PROCESS_INFORMATION* info);

    // https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/process.c
    NTSYSAPI BOOLEAN WINAPI RtlIsCurrentProcess(
        _In_ HANDLE handle);

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlqueryprocessplaceholdercompatibilitymode
    NTSYSAPI CHAR RtlQueryProcessPlaceholderCompatibilityMode();

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlsetprocessplaceholdercompatibilitymode
    NTSYSAPI CHAR RtlSetProcessPlaceholderCompatibilityMode(
        CHAR Mode);

    // https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/process.c
    NTSYSAPI NTSTATUS WINAPI RtlWow64GetProcessMachines(
        HANDLE process,
        USHORT* current_ret,
        USHORT* native_ret);

    // https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/process.c
    NTSYSAPI NTSTATUS WINAPI RtlWow64GetSharedInfoProcess(
        HANDLE process,
        BOOLEAN* is_wow64,
        WOW64INFO* info);

}

#endif // _NTPROCESSES_
#pragma once

#ifndef _NTPROCESSES_
#define _NTPROCESSES_

#include "NtCommonDefs.h"

extern "C" {

    // https://urien.gitbook.io/diago-lima/a-deep-dive-into-exploiting-windows-thread-pools/attacking-worker-factories

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

    // https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntmmapi.h#L610C1-L656C58
    typedef struct _SECTION_IMAGE_INFORMATION {
        PVOID TransferAddress;
        ULONG ZeroBits;
        SIZE_T MaximumStackSize;
        SIZE_T CommittedStackSize;
        ULONG SubSystemType;
        union {
            struct {
                USHORT SubSystemMinorVersion;
                USHORT SubSystemMajorVersion;
            } STRUCTDUMMYNAME;
            ULONG SubSystemVersion;
        } UNIONDUMMYNAME1;
        union {
            struct {
                USHORT MajorOperatingSystemVersion;
                USHORT MinorOperatingSystemVersion;
            } STRUCTDUMMYNAME;
            ULONG OperatingSystemVersion;
        } UNIONDUMMYNAME2;
        USHORT ImageCharacteristics;
        USHORT DllCharacteristics;
        USHORT Machine;
        BOOLEAN ImageContainsCode;
        union {
            UCHAR ImageFlags;
            struct {
                UCHAR ComPlusNativeReady : 1;
                UCHAR ComPlusILOnly : 1;
                UCHAR ImageDynamicallyRelocated : 1;
                UCHAR ImageMappedFlat : 1;
                UCHAR BaseBelow4gb : 1;
                UCHAR ComPlusPrefer32bit : 1;
                UCHAR Reserved : 2;
            } STRUCTDUMMYNAME;
        } UNIONDUMMYNAME3;
        ULONG LoaderFlags;
        ULONG ImageFileSize;
        ULONG CheckSum;
    } SECTION_IMAGE_INFORMATION, * PSECTION_IMAGE_INFORMATION;

    DECLARE_HANDLE(HPSS);
    DECLARE_HANDLE(HPSSWALK);

    // https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntrtl.h#L3167
    typedef struct _RTL_USER_PROCESS_INFORMATION {
        ULONG Length;
        HANDLE ProcessHandle;
        HANDLE ThreadHandle;
        CLIENT_ID ClientId;
        SECTION_IMAGE_INFORMATION ImageInformation;
    } RTL_USER_PROCESS_INFORMATION, * PRTL_USER_PROCESS_INFORMATION;

    // https://github.com/winsiderss/systeminformer/blob/cc931ddaf76f62e313cf7b9f5a81ef0c54590088/phnt/include/ntexapi.h#L1523C1-L1542C52
    typedef enum _WORKERFACTORYINFOCLASS {
        WorkerFactoryTimeout, // LARGE_INTEGER
        WorkerFactoryRetryTimeout, // LARGE_INTEGER
        WorkerFactoryIdleTimeout, // s: LARGE_INTEGER
        WorkerFactoryBindingCount, // s: ULONG
        WorkerFactoryThreadMinimum, // s: ULONG
        WorkerFactoryThreadMaximum, // s: ULONG
        WorkerFactoryPaused, // ULONG or BOOLEAN
        WorkerFactoryBasicInformation, // q: WORKER_FACTORY_BASIC_INFORMATION
        WorkerFactoryAdjustThreadGoal,
        WorkerFactoryCallbackType,
        WorkerFactoryStackInformation, // 10
        WorkerFactoryThreadBasePriority, // s: ULONG
        WorkerFactoryTimeoutWaiters, // s: ULONG, since THRESHOLD
        WorkerFactoryFlags, // s: ULONG
        WorkerFactoryThreadSoftMaximum, // s: ULONG
        WorkerFactoryThreadCpuSets, // since REDSTONE5
        MaxWorkerFactoryInfoClass
    } WORKERFACTORYINFOCLASS, * PWORKERFACTORYINFOCLASS;

    /* A pointer to a function that serves as an APC routine.
     * @param ApcArgument1 Optional. A pointer to the first argument to be passed to the APC routine.
     * @param ApcArgument2 Optional. A pointer to the second argument to be passed to the APC routine.
     * @param ApcArgument3 Optional. A pointer to the third argument to be passed to the APC routine.*/
    typedef VOID(NTAPI* PPS_APC_ROUTINE)(
        _In_opt_ PVOID ApcArgument1,
        _In_opt_ PVOID ApcArgument2,
        _In_opt_ PVOID ApcArgument3);

    typedef enum _HARDERROR_RESPONSE_OPTION {
        OptionAbortRetryIgnore,
        OptionOk,
        OptionOkCancel,
        OptionRetryCancel,
        OptionYesNo,
        OptionYesNoCancel,
        OptionShutdownSystem
    } HARDERROR_RESPONSE_OPTION, * PHARDERROR_RESPONSE_OPTION;

    typedef enum _PSS_WALK_INFORMATION_CLASS {
        PSS_WALK_AUXILIARY_PAGES = 0,
        PSS_WALK_VA_SPACE = 1,
        PSS_WALK_HANDLES = 2,
        PSS_WALK_THREADS = 3,
        PSS_WALK_THREAD_NAME
    } PSS_WALK_INFORMATION_CLASS;

    typedef struct _WOW64INFO {
        ULONG NativeSystemPageSize;
        ULONG CpuFlags;
        ULONG Wow64ExecuteFlags;
        ULONG unknown;
        ULONGLONG SectionHandle;
        ULONGLONG CrossProcessWorkList;
        USHORT NativeMachineType;
        USHORT EmulatedMachineType;
    } WOW64INFO;

    // https://github.com/winsiderss/systeminformer/blob/cc931ddaf76f62e313cf7b9f5a81ef0c54590088/phnt/include/ntpsapi.h#L177
    typedef enum _PROCESSINFOCLASS {
        ProcessBasicInformation, // q: PROCESS_BASIC_INFORMATION, PROCESS_EXTENDED_BASIC_INFORMATION
        ProcessQuotaLimits, // qs: QUOTA_LIMITS, QUOTA_LIMITS_EX
        ProcessIoCounters, // q: IO_COUNTERS
        ProcessVmCounters, // q: VM_COUNTERS, VM_COUNTERS_EX, VM_COUNTERS_EX2
        ProcessTimes, // q: KERNEL_USER_TIMES
        ProcessBasePriority, // s: KPRIORITY
        ProcessRaisePriority, // s: ULONG
        ProcessDebugPort, // q: HANDLE
        ProcessExceptionPort, // s: PROCESS_EXCEPTION_PORT (requires SeTcbPrivilege)
        ProcessAccessToken, // s: PROCESS_ACCESS_TOKEN
        ProcessLdtInformation, // qs: PROCESS_LDT_INFORMATION // 10
        ProcessLdtSize, // s: PROCESS_LDT_SIZE
        ProcessDefaultHardErrorMode, // qs: ULONG
        ProcessIoPortHandlers, // (kernel-mode only) // s: PROCESS_IO_PORT_HANDLER_INFORMATION
        ProcessPooledUsageAndLimits, // q: POOLED_USAGE_AND_LIMITS
        ProcessWorkingSetWatch, // q: PROCESS_WS_WATCH_INFORMATION[]; s: void
        ProcessUserModeIOPL, // qs: ULONG (requires SeTcbPrivilege)
        ProcessEnableAlignmentFaultFixup, // s: BOOLEAN
        ProcessPriorityClass, // qs: PROCESS_PRIORITY_CLASS
        ProcessWx86Information, // qs: ULONG (requires SeTcbPrivilege) (VdmAllowed)
        ProcessHandleCount, // q: ULONG, PROCESS_HANDLE_INFORMATION // 20
        ProcessAffinityMask, // (q >WIN7)s: KAFFINITY, qs: GROUP_AFFINITY
        ProcessPriorityBoost, // qs: ULONG
        ProcessDeviceMap, // qs: PROCESS_DEVICEMAP_INFORMATION, PROCESS_DEVICEMAP_INFORMATION_EX
        ProcessSessionInformation, // q: PROCESS_SESSION_INFORMATION
        ProcessForegroundInformation, // s: PROCESS_FOREGROUND_BACKGROUND
        ProcessWow64Information, // q: ULONG_PTR
        ProcessImageFileName, // q: UNICODE_STRING
        ProcessLUIDDeviceMapsEnabled, // q: ULONG
        ProcessBreakOnTermination, // qs: ULONG
        ProcessDebugObjectHandle, // q: HANDLE // 30
        ProcessDebugFlags, // qs: ULONG
        ProcessHandleTracing, // q: PROCESS_HANDLE_TRACING_QUERY; s: PROCESS_HANDLE_TRACING_ENABLE[_EX] or void to disable
        ProcessIoPriority, // qs: IO_PRIORITY_HINT
        ProcessExecuteFlags, // qs: ULONG (MEM_EXECUTE_OPTION_*)
        ProcessTlsInformation, // PROCESS_TLS_INFORMATION // ProcessResourceManagement
        ProcessCookie, // q: ULONG
        ProcessImageInformation, // q: SECTION_IMAGE_INFORMATION
        ProcessCycleTime, // q: PROCESS_CYCLE_TIME_INFORMATION // since VISTA
        ProcessPagePriority, // qs: PAGE_PRIORITY_INFORMATION
        ProcessInstrumentationCallback, // s: PVOID or PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION // 40
        ProcessThreadStackAllocation, // s: PROCESS_STACK_ALLOCATION_INFORMATION, PROCESS_STACK_ALLOCATION_INFORMATION_EX
        ProcessWorkingSetWatchEx, // q: PROCESS_WS_WATCH_INFORMATION_EX[]; s: void
        ProcessImageFileNameWin32, // q: UNICODE_STRING
        ProcessImageFileMapping, // q: HANDLE (input)
        ProcessAffinityUpdateMode, // qs: PROCESS_AFFINITY_UPDATE_MODE
        ProcessMemoryAllocationMode, // qs: PROCESS_MEMORY_ALLOCATION_MODE
        ProcessGroupInformation, // q: USHORT[]
        ProcessTokenVirtualizationEnabled, // s: ULONG
        ProcessConsoleHostProcess, // qs: ULONG_PTR // ProcessOwnerInformation
        ProcessWindowInformation, // q: PROCESS_WINDOW_INFORMATION // 50
        ProcessHandleInformation, // q: PROCESS_HANDLE_SNAPSHOT_INFORMATION // since WIN8
        ProcessMitigationPolicy, // s: PROCESS_MITIGATION_POLICY_INFORMATION
        ProcessDynamicFunctionTableInformation, // s: PROCESS_DYNAMIC_FUNCTION_TABLE_INFORMATION
        ProcessHandleCheckingMode, // qs: ULONG; s: 0 disables, otherwise enables
        ProcessKeepAliveCount, // q: PROCESS_KEEPALIVE_COUNT_INFORMATION
        ProcessRevokeFileHandles, // s: PROCESS_REVOKE_FILE_HANDLES_INFORMATION
        ProcessWorkingSetControl, // s: PROCESS_WORKING_SET_CONTROL
        ProcessHandleTable, // q: ULONG[] // since WINBLUE
        ProcessCheckStackExtentsMode, // qs: ULONG // KPROCESS->CheckStackExtents (CFG)
        ProcessCommandLineInformation, // q: UNICODE_STRING // 60
        ProcessProtectionInformation, // q: PS_PROTECTION
        ProcessMemoryExhaustion, // s: PROCESS_MEMORY_EXHAUSTION_INFO // since THRESHOLD
        ProcessFaultInformation, // s: PROCESS_FAULT_INFORMATION
        ProcessTelemetryIdInformation, // q: PROCESS_TELEMETRY_ID_INFORMATION
        ProcessCommitReleaseInformation, // qs: PROCESS_COMMIT_RELEASE_INFORMATION
        ProcessDefaultCpuSetsInformation, // qs: SYSTEM_CPU_SET_INFORMATION[5]
        ProcessAllowedCpuSetsInformation, // qs: SYSTEM_CPU_SET_INFORMATION[5]
        ProcessSubsystemProcess,
        ProcessJobMemoryInformation, // q: PROCESS_JOB_MEMORY_INFO
        ProcessInPrivate, // q: BOOLEAN; s: void // ETW // since THRESHOLD2 // 70
        ProcessRaiseUMExceptionOnInvalidHandleClose, // qs: ULONG; s: 0 disables, otherwise enables
        ProcessIumChallengeResponse,
        ProcessChildProcessInformation, // q: PROCESS_CHILD_PROCESS_INFORMATION
        ProcessHighGraphicsPriorityInformation, // qs: BOOLEAN (requires SeTcbPrivilege)
        ProcessSubsystemInformation, // q: SUBSYSTEM_INFORMATION_TYPE // since REDSTONE2
        ProcessEnergyValues, // q: PROCESS_ENERGY_VALUES, PROCESS_EXTENDED_ENERGY_VALUES
        ProcessPowerThrottlingState, // qs: POWER_THROTTLING_PROCESS_STATE
        ProcessReserved3Information, // ProcessActivityThrottlePolicy // PROCESS_ACTIVITY_THROTTLE_POLICY
        ProcessWin32kSyscallFilterInformation, // q: WIN32K_SYSCALL_FILTER
        ProcessDisableSystemAllowedCpuSets, // s: BOOLEAN // 80
        ProcessWakeInformation, // q: PROCESS_WAKE_INFORMATION
        ProcessEnergyTrackingState, // qs: PROCESS_ENERGY_TRACKING_STATE
        ProcessManageWritesToExecutableMemory, // MANAGE_WRITES_TO_EXECUTABLE_MEMORY // since REDSTONE3
        ProcessCaptureTrustletLiveDump,
        ProcessTelemetryCoverage, // q: TELEMETRY_COVERAGE_HEADER; s: TELEMETRY_COVERAGE_POINT
        ProcessEnclaveInformation,
        ProcessEnableReadWriteVmLogging, // qs: PROCESS_READWRITEVM_LOGGING_INFORMATION
        ProcessUptimeInformation, // q: PROCESS_UPTIME_INFORMATION
        ProcessImageSection, // q: HANDLE
        ProcessDebugAuthInformation, // since REDSTONE4 // 90
        ProcessSystemResourceManagement, // s: PROCESS_SYSTEM_RESOURCE_MANAGEMENT
        ProcessSequenceNumber, // q: ULONGLONG
        ProcessLoaderDetour, // since REDSTONE5
        ProcessSecurityDomainInformation, // q: PROCESS_SECURITY_DOMAIN_INFORMATION
        ProcessCombineSecurityDomainsInformation, // s: PROCESS_COMBINE_SECURITY_DOMAINS_INFORMATION
        ProcessEnableLogging, // qs: PROCESS_LOGGING_INFORMATION
        ProcessLeapSecondInformation, // qs: PROCESS_LEAP_SECOND_INFORMATION
        ProcessFiberShadowStackAllocation, // s: PROCESS_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION // since 19H1
        ProcessFreeFiberShadowStackAllocation, // s: PROCESS_FREE_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION
        ProcessAltSystemCallInformation, // s: PROCESS_SYSCALL_PROVIDER_INFORMATION // since 20H1 // 100
        ProcessDynamicEHContinuationTargets, // s: PROCESS_DYNAMIC_EH_CONTINUATION_TARGETS_INFORMATION
        ProcessDynamicEnforcedCetCompatibleRanges, // s: PROCESS_DYNAMIC_ENFORCED_ADDRESS_RANGE_INFORMATION // since 20H2
        ProcessCreateStateChange, // since WIN11
        ProcessApplyStateChange,
        ProcessEnableOptionalXStateFeatures, // s: ULONG64 // optional XState feature bitmask
        ProcessAltPrefetchParam, // qs: OVERRIDE_PREFETCH_PARAMETER // App Launch Prefetch (ALPF) // since 22H1
        ProcessAssignCpuPartitions, // HANDLE
        ProcessPriorityClassEx, // s: PROCESS_PRIORITY_CLASS_EX
        ProcessMembershipInformation, // q: PROCESS_MEMBERSHIP_INFORMATION
        ProcessEffectiveIoPriority, // q: IO_PRIORITY_HINT // 110
        ProcessEffectivePagePriority, // q: ULONG
        ProcessSchedulerSharedData, // SCHEDULER_SHARED_DATA_SLOT_INFORMATION // since 24H2
        ProcessSlistRollbackInformation,
        ProcessNetworkIoCounters, // q: PROCESS_NETWORK_COUNTERS
        ProcessFindFirstThreadByTebValue, // PROCESS_TEB_VALUE_INFORMATION
        ProcessEnclaveAddressSpaceRestriction, // since 25H2
        ProcessAvailableCpus,
        MaxProcessInfoClass
    } PROCESSINFOCLASS;

    // https://github.com/winsiderss/systeminformer/blob/cc931ddaf76f62e313cf7b9f5a81ef0c54590088/phnt/include/ntpsapi.h#L302
    typedef enum _THREADINFOCLASS {
        ThreadBasicInformation, // q: THREAD_BASIC_INFORMATION
        ThreadTimes, // q: KERNEL_USER_TIMES
        ThreadPriority, // s: KPRIORITY (requires SeIncreaseBasePriorityPrivilege)
        ThreadBasePriority, // s: KPRIORITY
        ThreadAffinityMask, // s: KAFFINITY
        ThreadImpersonationToken, // s: HANDLE
        ThreadDescriptorTableEntry, // q: DESCRIPTOR_TABLE_ENTRY (or WOW64_DESCRIPTOR_TABLE_ENTRY)
        ThreadEnableAlignmentFaultFixup, // s: BOOLEAN
        ThreadEventPair, // Obsolete
        ThreadQuerySetWin32StartAddress, // q: ULONG_PTR
        ThreadZeroTlsCell, // s: ULONG // TlsIndex // 10
        ThreadPerformanceCount, // q: LARGE_INTEGER
        ThreadAmILastThread, // q: ULONG
        ThreadIdealProcessor, // s: ULONG
        ThreadPriorityBoost, // qs: ULONG
        ThreadSetTlsArrayAddress, // s: ULONG_PTR // Obsolete
        ThreadIsIoPending, // q: ULONG
        ThreadHideFromDebugger, // q: BOOLEAN; s: void
        ThreadBreakOnTermination, // qs: ULONG
        ThreadSwitchLegacyState, // s: void // NtCurrentThread // NPX/FPU
        ThreadIsTerminated, // q: ULONG // 20
        ThreadLastSystemCall, // q: THREAD_LAST_SYSCALL_INFORMATION
        ThreadIoPriority, // qs: IO_PRIORITY_HINT (requires SeIncreaseBasePriorityPrivilege)
        ThreadCycleTime, // q: THREAD_CYCLE_TIME_INFORMATION (requires THREAD_QUERY_LIMITED_INFORMATION)
        ThreadPagePriority, // qs: PAGE_PRIORITY_INFORMATION
        ThreadActualBasePriority, // s: LONG (requires SeIncreaseBasePriorityPrivilege)
        ThreadTebInformation, // q: THREAD_TEB_INFORMATION (requires THREAD_GET_CONTEXT + THREAD_SET_CONTEXT)
        ThreadCSwitchMon, // Obsolete
        ThreadCSwitchPmu, // Obsolete
        ThreadWow64Context, // qs: WOW64_CONTEXT, ARM_NT_CONTEXT since 20H1
        ThreadGroupInformation, // qs: GROUP_AFFINITY // 30
        ThreadUmsInformation, // q: THREAD_UMS_INFORMATION // Obsolete
        ThreadCounterProfiling, // q: BOOLEAN; s: THREAD_PROFILING_INFORMATION?
        ThreadIdealProcessorEx, // qs: PROCESSOR_NUMBER; s: previous PROCESSOR_NUMBER on return
        ThreadCpuAccountingInformation, // q: BOOLEAN; s: HANDLE (NtOpenSession) // NtCurrentThread // since WIN8
        ThreadSuspendCount, // q: ULONG // since WINBLUE
        ThreadHeterogeneousCpuPolicy, // q: KHETERO_CPU_POLICY // since THRESHOLD
        ThreadContainerId, // q: GUID
        ThreadNameInformation, // qs: THREAD_NAME_INFORMATION (requires THREAD_SET_LIMITED_INFORMATION)
        ThreadSelectedCpuSets, // q: ULONG[]
        ThreadSystemThreadInformation, // q: SYSTEM_THREAD_INFORMATION // 40
        ThreadActualGroupAffinity, // q: GROUP_AFFINITY // since THRESHOLD2
        ThreadDynamicCodePolicyInfo, // q: ULONG; s: ULONG (NtCurrentThread)
        ThreadExplicitCaseSensitivity, // qs: ULONG; s: 0 disables, otherwise enables // (requires SeDebugPrivilege and PsProtectedSignerAntimalware)
        ThreadWorkOnBehalfTicket, // RTL_WORK_ON_BEHALF_TICKET_EX
        ThreadSubsystemInformation, // q: SUBSYSTEM_INFORMATION_TYPE // since REDSTONE2
        ThreadDbgkWerReportActive, // s: ULONG; s: 0 disables, otherwise enables
        ThreadAttachContainer, // s: HANDLE (job object) // NtCurrentThread
        ThreadManageWritesToExecutableMemory, // MANAGE_WRITES_TO_EXECUTABLE_MEMORY // since REDSTONE3
        ThreadPowerThrottlingState, // qs: POWER_THROTTLING_THREAD_STATE // since REDSTONE3 (set), WIN11 22H2 (query)
        ThreadWorkloadClass, // THREAD_WORKLOAD_CLASS // since REDSTONE5 // 50
        ThreadCreateStateChange, // since WIN11
        ThreadApplyStateChange,
        ThreadStrongerBadHandleChecks, // s: ULONG // NtCurrentThread // since 22H1
        ThreadEffectiveIoPriority, // q: IO_PRIORITY_HINT
        ThreadEffectivePagePriority, // q: ULONG
        ThreadUpdateLockOwnership, // THREAD_LOCK_OWNERSHIP // since 24H2
        ThreadSchedulerSharedDataSlot, // SCHEDULER_SHARED_DATA_SLOT_INFORMATION
        ThreadTebInformationAtomic, // q: THREAD_TEB_INFORMATION (requires THREAD_GET_CONTEXT + THREAD_QUERY_INFORMATION)
        ThreadIndexInformation, // THREAD_INDEX_INFORMATION
        MaxThreadInfoClass
    } THREADINFOCLASS;

    // https://github.com/winsiderss/systeminformer/blob/cc931ddaf76f62e313cf7b9f5a81ef0c54590088/phnt/include/ntpsapi.h#L3761C1-L3765C25
    typedef enum _PSSNT_DUPLICATE_FLAGS {
        PSSNT_DUPLICATE_NONE = 0x00,
        PSSNT_DUPLICATE_CLOSE_SOURCE = 0x01
    } PSSNT_DUPLICATE_FLAGS;

    // ============================= functions =============================
    
	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSAPI NTSTATUS NTAPI NtAcquireProcessActivityReference(
		_Out_ PHANDLE pHandle,
		_In_ HANDLE hProcess,
		ULONG Unknown);
	//ZwAcquireProcessActivityReference

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSAPI NTSTATUS NTAPI NtAlertResumeThread(
		_In_ HANDLE ThreadHandle,
		_Out_ PULONG pSuspendCount);
	//ZwAlertResumeThread

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSAPI NTSTATUS NTAPI NtAlertThreadByThreadId(
		_In_ ULONG ThreadId);
	//ZwAlertThreadByThreadId

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSAPI NTSTATUS NTAPI NtApphelpCacheControl(
		_In_ ULONG ServiceClass,
		_In_ PUNICODE_STRING ServiceData);
	//ZwApphelpCacheControl

    // https://www.microsoft.com/en-us/security/blog/2022/06/30/using-process-creation-properties-to-catch-evasion-techniques/
    // https://captmeelo.com/redteam/maldev/2022/05/10/ntcreateuserprocess.html
	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSAPI NTSTATUS NTAPI NtCreateProcess(
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
	NTSYSAPI NTSTATUS NTAPI NtCreateProcessEx(
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
	NTSYSAPI NTSTATUS NTAPI NtCreateThread(
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
	NTSYSAPI NTSTATUS NTAPI NtCreateThreadEx(
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
	NTSYSAPI NTSTATUS NTAPI NtCreateUserProcess(
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
	NTSYSAPI NTSTATUS NTAPI NtCreateWorkerFactory(
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
	NTSYSAPI NTSTATUS NTAPI NtDelayExecution(
		_In_ BOOLEAN Alertable,
		_In_ PLARGE_INTEGER DelayInterval);
	//ZwDelayExecution

    // https://processhacker.sourceforge.io/doc/ntzwapi_8h_source.html
    NTSYSAPI NTSTATUS NTAPI ZwGetContextThread(
        _In_ HANDLE ThreadHandle,
        _Inout_ PCONTEXT ThreadContext);
    //ZwGetContextThread

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSAPI NTSTATUS NTAPI NtGetNextProcess(
        HANDLE ProcessHandle,
        PROCESS_ACCESS_MASK DesiredAccess,
        ULONG HandleAttributes,
        ULONG Flags,
        PHANDLE NewProcessHandle);
    //ZwGetNextProcess

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSAPI NTSTATUS NTAPI NtGetNextThread(
        HANDLE ProcessHandle,
        HANDLE ThreadHandle,
        THREAD_ACCESS_MASK DesiredAccess,
        ULONG HandleAttributes,
        ULONG Flags,
        PHANDLE NewThreadHandle);
    //ZwGetNextThread

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-ntopenprocess
    NTSYSAPI NTSTATUS NtOpenProcess(
        _Out_ PHANDLE ProcessHandle,
        _In_ ACCESS_MASK DesiredAccess,
        _In_ POBJECT_ATTRIBUTES ObjectAttributes,
        _In_opt_ PCLIENT_ID ClientId);
    //ZwOpenProcess

    // https://learn.microsoft.com/en-us/windows/win32/devnotes/ntopenthread
    NTSYSAPI NTSTATUS NtOpenThread(
        _Out_ PHANDLE ThreadHandle,
        _In_ ACCESS_MASK DesiredAccess,
        _In_ POBJECT_ATTRIBUTES ObjectAttributes,
        _In_ PCLIENT_ID ClientId);
    //ZwOpenThread

    // See winternl.h
    // https://processhacker.sourceforge.io/doc/ntzwapi_8h_source.html
    NTSYSAPI NTSTATUS NTAPI NtQueryInformationProcess(
        _In_ HANDLE ProcessHandle,
        _In_ PROCESSINFOCLASS ProcessInformationClass,
        _Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
        _In_ ULONG ProcessInformationLength,
        _Out_opt_ PULONG ReturnLength);
    //ZwQueryInformationProcess

    // See winternl.h
    // https://processhacker.sourceforge.io/doc/ntzwapi_8h_source.html
    NTSYSAPI NTSTATUS NTAPI NtQueryInformationThread(
        _In_ HANDLE ThreadHandle,
        _In_ THREADINFOCLASS ThreadInformationClass,
        _Out_writes_bytes_(ThreadInformationLength) PVOID ThreadInformation,
        _In_ ULONG ThreadInformationLength,
        _Out_opt_ PULONG ReturnLength);
    //ZwQueryInformationThread

    // https://github.com/Uri3n/Thread-Pool-Injection-PoC/blob/main/include/FunctionPtrs.hpp
    // https://urien.gitbook.io/diago-lima/a-deep-dive-into-exploiting-windows-thread-pools/attacking-worker-factories
    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSAPI NTSTATUS NTAPI NtQueryInformationWorkerFactory(
        _In_ HANDLE WorkerFactoryHandle,
        _In_ WORKERFACTORYINFOCLASS WorkerFactoryInformationClass,
        _Out_ PVOID Buffer,
        _In_ ULONG BufferLength,
        _Out_opt_ PULONG ReturnLength);
    //ZwQueryInformationWorkerFactory

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSAPI NTSTATUS NTAPI NtQueueApcThread(
        _In_ HANDLE ThreadHandle,
        _In_ PVOID ApcRoutine,
        _In_ PVOID Context,
        _In_ PVOID Argument1,
        _In_ PVOID Argument2);
    //ZwQueueApcThread

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSAPI NTSTATUS NTAPI NtQueueApcThreadEx(
        _In_ HANDLE ThreadHandle,
        _In_ HANDLE ApcReserve,
        _In_ PVOID ApcRoutine,
        _In_ PVOID Context,
        _In_ PVOID Argument1,
        _In_ PVOID Argument2);
    //ZwQueueApcThreadEx

    // https://github.com/winsiderss/systeminformer/blob/cc931ddaf76f62e313cf7b9f5a81ef0c54590088/phnt/include/ntpsapi.h#L2666
    NTSYSAPI NTSTATUS NTAPI NtQueueApcThreadEx2(
        _In_ HANDLE ThreadHandle,
        _In_ HANDLE ApcReserve,
        _In_ ULONG QueueUserApcFlags,
        _In_ PPS_APC_ROUTINE ApcRoutine,
        _In_opt_ PVOID SystemArgument1,
        _In_opt_ PVOID SystemArgument2,
        _In_opt_ PVOID SystemArgument3);
    //ZwQueueApcThreadEx2

    // https://github.com/winsiderss/systeminformer/blob/cc931ddaf76f62e313cf7b9f5a81ef0c54590088/phnt/include/ntexapi.h#L5909
    NTSYSAPI NTSTATUS NTAPI NtRaiseHardError(
        _In_ NTSTATUS ErrorStatus,
        _In_ ULONG NumberOfParameters,
        _In_ ULONG ParameterMask,
        _In_reads_(NumberOfParameters) PULONG_PTR Parameters,
        _In_ HARDERROR_RESPONSE_OPTION ResponseOptions,
        _Out_ PULONG Response);
    //ZwRaiseHardError

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSAPI NTSTATUS NTAPI NtReleaseWorkerFactoryWorker(
        _In_ HANDLE WorkerFactoryHandle);
    //ZwReleaseWorkerFactoryWorker

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSAPI NTSTATUS NTAPI NtResumeProcess(
        _In_ HANDLE hProcess);
    //ZwResumeProcess

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSAPI NTSTATUS NTAPI NtResumeThread(
        _In_ HANDLE ThreadHandle,
        _Out_ PULONG SuspendCount);
    //ZwResumeThread

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSAPI NTSTATUS NTAPI NtSetContextThread(
        _In_ HANDLE ThreadHandle,
        _In_ PCONTEXT pContext);
    //ZwSetContextThread

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSAPI NTSTATUS NTAPI NtSetDefaultHardErrorPort(
        _In_ HANDLE Port);
    //ZwSetDefaultHardErrorPort

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSAPI NTSTATUS NTAPI NtSetInformationProcess(
        _In_ HANDLE ProcessHandle,
        _In_ PROCESSINFOCLASS ProcessInformationClass,
        _In_ PVOID ProcessInformation,
        _In_ ULONG Length);
    //ZwSetInformationProcess

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntsetinformationthread
    // See winternl.h
    // https://processhacker.sourceforge.io/doc/ntzwapi_8h_source.html
    NTSYSAPI NTSTATUS NTAPI ZwSetInformationThread(
        _In_ HANDLE ThreadHandle,
        _In_ THREADINFOCLASS ThreadInformationClass,
        _In_reads_bytes_(ThreadInformationLength) PVOID ThreadInformation,
        _In_ ULONG ThreadInformationLength);
    // ZwSetInformationThread

    // https://urien.gitbook.io/diago-lima/a-deep-dive-into-exploiting-windows-thread-pools/attacking-worker-factories
    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSAPI NTSTATUS NTAPI NtSetInformationWorkerFactory(
        _In_ HANDLE WorkerFactoryHandle,
        _In_ WORKERFACTORYINFOCLASS InformationClass,
        _In_ PVOID Buffer,
        _In_ ULONG BufferLength);
    //ZwSetInformationWorkerFactory

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSAPI NTSTATUS NTAPI NtShutdownWorkerFactory(
        _In_ HANDLE WorkerFactoryHandle,
        _Inout_ PULONG PendingWorkerCount);
    //ZwShutdownWorkerFactory

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSAPI NTSTATUS NTAPI NtSuspendProcess(
        _In_ HANDLE ProcessHandle);
    //ZwSuspendProcess

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSAPI NTSTATUS NTAPI NtSuspendThread(
        _In_ HANDLE ThreadHandle,
        _Out_opt_ PULONG PreviousSuspendCount);
    //ZwSuspendThread

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSAPI NTSTATUS NTAPI NtTerminateProcess(
        _In_ HANDLE ProcessHandle,
        _In_ NTSTATUS ExitStatus);
    //ZwTerminateProcess

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSAPI NTSTATUS NTAPI NtTerminateThread(
        _In_ HANDLE ThreadHandle,
        _In_ NTSTATUS ExitStatus);
    //ZwTerminateThread

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSAPI NTSTATUS NTAPI NtTestAlert();
    //ZwTestAlert

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSAPI NTSTATUS NTAPI NtUmsThreadYield(
        _In_ PVOID SchedulerParam);
    //ZwUmsThreadYield

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSAPI NTSTATUS NTAPI NtWaitForAlertByThreadId(
        _In_ HANDLE Handle,
        _In_opt_ PLARGE_INTEGER Timeout);
    //ZwWaitForAlertByThreadId

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSAPI NTSTATUS NTAPI NtWaitForWorkViaWorkerFactory(
        _In_ HANDLE WorkerFactoryHandle,
        _Out_ PVOID MiniPacket);
    //ZwWaitForWorkViaWorkerFactory

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSAPI NTSTATUS NTAPI NtWorkerFactoryWorkerReady(
        _In_ HANDLE WorkerFactoryHandle);
    //ZwWorkerFactoryWorkerReady

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSAPI NTSTATUS NTAPI NtYieldExecution();
    //ZwYieldExecution

    //https://github.com/fortra/nanodump/blob/main/include/handle.h
    NTSYSAPI NTSTATUS NTAPI PssNtCaptureSnapshot(
        PHANDLE SnapshotHandle,
        HANDLE ProcessHandle,
        DWORD CaptureFlags,
        DWORD ThreadContextFlags);

    // https://github.com/winsiderss/systeminformer/blob/cc931ddaf76f62e313cf7b9f5a81ef0c54590088/phnt/include/ntpsapi.h#L3814
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
        _In_ HPSS SnapshotHandle,
        _In_ PSS_WALK_INFORMATION_CLASS InformationClass,
        _In_ HPSSWALK WalkMarkerHandle,
        _Out_ void* Buffer,
        _In_ DWORD BufferLength);

    // https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntrtl.h#L3177C1-L3191C7
    NTSYSAPI NTSTATUS NTAPI RtlCreateUserProcess(
        _In_ PUNICODE_STRING NtImagePathName,
        _In_ ULONG ExtendedParameters, // HIWORD(NumaNodeNumber), LOWORD(Reserved)
        _In_ PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
        _In_opt_ PSECURITY_DESCRIPTOR ProcessSecurityDescriptor,
        _In_opt_ PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
        _In_opt_ HANDLE ParentProcess,
        _In_ BOOLEAN InheritHandles,
        _In_opt_ HANDLE DebugPort,
        _In_opt_ HANDLE TokenHandle, // used to be ExceptionPort
        _Out_ PRTL_USER_PROCESS_INFORMATION ProcessInformation);

    // https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/process.c
    NTSYSAPI BOOLEAN NTAPI RtlIsCurrentProcess(
        _In_ HANDLE handle);

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlqueryprocessplaceholdercompatibilitymode
    NTSYSAPI CHAR RtlQueryProcessPlaceholderCompatibilityMode();

    // https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntrtl.h#L9346
    NTSYSAPI NTSTATUS NTAPI RtlQueueApcWow64Thread(
        _In_ HANDLE ThreadHandle,
        _In_ PPS_APC_ROUTINE ApcRoutine,
        _In_opt_ PVOID NormalContext,
        _In_opt_ PVOID SystemArgument1,
        _In_opt_ PVOID SystemArgument2);

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlsetprocessplaceholdercompatibilitymode
    NTSYSAPI CHAR RtlSetProcessPlaceholderCompatibilityMode(
        CHAR Mode);

    // https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/process.c
    NTSYSAPI NTSTATUS NTAPI RtlWow64GetProcessMachines(
        HANDLE process,
        USHORT* current_ret,
        USHORT* native_ret);

    // https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/process.c
    NTSYSAPI NTSTATUS NTAPI RtlWow64GetSharedInfoProcess(
        HANDLE process,
        BOOLEAN* is_wow64,
        WOW64INFO* info);

}

#endif // _NTPROCESSES_
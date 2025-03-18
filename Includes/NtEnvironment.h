#pragma once

#ifndef _NTENVIRONMENT_
#define _NTENVIRONMENT_

#include "NtCommonDefs.h"

extern "C" {

    // NO UNRESOLVED FUNCTIONS

    // The official list from the Windows SDK is largely incomplete.
    // A more extensive list can be found from :
    // https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntexapi/system_information_class.htm
    typedef enum _SYSTEM_INFORMATION_CLASS {
        SystemBasicInformation = 0,
        SystemProcessorInformation = 1, // Undocumented
        SystemPerformanceInformation = 2,
        SystemTimeOfDayInformation = 3,
        SystemPathInformation = 4, // Undocumented
        SystemProcessInformation = 5,
        SystemCallCountInformation = 6, // Undocumented
        SystemDeviceInformation = 7, // Undocumented
        SystemProcessorPerformanceInformation = 8,
        SystemFlagsInformation = 9, // Undocumented
        SystemCallTimeInformation = 10,  // Undocumented
        SystemModuleInformation	= 11, // Undocumented
        SystemLocksInformation = 12, // Undocumented
        SystemStackTraceInformation = 13, // Undocumented
        SystemPagedPoolInformation = 14, // Undocumented
        SystemNonPagedPoolInformation = 15, // Undocumented
        SystemHandleInformation = 16, // Undocumented
        SystemObjectInformation = 17, // Undocumented
        SystemPageFileInformation = 18, // Undocumented
        SystemVdmInstemulInformation = 19, // Undocumented
        SystemVdmBopInformation = 20, // Undocumented
        SystemFileCacheInformation = 21, // Undocumented
        SystemPoolTagInformation = 22, // Undocumented
        SystemInterruptInformation = 23,
        SystemDpcBehaviorInformation = 24, // Undocumented
        SystemFullMemoryInformation	= 25, // Undocumented
        SystemLoadGdiDriverInformation = 26, // Undocumented
        SystemUnloadGdiDriverInformation = 27, // Undocumented
        SystemTimeAdjustmentInformation	= 28, // Undocumented
        SystemSummaryMemoryInformation = 29, // Undocumented
        SystemNextEventIdInformation = 30, // Undocumented
        SystemMirrorMemoryInformation = 30, // Undocumented
        SystemEventIdsInformation = 31, // Undocumented
        SystemPerformanceTraceInformation = 31, // Undocumented
        SystemCrashDumpInformation = 32, // Undocumented
        SystemExceptionInformation = 33,
        SystemCrashDumpStateInformation = 34, // Undocumented
        SystemKernelDebuggerInformation = 35, // Undocumented
        SystemContextSwitchInformation = 36, // Undocumented
        SystemRegistryQuotaInformation = 37,
        SystemExtendServiceTableInformation = 38, // Undocumented
        SystemPrioritySeperation = 39, // Undocumented
        SystemPlugPlayBusInformation = 40, // Undocumented
        SystemVerifierAddDriverInformation = 40, // Undocumented
        SystemDockInformation = 41, // Undocumented 3.51 to 4.0
        SystemVerifierRemoveDriverInformation = 41, // Undocumented	5.1 and higher
        SystemPowerInformation = 42, // Undocumented 3.51 to 5.0
        SystemProcessorIdleInformation = 42, // Undocumented 5.1 and higher
        SystemProcessorSpeedInformation	= 43, // Undocumented 3.51 to 4.0
        SystemLegacyDriverInformation = 43, // Undocumented 5.0 and higher
        SystemCurrentTimeZoneInformation = 44, // Undocumented 
        SystemLookasideInformation = 45,
        SystemTimeSlipNotification = 46, // Undocumented 5.0 and higher
        SystemSessionCreate	= 47, // Undocumented 5.0 and higher
        SystemSessionDetach	= 48, // Undocumented 5.0 and higher
        SystemSessionInformation = 49, // Undocumented 5.0 and higher
        SystemRangeStartInformation = 50, // Undocumented 5.0 and higher
        SystemVerifierInformation = 51, // Undocumented 5.0 and higher
        SystemVerifierThunkExtend = 52, // Undocumented 5.0 and higher
        SystemSessionProcessInformation = 53, // Undocumented 5.0 and higher
        SystemObjectSecurityMode = 54, // Undocumented late 5.0 only later as 0x46
        SystemLoadGdiDriverInSystemSpace = 54, // Undocumented 5.1 and higher
        SystemNumaProcessorMap = 55, // Undocumented 5.1 and higher
        SystemPrefetcherInformation	= 56, // Undocumented 5.1 and higher
        SystemExtendedProcessInformation = 57, // Undocumented 5.1 and higher
        SystemRecommendedSharedDataAlignment = 58, // Undocumented 5.1 and higher
        SystemComPlusPackage = 59, // Undocumented 5.1 and higher
        SystemNumaAvailableMemory = 60, // Undocumented 5.1 and higher
        SystemProcessorPowerInformation	= 61, // Undocumented 5.1 and higher
        SystemEmulationBasicInformation	= 62, // Undocumented 5.1 and higher
        SystemEmulationProcessorInformation	= 63, // Undocumented 5.1 and higher
        SystemExtendedHandleInformation	= 64, // Undocumented 5.1 and higher
        SystemLostDelayedWriteInformation = 65, // Undocumented 5.1 and higher
        SystemBigPoolInformation = 66, // Undocumented 5.2 and higher
        SystemSessionPoolTagInformation	= 67, // Undocumented 5.2 and higher
        SystemSessionMappedViewInformation = 68, // Undocumented 5.2 and higher
        SystemHotpatchInformation = 69, // Undocumented late 5.1 and higher
        _SystemObjectSecurityMode = 70, // Undocumented late 5.1 and higher earlier as 0x36
        SystemWatchdogTimerHandler = 71, // Undocumented 5.2 and higher
        SystemWatchdogTimerInformation = 72, // Undocumented 5.2 and higher
        SystemLogicalProcessorInformation = 73, // Undocumented very late 5.1 and higher
        SystemWow64SharedInformationObsolete = 74, // Undocumented late 5.2 and higher
        SystemRegisterFirmwareTableInformationHandler = 75, // Undocumented late 5.2 and higher
        SystemFirmwareTableInformation = 76, // Undocumented late 5.2 and higher
        SystemModuleInformationEx = 77, // Undocumented 6.0 and higher
        SystemVerifierTriageInformation	= 78, // Undocumented 6.0 and higher
        SystemSuperfetchInformation	= 79, // Undocumented 6.0 and higher
        SystemMemoryListInformation	= 80, // Undocumented 6.0 and higher
        SystemFileCacheInformationEx = 81, // Undocumented late 5.2 and higher
        SystemThreadPriorityClientIdInformation	= 82, // Undocumented 6.0 and higher
        SystemProcessorIdleCycleTimeInformation	= 83, // Undocumented 6.0 and higher
        SystemVerifierCancellationInformation = 84, // Undocumented 6.0 and higher
        SystemProcessorPowerInformationEx = 85, // Undocumented 6.0 and higher
        SystemRefTraceInformation = 86, // Undocumented 6.0 and higher
        SystemSpecialPoolInformation = 87, // Undocumented 6.0 and higher
        SystemProcessIdInformation = 88, // Undocumented 6.0 and higher
        SystemErrorPortInformation = 89, // Undocumented 6.0 and higher
        SystemBootEnvironmentInformation = 90, // Undocumented 6.0 and higher
        SystemHypervisorInformation	= 91, // Undocumented 6.0 and higher
        SystemVerifierInformationEx	= 92, // Undocumented 6.0 and higher
        SystemTimeZoneInformation = 93, // Undocumented 6.0 and higher
        SystemImageFileExecutionOptionsInformation = 94, // Undocumented 6.0 and higher
        SystemCoverageInformation = 95, // Undocumented 6.0 and higher
        SystemPrefetchPatchInformation = 96, // Undocumented 6.0 and higher
        SystemVerifierFaultsInformation = 97, // Undocumented 6.0 and higher
        SystemSystemPartitionInformation = 98, // Undocumented 6.0 and higher
        SystemSystemDiskInformation = 99, // Undocumented 6.0 and higher
        SystemProcessorPerformanceDistribution = 100, // Undocumented 6.0 and higher
        SystemNumaProximityNodeInformation = 101, // Undocumented 6.0 and higher
        SystemDynamicTimeZoneInformation = 102, // Undocumented 6.0 and higher
        SystemCodeIntegrityInformation = 103,
        SystemProcessorMicrocodeUpdateInformation = 104, // Undocumented 6.0 and higher
        SystemProcessorBrandString = 105, // Undocumented late 6.0 and higher
        SystemVirtualAddressInformation = 106, // Undocumented late 6.0 and higher
        SystemLogicalProcessorAndGroupInformation = 107, // Undocumented 6.1 and higher
        SystemProcessorCycleTimeInformation = 108, // Undocumented 6.1 and higher
        SystemStoreInformation = 109, // Undocumented 6.1 and higher
        SystemRegistryAppendString = 110, // Undocumented 6.1 and higher
        SystemAitSamplingValue = 111, // Undocumented 6.1 and higher
        SystemVhdBootInformation = 112, // Undocumented 6.1 and higher
        SystemCpuQuotaInformation = 113, // Undocumented 6.1 and higher
        SystemNativeBasicInformation = 114, // Undocumented 6.1 and higher
        SystemErrorPortTimeouts = 115, // Undocumented 	6.1 and higher
        SystemLowPriorityIoInformation = 116, // Undocumented 6.1 and higher
        SystemBootEntropyInformation = 117, // Undocumented 6.1 and higher
        SystemVerifierCountersInformation = 118, // Undocumented 6.1 and higher
        SystemPagedPoolInformationEx = 119, // Undocumented 6.1 and higher
        SystemSystemPtesInformationEx = 120, // Undocumented 6.1 and higher
        SystemNodeDistanceInformation = 121, // Undocumented 6.1 and higher
        SystemAcpiAuditInformation = 122, // Undocumented 6.1 and higher
        SystemBasicPerformanceInformation = 123, // Undocumented 6.1 and higher
        SystemQueryPerformanceCounterInformation = 124, // Undocumented late 6.1 and higher
        SystemSessionBigPoolInformation = 125, // Undocumented 6.2 and higher
        SystemBootGraphicsInformation = 126, // Undocumented 6.2 and higher
        SystemScrubPhysicalMemoryInformation = 127, // Undocumented 6.2 and higher
        SystemBadPageInformation = 128, // Undocumented 6.2 and higher
        SystemProcessorProfileControlArea = 129, // Undocumented 6.2 and higher
        SystemCombinePhysicalMemoryInformation = 130, // Undocumented 6.2 and higher
        SystemEntropyInterruptTimingInformation = 131, // Undocumented 6.2 and higher
        SystemConsoleInformation = 132, // Undocumented 6.2 and higher
        SystemPlatformBinaryInformation = 133, // Undocumented 6.2 and higher
        SystemThrottleNotificationInformation = 134, // Undocumented 6.2 only
        SystemPolicyInformation	= 134, // 6.3 and higher
        SystemHypervisorProcessorCountInformation = 135, // Undocumented 6.2 and higher
        SystemDeviceDataInformation = 136, // Undocumented 6.2 and higher
        SystemDeviceDataEnumerationInformation = 137, // Undocumented 6.2 and higher
        SystemMemoryTopologyInformation = 138, // Undocumented 6.2 and higher
        SystemMemoryChannelInformation = 139, // Undocumented 6.2 and higher
        SystemBootLogoInformation = 140, // Undocumented 6.2 and higher
        SystemProcessorPerformanceInformationEx = 141, // Undocumented 6.2 and higher
        SystemCriticalProcessErrorLogInformation = 142, // Undocumented 1607 and higher
        SystemSecureBootPolicyInformation = 143, // Undocumented 6.2 and higher
        SystemPageFileInformationEx = 144, // Undocumented 6.2 and higher
        SystemSecureBootInformation = 145, // Undocumented 6.2 and higher
        SystemEntropyInterruptTimingRawInformation = 146, // Undocumented 6.2 and higher
        SystemPortableWorkspaceEfiLauncherInformation = 147, // Undocumented 6.2 and higher
        SystemFullProcessInformation = 148, // Undocumented 6.2 and higher
        SystemKernelDebuggerInformationEx = 149, // Undocumented 6.3 and higher
        SystemBootMetadataInformation = 150, // Undocumented 6.3 and higher
        SystemSoftRebootInformation = 151, // Undocumented 	6.3 and higher
        SystemElamCertificateInformation = 152, // Undocumented 6.3 and higher
        SystemOfflineDumpConfigInformation = 153, // Undocumented 6.3 and higher
        SystemProcessorFeaturesInformation = 154, // Undocumented 6.3 and higher
        SystemRegistryReconciliationInformation = 155, // Undocumented 6.3 and higher
        SystemEdidInformation = 156, // Undocumented 6.3 and higher
        SystemManufacturingInformation = 157, // Undocumented 10.0 and higher
        SystemEnergyEstimationConfigInformation = 158, // Undocumented 10.0 and higher
        SystemHypervisorDetailInformation = 159, // Undocumented 10.0 and higher
        SystemProcessorCycleStatsInformation = 160, // Undocumented 10.0 and higher
        SystemVmGenerationCountInformation = 161, // Undocumented 10.0 and higher
        SystemTrustedPlatformModuleInformation = 162, // Undocumented 10.0 and higher
        SystemKernelDebuggerFlags = 163, // Undocumented 10.0 and higher
        SystemCodeIntegrityPolicyInformation = 164, // Undocumented 10.0 and higher
        SystemIsolatedUserModeInformation = 165, // Undocumented 10.0 and higher
        SystemHardwareSecurityTestInterfaceResultsInformation = 166, // Undocumented 10.0 and higher
        SystemSingleModuleInformation = 167, // Undocumented 10.0 and higher
        SystemAllowedCpuSetsInformation = 168, // Undocumented 10.0 and higher
        SystemDmaProtectionInformation = 169, // Undocumented 10.0 and higher
        SystemInterruptCpuSetsInformation = 170, // Undocumented 10.0 and higher
        SystemSecureBootPolicyFullInformation = 171, // Undocumented 10.0 and higher
        SystemCodeIntegrityPolicyFullInformation = 172, // Undocumented 10.0 and higher
        SystemAffinitizedInterruptProcessorInformation = 173, // Undocumented 10.0 and higher
        SystemRootSiloInformation = 174, // Undocumented 10.0 and higher
        SystemCpuSetInformation = 175, // Undocumented 10.0 and higher
        SystemCpuSetTagInformation = 176, // Undocumented 10.0 and higher
        SystemWin32WerStartCallout = 177, // Undocumented 1511 and higher
        SystemSecureKernelProfileInformation = 178, // Undocumented 1511 and higher
        SystemCodeIntegrityPlatformManifestInformation = 179, // Undocumented 1607 and higher
        SystemInterruptSteeringInformation = 180, // Undocumented 1607 and higher
        SystemSuppportedProcessorArchitectures = 181, // Undocumented 1607 and higher
        SystemMemoryUsageInformation = 182, // Undocumented 1607 and higher
        SystemCodeIntegrityCertificateInformation = 183, // Undocumented 1607 and higher
        SystemPhysicalMemoryInformation = 184, // Undocumented 1703 and higher
        SystemControlFlowTransition = 185, // Undocumented 1703 and higher
        SystemKernelDebuggingAllowed = 186, // Undocumented 1703 and higher
        SystemActivityModerationExeState = 187, // Undocumented 1703 and higher
        SystemActivityModerationUserSettings = 188, // Undocumented 1703 and higher
        SystemCodeIntegrityPoliciesFullInformation = 189, // Undocumented 1703 and higher
        SystemCodeIntegrityUnlockInformation = 190, // Undocumented 1703 and higher
        SystemIntegrityQuotaInformation = 191, // Undocumented 1703 and higher
        SystemFlushInformation = 192, // Undocumented 1703 and higher
        SystemProcessorIdleMaskInformation = 193, // Undocumented 1709 and higher
        SystemSecureDumpEncryptionInformation = 194, // Undocumented 1709 and higher
        SystemWriteConstraintInformation = 195, // Undocumented 1709 and higher
        SystemKernelVaShadowInformation = 196, // Undocumented 1803 and higher
        SystemHypervisorSharedPageInformation = 197, // Undocumented 1803 and higher
        SystemFirmwareBootPerformanceInformation = 198, // Undocumented 1803 and higher
        SystemCodeIntegrityVerificationInformation = 199, // Undocumented 1803 and higher
        SystemFirmwarePartitionInformation = 200, // Undocumented 1803 and higher
        SystemSpeculationControlInformation	= 201, // Undocumented 1803 and higher
        SystemDmaGuardPolicyInformation = 202, // Undocumented 1803 and higher
        SystemEnclaveLaunchControlInformation = 203, // Undocumented 1803 and higher
        SystemWorkloadAllowedCpuSetsInformation = 204, // Undocumented 1809 and higher
        SystemCodeIntegrityUnlockModeInformation = 205, // Undocumented 1809 and higher
        SystemLeapSecondInformation	= 206, // Undocumented 1809 and higher
        SystemFlags2Information	= 207, // Undocumented 1809 and higher
        SystemSecurityModelInformation = 208, // Undocumented 1903 and higher
        SystemCodeIntegritySyntheticCacheInformation = 209, // Undocumented 1903 and higher
        SystemFeatureConfigurationInformation = 210, // Undocumented 2004 and higher
        SystemFeatureConfigurationSectionInformation = 211, // Undocumented 2004 and higher
        SystemFeatureUsageSubscriptionInformation = 212, // Undocumented 2004 and higher
        SystemSecureSpeculationControlInformation = 213, // Undocumented 2004 and higher
    } SYSTEM_INFORMATION_CLASS;


    // ========================= functions =========================
    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtEnumerateSystemEnvironmentValuesEx(
        _In_ ULONG Class,
        _Out_ PVOID Buffer,
        _In_ ULONG BufferLength);
    //ZwEnumerateSystemEnvironmentValuesEx

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI ULONG NTAPI NtGetCurrentProcessorNumber();
    //ZwGetCurrentProcessorNumber

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtGetCurrentProcessorNumberEx(
        _Out_opt_ PULONG ProcNumber);
    //ZwGetCurrentProcessorNumberEx

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtIsSystemResumeAutomatic();
    //ZwIsSystemResumeAutomatic

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtQueryDefaultLocale(
        _In_ BOOLEAN UserProfile,
        _Out_ PLCID DefaultLocaleId);
    //ZwQueryDefaultLocale

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtQueryDefaultUILanguage(
        _Out_ PULONG LanguageId);
    //ZwQueryDefaultUILanguage

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtQueryInstallUILanguage(
        _Out_ PULONG LanguageId);
    //ZwQueryInstallUILanguage

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtQuerySystemEnvironmentValue(
        _In_ PUNICODE_STRING Name,
        _Out_ PWSTR Value,
        _In_ ULONG Length,
        _Out_opt_ PULONG ReturnLength);
    //ZwQuerySystemEnvironmentValue

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtQuerySystemEnvironmentValueEx(
        _In_ PUNICODE_STRING VariableName,
        _In_ PVOID Guid,
        _Out_ PVOID Buffer,
        _Inout_ PULONG BufferLength,
        _Inout_ PULONG Attributes);
    //ZwQuerySystemEnvironmentValueEx

    // https://learn.microsoft.com/fr-fr/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation
    // See winternl.h
    // https://raw.githubusercontent.com/x64dbg/TitanEngine/refs/heads/x64dbg/TitanEngine/ntdll.h
    NTSYSCALLAPI NTSTATUS NTAPI NtQuerySystemInformation(
        _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
        _Inout_ PVOID SystemInformation,
        _In_ ULONG SystemInformationLength,
        _Out_opt_ PULONG ReturnLength);
    // ZwQuerySystemInformation

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtQuerySystemInformationEx(
        _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
        _In_ PULONG QueryType,
        _In_ ULONG Alignment,
        _Out_ PVOID SystemInformation,
        _In_ ULONG Length,
        _Out_opt_ PULONG ReturnLength);
    //ZwQuerySystemInformationEx

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtSetDefaultLocale(
        _In_ BOOLEAN UserProfile,
        _In_ LCID LocaleId);
    //ZwSetDefaultLocale

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtSetDefaultUILanguage(
        _In_ ULONG LanguageId);
    //ZwSetDefaultUILanguage

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtSetSystemEnvironmentValue(
        _In_ PUNICODE_STRING Name,
        _In_ PUNICODE_STRING Value);
    //ZwSetSystemEnvironmentValue

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtSetSystemEnvironmentValueEx(
        _In_ PUNICODE_STRING Name,
        _In_ PVOID Guid,
        _In_ PVOID Buffer,
        _In_ ULONG BufferLength,
        _In_ ULONG Attributes);
    //ZwSetSystemEnvironmentValueEx

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtSetSystemInformation(
        _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
        _In_ PVOID SystemInformation,
        _In_ ULONG Length);
    //ZwSetSystemInformation
}

#endif // _NTENVIRONMENT_
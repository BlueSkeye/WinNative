#pragma once

#ifndef _NTSYSINFO_
#define _NTSYSINFO_

#include "NtCommonDefs.h"

#ifdef __cplusplus
extern "C" {
#endif

    // The official list from the Windows SDK is largely incomplete.
    // More extensive lists can be found from :
    // https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntexapi/system_information_class.htm
    // https://github.com/winsiderss/systeminformer/blob/e3ed9a4814f316feff04ce715813f5e8c4c44dfc/phnt/include/ntexapi.h#L1830C1-L2085C1
    typedef enum _SYSTEM_INFORMATION_CLASS {
        SystemBasicInformation = 0, // q: SYSTEM_BASIC_INFORMATION
        SystemProcessorInformation = 1, // q: SYSTEM_PROCESSOR_INFORMATION
        SystemPerformanceInformation = 2, // q: SYSTEM_PERFORMANCE_INFORMATION
        SystemTimeOfDayInformation = 3, // q: SYSTEM_TIMEOFDAY_INFORMATION
        SystemPathInformation = 4, // not implemented
        SystemProcessInformation = 5, // q: SYSTEM_PROCESS_INFORMATION
        SystemCallCountInformation = 6, // q: SYSTEM_CALL_COUNT_INFORMATION
        SystemDeviceInformation = 7, // q: SYSTEM_DEVICE_INFORMATION
        SystemProcessorPerformanceInformation = 8, // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION (EX in: USHORT ProcessorGroup)
        SystemFlagsInformation = 9, // q: SYSTEM_FLAGS_INFORMATION
        SystemCallTimeInformation = 10, // not implemented // SYSTEM_CALL_TIME_INFORMATION // 10
        SystemModuleInformation = 11, // q: RTL_PROCESS_MODULES
        SystemLocksInformation = 12, // q: RTL_PROCESS_LOCKS
        SystemStackTraceInformation = 13, // q: RTL_PROCESS_BACKTRACES
        SystemPagedPoolInformation = 14, // not implemented
        SystemNonPagedPoolInformation = 15, // not implemented
        SystemHandleInformation = 16, // q: SYSTEM_HANDLE_INFORMATION
        SystemObjectInformation = 17, // q: SYSTEM_OBJECTTYPE_INFORMATION mixed with SYSTEM_OBJECT_INFORMATION
        SystemPageFileInformation = 18, // q: SYSTEM_PAGEFILE_INFORMATION
        SystemVdmInstemulInformation = 19, // q: SYSTEM_VDM_INSTEMUL_INFO
        SystemVdmBopInformation = 20, // not implemented // 20
        SystemFileCacheInformation = 21, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemCache)
        SystemPoolTagInformation = 22, // q: SYSTEM_POOLTAG_INFORMATION
        SystemInterruptInformation = 23, // q: SYSTEM_INTERRUPT_INFORMATION (EX in: USHORT ProcessorGroup)
        SystemDpcBehaviorInformation = 24, // q: SYSTEM_DPC_BEHAVIOR_INFORMATION; s: SYSTEM_DPC_BEHAVIOR_INFORMATION (requires SeLoadDriverPrivilege)
        SystemFullMemoryInformation = 25, // not implemented // SYSTEM_MEMORY_USAGE_INFORMATION
        SystemLoadGdiDriverInformation = 26, // s (kernel-mode only)
        SystemUnloadGdiDriverInformation = 27, // s (kernel-mode only)
        SystemTimeAdjustmentInformation = 28, // q: SYSTEM_QUERY_TIME_ADJUST_INFORMATION; s: SYSTEM_SET_TIME_ADJUST_INFORMATION (requires SeSystemtimePrivilege)
        SystemSummaryMemoryInformation = 29, // not implemented // SYSTEM_MEMORY_USAGE_INFORMATION
        SystemMirrorMemoryInformation = 30, // s (requires license value "Kernel-MemoryMirroringSupported") (requires SeShutdownPrivilege) // 30
        SystemPerformanceTraceInformation = 31, // q; s: (type depends on EVENT_TRACE_INFORMATION_CLASS)
        SystemObsolete0 = 32, // not implemented
        SystemExceptionInformation = 33, // q: SYSTEM_EXCEPTION_INFORMATION
        SystemCrashDumpStateInformation = 34, // s: SYSTEM_CRASH_DUMP_STATE_INFORMATION (requires SeDebugPrivilege)
        SystemKernelDebuggerInformation = 35, // q: SYSTEM_KERNEL_DEBUGGER_INFORMATION
        SystemContextSwitchInformation = 36, // q: SYSTEM_CONTEXT_SWITCH_INFORMATION
        SystemRegistryQuotaInformation = 37, // q: SYSTEM_REGISTRY_QUOTA_INFORMATION; s (requires SeIncreaseQuotaPrivilege)
        SystemExtendServiceTableInformation = 38, // s (requires SeLoadDriverPrivilege) // loads win32k only
        SystemPrioritySeparation = 39, // s (requires SeTcbPrivilege)
        SystemVerifierAddDriverInformation = 40, // s: UNICODE_STRING (requires SeDebugPrivilege) // 40
        SystemVerifierRemoveDriverInformation = 41, // s: UNICODE_STRING (requires SeDebugPrivilege)
        SystemProcessorIdleInformation = 42, // q: SYSTEM_PROCESSOR_IDLE_INFORMATION (EX in: USHORT ProcessorGroup)
        SystemLegacyDriverInformation = 43, // q: SYSTEM_LEGACY_DRIVER_INFORMATION
        SystemCurrentTimeZoneInformation = 44, // q; s: RTL_TIME_ZONE_INFORMATION
        SystemLookasideInformation = 45, // q: SYSTEM_LOOKASIDE_INFORMATION
        SystemTimeSlipNotification = 46, // s: HANDLE (NtCreateEvent) (requires SeSystemtimePrivilege)
        SystemSessionCreate = 47, // not implemented
        SystemSessionDetach = 48, // not implemented
        SystemSessionInformation = 49, // not implemented (SYSTEM_SESSION_INFORMATION)
        SystemRangeStartInformation = 50, // q: SYSTEM_RANGE_START_INFORMATION // 50
        SystemVerifierInformation = 51, // q: SYSTEM_VERIFIER_INFORMATION; s (requires SeDebugPrivilege)
        SystemVerifierThunkExtend = 52, // s (kernel-mode only)
        SystemSessionProcessInformation = 53, // q: SYSTEM_SESSION_PROCESS_INFORMATION
        SystemLoadGdiDriverInSystemSpace = 54, // s: SYSTEM_GDI_DRIVER_INFORMATION (kernel-mode only) (same as SystemLoadGdiDriverInformation)
        SystemNumaProcessorMap = 55, // q: SYSTEM_NUMA_INFORMATION
        SystemPrefetcherInformation = 56, // q; s: PREFETCHER_INFORMATION // PfSnQueryPrefetcherInformation
        SystemExtendedProcessInformation = 57, // q: SYSTEM_EXTENDED_PROCESS_INFORMATION
        SystemRecommendedSharedDataAlignment = 58, // q: ULONG // KeGetRecommendedSharedDataAlignment
        SystemComPlusPackage = 58, // q; s: ULONG
        SystemNumaAvailableMemory = 60, // q: SYSTEM_NUMA_INFORMATION // 60
        SystemProcessorPowerInformation = 61, // q: SYSTEM_PROCESSOR_POWER_INFORMATION (EX in: USHORT ProcessorGroup)
        SystemEmulationBasicInformation = 62, // q: SYSTEM_BASIC_INFORMATION
        SystemEmulationProcessorInformation = 63, // q: SYSTEM_PROCESSOR_INFORMATION
        SystemExtendedHandleInformation = 64, // q: SYSTEM_HANDLE_INFORMATION_EX
        SystemLostDelayedWriteInformation = 65, // q: ULONG
        SystemBigPoolInformation = 66, // q: SYSTEM_BIGPOOL_INFORMATION
        SystemSessionPoolTagInformation = 67, // q: SYSTEM_SESSION_POOLTAG_INFORMATION
        SystemSessionMappedViewInformation = 68, // q: SYSTEM_SESSION_MAPPED_VIEW_INFORMATION
        SystemHotpatchInformation = 69, // q; s: SYSTEM_HOTPATCH_CODE_INFORMATION
        SystemObjectSecurityMode = 70, // q: ULONG // 70
        SystemWatchdogTimerHandler = 71, // s: SYSTEM_WATCHDOG_HANDLER_INFORMATION // (kernel-mode only)
        SystemWatchdogTimerInformation = 72, // q: SYSTEM_WATCHDOG_TIMER_INFORMATION // NtQuerySystemInformationEx // (kernel-mode only)
        SystemLogicalProcessorInformation = 73, // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION (EX in: USHORT ProcessorGroup) // NtQuerySystemInformationEx
        SystemWow64SharedInformationObsolete = 74, // not implemented
        SystemRegisterFirmwareTableInformationHandler = 75, // s: SYSTEM_FIRMWARE_TABLE_HANDLER // (kernel-mode only)
        SystemFirmwareTableInformation = 76, // SYSTEM_FIRMWARE_TABLE_INFORMATION
        SystemModuleInformationEx = 77, // q: RTL_PROCESS_MODULE_INFORMATION_EX // since VISTA
        SystemVerifierTriageInformation = 78, // not implemented
        SystemSuperfetchInformation = 79, // q; s: SUPERFETCH_INFORMATION // PfQuerySuperfetchInformation
        SystemMemoryListInformation = 80, // q: SYSTEM_MEMORY_LIST_INFORMATION; s: SYSTEM_MEMORY_LIST_COMMAND (requires SeProfileSingleProcessPrivilege) // 80
        SystemFileCacheInformationEx = 81, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (same as SystemFileCacheInformation)
        SystemThreadPriorityClientIdInformation = 82, // s: SYSTEM_THREAD_CID_PRIORITY_INFORMATION (requires SeIncreaseBasePriorityPrivilege) // NtQuerySystemInformationEx
        SystemProcessorIdleCycleTimeInformation = 83, // q: SYSTEM_PROCESSOR_IDLE_CYCLE_TIME_INFORMATION[] (EX in: USHORT ProcessorGroup) // NtQuerySystemInformationEx
        SystemVerifierCancellationInformation = 84, // SYSTEM_VERIFIER_CANCELLATION_INFORMATION // name:wow64:whNT32QuerySystemVerifierCancellationInformation
        SystemProcessorPowerInformationEx = 85, // not implemented
        SystemRefTraceInformation = 86, // q; s: SYSTEM_REF_TRACE_INFORMATION // ObQueryRefTraceInformation
        SystemSpecialPoolInformation = 87, // q; s: SYSTEM_SPECIAL_POOL_INFORMATION (requires SeDebugPrivilege) // MmSpecialPoolTag, then MmSpecialPoolCatchOverruns != 0
        SystemProcessIdInformation = 88, // q: SYSTEM_PROCESS_ID_INFORMATION
        SystemErrorPortInformation = 89, // s (requires SeTcbPrivilege)
        SystemBootEnvironmentInformation = 90, // q: SYSTEM_BOOT_ENVIRONMENT_INFORMATION // 90
        SystemHypervisorInformation = 91, // q: SYSTEM_HYPERVISOR_QUERY_INFORMATION
        SystemVerifierInformationEx = 92, // q; s: SYSTEM_VERIFIER_INFORMATION_EX
        SystemTimeZoneInformation = 93, // q; s: RTL_TIME_ZONE_INFORMATION (requires SeTimeZonePrivilege)
        SystemImageFileExecutionOptionsInformation = 04, // s: SYSTEM_IMAGE_FILE_EXECUTION_OPTIONS_INFORMATION (requires SeTcbPrivilege)
        SystemCoverageInformation = 95, // q: COVERAGE_MODULES s: COVERAGE_MODULE_REQUEST // ExpCovQueryInformation (requires SeDebugPrivilege)
        SystemPrefetchPatchInformation = 96, // SYSTEM_PREFETCH_PATCH_INFORMATION
        SystemVerifierFaultsInformation = 97, // s: SYSTEM_VERIFIER_FAULTS_INFORMATION (requires SeDebugPrivilege)
        SystemSystemPartitionInformation = 98, // q: SYSTEM_SYSTEM_PARTITION_INFORMATION
        SystemSystemDiskInformation = 99, // q: SYSTEM_SYSTEM_DISK_INFORMATION
        SystemProcessorPerformanceDistribution = 100, // q: SYSTEM_PROCESSOR_PERFORMANCE_DISTRIBUTION (EX in: USHORT ProcessorGroup) // NtQuerySystemInformationEx // 100
        SystemNumaProximityNodeInformation = 101, // q; s: SYSTEM_NUMA_PROXIMITY_MAP
        SystemDynamicTimeZoneInformation = 102, // q; s: RTL_DYNAMIC_TIME_ZONE_INFORMATION (requires SeTimeZonePrivilege)
        SystemCodeIntegrityInformation = 103, // q: SYSTEM_CODEINTEGRITY_INFORMATION // SeCodeIntegrityQueryInformation
        SystemProcessorMicrocodeUpdateInformation = 104, // s: SYSTEM_PROCESSOR_MICROCODE_UPDATE_INFORMATION
        SystemProcessorBrandString = 105, // q: CHAR[] // HaliQuerySystemInformation -> HalpGetProcessorBrandString, info class 23
        SystemVirtualAddressInformation = 106, // q: SYSTEM_VA_LIST_INFORMATION[]; s: SYSTEM_VA_LIST_INFORMATION[] (requires SeIncreaseQuotaPrivilege) // MmQuerySystemVaInformation
        SystemLogicalProcessorAndGroupInformation = 107, // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX (EX in: LOGICAL_PROCESSOR_RELATIONSHIP RelationshipType) // since WIN7 // NtQuerySystemInformationEx // KeQueryLogicalProcessorRelationship
        SystemProcessorCycleTimeInformation = 108, // q: SYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION[] (EX in: USHORT ProcessorGroup) // NtQuerySystemInformationEx
        SystemStoreInformation = 109, // q; s: SYSTEM_STORE_INFORMATION (requires SeProfileSingleProcessPrivilege) // SmQueryStoreInformation
        SystemRegistryAppendString = 110, // s: SYSTEM_REGISTRY_APPEND_STRING_PARAMETERS // 110
        SystemAitSamplingValue = 111, // s: ULONG (requires SeProfileSingleProcessPrivilege)
        SystemVhdBootInformation = 112, // q: SYSTEM_VHD_BOOT_INFORMATION
        SystemCpuQuotaInformation = 113, // q; s: PS_CPU_QUOTA_QUERY_INFORMATION
        SystemNativeBasicInformation = 114, // q: SYSTEM_BASIC_INFORMATION
        SystemErrorPortTimeouts = 115, // SYSTEM_ERROR_PORT_TIMEOUTS
        SystemLowPriorityIoInformation = 116, // q: SYSTEM_LOW_PRIORITY_IO_INFORMATION
        SystemTpmBootEntropyInformation = 117, // q: BOOT_ENTROPY_NT_RESULT // ExQueryBootEntropyInformation
        SystemVerifierCountersInformation = 118, // q: SYSTEM_VERIFIER_COUNTERS_INFORMATION
        SystemPagedPoolInformationEx = 119, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypePagedPool)
        SystemSystemPtesInformationEx = 120, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemPtes) // 120
        SystemNodeDistanceInformation = 121, // q: USHORT[4*NumaNodes] // (EX in: USHORT NodeNumber) // NtQuerySystemInformationEx
        SystemAcpiAuditInformation = 122, // q: SYSTEM_ACPI_AUDIT_INFORMATION // HaliQuerySystemInformation -> HalpAuditQueryResults, info class 26
        SystemBasicPerformanceInformation = 123, // q: SYSTEM_BASIC_PERFORMANCE_INFORMATION // name:wow64:whNtQuerySystemInformation_SystemBasicPerformanceInformation
        SystemQueryPerformanceCounterInformation = 124, // q: SYSTEM_QUERY_PERFORMANCE_COUNTER_INFORMATION // since WIN7 SP1
        SystemSessionBigPoolInformation = 125, // q: SYSTEM_SESSION_POOLTAG_INFORMATION // since WIN8
        SystemBootGraphicsInformation = 126, // q; s: SYSTEM_BOOT_GRAPHICS_INFORMATION (kernel-mode only)
        SystemScrubPhysicalMemoryInformation = 127, // q; s: MEMORY_SCRUB_INFORMATION
        SystemBadPageInformation = 128, // SYSTEM_BAD_PAGE_INFORMATION
        SystemProcessorProfileControlArea = 129, // q; s: SYSTEM_PROCESSOR_PROFILE_CONTROL_AREA
        SystemCombinePhysicalMemoryInformation = 130, // s: MEMORY_COMBINE_INFORMATION, MEMORY_COMBINE_INFORMATION_EX, MEMORY_COMBINE_INFORMATION_EX2 // 130
        SystemEntropyInterruptTimingInformation = 131, // q; s: SYSTEM_ENTROPY_TIMING_INFORMATION
        SystemConsoleInformation = 132, // q; s: SYSTEM_CONSOLE_INFORMATION
        SystemPlatformBinaryInformation = 133, // q: SYSTEM_PLATFORM_BINARY_INFORMATION (requires SeTcbPrivilege)
        SystemPolicyInformation = 134, // q: SYSTEM_POLICY_INFORMATION (Warbird/Encrypt/Decrypt/Execute)
        SystemHypervisorProcessorCountInformation = 135, // q: SYSTEM_HYPERVISOR_PROCESSOR_COUNT_INFORMATION
        SystemDeviceDataInformation = 136, // q: SYSTEM_DEVICE_DATA_INFORMATION
        SystemDeviceDataEnumerationInformation = 137, // q: SYSTEM_DEVICE_DATA_INFORMATION
        SystemMemoryTopologyInformation = 138, // q: SYSTEM_MEMORY_TOPOLOGY_INFORMATION
        SystemMemoryChannelInformation = 139, // q: SYSTEM_MEMORY_CHANNEL_INFORMATION
        SystemBootLogoInformation = 140, // q: SYSTEM_BOOT_LOGO_INFORMATION // 140
        SystemProcessorPerformanceInformationEx = 141, // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION_EX // (EX in: USHORT ProcessorGroup) // NtQuerySystemInformationEx // since WINBLUE
        SystemCriticalProcessErrorLogInformation = 142, // CRITICAL_PROCESS_EXCEPTION_DATA
        SystemSecureBootPolicyInformation = 143, // q: SYSTEM_SECUREBOOT_POLICY_INFORMATION
        SystemPageFileInformationEx = 144, // q: SYSTEM_PAGEFILE_INFORMATION_EX
        SystemSecureBootInformation = 145, // q: SYSTEM_SECUREBOOT_INFORMATION
        SystemEntropyInterruptTimingRawInformation = 146, // q; s: SYSTEM_ENTROPY_TIMING_INFORMATION
        SystemPortableWorkspaceEfiLauncherInformation = 147, // q: SYSTEM_PORTABLE_WORKSPACE_EFI_LAUNCHER_INFORMATION
        SystemFullProcessInformation = 148, // q: SYSTEM_EXTENDED_PROCESS_INFORMATION with SYSTEM_PROCESS_INFORMATION_EXTENSION (requires admin)
        SystemKernelDebuggerInformationEx = 149, // q: SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX
        SystemBootMetadataInformation = 150, // 150 // (requires SeTcbPrivilege)
        SystemSoftRebootInformation = 151, // q: ULONG
        SystemElamCertificateInformation = 152, // s: SYSTEM_ELAM_CERTIFICATE_INFORMATION
        SystemOfflineDumpConfigInformation = 153, // q: OFFLINE_CRASHDUMP_CONFIGURATION_TABLE_V2
        SystemProcessorFeaturesInformation = 154, // q: SYSTEM_PROCESSOR_FEATURES_INFORMATION
        SystemRegistryReconciliationInformation = 155, // s: NULL (requires admin) (flushes registry hives)
        SystemEdidInformation = 156, // q: SYSTEM_EDID_INFORMATION
        SystemManufacturingInformation = 157, // q: SYSTEM_MANUFACTURING_INFORMATION // since THRESHOLD
        SystemEnergyEstimationConfigInformation = 158, // q: SYSTEM_ENERGY_ESTIMATION_CONFIG_INFORMATION
        SystemHypervisorDetailInformation = 159, // q: SYSTEM_HYPERVISOR_DETAIL_INFORMATION
        SystemProcessorCycleStatsInformation = 160, // q: SYSTEM_PROCESSOR_CYCLE_STATS_INFORMATION (EX in: USHORT ProcessorGroup) // NtQuerySystemInformationEx // 160
        SystemVmGenerationCountInformation = 161,
        SystemTrustedPlatformModuleInformation = 162, // q: SYSTEM_TPM_INFORMATION
        SystemKernelDebuggerFlags = 163, // SYSTEM_KERNEL_DEBUGGER_FLAGS
        SystemCodeIntegrityPolicyInformation = 164, // q; s: SYSTEM_CODEINTEGRITYPOLICY_INFORMATION
        SystemIsolatedUserModeInformation = 165, // q: SYSTEM_ISOLATED_USER_MODE_INFORMATION
        SystemHardwareSecurityTestInterfaceResultsInformation = 166,
        SystemSingleModuleInformation = 167, // q: SYSTEM_SINGLE_MODULE_INFORMATION
        SystemAllowedCpuSetsInformation = 168, // s: SYSTEM_WORKLOAD_ALLOWED_CPU_SET_INFORMATION
        SystemVsmProtectionInformation = 169, // q: SYSTEM_VSM_PROTECTION_INFORMATION (previously SystemDmaProtectionInformation)
        SystemInterruptCpuSetsInformation = 170, // q: SYSTEM_INTERRUPT_CPU_SET_INFORMATION // 170
        SystemSecureBootPolicyFullInformation = 171, // q: SYSTEM_SECUREBOOT_POLICY_FULL_INFORMATION
        SystemCodeIntegrityPolicyFullInformation = 172,
        SystemAffinitizedInterruptProcessorInformation = 173, // q: KAFFINITY_EX // (requires SeIncreaseBasePriorityPrivilege)
        SystemRootSiloInformation = 174, // q: SYSTEM_ROOT_SILO_INFORMATION
        SystemCpuSetInformation = 175, // q: SYSTEM_CPU_SET_INFORMATION // since THRESHOLD2
        SystemCpuSetTagInformation = 176, // q: SYSTEM_CPU_SET_TAG_INFORMATION
        SystemWin32WerStartCallout = 177,
        SystemSecureKernelProfileInformation = 178, // q: SYSTEM_SECURE_KERNEL_HYPERGUARD_PROFILE_INFORMATION
        SystemCodeIntegrityPlatformManifestInformation = 179, // q: SYSTEM_SECUREBOOT_PLATFORM_MANIFEST_INFORMATION // NtQuerySystemInformationEx // since REDSTONE
        SystemInterruptSteeringInformation = 180, // q: in: SYSTEM_INTERRUPT_STEERING_INFORMATION_INPUT, out: SYSTEM_INTERRUPT_STEERING_INFORMATION_OUTPUT // NtQuerySystemInformationEx // 180
        SystemSupportedProcessorArchitectures = 181, // p: in opt: HANDLE, out: SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION[] // NtQuerySystemInformationEx
        SystemMemoryUsageInformation = 182, // q: SYSTEM_MEMORY_USAGE_INFORMATION
        SystemCodeIntegrityCertificateInformation = 183, // q: SYSTEM_CODEINTEGRITY_CERTIFICATE_INFORMATION
        SystemPhysicalMemoryInformation = 184, // q: SYSTEM_PHYSICAL_MEMORY_INFORMATION // since REDSTONE2
        SystemControlFlowTransition = 185, // (Warbird/Encrypt/Decrypt/Execute)
        SystemKernelDebuggingAllowed = 186, // s: ULONG
        SystemActivityModerationExeState = 187, // SYSTEM_ACTIVITY_MODERATION_EXE_STATE
        SystemActivityModerationUserSettings = 188, // SYSTEM_ACTIVITY_MODERATION_USER_SETTINGS
        SystemCodeIntegrityPoliciesFullInformation = 189, // NtQuerySystemInformationEx
        SystemCodeIntegrityUnlockInformation = 190, // SYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION // 190
        SystemIntegrityQuotaInformation = 191,
        SystemFlushInformation = 192, // q: SYSTEM_FLUSH_INFORMATION
        SystemProcessorIdleMaskInformation = 193, // q: ULONG_PTR[ActiveGroupCount] // since REDSTONE3
        SystemSecureDumpEncryptionInformation = 194, // NtQuerySystemInformationEx
        SystemWriteConstraintInformation = 195, // SYSTEM_WRITE_CONSTRAINT_INFORMATION
        SystemKernelVaShadowInformation = 196, // SYSTEM_KERNEL_VA_SHADOW_INFORMATION
        SystemHypervisorSharedPageInformation = 197, // SYSTEM_HYPERVISOR_SHARED_PAGE_INFORMATION // since REDSTONE4
        SystemFirmwareBootPerformanceInformation = 198,
        SystemCodeIntegrityVerificationInformation = 199, // SYSTEM_CODEINTEGRITYVERIFICATION_INFORMATION
        SystemFirmwarePartitionInformation = 200, // SYSTEM_FIRMWARE_PARTITION_INFORMATION // 200
        SystemSpeculationControlInformation = 201, // SYSTEM_SPECULATION_CONTROL_INFORMATION // (CVE-2017-5715) REDSTONE3 and above.
        SystemDmaGuardPolicyInformation = 202, // SYSTEM_DMA_GUARD_POLICY_INFORMATION
        SystemEnclaveLaunchControlInformation = 203, // SYSTEM_ENCLAVE_LAUNCH_CONTROL_INFORMATION
        SystemWorkloadAllowedCpuSetsInformation = 204, // SYSTEM_WORKLOAD_ALLOWED_CPU_SET_INFORMATION // since REDSTONE5
        SystemCodeIntegrityUnlockModeInformation = 205, // SYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION
        SystemLeapSecondInformation = 206, // SYSTEM_LEAP_SECOND_INFORMATION
        SystemFlags2Information = 207, // q: SYSTEM_FLAGS_INFORMATION
        SystemSecurityModelInformation = 208, // SYSTEM_SECURITY_MODEL_INFORMATION // since 19H1
        SystemCodeIntegritySyntheticCacheInformation = 209, // NtQuerySystemInformationEx
        SystemFeatureConfigurationInformation = 210, // q: in: SYSTEM_FEATURE_CONFIGURATION_QUERY, out: SYSTEM_FEATURE_CONFIGURATION_INFORMATION; s: SYSTEM_FEATURE_CONFIGURATION_UPDATE // NtQuerySystemInformationEx // since 20H1 // 210
        SystemFeatureConfigurationSectionInformation = 211, // q: in: SYSTEM_FEATURE_CONFIGURATION_SECTIONS_REQUEST, out: SYSTEM_FEATURE_CONFIGURATION_SECTIONS_INFORMATION // NtQuerySystemInformationEx
        SystemFeatureUsageSubscriptionInformation = 212, // q: SYSTEM_FEATURE_USAGE_SUBSCRIPTION_DETAILS; s: SYSTEM_FEATURE_USAGE_SUBSCRIPTION_UPDATE
        SystemSecureSpeculationControlInformation = 213, // SECURE_SPECULATION_CONTROL_INFORMATION
        SystemSpacesBootInformation = 214, // since 20H2
        SystemFwRamdiskInformation = 215, // SYSTEM_FIRMWARE_RAMDISK_INFORMATION
        SystemWheaIpmiHardwareInformation = 216,
        SystemDifSetRuleClassInformation = 217, // SYSTEM_DIF_VOLATILE_INFORMATION
        SystemDifClearRuleClassInformation = 218,
        SystemDifApplyPluginVerificationOnDriver = 219, // SYSTEM_DIF_PLUGIN_DRIVER_INFORMATION
        SystemDifRemovePluginVerificationOnDriver = 220, // SYSTEM_DIF_PLUGIN_DRIVER_INFORMATION // 220
        SystemShadowStackInformation = 221, // SYSTEM_SHADOW_STACK_INFORMATION
        SystemBuildVersionInformation = 222, // q: in: ULONG (LayerNumber), out: SYSTEM_BUILD_VERSION_INFORMATION // NtQuerySystemInformationEx // 222
        SystemPoolLimitInformation = 223, // SYSTEM_POOL_LIMIT_INFORMATION (requires SeIncreaseQuotaPrivilege) // NtQuerySystemInformationEx
        SystemCodeIntegrityAddDynamicStore = 224,
        SystemCodeIntegrityClearDynamicStores = 225,
        SystemDifPoolTrackingInformation = 226,
        SystemPoolZeroingInformation = 227, // q: SYSTEM_POOL_ZEROING_INFORMATION
        SystemDpcWatchdogInformation = 228, // q; s: SYSTEM_DPC_WATCHDOG_CONFIGURATION_INFORMATION
        SystemDpcWatchdogInformation2 = 229, // q; s: SYSTEM_DPC_WATCHDOG_CONFIGURATION_INFORMATION_V2
        SystemSupportedProcessorArchitectures2 = 230, // q: in opt: HANDLE, out: SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION[] // NtQuerySystemInformationEx // 230
        SystemSingleProcessorRelationshipInformation = 231, // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX // (EX in: PROCESSOR_NUMBER Processor) // NtQuerySystemInformationEx
        SystemXfgCheckFailureInformation = 232, // q: SYSTEM_XFG_FAILURE_INFORMATION
        SystemIommuStateInformation = 233, // SYSTEM_IOMMU_STATE_INFORMATION // since 22H1
        SystemHypervisorMinrootInformation = 234, // SYSTEM_HYPERVISOR_MINROOT_INFORMATION
        SystemHypervisorBootPagesInformation = 235, // SYSTEM_HYPERVISOR_BOOT_PAGES_INFORMATION
        SystemPointerAuthInformation = 236, // SYSTEM_POINTER_AUTH_INFORMATION
        SystemSecureKernelDebuggerInformation = 237, // NtQuerySystemInformationEx
        SystemOriginalImageFeatureInformation = 238, // q: in: SYSTEM_ORIGINAL_IMAGE_FEATURE_INFORMATION_INPUT, out: SYSTEM_ORIGINAL_IMAGE_FEATURE_INFORMATION_OUTPUT // NtQuerySystemInformationEx
        SystemMemoryNumaInformation = 239, // SYSTEM_MEMORY_NUMA_INFORMATION_INPUT, SYSTEM_MEMORY_NUMA_INFORMATION_OUTPUT // NtQuerySystemInformationEx
        SystemMemoryNumaPerformanceInformation = 240, // SYSTEM_MEMORY_NUMA_PERFORMANCE_INFORMATION_INPUTSYSTEM_MEMORY_NUMA_PERFORMANCE_INFORMATION_INPUT, SYSTEM_MEMORY_NUMA_PERFORMANCE_INFORMATION_OUTPUT // since 24H2 // 240
        SystemCodeIntegritySignedPoliciesFullInformation = 241,
        SystemSecureCoreInformation = 242, // SystemSecureSecretsInformation
        SystemTrustedAppsRuntimeInformation = 243, // SYSTEM_TRUSTEDAPPS_RUNTIME_INFORMATION
        SystemBadPageInformationEx = 244, // SYSTEM_BAD_PAGE_INFORMATION
        SystemResourceDeadlockTimeout = 245, // ULONG
        SystemBreakOnContextUnwindFailureInformation = 246, // ULONG (requires SeDebugPrivilege)
        SystemOslRamdiskInformation = 247, // SYSTEM_OSL_RAMDISK_INFORMATION
        SystemCodeIntegrityPolicyManagementInformation = 248, // since 25H2
        SystemMemoryNumaCacheInformation = 249,
        SystemProcessorFeaturesBitMapInformation = 250,
        MaxSystemInfoClass
    } SYSTEM_INFORMATION_CLASS;

    // https://learn.microsoft.com/nl-nl/windows/win32/api/winnt/ne-winnt-logical_processor_relationship
    // Query extension for SystemLogicalProcessorAndGroupInformation
    typedef enum _LOGICAL_PROCESSOR_RELATIONSHIP {
        RelationProcessorCore,
        RelationNumaNode,
        RelationCache,
        RelationProcessorPackage,
        RelationGroup,
        RelationProcessorDie,
        RelationNumaNodeEx,
        RelationProcessorModule,
        RelationAll = 0xffff
    } LOGICAL_PROCESSOR_RELATIONSHIP;

    // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-processor_relationship
    typedef struct _PROCESSOR_RELATIONSHIP {
        BYTE           Flags;
        BYTE           EfficiencyClass;
        BYTE           Reserved[20];
        WORD           GroupCount;
        GROUP_AFFINITY GroupMask[ANYSIZE_ARRAY];
    } PROCESSOR_RELATIONSHIP, * PPROCESSOR_RELATIONSHIP;

    // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-numa_node_relationship
    typedef struct _NUMA_NODE_RELATIONSHIP {
        DWORD NodeNumber;
        BYTE  Reserved[18];
        WORD  GroupCount;
        union {
            GROUP_AFFINITY GroupMask;
            GROUP_AFFINITY GroupMasks[ANYSIZE_ARRAY];
        } DUMMYUNIONNAME;
    } NUMA_NODE_RELATIONSHIP, * PNUMA_NODE_RELATIONSHIP;

    // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-processor_cache_type
    typedef enum _PROCESSOR_CACHE_TYPE {
        CacheUnified,
        CacheInstruction,
        CacheData,
        CacheTrace,
        CacheUnknown
    } PROCESSOR_CACHE_TYPE, * PPROCESSOR_CACHE_TYPE;

    // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-cache_relationship
    typedef struct _CACHE_RELATIONSHIP {
        BYTE                 Level;
        BYTE                 Associativity;
        WORD                 LineSize;
        DWORD                CacheSize;
        PROCESSOR_CACHE_TYPE Type;
        BYTE                 Reserved[18];
        WORD                 GroupCount;
        union {
            GROUP_AFFINITY GroupMask;
            GROUP_AFFINITY GroupMasks[ANYSIZE_ARRAY];
        } DUMMYUNIONNAME;
    } CACHE_RELATIONSHIP, * PCACHE_RELATIONSHIP;

    // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-processor_group_info
    typedef struct _PROCESSOR_GROUP_INFO {
        BYTE      MaximumProcessorCount;
        BYTE      ActiveProcessorCount;
        BYTE      Reserved[38];
        KAFFINITY ActiveProcessorMask;
    } PROCESSOR_GROUP_INFO, * PPROCESSOR_GROUP_INFO;

    // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-group_relationship
    typedef struct _GROUP_RELATIONSHIP {
        WORD                 MaximumGroupCount;
        WORD                 ActiveGroupCount;
        BYTE                 Reserved[20];
        PROCESSOR_GROUP_INFO GroupInfo[ANYSIZE_ARRAY];
    } GROUP_RELATIONSHIP, * PGROUP_RELATIONSHIP;

    // https://learn.microsoft.com/nl-nl/windows/win32/api/winnt/ns-winnt-system_logical_processor_information_ex
    // Answer for SystemLogicalProcessorAndGroupInformation
    typedef struct _SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX {
        LOGICAL_PROCESSOR_RELATIONSHIP Relationship;
        DWORD                          Size;
        union {
            PROCESSOR_RELATIONSHIP Processor;
            NUMA_NODE_RELATIONSHIP NumaNode;
            CACHE_RELATIONSHIP     Cache;
            GROUP_RELATIONSHIP     Group;
        } DUMMYUNIONNAME;
    } SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX, * PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX;
        
#ifdef __cplusplus
}
#endif

#endif // _NTSYSINFO_
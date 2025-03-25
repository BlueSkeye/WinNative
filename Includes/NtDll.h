#pragma once

#include "NtCommonDefs.h"
#include "NtAccessRights.h"
#include "NtExceptionRecord.h"
#include "NtPeImage.h"
#include "NtRuntimeFunctions.h"

#ifndef _NTDLL_
#define _NTDLL_

#ifdef __cplusplus
extern "C" {
#endif

	// UNRESOLVED FUNCTIONS

	// Theese three functions are quite intricated. Actually the exported addresses are just in the
	// middle of the RtlInterlockedPopEntrySList function itself. They are most certainly used for
	// handling some intricate use cases where the "pop entry" is not so interlocked because the
	// operation has been preempted and initial acquired lock may have been released !!! requiring
	// some kind of "restart".
	//ExpInterlockedPopEntrySListEnd
	//ExpInterlockedPopEntrySListFault
	//ExpInterlockedPopEntrySListResume

	//RtlActivateActivationContextUnsafeFast
	// END OF UNRESOLVED FUNCTIONS

	// From ntdef.h
	typedef LARGE_INTEGER PHYSICAL_ADDRESS, * PPHYSICAL_ADDRESS;
	typedef void* PUMS_CONTEXT;

	// From winnt.h
	typedef enum _OS_DEPLOYEMENT_STATE_VALUES {
		OS_DEPLOYMENT_STANDARD = 1,
		OS_DEPLOYMENT_COMPACT
	} OS_DEPLOYEMENT_STATE_VALUES;

	// https://processhacker.sourceforge.io/doc/ntioapi_8h_source.html
	typedef enum _IO_SESSION_EVENT {
		IoSessionEventIgnore,
		IoSessionEventCreated,
		IoSessionEventTerminated,
		IoSessionEventConnected,
		IoSessionEventDisconnected,
		IoSessionEventLogon,
		IoSessionEventLogoff,
		IoSessionEventMax
	} IO_SESSION_EVENT;

	// https://processhacker.sourceforge.io/doc/ntioapi_8h_source.html
	typedef enum _IO_SESSION_STATE {
		IoSessionStateCreated,
		IoSessionStateInitialized,
		IoSessionStateConnected,
		IoSessionStateDisconnected,
		IoSessionStateDisconnectedLoggedOn,
		IoSessionStateLoggedOn,
		IoSessionStateLoggedOff,
		IoSessionStateTerminated,
		IoSessionStateMax
	} IO_SESSION_STATE;

	// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FHardware%2FNtShutdownSystem.html
	typedef enum _SHUTDOWN_ACTION {
		ShutdownNoReboot,
		ShutdownReboot,
		ShutdownPowerOff
	} SHUTDOWN_ACTION, * PSHUTDOWN_ACTION;

	// privatehttps://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntrtl.h#L7381C1-L7386C34
	typedef struct _RTL_BITMAP_EX {
		ULONG64 SizeOfBitMap;
		PULONG64 Buffer;
	} RTL_BITMAP_EX, * PRTL_BITMAP_EX;

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_cm_partial_resource_descriptor
	typedef struct _CM_PARTIAL_RESOURCE_DESCRIPTOR {
		UCHAR  Type;
		UCHAR  ShareDisposition;
		USHORT Flags;
		union {
			struct {
				PHYSICAL_ADDRESS Start;
				ULONG            Length;
			} Generic;
			struct {
				PHYSICAL_ADDRESS Start;
				ULONG            Length;
			} Port;
			struct {
				USHORT    Level;
				USHORT    Group;
				ULONG     Vector;
				KAFFINITY Affinity;
			} Interrupt;
			struct {
				union {
					struct {
						USHORT    Group;
						USHORT    Reserved;
						USHORT    MessageCount;
						ULONG     Vector;
						KAFFINITY Affinity;
					} Raw;
					struct {
						USHORT    Level;
						USHORT    Group;
						KAFFINITY Affinity;
					} Translated;
				} DUMMYUNIONNAME;
			} MessageInterrupt;
			struct {
				PHYSICAL_ADDRESS Start;
				ULONG            Length;
			} Memory;
			struct {
				ULONG Channel;
				ULONG Port;
				ULONG Reserved1;
			} Dma;
			struct {
				ULONG Channel;
				ULONG RequestLine;
				UCHAR TransferWidth;
				UCHAR Reserved1;
				UCHAR Reserved2;
				UCHAR Reserved3;
			} DmaV3;
			struct {
				ULONG Data[3];
			} DevicePrivate;
			struct {
				ULONG Start;
				ULONG Length;
				ULONG Reserved;
			} BusNumber;
			struct {
				ULONG DataSize;
				ULONG Reserved1;
				ULONG Reserved2;
			} DeviceSpecificData;
			struct {
				PHYSICAL_ADDRESS Start;
				ULONG            Length40;
			} Memory40;
			struct {
				PHYSICAL_ADDRESS Start;
				ULONG            Length48;
			} Memory48;
			struct {
				PHYSICAL_ADDRESS Start;
				ULONG            Length64;
			} Memory64;
			struct {
				UCHAR Class;
				UCHAR Type;
				UCHAR Reserved1;
				UCHAR Reserved2;
				ULONG IdLowPart;
				ULONG IdHighPart;
			} Connection;
		} u;
	} CM_PARTIAL_RESOURCE_DESCRIPTOR, * PCM_PARTIAL_RESOURCE_DESCRIPTOR;

	// From winnt.h
	struct _RTL_CRITICAL_SECTION {
		PRTL_CRITICAL_SECTION_DEBUG DebugInfo;
		//  The following three fields control entering and exiting the critical
		//  section for the resource
		LONG LockCount;
		LONG RecursionCount;
		HANDLE OwningThread;        // from the thread's ClientId->UniqueThread
		HANDLE LockSemaphore;
		ULONG_PTR SpinCount;        // force size on 64-bit systems when packed
	};

	// https://processhacker.sourceforge.io/doc/struct___r_t_l___r_e_s_o_u_r_c_e.html
	typedef struct _RTL_RESOURCE {
		RTL_CRITICAL_SECTION CriticalSection;
		HANDLE SharedSemaphore;
		ULONG NumberOfWaitingShared;
		HANDLE ExclusiveSemaphore;
		ULONG NumberOfWaitingExclusive;
		LONG NumberOfActive;
		HANDLE ExclusiveOwnerThread;
		ULONG Flags;
		PRTL_RESOURCE_DEBUG DebugInfo;
	}RTL_RESOURCE, *PRTL_RESOURCE;

	// https://doxygen.reactos.org/dc/d65/rxact_8c_source.html
	typedef struct _RXACT_DATA {
		ULONG ActionCount;
		ULONG BufferSize;
		ULONG CurrentSize;
	} RXACT_DATA, * PRXACT_DATA;

	// https://doxygen.reactos.org/dc/d65/rxact_8c_source.html
	typedef struct _RXACT_CONTEXT {
		HANDLE RootDirectory;
		HANDLE KeyHandle;
		BOOLEAN CanUseHandles;
		PRXACT_DATA Data;
	} RXACT_CONTEXT, * PRXACT_CONTEXT;

	// https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/shared/ntrtl_x/rtl_barrier.htm
	typedef struct _RTL_BARRIER RTL_BARRIER, * PRTL_BARRIER;
	// Warning. If dynamically aligned, make sure to algin the dynamically allocated space
	// on an 8 byte boundary, such as using a function equivalent to _aligned_malloc
	__declspec(align(8)) struct _RTL_BARRIER {
		volatile DWORD NumberOfThreadsInBarrier;
		volatile DWORD PhaseNumber;
		RTL_SRWLOCK RtlDeleteSafety;
		DWORD ParticipatingThreadsCount;
		DWORD Unused1;
		DWORD Unused2;
		DWORD Unused3;
	};

	// https://processhacker.sourceforge.io/doc/struct___r_t_l___d_e_b_u_g___i_n_f_o_r_m_a_t_i_o_n.html
	typedef struct _RTL_DEBUG_INFORMATION {
		HANDLE SectionHandleClient;
		PVOID ViewBaseClient;
		PVOID ViewBaseTarget;
		ULONG_PTR ViewBaseDelta;
		HANDLE EventPairClient;
		HANDLE EventPairTarget;
		HANDLE TargetProcessId;
		HANDLE TargetThreadHandle;
		ULONG Flags;
		SIZE_T OffsetFree;
		SIZE_T CommitSize;
		SIZE_T ViewSize;
	} RTL_DEBUG_INFORMATION, *PRTL_DEBUG_INFORMATION;

	// https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntrtl.h#L8722C1-L8730C1
	typedef struct _RTL_ACE_DATA {
		UCHAR AceType;
		UCHAR InheritFlags;
		UCHAR AceFlags;
		ACCESS_MASK AccessMask;
		PSID* Sid;
	} RTL_ACE_DATA, * PRTL_ACE_DATA;

	// https://processhacker.sourceforge.io/doc/struct___i_n_i_t_i_a_l___t_e_b.html
	typedef struct _INITIAL_TEB {
		struct {
			PVOID OldStackBase;
			PVOID OldStackLimit;
		} OldInitialTeb;
		PVOID StackBase;
		PVOID StackLimit;
		PVOID StackAllocationBase;
	} INITIAL_TEB, *PINITIAL_TEB;

	typedef NTSTATUS(NTAPI* PUSER_THREAD_START_ROUTINE)(
		_In_ PVOID ThreadParameter);

	// https://github.com/zodiacon/WindowsInternals/blob/b895f4261e64861d45168001a17cc8cd72a79a50/MemLimit/ndk/rtltypes.h#L748C1-L758C66
	typedef struct _RTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME_EXTENDED {
		ULONG Size;
		ULONG Format;
		RTL_ACTIVATION_CONTEXT_STACK_FRAME Frame;
		PVOID Extra1;
		PVOID Extra2;
		PVOID Extra3;
		PVOID Extra4;
	} RTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME_EXTENDED,
		* PRTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME_EXTENDED;

	// From winnt.h
#define RTL_CORRELATION_VECTOR_STRING_LENGTH 129
#define RTL_CORRELATION_VECTOR_VERSION_1 ((CHAR)1)
#define RTL_CORRELATION_VECTOR_VERSION_2 ((CHAR)2)
#define RTL_CORRELATION_VECTOR_VERSION_CURRENT RTL_CORRELATION_VECTOR_VERSION_2
#define RTL_CORRELATION_VECTOR_V1_PREFIX_LENGTH (16)
#define RTL_CORRELATION_VECTOR_V1_LENGTH (64)
#define RTL_CORRELATION_VECTOR_V2_PREFIX_LENGTH (22)
#define RTL_CORRELATION_VECTOR_V2_LENGTH (128)
	typedef struct CORRELATION_VECTOR {
		CHAR Version;
		CHAR Vector[RTL_CORRELATION_VECTOR_STRING_LENGTH];
	} CORRELATION_VECTOR, *PCORRELATION_VECTOR;
	
	// From wdm.h
	typedef struct _RTL_BITMAP_RUN {
		ULONG StartingIndex;
	} RTL_BITMAP_RUN, * PRTL_BITMAP_RUN;

	// https://doxygen.reactos.org/d5/df7/ndk_2rtltypes_8h_source.html
	typedef struct _MESSAGE_RESOURCE_ENTRY {
		USHORT Length;
		USHORT Flags;
		UCHAR Text[ANYSIZE_ARRAY];
	} MESSAGE_RESOURCE_ENTRY, * PMESSAGE_RESOURCE_ENTRY;

	// From winnt.h
	typedef VOID (NTAPI* PFLS_CALLBACK_FUNCTION) (
		_In_ PVOID lpFlsData);

	// From ntifs.h
	//  The context structure is used when generating 8.3 names.  The caller must
	//  always zero out the structure before starting a new generation sequence
	typedef struct _GENERATE_NAME_CONTEXT {
		//  The structure is divided into two strings.  The Name, and extension.
		//  Each part contains the value that was last inserted in the name.
		//  The length values are in terms of wchars and not bytes.  We also
		//  store the last index value used in the generation collision algorithm.
		USHORT Checksum;
		BOOLEAN ChecksumInserted;
		_Field_range_(<= , 8) UCHAR NameLength;        // not including extension
		WCHAR NameBuffer[8];                          // e.g., "ntoskrnl"
		_Field_range_(<= , 4) ULONG ExtensionLength;   // including dot
		WCHAR ExtensionBuffer[4];                     // e.g., ".exe"
		ULONG LastIndexValue;
	} GENERATE_NAME_CONTEXT, * PGENERATE_NAME_CONTEXT;

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L3436C1-L3440C34
	typedef struct _CONTEXT_CHUNK {
		LONG Offset; // Offset may be negative.
		ULONG Length;
	} CONTEXT_CHUNK, * PCONTEXT_CHUNK;

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L3442C1-L3448C28
	typedef struct _CONTEXT_EX {
		CONTEXT_CHUNK All;
		CONTEXT_CHUNK Legacy;
		CONTEXT_CHUNK XState;
		CONTEXT_CHUNK KernelCet;
	} CONTEXT_EX, * PCONTEXT_EX;

	// From ntddk.h
	typedef enum _STATE_LOCATION_TYPE {
		LocationTypeRegistry = 0,
		LocationTypeFileSystem = 1,
		LocationTypeMaximum = 2
	} STATE_LOCATION_TYPE;

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L10596C1-L10618C21
	typedef enum _RTL_BSD_ITEM_TYPE {
		RtlBsdItemVersionNumber, // q; s: ULONG
		RtlBsdItemProductType, // q; s: NT_PRODUCT_TYPE (ULONG)
		RtlBsdItemAabEnabled, // q: s: BOOLEAN // AutoAdvancedBoot
		RtlBsdItemAabTimeout, // q: s: UCHAR // AdvancedBootMenuTimeout
		RtlBsdItemBootGood, // q: s: BOOLEAN // LastBootSucceeded
		RtlBsdItemBootShutdown, // q: s: BOOLEAN // LastBootShutdown
		RtlBsdSleepInProgress, // q: s: BOOLEAN // SleepInProgress
		RtlBsdPowerTransition, // q: s: RTL_BSD_DATA_POWER_TRANSITION
		RtlBsdItemBootAttemptCount, // q: s: UCHAR // BootAttemptCount
		RtlBsdItemBootCheckpoint, // q: s: UCHAR // LastBootCheckpoint
		RtlBsdItemBootId, // q; s: ULONG (USER_SHARED_DATA->BootId)
		RtlBsdItemShutdownBootId, // q; s: ULONG
		RtlBsdItemReportedAbnormalShutdownBootId, // q; s: ULONG
		RtlBsdItemErrorInfo, // RTL_BSD_DATA_ERROR_INFO
		RtlBsdItemPowerButtonPressInfo, // RTL_BSD_POWER_BUTTON_PRESS_INFO
		RtlBsdItemChecksum, // q: s: UCHAR
		RtlBsdPowerTransitionExtension,
		RtlBsdItemFeatureConfigurationState, // q; s: ULONG
		RtlBsdItemRevocationListInfo, // 24H2
		RtlBsdItemMax
	} RTL_BSD_ITEM_TYPE;

	// Reversed. Invoked by KERNEL32.DLL in 10.0.19045.0 version
	typedef struct _COMPLETION_LIST {
		PVOID Unknown;
	} COMPLETION_LIST, * PCOMPLETION_LIST;

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L9570C1-L9579C52
	typedef struct _RTL_UNLOAD_EVENT_TRACE {
		PVOID BaseAddress;
		SIZE_T SizeOfImage;
		ULONG Sequence;
		ULONG TimeDateStamp;
		ULONG CheckSum;
		WCHAR ImageName[32];
		ULONG Version[2];
	} RTL_UNLOAD_EVENT_TRACE, * PRTL_UNLOAD_EVENT_TRACE;

	// From winnt.h
	typedef struct _OSVERSIONINFOW {
		DWORD dwOSVersionInfoSize;
		DWORD dwMajorVersion;
		DWORD dwMinorVersion;
		DWORD dwBuildNumber;
		DWORD dwPlatformId;
		WCHAR  szCSDVersion[128];     // Maintenance string for PSS usage
	} OSVERSIONINFOW, * POSVERSIONINFOW, * LPOSVERSIONINFOW, RTL_OSVERSIONINFOW, * PRTL_OSVERSIONINFOW;

	// From miniport.h
	typedef USHORT IRQ_DEVICE_POLICY, * PIRQ_DEVICE_POLICY;
	enum _IRQ_DEVICE_POLICY_USHORT {
		IrqPolicyMachineDefault = 0,
		IrqPolicyAllCloseProcessors = 1,
		IrqPolicyOneCloseProcessor = 2,
		IrqPolicyAllProcessorsInMachine = 3,
		IrqPolicyAllProcessorsInGroup = 3,
		IrqPolicySpecifiedProcessors = 4,
		IrqPolicySpreadMessagesAcrossAllProcessors = 5,
		IrqPolicyAllProcessorsInMachineWhenSteered = 6,
		IrqPolicyAllProcessorsInGroupWhenSteered = 6
	};

	// From miniport.h
	// Define interrupt priority policy values
	typedef enum _IRQ_PRIORITY {
		IrqPriorityUndefined = 0,
		IrqPriorityLow,
		IrqPriorityNormal,
		IrqPriorityHigh
	} IRQ_PRIORITY, * PIRQ_PRIORITY;

	// From miniport.h
	// NT_PROCESSOR_GROUPS is defined for systems with more than 64 processors.
	// See : https://community.osr.com/t/implementing-processor-groups/56330
	// This structure defines one type of resource requested by the driver
	typedef struct _IO_RESOURCE_DESCRIPTOR {
		UCHAR Option;
		UCHAR Type;                         // use CM_RESOURCE_TYPE
		UCHAR ShareDisposition;             // use CM_SHARE_DISPOSITION
		UCHAR Spare1;
		USHORT Flags;                       // use CM resource flag defines
		USHORT Spare2;                      // align
		union {
			struct {
				ULONG Length;
				ULONG Alignment;
				PHYSICAL_ADDRESS MinimumAddress;
				PHYSICAL_ADDRESS MaximumAddress;
			} Port;
			struct {
				ULONG Length;
				ULONG Alignment;
				PHYSICAL_ADDRESS MinimumAddress;
				PHYSICAL_ADDRESS MaximumAddress;
			} Memory;
			struct {
				ULONG MinimumVector;
				ULONG MaximumVector;
#if defined(NT_PROCESSOR_GROUPS)
				IRQ_DEVICE_POLICY AffinityPolicy;
				USHORT Group;
#else
				IRQ_DEVICE_POLICY AffinityPolicy;
#endif
				IRQ_PRIORITY PriorityPolicy;
				KAFFINITY TargetedProcessors;
			} Interrupt;
			struct {
				ULONG MinimumChannel;
				ULONG MaximumChannel;
			} Dma;
			struct {
				ULONG RequestLine;
				ULONG Reserved;
				ULONG Channel;
				ULONG TransferWidth;
			} DmaV3;
			struct {
				ULONG Length;
				ULONG Alignment;
				PHYSICAL_ADDRESS MinimumAddress;
				PHYSICAL_ADDRESS MaximumAddress;
			} Generic;
			struct {
				ULONG Data[3];
			} DevicePrivate;
			// Bus Number information.
			struct {
				ULONG Length;
				ULONG MinBusNumber;
				ULONG MaxBusNumber;
				ULONG Reserved;
			} BusNumber;
			struct {
				ULONG Priority;   // use LCPRI_Xxx values in cfg.h
				ULONG Reserved1;
				ULONG Reserved2;
			} ConfigData;
			// The following structures provide descriptions
			// for memory resource requirement greater than MAXULONG
			struct {
				ULONG Length40;
				ULONG Alignment40;
				PHYSICAL_ADDRESS MinimumAddress;
				PHYSICAL_ADDRESS MaximumAddress;
			} Memory40;
			struct {
				ULONG Length48;
				ULONG Alignment48;
				PHYSICAL_ADDRESS MinimumAddress;
				PHYSICAL_ADDRESS MaximumAddress;
			} Memory48;
			struct {
				ULONG Length64;
				ULONG Alignment64;
				PHYSICAL_ADDRESS MinimumAddress;
				PHYSICAL_ADDRESS MaximumAddress;
			} Memory64;
			struct {
				UCHAR Class;
				UCHAR Type;
				UCHAR Reserved1;
				UCHAR Reserved2;
				ULONG IdLowPart;
				ULONG IdHighPart;
			} Connection;
		} u;
	} IO_RESOURCE_DESCRIPTOR, * PIO_RESOURCE_DESCRIPTOR;

	// https://github.com/wine-mirror/wine/blob/0927c5c3da7cda8cf476416260286bd299ad6319/include/winnt.h#L1478C1-L1482C36
	typedef struct _XSTATE_FEATURE {
		ULONG Offset;
		ULONG Size;
	} XSTATE_FEATURE, * PXSTATE_FEATURE;

	// https://github.com/wine-mirror/wine/blob/0927c5c3da7cda8cf476416260286bd299ad6319/include/winnt.h#L1484C1-L1499C1
#define MAXIMUM_XSTATE_FEATURES 64
	typedef struct _XSTATE_CONFIGURATION {
		ULONG64 EnabledFeatures;
		ULONG64 EnabledVolatileFeatures;
		ULONG Size;
		ULONG OptimizedSave : 1;
		ULONG CompactionEnabled : 1;
		XSTATE_FEATURE Features[MAXIMUM_XSTATE_FEATURES];
		ULONG64 EnabledSupervisorFeatures;
		ULONG64 AlignedFeatures;
		ULONG AllFeatureSize;
		ULONG AllFeatures[MAXIMUM_XSTATE_FEATURES];
		ULONG64 EnabledUserVisibleSupervisorFeatures;
	} XSTATE_CONFIGURATION, * PXSTATE_CONFIGURATION;

	// https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntrtl.h#L10930C1-L10935C56
	typedef struct _RTL_FEATURE_USAGE_REPORT {
		ULONG FeatureId;
		USHORT ReportingKind;
		USHORT ReportingOptions;
	} RTL_FEATURE_USAGE_REPORT, * PRTL_FEATURE_USAGE_REPORT;

	typedef struct _RTL_UNKNOWN_FLS_DATA RTL_UNKNOWN_FLS_DATA, * PRTL_UNKNOWN_FLS_DATA;

	typedef ULONG RTL_FEATURE_ID;

	// https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntrtl.h#L10938C1-L10943C34
	typedef enum _RTL_FEATURE_CONFIGURATION_TYPE {
		RtlFeatureConfigurationBoot,
		RtlFeatureConfigurationRuntime,
		RtlFeatureConfigurationCount
	} RTL_FEATURE_CONFIGURATION_TYPE;

	typedef ULONG RTL_FEATURE_VARIANT_PAYLOAD;

	// https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntrtl.h#L10946C1-L10964C58
	typedef struct _RTL_FEATURE_CONFIGURATION {
		RTL_FEATURE_ID FeatureId;
		union {
			ULONG Flags;
			struct {
				ULONG Priority : 4;
				ULONG EnabledState : 2;
				ULONG IsWexpConfiguration : 1;
				ULONG HasSubscriptions : 1;
				ULONG Variant : 6;
				ULONG VariantPayloadKind : 2;
				ULONG Reserved : 16;
			} DUMMYSTRUCTNAME;
		} DUMMYUNIONNAME;
		RTL_FEATURE_VARIANT_PAYLOAD VariantPayload;
	} RTL_FEATURE_CONFIGURATION, * PRTL_FEATURE_CONFIGURATION;

	typedef ULONGLONG RTL_FEATURE_CHANGE_STAMP, * PRTL_FEATURE_CHANGE_STAMP;

	// https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntrtl.h#L9836C1-L9857C27
	typedef enum _IMAGE_MITIGATION_POLICY {
		ImageDepPolicy, // RTL_IMAGE_MITIGATION_DEP_POLICY
		ImageAslrPolicy, // RTL_IMAGE_MITIGATION_ASLR_POLICY
		ImageDynamicCodePolicy, // RTL_IMAGE_MITIGATION_DYNAMIC_CODE_POLICY
		ImageStrictHandleCheckPolicy, // RTL_IMAGE_MITIGATION_STRICT_HANDLE_CHECK_POLICY
		ImageSystemCallDisablePolicy, // RTL_IMAGE_MITIGATION_SYSTEM_CALL_DISABLE_POLICY
		ImageMitigationOptionsMask,
		ImageExtensionPointDisablePolicy, // RTL_IMAGE_MITIGATION_EXTENSION_POINT_DISABLE_POLICY
		ImageControlFlowGuardPolicy, // RTL_IMAGE_MITIGATION_CONTROL_FLOW_GUARD_POLICY
		ImageSignaturePolicy, // RTL_IMAGE_MITIGATION_BINARY_SIGNATURE_POLICY
		ImageFontDisablePolicy, // RTL_IMAGE_MITIGATION_FONT_DISABLE_POLICY
		ImageImageLoadPolicy, // RTL_IMAGE_MITIGATION_IMAGE_LOAD_POLICY
		ImagePayloadRestrictionPolicy, // RTL_IMAGE_MITIGATION_PAYLOAD_RESTRICTION_POLICY
		ImageChildProcessPolicy, // RTL_IMAGE_MITIGATION_CHILD_PROCESS_POLICY
		ImageSehopPolicy, // RTL_IMAGE_MITIGATION_SEHOP_POLICY
		ImageHeapPolicy, // RTL_IMAGE_MITIGATION_HEAP_POLICY
		ImageUserShadowStackPolicy, // RTL_IMAGE_MITIGATION_USER_SHADOW_STACK_POLICY
		ImageRedirectionTrustPolicy, // RTL_IMAGE_MITIGATION_REDIRECTION_TRUST_POLICY
		ImageUserPointerAuthPolicy, // RTL_IMAGE_MITIGATION_USER_POINTER_AUTH_POLICY
		MaxImageMitigationPolicy
	} IMAGE_MITIGATION_POLICY;

	// From winnt.h
	typedef enum _ACTIVATION_CONTEXT_INFO_CLASS {
		ActivationContextBasicInformation = 1,
		ActivationContextDetailedInformation = 2,
		AssemblyDetailedInformationInActivationContext = 3,
		FileInformationInAssemblyOfAssemblyInActivationContext = 4,
		RunlevelInformationInActivationContext = 5,
		CompatibilityInformationInActivationContext = 6,
		ActivationContextManifestResourceName = 7,
		MaxActivationContextInfoClass,
		// compatibility with old names
		AssemblyDetailedInformationInActivationContxt = 3,
		FileInformationInAssemblyOfAssemblyInActivationContxt = 4
	} ACTIVATION_CONTEXT_INFO_CLASS;

	// https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntrtl.h#L9185C1-L9194C65
	typedef NTSTATUS(NTAPI* PRTL_QUERY_REGISTRY_ROUTINE)(
		_In_ PCWSTR ValueName,
		_In_ ULONG ValueType,
		_In_ PVOID ValueData,
		_In_ ULONG ValueLength,
		_In_opt_ PVOID Context,
		_In_opt_ PVOID EntryContext);

	// https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntrtl.h#L9196C1-L9205C56
	typedef struct _RTL_QUERY_REGISTRY_TABLE {
		PRTL_QUERY_REGISTRY_ROUTINE QueryRoutine;
		ULONG Flags;
		PWSTR Name;
		PVOID EntryContext;
		ULONG DefaultType;
		PVOID DefaultData;
		ULONG DefaultLength;
	} RTL_QUERY_REGISTRY_TABLE, * PRTL_QUERY_REGISTRY_TABLE;

	// From winnt.h
	typedef enum _RTL_UMS_THREAD_INFO_CLASS {
		UmsThreadInvalidInfoClass = 0,
		UmsThreadUserContext,
		UmsThreadPriority,              // Reserved
		UmsThreadAffinity,              // Reserved
		UmsThreadTeb,
		UmsThreadIsSuspended,
		UmsThreadIsTerminated,
		UmsThreadMaxInfoClass
	} RTL_UMS_THREAD_INFO_CLASS, * PRTL_UMS_THREAD_INFO_CLASS;

	// From winnt.h
	typedef VOID(NTAPI* WORKERCALLBACKFUNC) (PVOID);

	// From winnt.h
	typedef struct _CUSTOM_SYSTEM_EVENT_TRIGGER_CONFIG {
		// Size of the structure in bytes
		DWORD Size;
		// Guid used to identify background task to trigger
		PCWSTR TriggerId;
	} CUSTOM_SYSTEM_EVENT_TRIGGER_CONFIG, * PCUSTOM_SYSTEM_EVENT_TRIGGER_CONFIG;

	// From winnt.h
	typedef enum _HARDWARE_COUNTER_TYPE {
		PMCCounter,
		MaxHardwareCounterType
	} HARDWARE_COUNTER_TYPE, * PHARDWARE_COUNTER_TYPE;

	// From winnt.h
	typedef struct _HARDWARE_COUNTER_DATA {
		HARDWARE_COUNTER_TYPE Type;
		DWORD Reserved;
		DWORD64 Value;
	} HARDWARE_COUNTER_DATA, * PHARDWARE_COUNTER_DATA;

	// From winnt.h
#define MAX_HW_COUNTERS 16
	typedef struct _PERFORMANCE_DATA {
		WORD   Size;
		BYTE  Version;
		BYTE  HwCountersCount;
		DWORD ContextSwitchCount;
		DWORD64 WaitReasonBitMap;
		DWORD64 CycleTime;
		DWORD RetryCount;
		DWORD Reserved;
		HARDWARE_COUNTER_DATA HwCounters[MAX_HW_COUNTERS];
	} PERFORMANCE_DATA, * PPERFORMANCE_DATA;

	typedef VOID(NTAPI* PRTL_FEATURE_CONFIGURATION_CHANGE_CALLBACK)(
		_In_opt_ PVOID Context);

	// https://github.com/winsiderss/systeminformer/blob/bc71c2c1962be178e13cd0f84f63348f468a0701/phnt/include/ntrtl.h#L10923
	typedef PVOID RTL_FEATURE_CONFIGURATION_CHANGE_REGISTRATION, * PRTL_FEATURE_CONFIGURATION_CHANGE_REGISTRATION;

	// From winnt.h
	typedef union _RTL_RUN_ONCE {
		PVOID Ptr;
	} RTL_RUN_ONCE, * PRTL_RUN_ONCE;

#define INIT_ONCE_STATIC_INIT RTL_RUN_ONCE_INIT
	typedef /*_IRQL_requires_same_*/ ULONG /* LOGICAL */ (NTAPI* PRTL_RUN_ONCE_INIT_FN)(
		_Inout_ PRTL_RUN_ONCE RunOnce,
		_Inout_opt_ PVOID Parameter,
		_Inout_opt_ PVOID* Context);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L10894C1-L10914C76
	typedef enum _RTL_FEATURE_CONFIGURATION_PRIORITY {
		FeatureConfigurationPriorityImageDefault = 0,
		FeatureConfigurationPriorityEKB = 1,
		FeatureConfigurationPrioritySafeguard = 2,
		FeatureConfigurationPriorityPersistent = FeatureConfigurationPrioritySafeguard,
		FeatureConfigurationPriorityReserved3 = 3,
		FeatureConfigurationPriorityService = 4,
		FeatureConfigurationPriorityReserved5 = 5,
		FeatureConfigurationPriorityDynamic = 6,
		FeatureConfigurationPriorityReserved7 = 7,
		FeatureConfigurationPriorityUser = 8,
		FeatureConfigurationPrioritySecurity = 9,
		FeatureConfigurationPriorityUserPolicy = 10,
		FeatureConfigurationPriorityReserved11 = 11,
		FeatureConfigurationPriorityTest = 12,
		FeatureConfigurationPriorityReserved13 = 13,
		FeatureConfigurationPriorityReserved14 = 14,
		FeatureConfigurationPriorityImageOverride = 15,
		FeatureConfigurationPriorityMax = FeatureConfigurationPriorityImageOverride
	} RTL_FEATURE_CONFIGURATION_PRIORITY, * PRTL_FEATURE_CONFIGURATION_PRIORITY;

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L10917C1-L10922C29
	typedef enum _RTL_FEATURE_ENABLED_STATE {
		FeatureEnabledStateDefault,
		FeatureEnabledStateDisabled,
		FeatureEnabledStateEnabled
	} RTL_FEATURE_ENABLED_STATE;

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L10925
	typedef enum _RTL_FEATURE_ENABLED_STATE_OPTIONS {
		FeatureEnabledStateOptionsNone,
		FeatureEnabledStateOptionsWexpConfig
	} RTL_FEATURE_ENABLED_STATE_OPTIONS, * PRTL_FEATURE_ENABLED_STATE_OPTIONS;

	typedef UCHAR RTL_FEATURE_VARIANT;

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L10932C1-L10937C72
	typedef enum _RTL_FEATURE_VARIANT_PAYLOAD_KIND {
		FeatureVariantPayloadKindNone,
		FeatureVariantPayloadKindResident,
		FeatureVariantPayloadKindExternal
	} RTL_FEATURE_VARIANT_PAYLOAD_KIND, * PRTL_FEATURE_VARIANT_PAYLOAD_KIND;

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L10940C1-L10946C78
	typedef enum _RTL_FEATURE_CONFIGURATION_OPERATION {
		FeatureConfigurationOperationNone = 0,
		FeatureConfigurationOperationFeatureState = 1,
		FeatureConfigurationOperationVariantState = 2,
		FeatureConfigurationOperationResetState = 4
	} RTL_FEATURE_CONFIGURATION_OPERATION, * PRTL_FEATURE_CONFIGURATION_OPERATION;

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L10949C1-L10960C72
	typedef struct _RTL_FEATURE_CONFIGURATION_UPDATE {
		RTL_FEATURE_ID FeatureId;
		RTL_FEATURE_CONFIGURATION_PRIORITY Priority;
		RTL_FEATURE_ENABLED_STATE EnabledState;
		RTL_FEATURE_ENABLED_STATE_OPTIONS EnabledStateOptions;
		RTL_FEATURE_VARIANT Variant;
		UCHAR Reserved[3];
		RTL_FEATURE_VARIANT_PAYLOAD_KIND VariantPayloadKind;
		RTL_FEATURE_VARIANT_PAYLOAD VariantPayload;
		RTL_FEATURE_CONFIGURATION_OPERATION Operation;
	} RTL_FEATURE_CONFIGURATION_UPDATE, * PRTL_FEATURE_CONFIGURATION_UPDATE;

	// From winnt.h
	typedef VOID(NTAPI* APC_CALLBACK_FUNCTION)(
		DWORD Arg1,
		PVOID Arg2,
		PVOID Arg3);

	// From winnt.h
	typedef DWORD(NTAPI* PTHREAD_START_ROUTINE)(
		LPVOID lpThreadParameter);

	// From winnt.h
	typedef NTSTATUS(NTAPI* PRTL_START_POOL_THREAD)(
		_In_ PTHREAD_START_ROUTINE Function,
		_In_ PVOID Parameter,
		_Out_ PHANDLE ThreadHandle);

	// From winbase.h
	typedef NTSTATUS(NTAPI *PRTL_EXIT_POOL_THREAD)(
		_In_ NTSTATUS ExitStatus);

	// Reversed
	typedef struct _REGISTRY_TRANSACTION_STATE {
		DWORD Unknown1;
		DWORD StateSize;
		DWORD Unknwon2;
	} REGISTRY_TRANSACTION_STATE, * PREGISTRY_TRANSACTION_STATE;
	typedef struct _REGISTRY_TRANSACTION {
		PVOID Unknown1;
		PVOID Unknown2;
		PVOID Unknown3;
		PREGISTRY_TRANSACTION_STATE State;
	} REGISTRY_TRANSACTION, * PREGISTRY_TRANSACTION;

	// https://github.com/winsiderss/systeminformer/blob/bc71c2c1962be178e13cd0f84f63348f468a0701/phnt/include/ntrtl.h#L11039C1-L11043C1
	typedef struct _RTL_FEATURE_USAGE_SUBSCRIPTION_TARGET {
		ULONG Data[2];
	} RTL_FEATURE_USAGE_SUBSCRIPTION_TARGET, * PRTL_FEATURE_USAGE_SUBSCRIPTION_TARGET;

	// https://github.com/winsiderss/systeminformer/blob/bc71c2c1962be178e13cd0f84f63348f468a0701/phnt/include/ntrtl.h#L11053C1-L11059C84
	typedef struct _RTL_FEATURE_USAGE_SUBSCRIPTION_DETAILS {
		RTL_FEATURE_ID FeatureId;
		USHORT ReportingKind;
		USHORT ReportingOptions;
		RTL_FEATURE_USAGE_SUBSCRIPTION_TARGET ReportingTarget;
	} RTL_FEATURE_USAGE_SUBSCRIPTION_DETAILS, * PRTL_FEATURE_USAGE_SUBSCRIPTION_DETAILS;

	// https://undoc.airesoft.co.uk/ntdll.dll/RtlTraceDatabaseCreate.php
	typedef ULONG(NTAPI* PRTL_TRACE_HASH_FUNCTION)(PVOID* ppFrames, ULONG numFrames);

	typedef RTL_CRITICAL_SECTION CRITICAL_SECTION;

	// https://undoc.airesoft.co.uk/ntdll.dll/RtlTraceDatabaseCreate.php
	typedef struct _RTL_TRACE_DATABASE {
		ULONG Magic; // 0xABCDCCCC
		ULONG Flags; // value passed as flags parameter
		ULONG Tag; // value passed as tag parameter
		struct _RTL_TRACE_SEGMENT* SegmentList;
		SIZE_T MaximumSize; // value passed as MaximumSize parameter
		SIZE_T CurrentSize; // current size in bytes
		PVOID Owner; // unused
		CRITICAL_SECTION Lock; // the lock taken every time a RtlTraceDatabase* is called
		ULONG NoOfBuckets; // value passed as buckets parameter and number of pointers in the Buckets array
		struct _RTL_TRACE_BLOCK** Buckets;
		PRTL_TRACE_HASH_FUNCTION HashFunction;
		SIZE_T NoOfTraces; // number of traces in the database
		SIZE_T NoOfHits; // number of times RtlTraceDatabaseAdd has been called with a trace already in the database
		ULONG HashCounter[0x10];
	} RTL_TRACE_DATABASE, * PRTL_TRACE_DATABASE;

	// https://undoc.airesoft.co.uk/ntdll.dll/RtlTraceDatabaseCreate.php
	typedef struct _RTL_TRACE_BLOCK {
		ULONG Magic; // 0xABCDAAAA
		ULONG Count; // number of times referenced
		ULONG Size; // number of entries in the Trace array
		SIZE_T UserCount; // 0
		SIZE_T UserSize; // 0
		PVOID UserContext; // 0
		struct _RTL_TRACE_BLOCK* Next; // next block in this bucket
		PVOID* Trace; // the stack trace
	} RTL_TRACE_BLOCK, * PRTL_TRACE_BLOCK;

	// https://undoc.airesoft.co.uk/ntdll.dll/RtlTraceDatabaseEnumerate.php
	typedef struct _RTL_TRACE_ENUM {
		PRTL_TRACE_DATABASE pDatabase; // will be set to pDatabase by the function
		ULONG bucketIndex; // bucket index of the block returned in ppBlock
		PRTL_TRACE_BLOCK pStartingBlock; // a block to start enumeration from
	} RTL_TRACE_ENUM, * PRTL_TRACE_ENUM;

	// From winnt.h
	typedef struct _OSVERSIONINFOEXW {
		DWORD dwOSVersionInfoSize;
		DWORD dwMajorVersion;
		DWORD dwMinorVersion;
		DWORD dwBuildNumber;
		DWORD dwPlatformId;
		WCHAR  szCSDVersion[128];     // Maintenance string for PSS usage
		WORD   wServicePackMajor;
		WORD   wServicePackMinor;
		WORD   wSuiteMask;
		BYTE  wProductType;
		BYTE  wReserved;
	} OSVERSIONINFOEXW, * POSVERSIONINFOEXW, * LPOSVERSIONINFOEXW, RTL_OSVERSIONINFOEXW, * PRTL_OSVERSIONINFOEXW;

	typedef /*_IRQL_requires_same_*/ EXCEPTION_DISPOSITION (NTAPI* EXCEPTION_ROUTINE)(
		_Inout_ struct _EXCEPTION_RECORD* ExceptionRecord,
		_In_ PVOID EstablisherFrame,
		_Inout_ struct _CONTEXT* ContextRecord,
		_In_ PVOID DispatcherContext);

	// From winnt.h
	// Nonvolatile context pointer record.
	typedef struct _KNONVOLATILE_CONTEXT_POINTERS {
		union {
			PM128A FloatingContext[16];
			struct {
				PM128A Xmm0;
				PM128A Xmm1;
				PM128A Xmm2;
				PM128A Xmm3;
				PM128A Xmm4;
				PM128A Xmm5;
				PM128A Xmm6;
				PM128A Xmm7;
				PM128A Xmm8;
				PM128A Xmm9;
				PM128A Xmm10;
				PM128A Xmm11;
				PM128A Xmm12;
				PM128A Xmm13;
				PM128A Xmm14;
				PM128A Xmm15;
			} DUMMYSTRUCTNAME;
		} DUMMYUNIONNAME;
		union {
			PDWORD64 IntegerContext[16];
			struct {
				PDWORD64 Rax;
				PDWORD64 Rcx;
				PDWORD64 Rdx;
				PDWORD64 Rbx;
				PDWORD64 Rsp;
				PDWORD64 Rbp;
				PDWORD64 Rsi;
				PDWORD64 Rdi;
				PDWORD64 R8;
				PDWORD64 R9;
				PDWORD64 R10;
				PDWORD64 R11;
				PDWORD64 R12;
				PDWORD64 R13;
				PDWORD64 R14;
				PDWORD64 R15;
			} DUMMYSTRUCTNAME;
		} DUMMYUNIONNAME2;
	} KNONVOLATILE_CONTEXT_POINTERS, * PKNONVOLATILE_CONTEXT_POINTERS;
	
	// https://undoc.airesoft.co.uk/ntdll.dll/SbSelectProcedure.php
	typedef PVOID(NTAPI* pfnBranchFunc)(PVOID);
	typedef struct _SWITCHBRANCH_BRANCH_DETAILS {
		PCSTR pSpecificName; // the name of this branch
		pfnBranchFunc pBranch;
		ULONG unk; // always 1
		// 4-byte paadding on x64
		PCSTR pDescription;
		ULONG unk2; // 
		ULONG unk3; // always 0
		ULONG unk4; // always 1
		ULONG unk5; // always 0
		// the windows compatability guid specified in the manifest
		// that results in this branch being taken
		GUID windowsCompatGuid;
		// an id for this branch
		GUID branchGuid;
	} SWITCHBRANCH_BRANCH_DETAILS, * PSWITCHBRANCH_BRANCH_DETAILS;

	// https://undoc.airesoft.co.uk/ntdll.dll/SbSelectProcedure.php
	typedef struct _SWITCHBRANCH_SCENARIO_TABLE_ENTRY {
		PCSTR pBranchName;
		PCSTR pBranchDescription;
		PCSTR pBranchReason;
		ULONG unk; // always 1
		ULONG unk2; // always 0
		ULONG unk3; // always 0
		ULONG unk4; // always 1
		ULONG unk5; // always 0
		GUID scenarioGuid;
		ULONG numScenarioBranches;
		SWITCHBRANCH_BRANCH_DETAILS branches[ANYSIZE_ARRAY]; // numScenarioBranches long
	} SWITCHBRANCH_SCENARIO_TABLE_ENTRY, * PSWITCHBRANCH_SCENARIO_TABLE_ENTRY;

	// https://undoc.airesoft.co.uk/ntdll.dll/SbSelectProcedure.php
	typedef struct _SWITCHBRANCH_SCENARIO_TABLE_ENTRIES {
		ULONG numScenarios;
		SWITCHBRANCH_SCENARIO_TABLE_ENTRY* pEntries[ANYSIZE_ARRAY]; // numScenarios long
	} SWITCHBRANCH_SCENARIO_TABLE_ENTRIES, * PSWITCHBRANCH_SCENARIO_TABLE_ENTRIES;

	// https://undoc.airesoft.co.uk/ntdll.dll/SbSelectProcedure.php
	typedef struct _SWITCHBRANCH_CACHED_MODULE_TABLE {
		ULONG64 changeCount;
		ULONG unk;
		ULONG numScenarios;
		PVOID pScenarios[ANYSIZE_ARRAY]; // numScenarios in size
	} SWITCHBRANCH_CACHED_MODULE_TABLE, * PSWITCHBRANCH_CACHED_MODULE_TABLE;

	// https://undoc.airesoft.co.uk/ntdll.dll/SbSelectProcedure.php
	typedef PVOID(NTAPI* pfnFilterFunc)(PVOID);
	typedef struct _SWITCHBRANCH_SCENARIO_TABLE {
		ULONG tag; // always 'EsLk', not ever checked even on checked builds
		ULONG unk; // Always 0x1000000
		SWITCHBRANCH_CACHED_MODULE_TABLE* pModuleTable;
		PVOID unk2; // always 0
		SWITCHBRANCH_SCENARIO_TABLE_ENTRIES* pScenarios;
		// this function probably has greater significance, but all occurances just return a string like
		// SbFilterProcedure_DdrawNamespace,
		// SbFilterProcedure_Scenario etc
		pfnFilterFunc filterProcedure;
	} SWITCHBRANCH_SCENARIO_TABLE, * PSWITCHBRANCH_SCENARIO_TABLE;

	typedef struct _PS_PKG_CLAIM {
		ULONG Flags;  // PSM_ACTIVATION_TOKEN_*
		ULONG Origin; // PackageOrigin
	} PS_PKG_CLAIM, * PPS_PKG_CLAIM;

	typedef /*_IRQL_requires_same_*/ EXCEPTION_DISPOSITION (NTAPI* PEXCEPTION_ROUTINE)(
		_Inout_ struct _EXCEPTION_RECORD* ExceptionRecord,
		_In_ PVOID EstablisherFrame,
		_Inout_ struct _CONTEXT* ContextRecord,
		_In_ PVOID DispatcherContext);

	typedef VOID(NTAPI* WAITORTIMERCALLBACKFUNC)(
		PVOID Unknown1,
		BOOLEAN Unknown2);

	// ============================ functions 
	
	// https://www.sstic.org/media/SSTIC2019/SSTIC-actes/dll_shell_game_and_other_misdirections/SSTIC2019-Article-dll_shell_game_and_other_misdirections-georges.pdf
	// https://learn.microsoft.com/en-us/windows/win32/sysinfo/apisetqueryapisetpresence
	NTSYSAPI BOOL NTAPI ApiSetQueryApiSetPresence(
		_In_ PCUNICODE_STRING Namespace,
		_Out_ PBOOLEAN Present);

	//https://learn.microsoft.com/en-us/windows/win32/sysinfo/apisetqueryapisetpresenceex
	NTSYSAPI BOOL NTAPI ApiSetQueryApiSetPresenceEx(
		_In_ PCUNICODE_STRING Namespace,
		_Out_ PBOOLEAN IsInSchema,
		_Out_ PBOOLEAN Present);

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSAPI NTSTATUS NTAPI NtAllocateUuids(
		_Out_ PLARGE_INTEGER UuidLastTimeAllocated,
		_Out_ PULONG UuidDeltaTime,
		_Out_ PULONG UuidSequenceNumber,
		_Out_ PUCHAR UuidSeed);
	//ZwAllocateUuids

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSAPI NTSTATUS NTAPI NtCallbackReturn(
		_In_opt_ PVOID Result,
		_In_ ULONG ResultLength,
		_In_ NTSTATUS Status);
	//ZwCallbackReturn

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntclose
	NTSYSAPI NTSTATUS NTAPI NtClose(
		_In_ HANDLE Handle);
	// ZwClose

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSAPI NTSTATUS NTAPI NtDirectGraphicsCall(
		ULONG Unknown1,
		ULONG Unknown2,
		ULONG Unknown3,
		ULONG Unknown4,
		ULONG Unknown5);
	//ZwDirectGraphicsCall

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSAPI NTSTATUS NTAPI NtDisplayString(
		_In_ PUNICODE_STRING Message);
	//ZwDisplayString

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSAPI NTSTATUS NTAPI NtDrawText(
		_In_ PUNICODE_STRING Text);
	//ZwDrawText

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSAPI NTSTATUS NTAPI NtFlushInstallUILanguage(
		_In_ ULONG InstallUILanguage,
		_In_ ULONG SetComittedFlag);
	//ZwFlushInstallUILanguage

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSAPI NTSTATUS NTAPI NtGetMUIRegistryInfo(
		_In_ ULONG Flags,
		_Inout_ PULONG BufferLength,
		_Out_ PVOID Buffer);
	//ZwGetMUIRegistryInfo

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSAPI NTSTATUS NTAPI NtGetTickCount();

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSAPI NTSTATUS NTAPI NtIsUILanguageComitted();
	//ZwIsUILanguageComitted

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSAPI NTSTATUS NTAPI NtLockProductActivationKeys(
		_In_ PULONG ProductBuild,
		_In_ PULONG SafeMode);
	//ZwLockProductActivationKeys

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSAPI NTSTATUS NTAPI NtMapCMFModule(
		_In_ ULONG What,
		_In_ ULONG Index,
		_Out_opt_ PULONG CacheIndexOut,
		_Out_opt_ PULONG CacheFlagsOut,
		_Out_opt_ PULONG ViewSizeOut,
		_Out_opt_ PPVOID BaseAddress);
	//ZwMapCMFModule

	// https://processhacker.sourceforge.io/doc/ntioapi_8h.html#a23719c37bc09be8bb0b4e3d296ce3fd6
	NTSYSAPI NTSTATUS NTAPI NtNotifyChangeSession(
		_In_ HANDLE Session,
		_In_ ULONG IoStateSequence,
		_In_ PLARGE_INTEGER ChangeTimeStamp,
		_In_ IO_SESSION_EVENT Action,
		_In_ IO_SESSION_STATE IoState,
		_In_ IO_SESSION_STATE IoState2,
		_In_reads_bytes_opt_(PayloadSize) PVOID Payload,
		_In_ ULONG PayloadSize);
	//ZwNotifyChangeSession

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSAPI NTSTATUS NTAPI NtOpenSession(
		_Out_ PHANDLE SessionHandle,
		_In_ ACCESS_MASK DesiredAccess,
		_In_ POBJECT_ATTRIBUTES ObjectAttributes);
	//ZwOpenSession

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSAPI NTSTATUS NTAPI NtQueryLicenseValue(
		_In_ PUNICODE_STRING Name,
		_Out_opt_ PULONG Type,
		_Out_ PVOID Buffer,
		_In_ ULONG Length,
		_Out_ PULONG ReturnedLength);
	//ZwQueryLicenseValue

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSAPI NTSTATUS NTAPI NtRevertContainerImpersonation();
	//ZwRevertContainerImpersonation

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSAPI NTSTATUS NTAPI NtSetLdtEntries(
		_In_ ULONG Selector1,
		_In_ ULONG LdtEntry1L,
		_In_ ULONG LdtEntry1H,
		_In_ ULONG Selector2,
		_In_ ULONG LdtEntry2L,
		_In_ ULONG LdtEntry2H);
	//ZwSetLdtEntries
	
	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSAPI NTSTATUS NTAPI NtSetUuidSeed(
		_In_ PUCHAR UuidSeed);
	//ZwSetUuidSeed

	// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FHardware%2FNtShutdownSystem.html
	NTSYSAPI NTSTATUS NTAPI NtShutdownSystem(
		_In_ SHUTDOWN_ACTION Action);
	//ZwShutdownSystem

	// https://learn.microsoft.com/fr-fr/windows/win32/api/winuser/nf-winuser-defwindowproca
	// Forwarded from USER32:DefWindowProcA
	NTSYSAPI LONG_PTR NTAPI NtdllDefWindowProc_A(
		_In_ HANDLE hWnd,
		_In_ UINT Msg,
		_In_ WORD wParam,
		_In_ DWORD lParam);

	// https://learn.microsoft.com/fr-fr/windows/win32/api/winuser/nf-winuser-defwindowprocw
	NTSYSAPI LONG_PTR NTAPI NtdllDefWindowProc_W(
		_In_ HANDLE hWnd,
		_In_ UINT Msg,
		_In_ WORD wParam,
		_In_ DWORD lParam);

	// https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-defdlgproca
	// Forwarded from USER32:DefDlgProcA
	NTSYSAPI LONG_PTR NTAPI NtdllDialogWndProc_A(
		_In_ HANDLE   hDlg,
		_In_ UINT   Msg,
		_In_ WORD wParam,
		_In_ DWORD lParam);

	// https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-defdlgprocw
	// Forwarded from USER32:DefDlgProcW
	NTSYSAPI LONG_PTR NTAPI NtdllDialogWndProc_W(
		_In_ HANDLE   hDlg,
		_In_ UINT   Msg,
		_In_ WORD wParam,
		_In_ DWORD lParam);

	// https://doxygen.reactos.org/dc/d65/rxact_8c.html
	NTSYSAPI NTSTATUS NTAPI RtlAbortRXact(
		PRXACT_CONTEXT Context);

	// Reversed
	NTSYSAPI NTSTATUS NTAPI RtlAcquirePebLock();

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI VOID NTAPI RtlReleaseSRWLockExclusive(
		_Inout_ PRTL_SRWLOCK SRWLock);

	//https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI BOOLEAN NTAPI RtlAcquireResourceExclusive(
		_Inout_ PRTL_RESOURCE Resource,
		_In_ BOOLEAN Wait);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI BOOLEAN NTAPI RtlAcquireResourceShared(
		_Inout_ PRTL_RESOURCE Resource,
		_In_ BOOLEAN Wait);

	//https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI VOID NTAPI RtlAcquireSRWLockExclusive(
		_Inout_ PRTL_SRWLOCK SRWLock);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI VOID NTAPI RtlAcquireSRWLockShared(
		_Inout_ PRTL_SRWLOCK SRWLock);

	// https://doxygen.reactos.org/dc/d65/rxact_8c.html
	NTSYSAPI NTSTATUS NTAPI RtlAddActionToRXact(
		PRXACT_CONTEXT Context,
		ULONG ActionType,
		PUNICODE_STRING KeyName,
		ULONG ValueType,
		PVOID ValueData,
		ULONG ValueDataSize);

	//RtlAddAttributeActionToRXact
	NTSYSAPI NTSTATUS NTAPI RtlAddAttributeActionToRXact(
		PRXACT_CONTEXT Context,
		ULONG ActionType,
		PUNICODE_STRING KeyName,
		HANDLE KeyHandle,
		PUNICODE_STRING ValueName,
		ULONG ValueType,
		PVOID ValueData,
		ULONG ValueDataSize);

	// https://doxygen.reactos.org/d2/d94/appverifier_8c.html
	NTSYSAPI VOID NTAPI RtlApplicationVerifierStop(
		_In_ ULONG_PTR Code,
		_In_ PCSTR Message,
		_In_ PVOID Value1,
		_In_ PCSTR Description1,
		_In_ PVOID Value2,
		_In_ PCSTR Description2,
		_In_ PVOID Value3,
		_In_ PCSTR Description3,
		_In_ PVOID Value4,
		_In_ PCSTR Description4);

	// https://doxygen.reactos.org/dc/d65/rxact_8c.html
	NTSYSAPI NTSTATUS NTAPI RtlApplyRXact(
		PRXACT_CONTEXT Context);

	// https://doxygen.reactos.org/dc/d65/rxact_8c.html
	NTSYSAPI NTSTATUS NTAPI RtlApplyRXactNoFlush(
		PRXACT_CONTEXT Context);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlarebitsclear
	NTSYSAPI BOOLEAN RtlAreBitsClear(
		_In_ PRTL_BITMAP BitMapHeader,
		_In_ ULONG       StartingIndex,
		_In_ ULONG       Length);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlarebitsset
	NTSYSAPI BOOLEAN RtlAreBitsSet(
		_In_ PRTL_BITMAP BitMapHeader,
		_In_ ULONG       StartingIndex,
		_In_ ULONG       Length);

	// Reversed
	NTSYSAPI BOOLEAN NTAPI RtlAreLongPathsEnabled(VOID);
	
	// https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/shared/ntrtl_x/rtl_barrier.htm
	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI BOOLEAN NTAPI RtlBarrier(
		_Inout_ PRTL_BARRIER Barrier,
		_In_ ULONG Flags);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI BOOLEAN NTAPI RtlBarrierForDelete(
		_Inout_ PRTL_BARRIER Barrier,
		_In_ ULONG Flags);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L10109C1-L10116C7
	NTSYSAPI NTSTATUS NTAPI RtlCapabilityCheck(
		_In_opt_ HANDLE TokenHandle,
		_In_ PUNICODE_STRING CapabilityName,
		_Out_ PBOOLEAN HasCapability);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlcapturecontext
	NTSYSAPI VOID RtlCaptureContext(
		_Out_ PCONTEXT ContextRecord);

	// Guessed
	// https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/Diagnostics/Debug/fn.RtlCaptureContext2.html
	NTSYSAPI VOID RtlCaptureContext2(
		_Out_ PCONTEXT ContextRecord);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlcapturestackbacktrace
	NTSYSAPI USHORT RtlCaptureStackBackTrace(
		_In_ ULONG FramesToSkip,
		_In_ ULONG FramesToCapture,
		_Out_ PVOID* BackTrace,
		_Out_opt_ PULONG BackTraceHash);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L10720C1-L10727C1
	NTSYSAPI NTSTATUS NTAPI RtlCheckBootStatusIntegrity(
		_In_ HANDLE FileHandle,
		_Out_ PBOOLEAN Verified);

	// https://github.com/reactos/reactos/blob/master/sdk/lib/rtl/critical.c
	NTSYSAPI VOID NTAPI RtlCheckForOrphanedCriticalSections(
		HANDLE ThreadHandle);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L10771C1-L10777C1
	NTSYSAPI NTSTATUS NTAPI RtlCheckPortableOperatingSystem(
		_Out_ PBOOLEAN IsPortable); // VOID

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlcheckregistrykey
	NTSYSAPI NTSTATUS RtlCheckRegistryKey(
		_In_ ULONG RelativeTo,
		_In_ PWSTR Path);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L10086C1-L10093C1
	NTSYSAPI NTSTATUS NTAPI RtlCheckSandboxedToken(
		_In_opt_ HANDLE TokenHandle,
		_Out_ PBOOLEAN IsSandboxed);

	// https://github.com/winsiderss/phnt/blob/master/ntrtl.h
	NTSYSAPI NTSTATUS NTAPI RtlCheckTokenMembership(
		_In_opt_ HANDLE TokenHandle,
		_In_ PSID SidToCheck,
		_Out_ PBOOLEAN IsMember);

	// https://github.com/winsiderss/phnt/blob/master/ntrtl.h
	NTSYSAPI NTSTATUS NTAPI RtlCheckTokenMembershipEx(
		_In_opt_ HANDLE TokenHandle,
		_In_ PSID SidToCheck,
		_In_ ULONG Flags, // CTMF_VALID_FLAGS
		_Out_ PBOOLEAN IsMember);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L10097
	NTSYSAPI NTSTATUS NTAPI RtlCheckTokenCapability(
		_In_opt_ HANDLE TokenHandle,
		_In_ PSID CapabilitySidToCheck,
		_Out_ PBOOLEAN HasCapability);

	// https://ntdoc.m417z.com/rtlcleanupteblanglists
	NTSYSAPI VOID NTAPI RtlCleanUpTEBLangLists(VOID);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlclearallbits
	NTSYSAPI VOID RtlClearAllBits(
		_In_ PRTL_BITMAP BitMapHeader);

	// https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntrtl.h#L7409
	NTSYSAPI VOID NTAPI RtlClearAllBitsEx(
		_In_ PRTL_BITMAP_EX BitMapHeader);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlclearbit
	NTSYSAPI VOID RtlClearBit(
		_In_ PRTL_BITMAP BitMapHeader,
		_In_ ULONG BitNumber);

	// https://github.com/winsiderss/phnt/blob/master/ntrtl.h
	NTSYSAPI VOID NTAPI RtlClearBitEx(
		_In_ PRTL_BITMAP_EX BitMapHeader,
		_In_range_(< , BitMapHeader->SizeOfBitMap) ULONG64 BitNumber);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlclearbits
	NTSYSAPI VOID RtlClearBits(
		_In_ PRTL_BITMAP BitMapHeader,
		_In_ ULONG StartingIndex,
		_In_ ULONG NumberToClear);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlcmdecodememioresource
	NTSYSAPI ULONGLONG RtlCmDecodeMemIoResource(
		_In_ PCM_PARTIAL_RESOURCE_DESCRIPTOR Descriptor,
		_Out_opt_ PULONGLONG Start);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlcmencodememioresource
	NTSYSAPI NTSTATUS RtlCmEncodeMemIoResource(
		_In_ PCM_PARTIAL_RESOURCE_DESCRIPTOR Descriptor,
		_In_ UCHAR Type,
		_In_ ULONGLONG Length,
		_In_ ULONGLONG Start);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L6279C1-L6286C1
	NTSYSAPI PVOID NTAPI RtlCommitDebugInfo(
		_Inout_ PRTL_DEBUG_INFORMATION Buffer,
		_In_ SIZE_T Size);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI LONG NTAPI RtlCompareAltitudes(
		_In_ PUNICODE_STRING Altitude1,
		_In_ PUNICODE_STRING Altitude2);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlcompressbuffer
	NTSYSAPI NTSTATUS RtlCompressBuffer(
		_In_  USHORT CompressionFormatAndEngine,
		_In_  PUCHAR UncompressedBuffer,
		_In_  ULONG  UncompressedBufferSize,
		_Out_ PUCHAR CompressedBuffer,
		_In_  ULONG  CompressedBufferSize,
		_In_  ULONG  UncompressedChunkSize,
		_Out_ PULONG FinalCompressedSize,
		_In_  PVOID  WorkSpace);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	NTSYSAPI DWORD NTAPI RtlComputeCrc32(
		DWORD dwInitial,
		const PBYTE pData,
		int iLen);

	//https://doxygen.reactos.org/d8/dd5/ndk_2rtlfuncs_8h.html#affe1add420874a2869fbd93ddf8913fb
	NTSYSAPI NTSTATUS NTAPI RtlComputePrivatizedDllName_U(
		_In_ PUNICODE_STRING DllName,
		_Inout_ PUNICODE_STRING RealName,
		_Inout_ PUNICODE_STRING LocalName);

	// https://github.com/xmoezzz/NativeLib-R/blob/master/ntsmss.h
	NTSYSAPI NTSTATUS NTAPI RtlConnectToSm(
		_In_ PUNICODE_STRING ApiPortName,
		_In_ HANDLE ApiPortHandle,
		_In_ DWORD ProcessImageType,
		_Out_ PHANDLE SmssConnection);

	// https://doxygen.reactos.org/d6/d28/sdk_2lib_2rtl_2nls_8c.html
	NTSYSAPI NTSTATUS NTAPI RtlConsoleMultiByteToUnicodeN(
		_Out_ PWCHAR UnicodeString,
		_In_ ULONG UnicodeSize,
		_Out_ PULONG ResultSize,
		_In_ PCSTR MbString,
		_In_ ULONG MbSize,
		_Out_ PULONG Unknown);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	NTSYSAPI DWORD NTAPI RtlConvertDeviceFamilyInfoToString(
		PDWORD device_family_size,
		PDWORD device_form_size,
		WCHAR* device_family,
		WCHAR* device_form);

	//https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI VOID NTAPI RtlConvertExclusiveToShared(
		_Inout_ PRTL_RESOURCE Resource);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI NTSTATUS NTAPI RtlConvertLCIDToString(
		_In_ LCID LcidValue,
		_In_ ULONG Base,
		_In_ ULONG Padding,
		_Out_writes_(Size) PWSTR pResultBuf,
		_In_ ULONG Size);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI VOID NTAPI RtlConvertSharedToExclusive(
		_Inout_ PRTL_RESOURCE Resource);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L1256C1-L1261C7
	NTSYSAPI BOOLEAN NTAPI RtlConvertSRWLockExclusiveToShared(
		_Inout_ PRTL_SRWLOCK SRWLock);

	// https://github.com/winsiderss/phnt/blob/master/ntrtl.h
	NTSYSAPI VOID NTAPI RtlCopyBitMap(
		_In_ PRTL_BITMAP Source,
		_In_ PRTL_BITMAP Destination,
		_In_range_(0, Destination->SizeOfBitMap - 1) ULONG TargetBit);

	// https://github.com/winsiderss/phnt/blob/master/ntrtl.h
	NTSYSAPI NTSTATUS NTAPI RtlCopyContext(
		_Inout_ PCONTEXT Context,
		_In_ ULONG ContextFlags,
		_Out_ PCONTEXT Source);

	// https://github.com/winsiderss/phnt/blob/master/ntrtl.h
	NTSYSAPI NTSTATUS NTAPI RtlCopyExtendedContext(
		_Out_ PCONTEXT_EX Destination,
		_In_ ULONG ContextFlags,
		_In_ PCONTEXT_EX Source);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlcopyluid
	NTSYSAPI VOID RtlCopyLuid(
		_Out_ PLUID DestinationLuid,
		_In_  PLUID SourceLuid);

	// https://github.com/winsiderss/phnt/blob/master/ntrtl.h
	NTSYSAPI VOID NTAPI RtlCopyLuidAndAttributesArray(
		_In_ ULONG Count,
		_In_ PLUID_AND_ATTRIBUTES Src,
		_In_ PLUID_AND_ATTRIBUTES Dest);

	// https://github.com/winsiderss/phnt/blob/master/ntrtl.h
	NTSYSAPI ULONG NTAPI RtlCrc32(
		_In_reads_bytes_(Size) const void* Buffer,
		_In_ size_t Size,
		_In_ ULONG InitialCrc);

	// https://github.com/winsiderss/phnt/blob/master/ntrtl.h
	NTSYSAPI ULONGLONG NTAPI RtlCrc64(
		_In_reads_bytes_(Size) const void* Buffer,
		_In_ size_t Size,
		_In_ ULONGLONG InitialCrc);

	// https://github.com/winsiderss/phnt/blob/master/ntrtl.h
	NTSYSAPI NTSTATUS NTAPI RtlCreateEnvironment(
		_In_ BOOLEAN CloneCurrentEnvironment,
		_Out_ PVOID* Environment);

	// https://github.com/winsiderss/phnt/blob/master/ntrtl.h
	NTSYSAPI NTSTATUS NTAPI RtlCreateEnvironmentEx(
		_In_opt_ PVOID SourceEnvironment,
		_Out_ PVOID* Environment,
		_In_ ULONG Flags);

	// https://github.com/winsiderss/phnt/blob/master/ntrtl.h
	NTSYSAPI PRTL_DEBUG_INFORMATION NTAPI RtlCreateQueryDebugBuffer(
		_In_opt_ ULONG MaximumCommit,
		_In_ BOOLEAN UseEventPair);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlcreateregistrykey
	NTSYSAPI NTSTATUS RtlCreateRegistryKey(
		_In_ ULONG RelativeTo,
		_In_ PWSTR Path);

	//https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlcreatesystemvolumeinformationfolder
	NTSYSAPI NTSTATUS RtlCreateSystemVolumeInformationFolder(
		_In_ PCUNICODE_STRING VolumeRootPath);

	// https://github.com/winsiderss/phnt/blob/master/ntrtl.h
	NTSYSAPI NTSTATUS NTAPI RtlCreateUserStack(
		_In_opt_ SIZE_T CommittedStackSize,
		_In_opt_ SIZE_T MaximumStackSize,
		_In_opt_ ULONG_PTR ZeroBits,
		_In_ SIZE_T PageSize,
		_In_ ULONG_PTR ReserveAlignment,
		_Out_ PINITIAL_TEB InitialTeb);

	// https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntrtl.h#L3385
	NTSYSAPI NTSTATUS NTAPI RtlCreateUserThread(
		_In_ HANDLE ProcessHandle,
		_In_opt_ PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
		_In_ BOOLEAN CreateSuspended,
		_In_opt_ ULONG ZeroBits,
		_In_opt_ SIZE_T MaximumStackSize,
		_In_opt_ SIZE_T CommittedStackSize,
		_In_ PUSER_THREAD_START_ROUTINE StartAddress,
		_In_opt_ PVOID Parameter,
		_Out_opt_ PHANDLE ThreadHandle,
		_Out_opt_ PCLIENT_ID ClientId);

	// https://github.com/winsiderss/phnt/blob/master/ntrtl.h
	NTSYSAPI BOOLEAN NTAPI RtlCultureNameToLCID(
		_In_ PUNICODE_STRING String,
		_Out_ PLCID Lcid);

	// https://github.com/winsiderss/phnt/blob/master/ntrtl.h
	NTSYSAPI VOID NTAPI RtlDeCommitDebugInfo(
		_Inout_ PRTL_DEBUG_INFORMATION Buffer,
		_In_ PVOID p,
		_In_ SIZE_T Size);

	// https://github.com/reactos/reactos/blob/0089017d54a601ed317e885576471a73f96ad56c/sdk/include/ndk/rtlfuncs.h#L4104C1-L4109C3
	NTSYSAPI PRTL_ACTIVATION_CONTEXT_STACK_FRAME NTAPI RtlDeactivateActivationContextUnsafeFast(
		_In_ PRTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME_EXTENDED Frame);
	         
	// https://learn.microsoft.com/en-us/previous-versions/bb432242(v=vs.85)
	NTSYSAPI PVOID NTAPI RtlDecodePointer(
		_In_ PVOID Ptr);

	// https://learn.microsoft.com/en-us/previous-versions/dn877133(v=vs.85)
	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L9349C1-L9356C7
	NTSYSAPI NTSTATUS NTAPI RtlDecodeRemotePointer(
		_In_ HANDLE ProcessHandle,
		_In_ PVOID Pointer,
		_Out_ PVOID* DecodedPointer);

	// https://learn.microsoft.com/en-us/previous-versions/bb432243(v=vs.85)
	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L9330C1-L9335C7
	NTSYSAPI PVOID NTAPI RtlDecodeSystemPointer(
		_In_ PVOID Ptr);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtldecompressbuffer
	NTSYSAPI NTSTATUS NTAPI RtlDecompressBuffer(
		_In_  USHORT CompressionFormat,
		_Out_ PUCHAR UncompressedBuffer,
		_In_  ULONG  UncompressedBufferSize,
		_In_  PUCHAR CompressedBuffer,
		_In_  ULONG  CompressedBufferSize,
		_Out_ PULONG FinalUncompressedSize);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtldecompressbufferex
	NTSYSAPI NTSTATUS NTAPI RtlDecompressBufferEx(
		_In_  USHORT CompressionFormat,
		_Out_ PUCHAR UncompressedBuffer,
		_In_  ULONG  UncompressedBufferSize,
		_In_  PUCHAR CompressedBuffer,
		_In_  ULONG  CompressedBufferSize,
		_Out_ PULONG FinalUncompressedSize,
		_In_  PVOID  WorkSpace);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtldecompressfragment
	NTSYSAPI NTSTATUS NTAPI RtlDecompressFragment(
		_In_  USHORT CompressionFormat,
		_Out_ PUCHAR UncompressedFragment,
		_In_  ULONG  UncompressedFragmentSize,
		_In_  PUCHAR CompressedBuffer,
		_In_  ULONG  CompressedBufferSize,
		_In_  ULONG  FragmentOffset,
		_Out_ PULONG FinalUncompressedSize,
		_In_  PVOID  WorkSpace);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L8518C1-L8523C7
	NTSYSAPI NTSTATUS NTAPI RtlDefaultNpAcl(
		_Out_ PACL* Acl);

	//https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI NTSTATUS NTAPI RtlDeleteBarrier(
		_In_ PRTL_BARRIER Barrier);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L1006C1-L1011C7
	NTSYSAPI NTSTATUS NTAPI RtlDeleteCriticalSection(
		_Inout_ PRTL_CRITICAL_SECTION CriticalSection);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtldeleteregistryvalue
	NTSYSAPI NTSTATUS RtlDeleteRegistryValue(
		_In_ ULONG  RelativeTo,
		_In_ PCWSTR Path,
		_In_ PCWSTR ValueName);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L1127C1-L1132C7
	NTSYSAPI VOID NTAPI RtlDeleteResource(
		_Inout_ PRTL_RESOURCE Resource);

	// https://github.com/rpodgorny/wine/blob/master/dlls/ntdll/threadpool.c
	NTSYSAPI NTSTATUS NTAPI RtlDeregisterWait(
		_In_ HANDLE WaitHandle);

	// https://github.com/rpodgorny/wine/blob/master/dlls/ntdll/threadpool.c
	NTSYSAPI NTSTATUS NTAPI RtlDeregisterWaitEx(
		_In_ HANDLE WaitHandle,
		_In_opt_ HANDLE CompletionEvent);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L4368
	NTSYSAPI NTSTATUS NTAPI RtlDestroyEnvironment(
		_In_ _Post_invalid_ PVOID Environment);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L6269C1-L6274C7
	NTSYSAPI NTSTATUS NTAPI RtlDestroyQueryDebugBuffer(
		_In_ PRTL_DEBUG_INFORMATION Buffer);

	//RtlDisableThreadProfiling
	NTSYSAPI NTSTATUS NTAPI RtlDisableThreadProfiling(
		_In_ PVOID PerformanceDataHandle);
	
	// https://learn.microsoft.com/en-us/windows/win32/devnotes/rtldllshutdowninprogress
	NTSYSAPI BOOLEAN NTAPI RtlDllShutdownInProgress(VOID);

	// https://doxygen.reactos.org/df/d18/sdk_2lib_2rtl_2unicode_8c.html
	// See also https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-dnshostnametocomputernamew
	NTSYSAPI NTSTATUS NTAPI RtlDnsHostNameToComputerName(
		_In_ PUNICODE_STRING ComputerName,
		_Out_opt_ PUNICODE_STRING DnsHostName,
		_In_ BOOLEAN AllocateComputerNameString);

	//https://learn.microsoft.com/fr-fr/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtldrainnonvolatileflush
	NTSYSAPI NTSTATUS NTAPI RtlDrainNonVolatileFlush(
		_In_ PVOID NvToken);

	// https://doxygen.reactos.org/de/df0/sdk_2lib_2rtl_2resource_8c.html
	NTSYSAPI VOID NTAPI RtlDumpResource(
		PRTL_RESOURCE Resource);

	// https://raw.githubusercontent.com/hfiref0x/KDU/master/Source/Shared/ntos/ntos.h
	NTSYSAPI VOID NTAPI RtlEnableEarlyCriticalSectionEventCreation(VOID);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI NTSTATUS NTAPI RtlEnableThreadProfiling(
		_In_ HANDLE ThreadHandle,
		_In_ ULONG Flags,
		_In_ ULONG64 HardwareCounters,
		_Out_ PVOID* PerformanceDataHandle);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	NTSYSAPI PVOID NTAPI RtlEncodePointer(
		PVOID ptr);

	// https://i.blackhat.com/USA-19/Thursday/us-19-Kotler-Process-Injection-Techniques-Gotta-Catch-Them-All-wp.pdf
	NTSYSAPI NTSTATUS RtlEncodeRemotePointer(
		_In_ HANDLE ProcessHandle,
		_In_ PVOID ptr,
		_Out_ PVOID* encoded_ptr);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI PVOID NTAPI RtlEncodeSystemPointer(
		_In_ PVOID Ptr);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L1014C1-L1019C7
	NTSYSAPI NTSTATUS NTAPI RtlEnterCriticalSection(
		_Inout_ PRTL_CRITICAL_SECTION CriticalSection);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI BOOLEAN NTAPI RtlEqualComputerName(
		_In_ PUNICODE_STRING String1,
		_In_ PUNICODE_STRING String2);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI BOOLEAN NTAPI RtlEqualDomainName(
		_In_ PUNICODE_STRING String1,
		_In_ PUNICODE_STRING String2);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlequalluid
	NTSYSAPI VOID NTAPI RtlEqualLuid(
		_In_ __int64 L1,
		_In_ __int64 L2);

	// https://github.com/winsiderss/systeminformer/blob/bc71c2c1962be178e13cd0f84f63348f468a0701/phnt/include/ntexapi.h#L1373
	typedef ULONG WNF_CHANGE_STAMP, * PWNF_CHANGE_STAMP;
	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L11296
	_Must_inspect_result_ NTSYSAPI BOOLEAN NTAPI RtlEqualWnfChangeStamps(
		_In_ WNF_CHANGE_STAMP ChangeStamp1,
		_In_ WNF_CHANGE_STAMP ChangeStamp2);

	// https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-executeumsthread
	// As of Windows 11, user-mode scheduling is not supported. All calls fail with the error
	// ERROR_NOT_SUPPORTED.
	NTSYSAPI NTSTATUS NTAPI RtlExecuteUmsThread(
		_Inout_ PUMS_CONTEXT UmsThread);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI NTSTATUS NTAPI RtlExpandEnvironmentStrings(
		_In_opt_ PVOID Environment,
		_In_reads_(SrcLength) PWSTR Src,
		_In_ SIZE_T SrcLength,
		_Out_writes_(DstLength) PWSTR Dst,
		_In_ SIZE_T DstLength,
		_Out_opt_ PSIZE_T ReturnLength);
	
	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI NTSTATUS NTAPI RtlExpandEnvironmentStrings_U(
		_In_opt_ PVOID Environment,
		_In_ PUNICODE_STRING Source,
		_Out_ PUNICODE_STRING Destination,
		_Out_opt_ PULONG ReturnedLength);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlextendcorrelationvector
	NTSYSAPI NTSTATUS RtlExtendCorrelationVector(
		_Inout_ PCORRELATION_VECTOR CorrelationVector);

	// https://microsoft.github.io/windows-docs-rs/doc/windows/Wdk/System/SystemServices/fn.RtlExtractBitMap.html
	NTSYSAPI VOID NTAPI RtlExtractBitMap(
		_In_ PRTL_BITMAP source,
		_In_ PRTL_BITMAP destination,
		_In_ ULONG targetbit,
		_In_ ULONG numberofbits);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlfindclearbits
	NTSYSAPI ULONG RtlFindClearBits(
		_In_ PRTL_BITMAP BitMapHeader,
		_In_ ULONG NumberToFind,
		_In_ ULONG HintIndex);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlfindclearbitsandset
	NTSYSAPI ULONG RtlFindClearBitsAndSet(
		_In_ PRTL_BITMAP BitMapHeader,
		_In_ ULONG NumberToFind,
		_In_ ULONG HintIndex);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlfindclearruns
	NTSYSAPI ULONG RtlFindClearRuns(
		_In_ PRTL_BITMAP BitMapHeader,
		_Out_ PRTL_BITMAP_RUN RunArray,
		_In_ ULONG SizeOfRunArray,
		_In_ BOOLEAN LocateLongestRuns);

	// https://doxygen.reactos.org/de/df5/xdk_2rtlfuncs_8h_source.html
	NTSYSAPI NTSTATUS NTAPI RtlFindClosestEncodableLength(
		_In_ ULONGLONG SourceLength,
		_Out_ PULONGLONG TargetLength);

	// https://github.com/ionescu007/lxss/blob/master/lxdrv/ntosp.h
	NTSYSAPI PVOID NTAPI RtlFindExportedRoutineByName(
		_In_ PVOID ImageBase,
		_In_ PCCH RoutineNam);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlfindlastbackwardrunclear
	NTSYSAPI ULONG RtlFindLastBackwardRunClear(
		_In_ PRTL_BITMAP BitMapHeader,
		_In_ ULONG FromIndex,
		_Out_ PULONG StartingRunIndex);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlfindleastsignificantbit
	NTSYSAPI CCHAR RtlFindLeastSignificantBit(
		_In_ ULONGLONG Set);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlfindlongestrunclear
	NTSYSAPI ULONG RtlFindLongestRunClear(
		_In_ PRTL_BITMAP BitMapHeader,
		_Out_ PULONG StartingIndex);

	// https://doxygen.reactos.org/de/d70/sdk_2lib_2rtl_2message_8c.html
	NTSYSAPI NTSTATUS NTAPI RtlFindMessage(
		_In_ PVOID BaseAddress,
		_In_ ULONG Type,
		_In_ ULONG Language,
		_In_ ULONG MessageId,
		_Out_ PMESSAGE_RESOURCE_ENTRY* MessageResourceEntry);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlfindmostsignificantbit
	NTSYSAPI CCHAR RtlFindMostSignificantBit(
		_In_ ULONGLONG Set);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlfindnextforwardrunclear
	NTSYSAPI ULONG RtlFindNextForwardRunClear(
		_In_ PRTL_BITMAP BitMapHeader,
		_In_ ULONG FromIndex,
		_Out_ PULONG StartingRunIndex);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlfindsetbits
	NTSYSAPI ULONG RtlFindSetBits(
		_In_ PRTL_BITMAP BitMapHeader,
		_In_ ULONG NumberToFind,
		_In_ ULONG HintIndex);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlfindsetbitsandclear
	NTSYSAPI ULONG RtlFindSetBitsAndClear(
		_In_ PRTL_BITMAP BitMapHeader,
		_In_ ULONG NumberToFind,
		_In_ ULONG HintIndex);

	// https://jabber-tools.github.io/google_cognitive_apis/doc/0.1.5/ntapi/ntrtl/fn.RtlFindClearBitsAndSet.html
	NTSYSAPI ULONG NTAPI RtlFindClearBitsAndSet(
		_In_ PRTL_BITMAP BitMapHeader,
		_In_ ULONG NumberToFind,
		_In_ ULONG HintIndex);

	//https://learn.microsoft.com/fr-fr/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlfindsetbits
	NTSYSAPI ULONG NTAPI RtlFindSetBits(
		_In_ PRTL_BITMAP BitMapHeader,
		_In_ ULONG NumberToFind,
		_In_ ULONG HintIndex);

	//https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-rtlfirstentryslist
	NTSYSAPI PSLIST_ENTRY NTAPI RtlFirstEntrySList(
		_In_ const SLIST_HEADER* ListHead);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L10227C1-L10234C1
	NTSYSAPI NTSTATUS NTAPI RtlFlsAlloc(
		_In_ PFLS_CALLBACK_FUNCTION Callback,
		_Out_ PULONG FlsIndex);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L10245C1-L10251C1
	NTSYSAPI NTSTATUS NTAPI RtlFlsFree(
		_In_ ULONG FlsIndex);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L10253C1-L10260C1
	NTSYSAPI NTSTATUS NTAPI RtlFlsGetValue(
		_In_ ULONG FlsIndex,
		_Out_ PVOID* FlsData);
	
	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L10268C1-L10275C1
	NTSYSAPI NTSTATUS NTAPI RtlFlsSetValue(
		_In_ ULONG FlsIndex,
		_In_ PVOID FlsData);

	// https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/rtl/regutil/formatcurrentuserkeypath.htm?ta=8.199996948242188&tx=91,109,113;90,103&ts=0,217
	NTSYSAPI NTSTATUS RtlFormatCurrentUserKeyPath(
		UNICODE_STRING* CurrentUserKeyPath);

	// https://doxygen.reactos.org/de/d70/sdk_2lib_2rtl_2message_8c.html
	NTSYSAPI NTSTATUS NTAPI RtlFormatMessage(
		_In_ PWSTR Message,
		_In_opt_ ULONG MaxWidth,
		_In_ BOOLEAN IgnoreInserts,
		_In_ BOOLEAN ArgumentsAreAnsi,
		_In_ BOOLEAN ArgumentsAreAnArray,
		_In_ va_list* Arguments,
		_Out_ PWSTR Buffer,
		_In_ ULONG BufferSize,
		_Out_opt_ PULONG ReturnLength);

	// https://doxygen.reactos.org/de/d70/sdk_2lib_2rtl_2message_8c.html
	NTSYSAPI NTSTATUS NTAPI RtlFormatMessageEx(
		_In_ PWSTR Message,
		_In_opt_ ULONG MaxWidth,
		_In_ BOOLEAN IgnoreInserts,
		_In_ BOOLEAN ArgumentsAreAnsi,
		_In_ BOOLEAN ArgumentsAreAnArray,
		_In_ va_list* Arguments,
		_Out_ PWSTR Buffer,
		_In_ ULONG BufferSize,
		_Out_opt_ PULONG ReturnLength,
		_In_ ULONG Flags);

	// https://i.blackhat.com/asia-19/Thu-March-28/bh-asia-Sun-How-to-Survive-the-Hardware-Assisted-Control-Flow-Integrity-Enforcement.pdf
	NTSYSAPI VOID NTAPI DeleteFiber(
		_In_ LPVOID lpFiber);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L3426C1-L3431C7
	NTSYSAPI NTSTATUS NTAPI RtlFreeUserStack(
		_In_ PVOID AllocationBase);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlgenerate8dot3name
	NTSYSAPI NTSTATUS NTAPI RtlGenerate8dot3Name(
		_In_ PCUNICODE_STRING Name,
		_In_ BOOLEAN AllowExtendedCharacters,
		_Inout_ PGENERATE_NAME_CONTEXT Context,
		_Inout_ PUNICODE_STRING Name8dot3);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L10008C1-L10013C7
	NTSYSAPI ULONG NTAPI RtlGetActiveConsoleId(VOID);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L10062C1-L10070C7
	NTSYSAPI NTSTATUS NTAPI RtlGetAppContainerNamedObjectPath(
		_In_opt_ HANDLE TokenHandle,
		_In_opt_ PSID AppContainerSid,
		_In_ BOOLEAN RelativePath,
		_Out_ PUNICODE_STRING ObjectPath); // RtlFreeUnicodeString

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L10075C1-L10081C7
	NTSYSAPI NTSTATUS NTAPI RtlGetAppContainerParent(
		_In_ PSID AppContainerSid,
		_Out_ PSID* AppContainerSidParent); // RtlFreeSid

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L9431C1-L9437C7
	NTSYSAPI VOID NTAPI RtlGetCallersAddress(
		// Use the intrinsic _ReturnAddress instead.
		_Out_ PVOID* CallersAddress,
		_Out_ PVOID* CallersCaller);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlgetcompressionworkspacesize
	NTSYSAPI NTSTATUS NTAPI RtlGetCompressionWorkSpaceSize(
		_In_  USHORT CompressionFormatAndEngine,
		_Out_ PULONG CompressBufferWorkSpaceSize,
		_Out_ PULONG CompressFragmentWorkSpaceSize);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L1051C1-L1056C7
	NTSYSAPI ULONG NTAPI RtlGetCriticalSectionRecursionCount(
		_In_ PRTL_CRITICAL_SECTION CriticalSection);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L4570C1-L4577C1
	NTSYSAPI ULONG NTAPI RtlGetCurrentDirectory_U(
		_In_ ULONG BufferLength,
		_Out_writes_bytes_(BufferLength) PWSTR Buffer);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/process.c
	NTSYSAPI PEB* NTAPI RtlGetCurrentPeb(VOID);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	NTSYSAPI void NTAPI RtlGetCurrentProcessorNumberEx(
		_Out_ PPROCESSOR_NUMBER processor);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L9984C1-L9989C7
	NTSYSAPI ULONG NTAPI RtlGetCurrentServiceSessionId(VOID);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	NTSYSAPI HANDLE NTAPI RtlGetCurrentTransaction(VOID);

	// Reversed
	NTSYSAPI NTSTATUS NTAPI RtlGetCurrentUmsThread(
		_Inout_ PHANDLE pHandle);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	NTSYSAPI void NTAPI RtlGetDeviceFamilyInfoEnum(
		ULONGLONG* version,
		DWORD* family,
		DWORD* form);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlgetenabledextendedfeatures
	NTSYSAPI ULONG64 RtlGetEnabledExtendedFeatures(
		_In_ ULONG64 FeatureMask);

	// https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/loader.c
	NTSYSAPI NTSTATUS NTAPI RtlGetExePath(
		PCWSTR name,
		PWSTR* path);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L3549C1-L3556C1
	NTSYSAPI NTSTATUS NTAPI RtlGetExtendedContextLength(
		_In_ ULONG ContextFlags,
		_Out_ PULONG ContextLength);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L3557C1-L3565C1
	NTSYSAPI NTSTATUS NTAPI RtlGetExtendedContextLength2(
		_In_ ULONG ContextFlags,
		_Out_ PULONG ContextLength,
		_In_ ULONG64 EnabledExtendedFeatures); // RtlGetEnabledExtendedFeatures(-1)

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L3566C1-L3572C1
	NTSYSAPI ULONG64 NTAPI RtlGetExtendedFeaturesMask(
		_In_ PCONTEXT_EX ContextEx);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L9409C1-L9415C1
	NTSYSAPI PTEB_ACTIVE_FRAME NTAPI RtlGetFrame(VOID);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L6467C1-L6473C1
	NTSYSAPI NTSTATUS NTAPI RtlGetLastNtStatus(VOID);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L6474C1-L6480C1
	NTSYSAPI LONG NTAPI RtlGetLastWin32Error(VOID);

	// Reversed
	NTSYSAPI NTSTATUS NTAPI RtlGetNextUmsListItem(
		_Inout_ PVOID* CurrentItem,
		_Out_ PVOID* NextItem);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L8865C1-L8871C1
	NTSYSAPI ULONG NTAPI RtlGetNtGlobalFlags(VOID);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L8873C1-L8879C1
	NTSYSAPI BOOLEAN NTAPI RtlGetNtProductType(
		_Out_ PNT_PRODUCT_TYPE NtProductType);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L4945C1-L4950C7
	NTSYSAPI PWSTR NTAPI RtlGetNtSystemRoot(VOID);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L8851C1-L8858C7
	NTSYSAPI VOID NTAPI RtlGetNtVersionNumbers(
		_Out_opt_ PULONG NtMajorVersion,
		_Out_opt_ PULONG NtMinorVersion,
		_Out_opt_ PULONG NtBuildNumber);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L2786C1-L2795C1
	NTSYSAPI NTSTATUS NTAPI RtlGetParentLocaleName(
		_In_ PCWSTR LocaleName,
		_Inout_ PUNICODE_STRING ParentLocaleName,
		_In_ ULONG Flags,
		_In_ BOOLEAN AllocateDestinationString);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlgetpersistedstatelocation
	NTSYSAPI NTSTATUS RtlGetPersistedStateLocation(
		_In_ PCWSTR SourceID,
		_In_opt_ PCWSTR CustomValue,
		_In_opt_ PCWSTR DefaultPath,
		_In_ STATE_LOCATION_TYPE StateLocationType,
		_In_ PWCHAR TargetPath,
		_In_ ULONG BufferLengthIn,
		_Out_opt_ PULONG BufferLengthOut);

	// https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getproductinfo
	// From Kernel32 to Imports from api-ms-win-core-sysinfo-l1-2-0.dll:__imp_GetProductInfo
	NTSYSAPI BOOL NTAPI RtlGetProductInfo(
		_In_ DWORD dwOSMajorVersion,
		_In_ DWORD dwOSMinorVersion,
		_In_ DWORD dwSpMajorVersion,
		_In_ DWORD dwSpMinorVersion,
		_Out_ PDWORD pdwReturnedProductType);

	// https://learn.microsoft.com/en-us/windows/win32/devnotes/rtlgetreturnaddresshijacktarget
	NTSYSAPI ULONG_PTR NTAPI RtlGetReturnAddressHijackTarget(VOID);

	// https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/loader.c
	NTSYSAPI NTSTATUS NTAPI RtlGetSearchPath(
		_Out_ PWSTR* path);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L10586C1-L10593C1
	NTSYSAPI NTSTATUS NTAPI RtlGetSessionProperties(
		_In_ ULONG SessionId,
		_Out_ PULONG SharedUserSessionId);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L10706C1-L10717C1
	NTSYSAPI NTSTATUS NTAPI RtlGetSetBootStatusData(
		_In_ HANDLE FileHandle,
		_In_ BOOLEAN Read,
		_In_ RTL_BSD_ITEM_TYPE DataClass,
		_In_ PVOID Buffer,
		_In_ ULONG BufferSize,
		_Out_opt_ PULONG ReturnLength);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L8882C1-L8887C7
	NTSYSAPI ULONG NTAPI RtlGetSuiteMask(VOID);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L10747C1-L10756C1
	NTSYSAPI NTSTATUS NTAPI RtlGetSystemBootStatus(
		_In_ RTL_BSD_ITEM_TYPE BootStatusInformationClass,
		_Out_ PVOID DataBuffer,
		_In_ ULONG DataLength,
		_Out_opt_ PULONG ReturnLength);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L2870C1-L2880C1
	NTSYSAPI NTSTATUS NTAPI RtlGetSystemPreferredUILanguages(
		_In_ ULONG Flags, // MUI_LANGUAGE_NAME
		_In_opt_ PCWSTR LocaleName,
		_Out_ PULONG NumberOfLanguages,
		_Out_writes_opt_(*ReturnLength) PZZWSTR Languages,
		_Inout_ PULONG ReturnLength);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L6506C1-L6512C1
	NTSYSAPI ULONG NTAPI RtlGetThreadErrorMode(VOID);

	// Reversed
	// Invoked by USER32.DLL and UXTHEME.DLL in 10.0.19045.0 version
	NTSYSAPI NTSTATUS NTAPI RtlGetThreadLangIdByIndex(
		_In_ DWORD ArgECX,
		_In_ DWORD ArgEDX,
		_Out_ PVOID ArgR8,
		_Out_ PVOID ArgR9);
	
	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L2848C1-L2857C1
	NTSYSAPI NTSTATUS NTAPI RtlGetThreadPreferredUILanguages(
		_In_ ULONG Flags, // MUI_LANGUAGE_NAME
		_Out_ PULONG NumberOfLanguages,
		_Out_writes_opt_(*ReturnLength) PZZWSTR Languages,
		_Inout_ PULONG ReturnLength);

	// Reversed
	NTSYSAPI NTSTATUS NTAPI RtlGetThreadWorkOnBehalfTicket(
		_Out_ PVOID pResult,
		_In_ DWORD Flags);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L10050C1-L10057C7
	NTSYSAPI NTSTATUS NTAPI RtlGetTokenNamedObjectPath(
		_In_ HANDLE TokenHandle,
		_In_opt_ PSID Sid,
		_Out_ PUNICODE_STRING ObjectPath); // RtlFreeUnicodeString

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L2903C1-L2913C1
	NTSYSAPI NTSTATUS NTAPI RtlGetUILanguageInfo(
		_In_ ULONG Flags,
		_In_ PCZZWSTR Languages,
		_Out_writes_opt_(*NumberOfFallbackLanguages) PZZWSTR FallbackLanguages,
		_Inout_opt_ PULONG NumberOfFallbackLanguages,
		_Out_ PULONG Attributes);

	NTSYSAPI NTSTATUS NTAPI RtlGetUmsCompletionListEvent(
		_In_ PCOMPLETION_LIST ArgRCX,
		_Out_ PHANDLE* pEvent);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L9600C1-L9607C7
	NTSYSAPI PRTL_UNLOAD_EVENT_TRACE NTAPI RtlGetUnloadEventTraceEx(
		_Out_ PULONG* ElementSize,
		_Out_ PULONG* ElementCount,
		_Out_ PVOID* EventTrace); // works across all processes

	//RtlGetUserPreferredUILanguages
	NTSYSAPI NTSTATUS NTAPI RtlGetUserPreferredUILanguages(
		_In_ ULONG Flags, // MUI_LANGUAGE_NAME
		_In_opt_ PCWSTR LocaleName,
		_Out_ PULONG NumberOfLanguages,
		_Out_writes_opt_(*ReturnLength) PZZWSTR Languages,
		_Inout_ PULONG ReturnLength);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlgetversion
	NTSYSAPI NTSTATUS RtlGetVersion(
		_Out_ PRTL_OSVERSIONINFOW lpVersionInformation);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L4151C1-L4159C1
	NTSYSAPI NTSTATUS NTAPI RtlGuardCheckLongJumpTarget(
		_In_ PVOID PcValue,
		_In_ BOOL IsFastFail,
		_Out_ PBOOL IsLongJumpTarget);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L2399C1-L2409C1
	NTSYSAPI NTSTATUS NTAPI RtlIdnToAscii(
		_In_ ULONG Flags,
		_In_ PCWSTR SourceString,
		_In_ LONG SourceStringLength,
		_Out_writes_to_(*DestinationStringLength, *DestinationStringLength) PWSTR DestinationString,
		_Inout_ PLONG DestinationStringLength);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L2421C1-L2431C1
	NTSYSAPI NTSTATUS NTAPI RtlIdnToNameprepUnicode(
		_In_ ULONG Flags,
		_In_ PCWSTR SourceString,
		_In_ LONG SourceStringLength,
		_Out_writes_to_(*DestinationStringLength, *DestinationStringLength) PWSTR DestinationString,
		_Inout_ PLONG DestinationStringLength);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L2410C1-L2420C1
	NTSYSAPI NTSTATUS NTAPI RtlIdnToUnicode(
		_In_ ULONG Flags,
		_In_ PCWSTR SourceString,
		_In_ LONG SourceStringLength,
		_Out_writes_to_(*DestinationStringLength, *DestinationStringLength) PWSTR DestinationString,
		_Inout_ PLONG DestinationStringLength);

	// https://doxygen.reactos.org/df/da2/sdk_2lib_2rtl_2image_8c.html
	NTSYSAPI PVOID NTAPI RtlImageDirectoryEntryToData(
		PVOID BaseAddress,
		BOOLEAN MappedAsImage,
		USHORT Directory,
		PULONG Size);

	// https://github.com/mic101/windows/blob/master/WRK-v1.2/base/ntos/rtl/rtlnthdr.c
	NTSYSAPI PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(
		_In_ PVOID Base);

	// https://github.com/mic101/windows/blob/master/WRK-v1.2/base/ntos/rtl/rtlnthdr.c
	NTSYSAPI NTSTATUS NTAPI RtlImageNtHeaderEx(
		_In_ ULONG Flags,
		_In_ PVOID Base,
		_In_ ULONG64 Size,
		_Out_ PIMAGE_NT_HEADERS* OutHeaders);

	// https://doxygen.reactos.org/df/da2/sdk_2lib_2rtl_2image_8c.html
	NTSYSAPI PIMAGE_SECTION_HEADER NTAPI RtlImageRvaToSection(
		PIMAGE_NT_HEADERS NtHeader,
		PVOID BaseAddress,
		ULONG Rva);

	// https://doxygen.reactos.org/df/da2/sdk_2lib_2rtl_2image_8c.html
	NTSYSAPI PVOID NTAPI RtlImageRvaToVa(
		PIMAGE_NT_HEADERS NtHeader,
		PVOID BaseAddress,
		ULONG Rva,
		PIMAGE_SECTION_HEADER* SectionHeader);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlincrementcorrelationvector
	NTSYSAPI NTSTATUS RtlIncrementCorrelationVector(
		_Inout_ PCORRELATION_VECTOR CorrelationVector);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI NTSTATUS NTAPI RtlInitBarrier(
		_Out_ PRTL_BARRIER Barrier,
		_In_ ULONG TotalThreads,
		_In_ ULONG SpinCount);

	//https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlinitializebitmap
	NTSYSAPI VOID RtlInitializeBitMap(
		_Out_ PRTL_BITMAP BitMapHeader,
		_In_ __drv_aliasesMem PULONG BitMapBuffer,
		_In_ ULONG SizeOfBitMap);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L7315C1-L7323C1
	NTSYSAPI VOID NTAPI RtlInitializeBitMapEx(
		_Out_ PRTL_BITMAP_EX BitMapHeader,
		_In_ PULONG64 BitMapBuffer,
		_In_ ULONG64 SizeOfBitMap);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI VOID NTAPI RtlInitializeContext(
		_In_ HANDLE Process,
		_Out_ PCONTEXT Context,
		_In_opt_ PVOID Parameter,
		_In_opt_ PVOID InitialPc,
		_In_opt_ PVOID InitialSp);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlinitializecorrelationvector
	NTSYSAPI NTSTATUS RtlInitializeCorrelationVector(
		_Inout_ PCORRELATION_VECTOR CorrelationVector,
		_In_ int Version,
		_In_ const GUID* Guid);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI NTSTATUS NTAPI RtlInitializeCriticalSection(
		_Out_ PRTL_CRITICAL_SECTION CriticalSection);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI NTSTATUS NTAPI RtlInitializeCriticalSectionAndSpinCount(
		_Inout_ PRTL_CRITICAL_SECTION CriticalSection,
		_In_ ULONG SpinCount);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L997C1-L1005C1
	NTSYSAPI NTSTATUS NTAPI RtlInitializeCriticalSectionEx(
		_Out_ PRTL_CRITICAL_SECTION CriticalSection,
		_In_ ULONG SpinCount,
		_In_ ULONG Flags);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L3512C1-L3520C1
	NTSYSAPI NTSTATUS NTAPI RtlInitializeExtendedContext(
		_Out_ PCONTEXT Context,
		_In_ ULONG ContextFlags,
		_Out_ PCONTEXT_EX* ContextEx);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L3521C1-L3530C1
	NTSYSAPI NTSTATUS NTAPI RtlInitializeExtendedContext2(
		_Out_ PCONTEXT Context,
		_In_ ULONG ContextFlags,
		_Out_ PCONTEXT_EX* ContextEx,
		_In_ ULONG64 EnabledExtendedFeatures); // RtlGetEnabledExtendedFeatures(-1)

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	NTSTATUS NTAPI RtlInitializeNtUserPfn(const void* client_procsA, ULONG procsA_size,
		const void* client_procsW, ULONG procsW_size,
		const void* client_workers, ULONG workers_size);

	// https://doxygen.reactos.org/dc/d65/rxact_8c.html
	NTSYSAPI NTSTATUS NTAPI RtlInitializeRXact(
		HANDLE RootDirectory,
		BOOLEAN Commit,
		PRXACT_CONTEXT* OutContext);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI VOID NTAPI RtlInitializeResource(
		_Out_ PRTL_RESOURCE Resource);

	// https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-rtlinitializeslisthead
	NTSYSAPI VOID RtlInitializeSListHead(
		_In_ PSLIST_HEADER ListHead);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI VOID NTAPI RtlInitializeSRWLock(
		_Out_ PRTL_SRWLOCK SRWLock);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI VOID NTAPI RtlInterlockedClearBitRun(
		_In_ PRTL_BITMAP BitMapHeader,
		_In_range_(0, BitMapHeader->SizeOfBitMap - NumberToClear) ULONG StartingIndex,
		_In_range_(0, BitMapHeader->SizeOfBitMap - StartingIndex) ULONG NumberToClear);

	//https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-rtlinterlockedflushslist
	NTSYSAPI PSLIST_ENTRY NTAPI RtlInterlockedFlushSList(
		_In_ PSLIST_HEADER ListHead);

	// https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-rtlinterlockedpopentryslist
	NTSYSAPI PSLIST_ENTRY NTAPI RtlInterlockedPopEntrySList(
		_In_ PSLIST_HEADER ListHead);

	// https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-rtlinterlockedpushentryslist
	NTSYSAPI PSLIST_ENTRY NTAPI RtlInterlockedPushEntrySList(
		_In_ PSLIST_HEADER                 ListHead,
		_In_ __drv_aliasesMem PSLIST_ENTRY ListEntry);
	
	// https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/sync.c
	NTSYSAPI PSLIST_ENTRY NTAPI RtlInterlockedPushListSList(
		_Inout_ PSLIST_HEADER SListHead,
		_Inout_ __drv_aliasesMem PSLIST_ENTRY List,
		_Inout_ PSLIST_ENTRY ListEnd,
		_In_ ULONG Count);
	
	// https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/sync.c
	NTSYSAPI PSLIST_ENTRY NTAPI RtlInterlockedPushListSListEx(
		PSLIST_HEADER list,
		PSLIST_ENTRY first,
		PSLIST_ENTRY last,
		ULONG count);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI VOID NTAPI RtlInterlockedSetBitRun(
		_In_ PRTL_BITMAP BitMapHeader,
		_In_range_(0, BitMapHeader->SizeOfBitMap - NumberToSet) ULONG StartingIndex,
		_In_range_(0, BitMapHeader->SizeOfBitMap - StartingIndex) ULONG NumberToSet);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtliodecodememioresource
	NTSYSAPI ULONGLONG RtlIoDecodeMemIoResource(
		_In_ PIO_RESOURCE_DESCRIPTOR Descriptor,
		_Out_opt_ PULONGLONG Alignment,
		_Out_opt_ PULONGLONG MinimumAddress,
		_Out_opt_ PULONGLONG MaximumAddress);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlioencodememioresource
	NTSYSAPI NTSTATUS RtlIoEncodeMemIoResource(
		_In_ PIO_RESOURCE_DESCRIPTOR Descriptor,
		_In_ UCHAR Type,
		_In_ ULONGLONG Length,
		_In_ ULONGLONG Alignment,
		_In_ ULONGLONG MinimumAddress,
		_In_ ULONGLONG MaximumAddress);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI LOGICAL NTAPI RtlIsCriticalSectionLocked(
		_In_ PRTL_CRITICAL_SECTION CriticalSection);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI LOGICAL NTAPI RtlIsCriticalSectionLockedByThread(
		_In_ PRTL_CRITICAL_SECTION CriticalSection);

	// Reversed
	NTSYSAPI BOOL NTAPI RtlIsCurrentThread(
		_In_ HANDLE hThread);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L3403
	NTSYSAPI BOOLEAN NTAPI RtlIsCurrentThreadAttachExempt(VOID);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI ULONG NTAPI RtlIsDosDeviceName_U(
		_In_ PWSTR DosFileName);

	// Reversed
	// See also https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-kuser_shared_data
	NTSYSAPI BOOL NTAPI RtlIsMultiSessionSku(VOID);

	// https://codemachine.com/downloads/win10.1607/ntddk.h
	// _IRQL_requires_max_(PASSIVE_LEVEL)
	_Must_inspect_result_ NTSYSAPI BOOLEAN NTAPI RtlIsMultiUsersInSessionSku(VOID);

	// https://microsoft.github.io/windows-docs-rs/doc/windows/Wdk/System/SystemServices/fn.RtlIsMultiSessionSku.html
	NTSYSAPI BOOL NTAPI RtlIsMultiSessionSku(VOID);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L10160
	NTSYSAPI BOOLEAN NTAPI RtlIsParentOfChildAppContainer(
		_In_ PSID ParentAppContainerSid,
		_In_ PSID ChildAppContainerSid);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlispartialplaceholder
	NTSYSAPI BOOLEAN RtlIsPartialPlaceholder(
		_In_ ULONG FileAttributes,
		_In_ ULONG ReparseTag);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI BOOLEAN NTAPI RtlIsThreadWithinLoaderCallout(VOID);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlisstateseparationenabled
	NTSYSAPI BOOLEAN RtlIsStateSeparationEnabled();

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html#ad6df589c370b58b02583177842bb98ea
	NTSYSAPI BOOLEAN NTAPI RtlIsThreadWithinLoaderCallout(VOID);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI BOOLEAN NTAPI RtlIsValidLocaleName(
		_In_ PWSTR LocaleName,
		_In_ ULONG Flags);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI BOOLEAN NTAPI RtlLCIDToCultureName(
		_In_ LCID Lcid,
		_Inout_ PUNICODE_STRING String);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI NTSTATUS NTAPI RtlLcidToLocaleName(
		_In_ LCID lcid,
		_Inout_ PUNICODE_STRING LocaleName,
		_In_ ULONG Flags,
		_In_ BOOLEAN AllocateDestinationString);
	
	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI NTSTATUS NTAPI RtlLeaveCriticalSection(
		_Inout_ PRTL_CRITICAL_SECTION CriticalSection);
		
	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI NTSTATUS NTAPI RtlLocaleNameToLcid(
		_In_ PWSTR LocaleName,
		_Out_ PLCID lcid,
		_In_ ULONG Flags);

	// https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/exception.c
	NTSYSAPI PVOID NTAPI RtlLocateExtendedFeature(
		PCONTEXT_EX context_ex,
		ULONG feature_id,
		PULONG length);

	// https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/exception.c
	NTSYSAPI PVOID NTAPI RtlLocateExtendedFeature2(
		PCONTEXT_EX context_ex,
		ULONG feature_id,
		PXSTATE_CONFIGURATION xstate_config,
		ULONG* length);

	// https://windows-internals.com/cet-on-windows/
	NTSYSAPI PCONTEXT NTAPI RtlLocateLegacyContext(
		_In_ PCONTEXT_EX ContextEx,
		_Out_opt_ PULONG Length);

	// https://doxygen.reactos.org/de/d93/sdk_2lib_2rtl_2bootdata_8c.html
	NTSYSAPI NTSTATUS NTAPI RtlLockBootStatusData(
		_Out_ PHANDLE FileHandle);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI NTSTATUS NTAPI RtlLockCurrentThread(VOID);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI NTSTATUS NTAPI RtlLockModuleSection(
		_In_ PVOID Address);

	// https://github.com/mic101/windows/blob/master/WRK-v1.2/base/ntos/rtl/stktrace.c
	NTSYSAPI USHORT NTAPI RtlLogStackBackTrace(VOID);

	// https://doxygen.reactos.org/de/ddc/sdk_2lib_2rtl_2error_8c.html
	NTSYSAPI NTSTATUS NTAPI RtlMapSecurityErrorToNtStatus(
		_In_ ULONG SecurityError);

	// https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntrtl.h#L11179
	NTSYSAPI NTSTATUS NTAPI RtlNotifyFeatureUsage(
		_Inout_ RTL_FEATURE_USAGE_REPORT report);

	// https://doxygen.reactos.org/d3/d5a/RtlNtPathNameToDosPathName_8c_source.html
	NTSYSAPI NTSTATUS NTAPI RtlNtPathNameToDosPathName(
		ULONG Flags,
		PRTL_UNICODE_STRING_BUFFER Path,
		PULONG Type,
		PULONG Unknown4);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlntstatustodoserror
	// See winternl.h
	NTSYSAPI ULONG NTAPI RtlNtStatusToDosError(
		_In_ NTSTATUS Status);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlntstatustodoserrornoteb
	NTSYSAPI ULONG RtlNtStatusToDosErrorNoTeb(
		_In_ NTSTATUS Status);

	// Reversed
	NTSYSAPI PCWSTR RtlNtdllName;

	// https://learn.microsoft.com/fr-fr/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlnumberofclearbits
	NTSYSAPI ULONG RtlNumberOfClearBits(
		_In_ PRTL_BITMAP BitMapHeader);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlnumberofclearbits
	NTSYSAPI ULONG RtlNumberOfClearBits(
		_In_ PRTL_BITMAP BitMapHeader);

	//RtlNumberOfClearBitsInRange
	NTSYSAPI UINT NTAPI RtlNumberOfClearBitsInRange(
		PRTL_BITMAP bitmapheader,
		UINT startingindex,
		UINT length);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlnumberofsetbits
	NTSYSAPI ULONG RtlNumberOfSetBits(
		_In_ PRTL_BITMAP BitMapHeader);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlnumberofsetbits
	NTSYSAPI ULONG NTAPI RtlNumberOfSetBits(
		_In_ PRTL_BITMAP BitMapHeader);

	// Reversed. Based on call from RtlNumberOfClearBitsInRange
	NTSYSAPI UINT NTAPI RtlNumberOfSetBitsInRange(
		_In_ PRTL_BITMAP BitMapHeader);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlnumberofsetbitsulongptr
	NTSYSAPI ULONG RtlNumberOfSetBitsUlongPtr(
		_In_ ULONG_PTR Target);

	// https://doxygen.reactos.org/d5/dc9/sdk_2lib_2rtl_2registry_8c.html
	NTSYSAPI NTSTATUS NTAPI RtlOpenCurrentUser(
		_In_ ACCESS_MASK DesiredAccess,
		_Out_ PHANDLE KeyHandle);

	//RtlOsDeploymentState
	NTSYSAPI OS_DEPLOYEMENT_STATE_VALUES NTAPI RtlOsDeploymentState(
		_In_ ULONG 	Flags);

	// https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/thread.c
	NTSYSAPI void NTAPI RtlPopFrame(
		PTEB_ACTIVE_FRAME frame);

	// https://ntquery.wordpress.com/2014/03/29/anti-debug-fiber-local-storage-fls/#more-18
	// https://debugactiveprocess.medium.com/rtlprocessflsdata-as-anti-debugging-technique-c531174c6dc8
	NTSYSAPI NTSTATUS NTAPI RtlProcessFlsData(
		PRTL_UNKNOWN_FLS_DATA Buffer);

	// https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/thread.c
	NTSYSAPI VOID NTAPI RtlPushFrame(TEB_ACTIVE_FRAME* frame);

	//RtlQueryCriticalSectionOwner
	NTSYSAPI HANDLE NTAPI RtlQueryCriticalSectionOwner(
		_In_ HANDLE EventHandle);

	// https://learn.microsoft.com/fr-fr/windows/win32/api/winnt/nf-winnt-rtlquerydepthslist
	NTSYSAPI WORD RtlQueryDepthSList(
		_In_ PSLIST_HEADER ListHead);
	
	// https://undoc.airesoft.co.uk/ntdll.dll/RtlQueryElevationFlags.php
	NTSYSAPI NTSTATUS NTAPI RtlQueryElevationFlags(
		PDWORD pFlags);

	// Reversed. Based on invocation of RtlQueryEnvironmentVariable_U
	NTSYSAPI NTSTATUS NTAPI RtlQueryEnvironmentVariable(
		PWSTR Environment,
		PWSTR Name,
		UINT NameLength,
		PWSTR Value);

	// https://docs.rs/ntapi/latest/ntapi/ntrtl/fn.RtlQueryEnvironmentVariable_U.html
	NTSYSAPI NTSTATUS NTAPI RtlQueryEnvironmentVariable_U(
		PVOID Environment,
		PUNICODE_STRING Name,
		PUNICODE_STRING Value);

	// https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntrtl.h#L11187
	NTSYSAPI NTSTATUS NTAPI RtlQueryFeatureConfiguration(
		_In_ RTL_FEATURE_ID FeatureId,
		_In_ RTL_FEATURE_CONFIGURATION_TYPE ConfigurationType,
		_Out_ PRTL_FEATURE_CHANGE_STAMP ChangeStamp,
		_Out_ PRTL_FEATURE_CONFIGURATION FeatureConfiguration);

	// https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntrtl.h
	NTSYSAPI RTL_FEATURE_CHANGE_STAMP NTAPI RtlQueryFeatureConfigurationChangeStamp(VOID);

	// https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntrtl.h
	NTSYSAPI NTSTATUS NTAPI RtlQueryFeatureUsageNotificationSubscriptions(
		_Out_writes_(*SubscriptionCount) PRTL_FEATURE_USAGE_SUBSCRIPTION_DETAILS Subscriptions,
		_Inout_ PSIZE_T SubscriptionCount);

	// https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntrtl.h#L10017
	NTSYSAPI NTSTATUS NTAPI RtlQueryImageMitigationPolicy(
		_In_opt_ PCWSTR ImagePath, // NULL for system-wide defaults
		_In_ IMAGE_MITIGATION_POLICY Policy,
		_In_ ULONG Flags,
		_Inout_ PVOID Buffer,
		_In_ ULONG BufferSize);

	// https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntrtl.h#L4072
	NTSYSAPI NTSTATUS NTAPI RtlQueryInformationActiveActivationContext(
		_In_ ACTIVATION_CONTEXT_INFO_CLASS ActivationContextInformationClass,
		_Out_writes_bytes_(ActivationContextInformationLength) PVOID ActivationContextInformation,
		_In_ SIZE_T ActivationContextInformationLength,
		_Out_opt_ PSIZE_T ReturnLength);

	// https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/rtl/ldrreloc/querymoduleinformation.htm
	NTSYSAPI NTSTATUS NTAPI RtlQueryModuleInformation(
		PULONG InformationLength,
		ULONG SizePerModule,
		PVOID InformationBuffer);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L10487
	NTSYSAPI NTSTATUS NTAPI RtlQueryPackageClaims(
		_In_ HANDLE TokenHandle,
		_Out_writes_bytes_to_opt_(*PackageSize, *PackageSize) PWSTR PackageFullName,
		_Inout_opt_ PSIZE_T PackageSize,
		_Out_writes_bytes_to_opt_(*AppIdSize, *AppIdSize) PWSTR AppId,
		_Inout_opt_ PSIZE_T AppIdSize,
		_Out_opt_ PGUID DynamicId,
		_Out_opt_ PPS_PKG_CLAIM PkgClaim,
		_Out_opt_ PULONG64 AttributesPresent);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlquerypackageidentity
	NTSYSAPI NTSTATUS RtlQueryPackageIdentity(
		PVOID TokenObject,
		PWSTR PackageFullName,
		PSIZE_T PackageSize,
		PWSTR AppId,
		PSIZE_T AppIdSize,
		PBOOLEAN Packaged);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlquerypackageidentityex
	NTSYSAPI NTSTATUS RtlQueryPackageIdentityEx(
		PVOID TokenObject,
		PWSTR PackageFullName,
		PSIZE_T PackageSize,
		PWSTR AppId,
		PSIZE_T AppIdSize,
		LPGUID DynamicId,
		PULONG64 Flags);

	// https://learn.microsoft.com/en-us/windows/win32/api/profileapi/nf-profileapi-queryperformancecounter
	NTSYSAPI BOOL NTAPI RtlQueryPerformanceCounter(
		_Out_ PLARGE_INTEGER lpPerformanceCount);

	// https://learn.microsoft.com/en-us/windows/win32/api/profileapi/nf-profileapi-queryperformancefrequency
	NTSYSAPI BOOL NTAPI QueryPerformanceFrequency(
		_Out_ PLARGE_INTEGER lpFrequency);

	// https://github.com/winsiderss/phnt/blob/48759c9b5916a359df706789f71053e49b528a18/ntrtl.h#L10535C1-L10542C1
	NTSYSAPI NTSTATUS NTAPI RtlQueryProtectedPolicy(
		_In_ PGUID PolicyGuid,
		_Out_ PULONG_PTR PolicyValue);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlqueryregistryvaluewithfallback
	NTSYSAPI NTSTATUS RtlQueryRegistryValueWithFallback(
		_In_  HANDLE          PrimaryHandle,
		_In_  HANDLE          FallbackHandle,
		_In_  PUNICODE_STRING ValueName,
		_In_  ULONG           ValueLength,
		_Out_ PULONG          ValueType,
		_Out_ PVOID           ValueData,
		_Out_ PULONG          ResultLength);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues
	NTSYSAPI NTSTATUS RtlQueryRegistryValues(
		_In_ ULONG RelativeTo,
		_In_ PCWSTR Path,
		_Inout_ PRTL_QUERY_REGISTRY_TABLE QueryTable,
		_In_opt_ PVOID Context,
		_In_opt_ PVOID Environment);

	// https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntrtl.h#L9227
	NTSYSAPI NTSTATUS NTAPI RtlQueryRegistryValuesEx(
		_In_ ULONG RelativeTo,
		_In_ PCWSTR Path,
		_Inout_ _At_(*(*QueryTable).EntryContext, _Pre_unknown_) PRTL_QUERY_REGISTRY_TABLE QueryTable,
		_In_opt_ PVOID Context,
		_In_opt_ PVOID Environment);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlquerythreadplaceholdercompatibilitymode
	NTSYSAPI CHAR NTAPI RtlQueryThreadPlaceholderCompatibilityMode(VOID);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI NTSTATUS NTAPI RtlQueryThreadProfiling(
		_In_ HANDLE ThreadHandle,
		_Out_ PBOOLEAN Enabled);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L10149
	NTSYSAPI NTSTATUS NTAPI RtlQueryTokenHostIdAsUlong64(
		_In_ HANDLE TokenHandle,
		_Out_ PULONG64 HostId); // (WIN://PKGHOSTID)

	// https://learn.microsoft.com/fr-fr/windows/win32/api/winbase/nf-winbase-queryumsthreadinformation
	// https://www.geoffchappell.com/studies/windows/win32/kernel32/history/names61.htm
    // Based on reversing Kernel32::QueryUmsThreadInformation
	NTSYSAPI BOOL NTAPI RtlQueryUmsThreadInformation(
		PUMS_CONTEXT UmsThread,
		RTL_UMS_THREAD_INFO_CLASS UmsThreadInfoClass,
		PVOID UmsThreadInformation,
		ULONG UmsThreadInformationLength,
		PULONG ReturnLength);

	// https://gist.github.com/msmania/472912cd6e9ab067be3211ba3f5f0f9e
	typedef NTSTATUS (NTAPI *pWnfCallback)(
		uint64_t p1,
		void* p2,
		void* p3,
		void* p4,
		void* p5,
		void* p6);
	NTSYSAPI NTSTATUS NTAPI RtlQueryWnfStateData(
		uint32_t*,
		uint64_t,
		pWnfCallback,
		size_t,
		size_t);

	// https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntrtl.h#L8999
	NTSYSAPI NTSTATUS NTAPI RtlQueueWorkItem (
		_In_ WORKERCALLBACKFUNC function,
		_In_opt_ PVOID context,
		_In_ ULONG flags);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlraisecustomsystemeventtrigger
	NTSYSAPI NTSTATUS RtlRaiseCustomSystemEventTrigger(
		_In_ PCUSTOM_SYSTEM_EVENT_TRIGGER_CONFIG TriggerConfig);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlrandom
	NTSYSAPI ULONG RtlRandom(
		_Inout_ PULONG Seed);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlrandomex
	NTSYSAPI ULONG RtlRandomEx(
		_Inout_ PULONG Seed);

	// https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntrtl.h#L9310
	NTSYSAPI NTSTATUS NTAPI RtlReadThreadProfilingData(
		_In_ HANDLE PerformanceDataHandle,
		_In_ ULONG Flags,
		_Out_ PPERFORMANCE_DATA PerformanceData);

	// https://github.com/winsiderss/systeminformer/blob/bc71c2c1962be178e13cd0f84f63348f468a0701/phnt/include/ntrtl.h#L11233C1-L11242C1
	NTSYSAPI NTSTATUS NTAPI RtlRegisterFeatureConfigurationChangeNotification(
		_In_ PRTL_FEATURE_CONFIGURATION_CHANGE_CALLBACK Callback,
		_In_opt_ PVOID Context,
		_In_opt_ PRTL_FEATURE_CHANGE_STAMP ObservedChangeStamp,
		_Out_ PRTL_FEATURE_CONFIGURATION_CHANGE_REGISTRATION RegistrationHandle);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html#a3971f6c4d689c54c8b8f8b9a7d3a51f9
	NTSYSAPI NTSTATUS NTAPI RtlRegisterThreadWithCsrss(VOID);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html#a3971f6c4d689c54c8b8f8b9a7d3a51f9
	NTSYSAPI NTSTATUS NTAPI RtlRegisterWait(
		_Out_ PHANDLE WaitHandle,
		_In_ HANDLE Handle,
		_In_ WAITORTIMERCALLBACKFUNC Function,
		_In_ PVOID Context,
		_In_ ULONG Milliseconds,
		_In_ ULONG Flags);

	// https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/loader.c
	NTSYSAPI VOID NTAPI RtlReleasePath(
		_In_ PWSTR path);

	// https://github.com/reactos/reactos/blob/master/sdk/include/ndk/rtlfuncs.h#L2819
	NTSYSAPI VOID NTAPI RtlReleasePebLock(VOID);

	// https://doxygen.reactos.org/de/df0/sdk_2lib_2rtl_2resource_8c.html
	NTSYSAPI VOID NTAPI RtlReleaseResource(
		PRTL_RESOURCE Resource);

	// https://github.com/reactos/reactos/blob/master/sdk/include/ndk/rtlfuncs.h#L2819
	NTSYSAPI VOID NTAPI RtlReleaseSRWLockExclusive(
		_In_ _Out_ PRTL_SRWLOCK SRWLock);

	// https://github.com/reactos/reactos/blob/master/sdk/include/ndk/rtlfuncs.h#L2819
	NTSYSAPI VOID NTAPI RtlReleaseSRWLockShared(
		_In_ _Out_ PRTL_SRWLOCK SRWLock);

	// https://www.alex-ionescu.com/rtlremotecall/
	NTSYSAPI NTSTATUS NTAPI RtlRemoteCall(
		_In_ HANDLE Process,
		_In_ HANDLE Thread,
		_In_ PVOID CallSite,
		_In_ ULONG ArgumentCount,
		_In_ PULONG Arguments,
		_In_ BOOLEAN PassContext,
		_In_ BOOLEAN AlreadySuspended);

	// https://github.com/winsiderss/phnt/blob/master/ntrtl.h
	NTSYSAPI ULONG NTAPI RtlReplaceSystemDirectoryInPath(
		_Inout_ PUNICODE_STRING Destination,
		_In_ USHORT Machine, // IMAGE_FILE_MACHINE_I386
		_In_ USHORT TargetMachine, // IMAGE_FILE_MACHINE_TARGET_HOST
		_In_ BOOLEAN IncludePathSeperator);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	NTSYSAPI NTSTATUS NTAPI RtlResetNtUserPfn(void);

	// https://github.com/winsiderss/phnt/blob/master/ntrtl.h
	NTSYSAPI NTSTATUS NTAPI RtlRestoreBootStatusDefaults(
		_In_ HANDLE FileHandle);

	// https://github.com/winsiderss/phnt/blob/master/ntrtl.h
	NTSYSAPI VOID NTAPI RtlRestoreContext(
		_In_ PCONTEXT ContextRecord,
		_In_opt_ PEXCEPTION_RECORD ExceptionRecord);

	// https://github.com/winsiderss/phnt/blob/master/ntrtl.h
	NTSYSAPI VOID NTAPI RtlRestoreLastWin32Error(
		_In_ LONG Win32Error);

	// https://github.com/winsiderss/phnt/blob/master/ntrtl.h
	NTSYSAPI NTSTATUS NTAPI RtlRestoreSystemBootStatusDefaults(VOID);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	NTSYSAPI NTSTATUS NTAPI RtlRetrieveNtUserPfn(const void** client_procsA,
		const void** client_procsW,
		const void** client_workers);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlrunoncebegininitialize
	NTSYSAPI NTSTATUS RtlRunOnceBeginInitialize(
		_Inout_ PRTL_RUN_ONCE RunOnce,
		_In_ ULONG Flags,
		_Out_ PVOID* Context);

	// http://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlrunoncecomplete
	NTSYSAPI NTSTATUS RtlRunOnceComplete(
		_Inout_ PRTL_RUN_ONCE RunOnce,
		_In_ ULONG Flags,
		_In_opt_ PVOID Context);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlrunonceexecuteonce
	NTSYSAPI NTSTATUS RtlRunOnceExecuteOnce(
		PRTL_RUN_ONCE RunOnce,
		PRTL_RUN_ONCE_INIT_FN InitFn,
		PVOID Parameter,
		PVOID* Context);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlrunonceinitialize
	NTSYSAPI VOID RtlRunOnceInitialize(
		_Out_ PRTL_RUN_ONCE RunOnce);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlsetallbits
	NTSYSAPI VOID RtlSetAllBits(
		_In_ PRTL_BITMAP BitMapHeader);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlsetbit
	NTSYSAPI VOID RtlSetBit(
		_In_ PRTL_BITMAP BitMapHeader,
		_In_ ULONG BitNumber);

	// https://github.com/winsiderss/phnt/blob/master/ntrtl.h
	NTSYSAPI VOID NTAPI RtlSetBitEx(
		_In_ PRTL_BITMAP_EX BitMapHeader,
		_In_range_(< , BitMapHeader->SizeOfBitMap) ULONG64 BitNumber);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlsetbits
	NTSYSAPI VOID RtlSetBits(
		_In_ PRTL_BITMAP BitMapHeader,
		_In_ ULONG StartingIndex,
		_In_ ULONG NumberToSet);

	// https://github.com/winsiderss/phnt/blob/master/ntrtl.h
	NTSYSAPI ULONG NTAPI RtlSetCriticalSectionSpinCount(
		_Inout_ PRTL_CRITICAL_SECTION CriticalSection,
		_In_ ULONG SpinCount);

	// https://github.com/winsiderss/phnt/blob/master/ntrtl.h
	NTSYSAPI NTSTATUS NTAPI RtlSetCurrentDirectory_U(
		_In_ PUNICODE_STRING PathName);

	// https://github.com/winsiderss/phnt/blob/master/ntrtl.h
	NTSYSAPI NTSTATUS NTAPI RtlSetCurrentEnvironment(
		_In_ PVOID Environment,
		_Out_opt_ PVOID* PreviousEnvironment);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	NTSYSAPI BOOL NTAPI RtlSetCurrentTransaction(
		HANDLE new_transaction);

	// https://github.com/winsiderss/phnt/blob/master/ntrtl.h
	NTSYSAPI NTSTATUS NTAPI RtlSetEnvironmentStrings(
		_In_ PCWSTR NewEnvironment,
		_In_ SIZE_T NewEnvironmentSize);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L4385
	NTSYSAPI NTSTATUS NTAPI RtlSetEnvironmentVar(
		_Inout_opt_ PVOID* Environment,
		_In_reads_(NameLength) PCWSTR Name,
		_In_ SIZE_T NameLength,
		_In_reads_(ValueLength) PCWSTR Value,
		_In_opt_ SIZE_T ValueLength);

	// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FEnvironment%2FRtlSetEnvironmentVariable.html
	NTSYSAPI NTSTATUS NTAPI RtlSetEnvironmentVariable(
		_Inout_opt_ PVOID* Environment,
		_In_ PUNICODE_STRING VariableName,
		_In_ PUNICODE_STRING VariableValue);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L3590C1-L3596C7
	NTSYSAPI VOID NTAPI RtlSetExtendedFeaturesMask(
		_In_ PCONTEXT_EX ContextEx,
		_In_ ULONG64 FeatureMask);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L11118C1-L11126C7
	NTSYSAPI NTSTATUS NTAPI RtlSetFeatureConfigurations(
		_In_opt_ PRTL_FEATURE_CHANGE_STAMP PreviousChangeStamp,
		_In_ RTL_FEATURE_CONFIGURATION_TYPE ConfigurationType,
		_In_reads_(ConfigurationUpdateCount) PRTL_FEATURE_CONFIGURATION_UPDATE ConfigurationUpdates,
		_In_ SIZE_T ConfigurationUpdateCount);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L9951C1-L9961C1
	NTSYSAPI NTSTATUS NTAPI RtlSetImageMitigationPolicy(
		_In_opt_ PCWSTR ImagePath, // NULL for system-wide defaults
		_In_ IMAGE_MITIGATION_POLICY Policy,
		_In_ ULONG Flags,
		_Inout_ PVOID Buffer,
		_In_ ULONG BufferSize);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L8932C1-L8939C7
	NTSYSAPI NTSTATUS NTAPI RtlSetIoCompletionCallback(
		_In_ HANDLE FileHandle,
		_In_ APC_CALLBACK_FUNCTION CompletionProc,
		_In_ ULONG Flags);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L6488C1-L6493C7
	NTSYSAPI VOID NTAPI RtlSetLastWin32Error(
		_In_ LONG Win32Error);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L6481C1-L6486C7
	NTSYSAPI VOID NTAPI RtlSetLastWin32ErrorAndNtStatusFromNtStatus(
		_In_ NTSTATUS Status);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L10779C1-L10784C7
	NTSYSAPI NTSTATUS NTAPI RtlSetPortableOperatingSystem(
		_In_ BOOLEAN IsPortable);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L10544C1-L10551C7
	NTSYSAPI NTSTATUS NTAPI RtlSetProtectedPolicy(
		_In_ PGUID PolicyGuid,
		_In_ ULONG_PTR PolicyValue,
		_Out_ PULONG_PTR OldPolicyValue);

	// https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/loader.c
	NTSYSAPI NTSTATUS NTAPI RtlSetSearchPathMode(
		ULONG flags);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L10758C1-L10766C7
	NTSYSAPI NTSTATUS NTAPI RtlSetSystemBootStatus(
		_In_ RTL_BSD_ITEM_TYPE BootStatusInformationClass,
		_In_ PVOID DataBuffer,
		_In_ ULONG DataLength,
		_Out_opt_ PULONG ReturnLength);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L6513C1-L6519C7
	NTSYSAPI NTSTATUS NTAPI RtlSetThreadErrorMode(
		_In_ ULONG NewMode,
		_Out_opt_ PULONG OldMode);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L3316C1-L3323C7
	NTSYSAPI NTSTATUS NTAPI RtlSetThreadIsCritical(
		_In_ BOOLEAN NewValue,
		_Out_opt_ PBOOLEAN OldValue,
		_In_ BOOLEAN CheckFlag);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlsetthreadplaceholdercompatibilitymode
	NTSYSAPI CHAR RtlSetThreadPlaceholderCompatibilityMode(
		_In_ CHAR Mode);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L8955C1-L8961C7
	NTSYSAPI NTSTATUS NTAPI RtlSetThreadPoolStartFunc(
		_In_ PRTL_START_POOL_THREAD StartPoolThread,
		_In_ PRTL_EXIT_POOL_THREAD ExitPoolThread);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L3326C1-L3331C7
	NTSYSAPI PVOID NTAPI RtlSetThreadSubProcessTag(
		_In_ PVOID SubProcessTag);

	// Reversed
	NTSYSAPI NTSTATUS NTAPI RtlSetThreadWorkOnBehalfTicket(
		_In_ __int64* ThreadWork);

	// Reversed
	// Invoked by KERNEL32.DLL in 10.0.19045.0 version
	NTSYSAPI NTSTATUS NTAPI RtlSetUmsThreadInformation(
		_In_ PVOID pUmsThread,
		_In_ DWORD UmsThreadInformationKind,
		_In_ PVOID pBuffer,
		_In_ DWORD bufferLength);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L1326C1-L1333C7
	NTSYSAPI NTSTATUS NTAPI RtlSleepConditionVariableCS(
		_Inout_ PRTL_CONDITION_VARIABLE ConditionVariable,
		_Inout_ PRTL_CRITICAL_SECTION CriticalSection,
		_In_opt_ PLARGE_INTEGER Timeout);

	NTSYSAPI NTSTATUS NTAPI RtlStartRXact(
		_In_ PREGISTRY_TRANSACTION Transaction);

	// https://github.com/winsiderss/systeminformer/blob/bc71c2c1962be178e13cd0f84f63348f468a0701/phnt/include/ntrtl.h#L11252C1-L11258C7
	NTSYSAPI NTSTATUS NTAPI RtlSubscribeForFeatureUsageNotification(
		_In_reads_(SubscriptionCount) PRTL_FEATURE_USAGE_SUBSCRIPTION_DETAILS SubscriptionDetails,
		_In_ SIZE_T SubscriptionCount);

	// https://gist.github.com/msmania/472912cd6e9ab067be3211ba3f5f0f9e
	NTSYSAPI NTSTATUS NTAPI RtlSubscribeWnfStateChangeNotification(
		void*,
		uint64_t,
		uint32_t,
		pWnfCallback,
		size_t,
		size_t,
		size_t,
		size_t);

	// https://codemachine.com/downloads/win10.1511/winnt.h
	NTSYSAPI DWORD NTAPI RtlSwitchedVVI(
		_In_ PRTL_OSVERSIONINFOEXW VersionInfo,
		_In_ DWORD TypeMask,
		_In_ ULONGLONG  ConditionMask);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtltestbit
	NTSYSAPI BOOLEAN RtlTestBit(
		_In_ PRTL_BITMAP BitMapHeader,
		_In_ ULONG       BitNumber);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L7325C1-L7332C7
	_Check_return_ NTSYSAPI BOOLEAN NTAPI RtlTestBitEx(
		_In_ PRTL_BITMAP_EX BitMapHeader,
		_In_range_(< , BitMapHeader->SizeOfBitMap) ULONG64 BitNumber);

	// https://undoc.airesoft.co.uk/ntdll.dll/RtlTraceDatabaseAdd.php
	NTSYSAPI BOOLEAN NTAPI RtlTraceDatabaseAdd(
		PRTL_TRACE_DATABASE pDatabase,
		ULONG numFrames,
		PVOID* ppFrames,
		PRTL_TRACE_BLOCK* ppBlock);

	// https://undoc.airesoft.co.uk/ntdll.dll/RtlTraceDatabaseCreate.php
	NTSYSAPI PRTL_TRACE_DATABASE NTAPI RtlTraceDatabaseCreate(
		ULONG buckets,
		SIZE_T maximumSize,
		ULONG flags,
		ULONG tag,
		PRTL_TRACE_HASH_FUNCTION pfnHash);

	// https://undoc.airesoft.co.uk/ntdll.dll/RtlTraceDatabaseDestroy.php
	NTSYSAPI BOOLEAN NTAPI RtlTraceDatabaseDestroy(
		PRTL_TRACE_DATABASE pDatabase);

	// https://undoc.airesoft.co.uk/ntdll.dll/RtlTraceDatabaseEnumerate.php
	NTSYSAPI BOOLEAN NTAPI RtlTraceDatabaseEnumerate(
		PRTL_TRACE_DATABASE pDatabase,
		PRTL_TRACE_ENUM pEnumData,
		PRTL_TRACE_BLOCK* ppBlock);

	// https://undoc.airesoft.co.uk/ntdll.dll/RtlTraceDatabaseFind.php
	NTSYSAPI BOOLEAN NTAPI RtlTraceDatabaseFind(
		PRTL_TRACE_DATABASE pDatabase,
		ULONG numFrames,
		PVOID* ppFrames,
		PRTL_TRACE_BLOCK* ppBlock);

	// https://undoc.airesoft.co.uk/ntdll.dll/RtlTraceDatabaseLock.php
	NTSYSAPI BOOLEAN NTAPI RtlTraceDatabaseLock(
		PRTL_TRACE_DATABASE pDatabase);

	// https://undoc.airesoft.co.uk/ntdll.dll/RtlTraceDatabaseUnlock.php
	NTSYSAPI BOOLEAN NTAPI RtlTraceDatabaseUnlock(
		PRTL_TRACE_DATABASE pDatabase);

	// https://undoc.airesoft.co.uk/ntdll.dll/RtlTraceDatabaseValidate.php
	NTSYSAPI BOOLEAN NTAPI RtlTraceDatabaseValidate(
		PRTL_TRACE_DATABASE pDatabase);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L2952C1-L2957C7
	NTSYSAPI LOGICAL NTAPI RtlTryAcquirePebLock(VOID);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L1227C1-L1233C7
	_When_(return != 0, _Acquires_exclusive_lock_(*SRWLock)) NTSYSAPI BOOLEAN NTAPI
		RtlTryAcquireSRWLockExclusive(
			_Inout_ PRTL_SRWLOCK SRWLock);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L1236C1-L1242C7
	_When_(return != 0, _Acquires_shared_lock_(*SRWLock)) NTSYSAPI BOOLEAN NTAPI
		RtlTryAcquireSRWLockShared(
			_Inout_ PRTL_SRWLOCK SRWLock);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L1029C1-L1035C7
	_When_(return != 0, _Acquires_exclusive_lock_(*CriticalSection)) NTSYSAPI LOGICAL NTAPI
		RtlTryEnterCriticalSection(
			_Inout_ PRTL_CRITICAL_SECTION CriticalSection);

	// Reversed. Probable prototype.
	NTSYSAPI unsigned __int64 NTAPI RtlUdiv128(
		unsigned __int64 highDividend,
		unsigned __int64 lowDividend,
		unsigned __int64 divisor,
		unsigned __int64* remainder);

	// Reversed
	NTSYSAPI NTSTATUS NTAPI RtlUmsThreadYield(
		_In_ PVOID SchedulerParam);

	// https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-rtluniform
	// See winterl.h
	NTSYSAPI ULONG NTAPI RtlUniform(
		_Inout_ PULONG Seed);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L10698C1-L10703C7
	NTSYSAPI NTSTATUS NTAPI RtlUnlockBootStatusData(
		_In_ HANDLE FileHandle);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI NTSTATUS NTAPI RtlUnlockCurrentThread(VOID);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI NTSTATUS NTAPI RtlUnlockModuleSection(
		_In_ PVOID Address);

	// https://github.com/winsiderss/systeminformer/blob/bc71c2c1962be178e13cd0f84f63348f468a0701/phnt/include/ntrtl.h#L11244C1-L11249C7
	NTSYSAPI NTSTATUS NTAPI RtlUnregisterFeatureConfigurationChangeNotification(
		_In_ RTL_FEATURE_CONFIGURATION_CHANGE_REGISTRATION RegistrationHandle);

	// https://github.com/winsiderss/systeminformer/blob/bc71c2c1962be178e13cd0f84f63348f468a0701/phnt/include/ntrtl.h#L11261C1-L11267C7
	NTSYSAPI NTSTATUS NTAPI RtlUnsubscribeFromFeatureUsageNotifications(
		_In_reads_(SubscriptionCount) PRTL_FEATURE_USAGE_SUBSCRIPTION_DETAILS SubscriptionDetails,
		_In_ SIZE_T SubscriptionCount);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L3258C1-L3264C1
	NTSYSAPI VOID NTAPI RtlUpdateClonedCriticalSection(
		_Inout_ PRTL_CRITICAL_SECTION CriticalSection);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L3266C1-L3273C1
	NTSYSAPI VOID NTAPI RtlUpdateClonedSRWLock(
		_Inout_ PRTL_SRWLOCK SRWLock,
		_In_ LOGICAL Shared); // TRUE to set to shared acquire

	// https://github.com/aahmad097/AlternativeShellcodeExec/blob/master/RtlUserFiberStart/Source.cpp
	NTSYSAPI NTSTATUS NTAPI RtlUserFiberStart(VOID);
	
	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L8963C1-L8970C1
	NTSYSAPI VOID NTAPI RtlUserThreadStart(
		_In_ PTHREAD_START_ROUTINE Function,
		_In_ PVOID Parameter);

	//https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlvalidatecorrelationvector
	NTSYSAPI NTSTATUS RtlValidateCorrelationVector(
		PCORRELATION_VECTOR Vector);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlverifyversioninfo
	NTSYSAPI NTSTATUS RtlVerifyVersionInfo(
		_In_ PRTL_OSVERSIONINFOEXW VersionInfo,
		_In_ ULONG                 TypeMask,
		_In_ ULONGLONG             ConditionMask);

	// https://learn.microsoft.com/fr-fr/windows/win32/api/winnt/nf-winnt-rtlvirtualunwind
	NTSYSAPI PEXCEPTION_ROUTINE RtlVirtualUnwind(
		_In_ DWORD HandlerType,
		_In_ DWORD64 ImageBase,
		_In_ DWORD64 ControlPc,
		_In_ PRUNTIME_FUNCTION FunctionEntry,
		_Inout_ PCONTEXT ContextRecord,
		_Out_ PVOID * HandlerData,
		_Out_ PDWORD64 EstablisherFrame,
		_Inout_opt_ PKNONVOLATILE_CONTEXT_POINTERS ContextPointers);
	
	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L1416C1-L1425C1
	NTSYSAPI NTSTATUS NTAPI RtlWaitOnAddress(
		_In_reads_bytes_(AddressSize) volatile VOID * Address,
		_In_reads_bytes_(AddressSize) PVOID CompareAddress,
		_In_ SIZE_T AddressSize,
		_In_opt_ PLARGE_INTEGER Timeout);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L1426C1-L1432C1
	NTSYSAPI VOID NTAPI RtlWakeAddressAll(
		_In_ PVOID Address);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L1433C1-L1439C1
	NTSYSAPI VOID NTAPI RtlWakeAddressAllNoFence(
		_In_ PVOID Address);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L1440C1-L1446C1
	NTSYSAPI VOID NTAPI RtlWakeAddressSingle(
		_In_ PVOID Address);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L1447C1-L1453C1
	NTSYSAPI VOID NTAPI RtlWakeAddressSingleNoFence(
		_In_ PVOID Address);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L1355C1-L1361C1
	NTSYSAPI VOID NTAPI RtlWakeAllConditionVariable(
		_Inout_ PRTL_CONDITION_VARIABLE ConditionVariable);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L1347
	// winbase:WakeConditionVariable
	NTSYSAPI VOID NTAPI RtlWakeConditionVariable(
		_Inout_ PRTL_CONDITION_VARIABLE ConditionVariable);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L9421C1-L9429C1
	NTSYSAPI ULONG NTAPI RtlWalkFrameChain(
		_Out_writes_(Count - (Flags >> RTL_STACK_WALKING_MODE_FRAMES_TO_SKIP_SHIFT)) PVOID* Callers,
		_In_ ULONG Count,
		_In_ ULONG Flags);

	// Reversed
	NTSYSAPI BOOLEAN NTAPI RtlWnfCompareChangeStamp(
		_In_ __int64 ArgECX,
		_In_ __int64 ArgEDX);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L11362C1-L11368C1
	NTSYSAPI NTSTATUS NTAPI RtlWnfDllUnloadCallback(
		_In_ PVOID DllBase);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlwriteregistryvalue
	NTSYSAPI NTSTATUS RtlWriteRegistryValue(
		_In_ ULONG RelativeTo,
		_In_ PCWSTR Path,
		_In_ PCWSTR ValueName,
		_In_ ULONG  ValueType,
		_In_opt_ PVOID ValueData,
		_In_ ULONG  ValueLength);

	// https://doxygen.reactos.org/d5/de2/RtlpApplyLengthFunction_8c_source.html
	NTSYSAPI NTSTATUS NTAPI RtlpApplyLengthFunction(
		_In_ ULONG Flags,
		_In_ ULONG Type,
		_In_ PVOID UnicodeStringOrUnicodeStringBuffer,
		_In_ NTSTATUS(NTAPI* LengthFunction)(ULONG, PUNICODE_STRING, PULONG));

	// Reversed
	NTSYSAPI NTSTATUS NTAPI RtlpConvertCultureNamesToLCIDs(
		PCWSTR SourceString);

	// Reversed
	NTSYSAPI NTSTATUS NTAPI RtlpConvertLCIDsToCultureNames(
		PCWSTR SourceString);
		
	// Reversed from RtlGetDeviceFamilyInfoEnum call.
	NTSYSAPI VOID NTAPI RtlpGetDeviceFamilyInfoEnum(
		ULONGLONG* version,
		PDWORD family,
		PDWORD form);
	
	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L2882C1-L2889C1
	NTSYSAPI NTSTATUS NTAPI RtlpGetSystemDefaultUILanguage(
		_Out_ LANGID DefaultUILanguageId,
		_Inout_ PLCID Lcid);

	// Reversed
	NTSYSAPI NTSTATUS NTAPI RtlpInitializeLangRegistryInfo(
		_Inout_ PVOID Unknown);

	// https://doxygen.reactos.org/d0/d06/critical_8c.html
	NTSYSAPI VOID NTAPI RtlpNotOwnerCriticalSection(
		_In_ PRTL_CRITICAL_SECTION lpCriticalSection);

	// https://source.winehq.org/WineAPI/RtlpNtCreateKey.html
	NTSYSAPI NTSTATUS NTAPI RtlpNtCreateKey (
		PHANDLE retkey,
		ACCESS_MASK access,
		const POBJECT_ATTRIBUTES attr,
		ULONG TitleIndex,
		const PUNICODE_STRING Class,
		ULONG options,
		PULONG dispos);

	// https://github.com/arizvisa/ndk/blob/master/ndk/rtlfuncs.h
	NTSYSAPI NTSTATUS NTAPI RtlpNtEnumerateSubKey(
		_In_ HANDLE KeyHandle,
		_Inout_ PUNICODE_STRING SubKeyName,
		_In_ ULONG Index,
		_In_ ULONG Unused);

	// https://github.com/arizvisa/ndk/blob/master/ndk/rtlfuncs.h
	NTSYSAPI NTSTATUS NTAPI RtlpNtMakeTemporaryKey(
		_In_ HANDLE KeyHandle);

	// https://github.com/arizvisa/ndk/blob/master/ndk/rtlfuncs.h
	NTSYSAPI NTSTATUS NTAPI RtlpNtOpenKey(
		_Out_ HANDLE KeyHandle,
		_In_ ACCESS_MASK DesiredAccess,
		_In_ POBJECT_ATTRIBUTES ObjectAttributes,
		_In_ ULONG Unused);

	// https://github.com/arizvisa/ndk/blob/master/ndk/rtlfuncs.h
	NTSYSAPI NTSTATUS NTAPI RtlpNtSetValueKey(
		_In_ HANDLE KeyHandle,
		_In_ ULONG Type,
		_In_ PVOID Data,
		_In_ ULONG DataLength);

	// https://doxygen.reactos.org/d0/d06/critical_8c.html
	NTSYSAPI VOID NTAPI RtlpUnWaitCriticalSection(
		PRTL_CRITICAL_SECTION CriticalSection);

	// Reversed. Empty function always returning 0. Arguments unknown may not be VOID.
	NTSYSAPI NTSTATUS NTAPI RtlpWaitForCriticalSection(VOID);

	// https://undoc.airesoft.co.uk/ntdll.dll/SbExecuteProcedure.php
	NTSYSAPI PVOID NTAPI SbExecuteProcedure(
		ULONG signature,
		ULONG unk,
		const SWITCHBRANCH_SCENARIO_TABLE* pScenarioTable,
		ULONG scenarioIndex,
		PVOID pCtx);

	// https://undoc.airesoft.co.uk/ntdll.dll/SbSelectProcedure.php
	NTSYSAPI FARPROC NTAPI SbSelectProcedure(
		ULONG signature,
		ULONG unk,
		const SWITCHBRANCH_SCENARIO_TABLE* pScenarioTable,
		ULONG scenarioIndex);

	// https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-versetconditionmask
	NTSYSAPI ULONGLONG NTAPI VerSetConditionMask(
		_In_ ULONGLONG ConditionMask,
		_In_ DWORD     TypeMask,
		_In_ BYTE      Condition);

#ifdef __cplusplus
}
#endif

#endif
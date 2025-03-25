#pragma once

#ifndef _NTLOADER_
#define _NTLOADER_

#include "NtCommonDefs.h"
#include "NtPeImage.h"

#ifdef __cplusplus
extern "C" {
#endif

	// UNRESOLVED FUNCTIONS

	// https://www.alex-ionescu.com/secrets-of-the-application-compatilibity-database-sdb-part-1/
	//LdrInitShimEngineDynamic -> invoked by apphelp.dll

	// LdrRscIsTypeExist
	// |- LdrIsResItemExist
	//    |- LdrpSearchResourceSection_U
	//       |- LdrpGetRcConfig
	//       |- LdrpLoadResourceFromAlternativeModule
	//       |- RtlLoadString <---
	//       |- RtlpFileIsWin32WinRCManifest
	//       |- RtlFindMessage
	//       |- LdrFindResource_U
	//       |- LdrFindResourceEx_U
	//       |- LdrFindResourceDirectory_U
	//    |- LdrpResSearchResourceMappedFile

	// END OF UNRESOLVED FUNCTIONS

	typedef PVOID DLL_DIRECTORY_COOKIE, * PDLL_DIRECTORY_COOKIE;

	// https://learn.microsoft.com/en-us/windows/win32/devnotes/ldrdllnotification
	typedef struct _LDR_DLL_LOADED_NOTIFICATION_DATA {
		ULONG Flags;                    //Reserved.
		PCUNICODE_STRING FullDllName;   //The full path name of the DLL module.
		PCUNICODE_STRING BaseDllName;   //The base file name of the DLL module.
		PVOID DllBase;                  //A pointer to the base address for the DLL in memory.
		ULONG SizeOfImage;              //The size of the DLL image, in bytes.
	} LDR_DLL_LOADED_NOTIFICATION_DATA, * PLDR_DLL_LOADED_NOTIFICATION_DATA;
	typedef struct _LDR_DLL_UNLOADED_NOTIFICATION_DATA {
		ULONG Flags;                    //Reserved.
		PCUNICODE_STRING FullDllName;   //The full path name of the DLL module.
		PCUNICODE_STRING BaseDllName;   //The base file name of the DLL module.
		PVOID DllBase;                  //A pointer to the base address for the DLL in memory.
		ULONG SizeOfImage;              //The size of the DLL image, in bytes.
	} LDR_DLL_UNLOADED_NOTIFICATION_DATA, * PLDR_DLL_UNLOADED_NOTIFICATION_DATA;	typedef union _LDR_DLL_NOTIFICATION_DATA {
		LDR_DLL_LOADED_NOTIFICATION_DATA Loaded;
		LDR_DLL_UNLOADED_NOTIFICATION_DATA Unloaded;
	} LDR_DLL_NOTIFICATION_DATA, * PLDR_DLL_NOTIFICATION_DATA;
	typedef const LDR_DLL_NOTIFICATION_DATA* PCLDR_DLL_NOTIFICATION_DATA;
	typedef VOID(NTAPI* PLDR_DLL_NOTIFICATION_FUNCTION)(
		_In_     ULONG                       NotificationReason,
		_In_     PCLDR_DLL_NOTIFICATION_DATA NotificationData,
		_In_opt_ PVOID                       Context);

	// From minwinbase.h
	typedef LPVOID(NTAPI* PENCLAVE_ROUTINE)(
		LPVOID lpThreadParameter);
	typedef PENCLAVE_ROUTINE LPENCLAVE_ROUTINE;

	// https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
	typedef struct _RTL_PROCESS_MODULE_INFORMATION {
		PVOID Section;
		PVOID MappedBase;
		PVOID ImageBase;
		ULONG ImageSize;
		ULONG Flags;
		USHORT LoadOrderIndex;
		USHORT InitOrderIndex;
		USHORT LoadCount;
		USHORT OffsetToFileName;
		UCHAR FullPathName[256];
	} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;
	typedef struct _RTL_PROCESS_MODULES {
		ULONG NumberOfModules;
		_Field_size_(NumberOfModules) RTL_PROCESS_MODULE_INFORMATION Modules[1];
	} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

	// https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntldr.h#L618C1-L623C40
	typedef struct _LDR_FAILURE_DATA {
		NTSTATUS Status;
		WCHAR DllName[0x20];
		WCHAR AdditionalInfo[0x20];
	} LDR_FAILURE_DATA, * PLDR_FAILURE_DATA;

	// From winnt.h
	typedef struct _IMAGE_BASE_RELOCATION {
		DWORD   VirtualAddress;
		DWORD   SizeOfBlock;
		//  WORD    TypeOffset[1];
	} IMAGE_BASE_RELOCATION;
	typedef IMAGE_BASE_RELOCATION UNALIGNED* PIMAGE_BASE_RELOCATION;

	typedef struct _IMAGE_DELAYLOAD_DESCRIPTOR {
		union {
			DWORD AllAttributes;
			struct {
				DWORD RvaBased : 1;             // Delay load version 2
				DWORD ReservedAttributes : 31;
			} DUMMYSTRUCTNAME;
		} Attributes;
		DWORD DllNameRVA;                       // RVA to the name of the target library (NULL-terminate ASCII string)
		DWORD ModuleHandleRVA;                  // RVA to the HMODULE caching location (PHMODULE)
		DWORD ImportAddressTableRVA;            // RVA to the start of the IAT (PIMAGE_THUNK_DATA)
		DWORD ImportNameTableRVA;               // RVA to the start of the name table (PIMAGE_THUNK_DATA::AddressOfData)
		DWORD BoundImportAddressTableRVA;       // RVA to an optional bound IAT
		DWORD UnloadInformationTableRVA;        // RVA to an optional unload info table
		DWORD TimeDateStamp;                    // 0 if not bound,
		// Otherwise, date/time of the target DLL
	} IMAGE_DELAYLOAD_DESCRIPTOR, * PIMAGE_DELAYLOAD_DESCRIPTOR;
	typedef const IMAGE_DELAYLOAD_DESCRIPTOR* PCIMAGE_DELAYLOAD_DESCRIPTOR;
	
	typedef struct _LDR_RESOURCE_INFO {
		ULONG_PTR Type;
		ULONG_PTR Name;
		ULONG_PTR Language;
	} LDR_RESOURCE_INFO, * PLDR_RESOURCE_INFO;

	// https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntldr.h#L635C1-L639C1
	typedef struct _PS_MITIGATION_OPTIONS_MAP {
		ULONG_PTR Map[3]; // 2 < 20H1
	} PS_MITIGATION_OPTIONS_MAP, * PPS_MITIGATION_OPTIONS_MAP;

	typedef struct _PS_MITIGATION_AUDIT_OPTIONS_MAP {
		ULONG_PTR Map[3]; // 2 < 20H1
	} PS_MITIGATION_AUDIT_OPTIONS_MAP, * PPS_MITIGATION_AUDIT_OPTIONS_MAP;

	// https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntldr.h#L647C1-L676C56
	typedef struct _PS_SYSTEM_DLL_INIT_BLOCK {
		ULONG Size;
		ULONG_PTR SystemDllWowRelocation;
		ULONG_PTR SystemDllNativeRelocation;
		ULONG_PTR Wow64SharedInformation[16]; // use WOW64_SHARED_INFORMATION as index
		ULONG RngData;
		union {
			ULONG Flags;
			struct {
				ULONG CfgOverride : 1;
				ULONG Reserved : 31;
			} DUMMYSTRUCTNAME;
		} DUMMYUNIONNAME;
		PS_MITIGATION_OPTIONS_MAP MitigationOptionsMap;
		ULONG_PTR CfgBitMap;
		ULONG_PTR CfgBitMapSize;
		ULONG_PTR Wow64CfgBitMap;
		ULONG_PTR Wow64CfgBitMapSize;
		PS_MITIGATION_AUDIT_OPTIONS_MAP MitigationAuditOptionsMap; // REDSTONE3
		ULONG_PTR ScpCfgCheckFunction; // since 24H2
		ULONG_PTR ScpCfgCheckESFunction;
		ULONG_PTR ScpCfgDispatchFunction;
		ULONG_PTR ScpCfgDispatchESFunction;
		ULONG_PTR ScpArm64EcCallCheck;
		ULONG_PTR ScpArm64EcCfgCheckFunction;
		ULONG_PTR ScpArm64EcCfgCheckESFunction;
	} PS_SYSTEM_DLL_INIT_BLOCK, * PPS_SYSTEM_DLL_INIT_BLOCK;

	// From delayLoadHandler.h
	typedef struct _DELAYLOAD_PROC_DESCRIPTOR {
		ULONG ImportDescribedByName;
		union {
			LPCSTR Name;
			ULONG Ordinal;
		} Description;
	} DELAYLOAD_PROC_DESCRIPTOR, * PDELAYLOAD_PROC_DESCRIPTOR;

	// From ntimage.h
	typedef struct _IMAGE_THUNK_DATA64 {
		union {
			ULONGLONG ForwarderString;  // PBYTE 
			ULONGLONG Function;         // PDWORD
			ULONGLONG Ordinal;
			ULONGLONG AddressOfData;    // PIMAGE_IMPORT_BY_NAME
		} u1;
	} IMAGE_THUNK_DATA64;
	typedef IMAGE_THUNK_DATA64* PIMAGE_THUNK_DATA64;

	typedef PIMAGE_THUNK_DATA64 PIMAGE_THUNK_DATA;

	// From delayLoadHandler.h
	typedef struct _DELAYLOAD_INFO {
		ULONG Size;
		PCIMAGE_DELAYLOAD_DESCRIPTOR DelayloadDescriptor;
		PIMAGE_THUNK_DATA ThunkAddress;
		LPCSTR TargetDllName;
		DELAYLOAD_PROC_DESCRIPTOR TargetApiDescriptor;
		PVOID TargetModuleBase;
		PVOID Unused;
		ULONG LastError;
	} DELAYLOAD_INFO, * PDELAYLOAD_INFO;

	// From delayLoadHandler.h
	typedef PVOID (NTAPI* PDELAYLOAD_FAILURE_DLL_CALLBACK) (
		_In_ ULONG NotificationReason,
		_In_ PDELAYLOAD_INFO DelayloadInfo);

	// https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntldr.h#L1197C1-L1203C1
	typedef PVOID (NTAPI* PDELAYLOAD_FAILURE_SYSTEM_ROUTINE)(
		_In_ PCSTR DllName,
		_In_ PCSTR ProcedureName);

	// https://doxygen.reactos.org/dd/d83/ntdllp_8h.html#a72d5a00c3bbe34bc1c1a7ccee187de4f
	typedef NTSTATUS(NTAPI* PLDR_APP_COMPAT_DLL_REDIRECTION_CALLBACK_FUNCTION)(
		_In_ ULONG Flags,
		_In_ PCWSTR DllName,
		_In_opt_ PCWSTR DllPath,
		_Inout_opt_ PULONG DllCharacteristics,
		_In_ PVOID CallbackData,
		_Outptr_ PWSTR* EffectiveDllPath);

	// https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntldr.h#L17C1-L24C1
	typedef BOOLEAN (NTAPI* PLDR_INIT_ROUTINE)(
		_In_ PVOID DllHandle,
		_In_ ULONG Reason,
		_In_opt_ PVOID Context);

	// https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntldr.h#L25C1-L29C52
	typedef struct _LDR_SERVICE_TAG_RECORD {
		struct _LDR_SERVICE_TAG_RECORD* Next;
		ULONG ServiceTag;
	} LDR_SERVICE_TAG_RECORD, * PLDR_SERVICE_TAG_RECORD;

	// https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntldr.h#L31
	typedef struct _LDRP_CSLIST {
		PSINGLE_LIST_ENTRY Tail;
	} LDRP_CSLIST, * PLDRP_CSLIST;

	// https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntldr.h#L36C1-L53C18
	typedef enum _LDR_DDAG_STATE {
		LdrModulesMerged = -5,
		LdrModulesInitError = -4,
		LdrModulesSnapError = -3,
		LdrModulesUnloaded = -2,
		LdrModulesUnloading = -1,
		LdrModulesPlaceHolder = 0,
		LdrModulesMapping = 1,
		LdrModulesMapped = 2,
		LdrModulesWaitingForDependencies = 3,
		LdrModulesSnapping = 4,
		LdrModulesSnapped = 5,
		LdrModulesCondensed = 6,
		LdrModulesReadyToInit = 7,
		LdrModulesInitializing = 8,
		LdrModulesReadyToRun = 9
	} LDR_DDAG_STATE;

	// https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntldr.h#L55C1-L72C1
	typedef struct _LDR_DDAG_NODE {
		LIST_ENTRY Modules;
		PLDR_SERVICE_TAG_RECORD ServiceTagList;
		ULONG LoadCount;
		ULONG LoadWhileUnloadingCount;
		ULONG LowestLink;
		union {
			LDRP_CSLIST Dependencies;
			SINGLE_LIST_ENTRY RemovalLink;
		};
		LDRP_CSLIST IncomingDependencies;
		LDR_DDAG_STATE State;
		SINGLE_LIST_ENTRY CondenseLink;
		ULONG PreorderNumber;
	} LDR_DDAG_NODE, * PLDR_DDAG_NODE;

	typedef struct _LDRP_LOAD_CONTEXT* PLDRP_LOAD_CONTEXT;

	// https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntldr.h#L82C1-L95C46
	typedef enum _LDR_DLL_LOAD_REASON {
		LoadReasonStaticDependency,
		LoadReasonStaticForwarderDependency,
		LoadReasonDynamicForwarderDependency,
		LoadReasonDelayloadDependency,
		LoadReasonDynamicLoad,
		LoadReasonAsImageLoad,
		LoadReasonAsDataLoad,
		LoadReasonEnclavePrimary, // since REDSTONE3
		LoadReasonEnclaveDependency,
		LoadReasonPatchImage, // since WIN11
		LoadReasonUnknown = -1
	} LDR_DLL_LOAD_REASON, * PLDR_DLL_LOAD_REASON;

	// https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntldr.h#L97C1-L105C46
	typedef enum _LDR_HOT_PATCH_STATE {
		LdrHotPatchBaseImage,
		LdrHotPatchNotApplied,
		LdrHotPatchAppliedReverse,
		LdrHotPatchAppliedForward,
		LdrHotPatchFailedToPatch,
		LdrHotPatchStateMax,
	} LDR_HOT_PATCH_STATE, * PLDR_HOT_PATCH_STATE;

	// https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntldr.h#L141
	typedef struct _LDR_DATA_TABLE_ENTRY {
		LIST_ENTRY InLoadOrderLinks;
		LIST_ENTRY InMemoryOrderLinks;
		LIST_ENTRY InInitializationOrderLinks;
		PVOID DllBase;
		PLDR_INIT_ROUTINE EntryPoint;
		ULONG SizeOfImage;
		UNICODE_STRING FullDllName;
		UNICODE_STRING BaseDllName;
		union {
			UCHAR FlagGroup[4];
			ULONG Flags;
			struct {
				ULONG PackagedBinary : 1;
				ULONG MarkedForRemoval : 1;
				ULONG ImageDll : 1;
				ULONG LoadNotificationsSent : 1;
				ULONG TelemetryEntryProcessed : 1;
				ULONG ProcessStaticImport : 1;
				ULONG InLegacyLists : 1;
				ULONG InIndexes : 1;
				ULONG ShimDll : 1;
				ULONG InExceptionTable : 1;
				ULONG ReservedFlags1 : 2;
				ULONG LoadInProgress : 1;
				ULONG LoadConfigProcessed : 1;
				ULONG EntryProcessed : 1;
				ULONG ProtectDelayLoad : 1;
				ULONG ReservedFlags3 : 2;
				ULONG DontCallForThreads : 1;
				ULONG ProcessAttachCalled : 1;
				ULONG ProcessAttachFailed : 1;
				ULONG CorDeferredValidate : 1;
				ULONG CorImage : 1;
				ULONG DontRelocate : 1;
				ULONG CorILOnly : 1;
				ULONG ChpeImage : 1;
				ULONG ChpeEmulatorImage : 1;
				ULONG ReservedFlags5 : 1;
				ULONG Redirected : 1;
				ULONG ReservedFlags6 : 2;
				ULONG CompatDatabaseProcessed : 1;
			} DUMMYSTRUCTNAME;
		};
		USHORT ObsoleteLoadCount;
		USHORT TlsIndex;
		LIST_ENTRY HashLinks;
		ULONG TimeDateStamp;
		PACTIVATION_CONTEXT EntryPointActivationContext;
		PVOID Lock; // RtlAcquireSRWLockExclusive
		PLDR_DDAG_NODE DdagNode;
		LIST_ENTRY NodeModuleLink;
		PLDRP_LOAD_CONTEXT LoadContext;
		PVOID ParentDllBase;
		PVOID SwitchBackContext;
		RTL_BALANCED_NODE BaseAddressIndexNode;
		RTL_BALANCED_NODE MappingInfoIndexNode;
		PVOID OriginalBase;
		LARGE_INTEGER LoadTime;
		ULONG BaseNameHashValue;
		LDR_DLL_LOAD_REASON LoadReason; // since WIN8
		ULONG ImplicitPathOptions;
		ULONG ReferenceCount; // since WIN10
		ULONG DependentLoadFlags;
		UCHAR SigningLevel; // since REDSTONE2
		ULONG CheckSum; // since 22H1
		PVOID ActivePatchImageBase;
		LDR_HOT_PATCH_STATE HotPatchState;
	} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

	// https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntldr.h#L1101
	typedef VOID (NTAPI *PLDR_ENUM_CALLBACK)(
		_In_ PLDR_DATA_TABLE_ENTRY ModuleInformation,
		_In_ PVOID Parameter,
		_Out_ BOOLEAN* Stop);

	// https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntldr.h#L959C1-L975C1
	typedef struct _LDR_ENUM_RESOURCE_ENTRY {
		union {
			ULONG_PTR NameOrId;
			PIMAGE_RESOURCE_DIRECTORY_STRING Name;
			struct {
				USHORT Id;
				USHORT NameIsPresent;
			} DUMMYSTRUCTNAME;
		} Path[3];
		PVOID Data;
		ULONG Size;
		ULONG Reserved;
	} LDR_ENUM_RESOURCE_ENTRY, * PLDR_ENUM_RESOURCE_ENTRY;

	// https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntldr.h#L468C1-L473C65
	typedef VOID (NTAPI *PLDR_IMPORT_MODULE_CALLBACK)(
		_In_ PVOID Parameter,
		_In_ PSTR ModuleName);

	// https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntldr.h#L486C1-L491C1
	typedef struct _LDR_IMPORT_CALLBACK_INFO {
		PLDR_IMPORT_MODULE_CALLBACK ImportCallbackRoutine;
		PVOID ImportCallbackParameter;
	} LDR_IMPORT_CALLBACK_INFO, * PLDR_IMPORT_CALLBACK_INFO;

	// https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntldr.h#L493C1-L501C1
	typedef struct _LDR_SECTION_INFO {
		HANDLE SectionHandle;
		ACCESS_MASK DesiredAccess;
		POBJECT_ATTRIBUTES ObjA;
		ULONG SectionPageProtection;
		ULONG AllocationAttributes;
	} LDR_SECTION_INFO, * PLDR_SECTION_INFO;

	// https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntldr.h#L503
	typedef struct _LDR_VERIFY_IMAGE_INFO {
		ULONG Size;
		ULONG Flags;
		LDR_IMPORT_CALLBACK_INFO CallbackInfo;
		LDR_SECTION_INFO SectionInfo;
		USHORT ImageCharacteristics;
	} LDR_VERIFY_IMAGE_INFO, * PLDR_VERIFY_IMAGE_INFO;

	// Reversed
	typedef struct _STR1_BUFFER {
		DWORD BufferDataOffset;
		DWORD BufferDataLength;
	} STR1_BUFFER, * PSTR1_BUFFER;

	typedef struct _STR1 {
		__int64 field_0;
		__int64 field_8;
		__int64 field_10;
		__int64 field_18;
		__int64 field_20;
		__int64 field_28;
		__int64 field_30;
		__int64 field_38;
		__int64 field_40;
		__int64 field_48;
		DWORD field_50;
		STR1_BUFFER Buffer;
		STR1_BUFFER ResourceBuffer;
		STR1_BUFFER field_64;
		DWORD field_6C;
		DWORD field_70;
		DWORD field_74;
		__int64 field_78;
	} STR1, * PSTR1;

#define MAX_RESOURCE_ID 0x10000

	// ============================ functions ============================
	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
	NTSYSAPI NTSTATUS NTAPI LdrAccessResource(
		_In_ PVOID DllHandle,
		_In_ PIMAGE_RESOURCE_DATA_ENTRY ResourceDataEntry,
		_Out_opt_ PVOID* ResourceBuffer,
		_Out_opt_ PULONG ResourceLength);

	// See also https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-adddlldirectory
	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
	NTSYSAPI NTSTATUS NTAPI LdrAddDllDirectory(
		_In_ PUNICODE_STRING NewDirectory,
		_Out_ PDLL_DIRECTORY_COOKIE Cookie);

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
	NTSYSAPI NTSTATUS NTAPI LdrAddLoadAsDataTable(
		_In_ PVOID Module,
		_In_ PCWSTR FilePath,
		_In_ SIZE_T Size,
		_In_ HANDLE Handle,
		_In_opt_ PACTIVATION_CONTEXT ActCtx);

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
	NTSYSAPI NTSTATUS NTAPI LdrAddRefDll(
		_In_ ULONG Flags,
		_In_ PVOID DllHandle);

	// Reversed. Called by LdrpMapDllNtFileName
	NTSYSAPI NTSTATUS NTAPI LdrAppxHandleIntegrityFailure(
		_In_ NTSTATUS ntCreateSectionFailureCode);

	// See also https://learn.microsoft.com/en-us/windows/win32/api/enclaveapi/nf-enclaveapi-callenclave
	// https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
	NTSYSAPI NTSTATUS NTAPI LdrCallEnclave(
		_In_ PENCLAVE_ROUTINE Routine,
		_In_ ULONG Flags, // ENCLAVE_CALL_FLAG_*
		_Inout_ PVOID* RoutineParamReturn);

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
	NTSYSAPI BOOLEAN NTAPI LdrControlFlowGuardEnforced(VOID);

	// See also https://learn.microsoft.com/en-us/windows/win32/api/enclaveapi/nf-enclaveapi-createenclave
	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
	NTSYSAPI NTSTATUS NTAPI LdrCreateEnclave(
		_In_ HANDLE ProcessHandle,
		_Inout_ PVOID* BaseAddress,
		_In_ ULONG Reserved,
		_In_ SIZE_T Size,
		_In_ SIZE_T InitialCommitment,
		_In_ ULONG EnclaveType,
		_In_reads_bytes_(EnclaveInformationLength) PVOID EnclaveInformation,
		_In_ ULONG EnclaveInformationLength,
		_Out_ PULONG EnclaveError);

	// See also https://learn.microsoft.com/en-us/windows/win32/api/enclaveapi/nf-enclaveapi-deleteenclave
	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
	NTSYSAPI NTSTATUS NTAPI LdrDeleteEnclave(
		_In_ PVOID BaseAddress);

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
	NTSYSAPI NTSTATUS NTAPI LdrDisableThreadCalloutsForDll(
		_In_ PVOID DllImageBase);

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
	NTSYSAPI NTSTATUS NTAPI LdrEnumResources(
		_In_ PVOID DllHandle,
		_In_ PLDR_RESOURCE_INFO ResourceInfo,
		_In_ ULONG Level,
		_Inout_ PULONG ResourceCount,
		_Out_writes_to_opt_(*ResourceCount, *ResourceCount) PLDR_ENUM_RESOURCE_ENTRY Resources);

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
	NTSYSAPI NTSTATUS NTAPI LdrEnumerateLoadedModules(
		_In_ BOOLEAN ReservedFlag,
		_In_ PLDR_ENUM_CALLBACK EnumProc,
		_In_ PVOID Context);

	//https://learn.microsoft.com/en-us/windows/win32/devnotes/ldrfastfailinloadercallout
	NTSYSAPI VOID NTAPI LdrFastFailInLoaderCallout(VOID);

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
	NTSYSAPI NTSTATUS NTAPI LdrFindEntryForAddress(
		_In_ PVOID DllHandle,
		_Out_ PLDR_DATA_TABLE_ENTRY* Entry);
	
	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
	NTSYSAPI NTSTATUS NTAPI LdrFindResourceDirectory_U(
		_In_ PVOID DllHandle,
		_In_ PLDR_RESOURCE_INFO ResourceInfo,
		_In_ ULONG Level,
		_Out_ PIMAGE_RESOURCE_DIRECTORY* ResourceDirectory);

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
	NTSYSAPI NTSTATUS NTAPI LdrFindResourceEx_U(
		_In_ ULONG Flags,
		_In_ PVOID DllHandle,
		_In_ PLDR_RESOURCE_INFO ResourceInfo,
		_In_ ULONG Level,
		_Out_ PIMAGE_RESOURCE_DATA_ENTRY* ResourceDataEntry);

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
	NTSYSAPI NTSTATUS NTAPI LdrFindResource_U(
		_In_ PVOID DllHandle,
		_In_ PLDR_RESOURCE_INFO ResourceInfo,
		_In_ ULONG Level,
		_Out_ PIMAGE_RESOURCE_DATA_ENTRY* ResourceDataEntry);

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
	NTSYSAPI BOOLEAN NTAPI LdrFlushAlternateResourceModules(VOID);

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
	NTSYSAPI NTSTATUS NTAPI LdrGetDllDirectory(
		_Out_ PUNICODE_STRING DllDirectory);

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
	NTSYSAPI NTSTATUS NTAPI LdrGetDllFullName(
		_In_ PVOID DllHandle,
		_Out_ PUNICODE_STRING FullDllName);

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
	NTSYSAPI NTSTATUS NTAPI LdrGetDllHandle(
		_In_opt_ PCWSTR DllPath,
		_In_opt_ PULONG DllCharacteristics,
		_In_ PUNICODE_STRING DllName,
		_Out_ PVOID* DllHandle);

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
	NTSYSAPI NTSTATUS NTAPI LdrGetDllHandleByMapping(
		_In_ PVOID BaseAddress,
		_Out_ PVOID* DllHandle);

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
	NTSYSAPI NTSTATUS NTAPI LdrGetDllHandleByName(
		_In_opt_ PUNICODE_STRING BaseDllName,
		_In_opt_ PUNICODE_STRING FullDllName,
		_Out_ PVOID* DllHandle);
	
	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
	NTSYSAPI NTSTATUS NTAPI LdrGetDllHandleEx(
		_In_ ULONG Flags,
		_In_opt_ PCWSTR DllPath,
		_In_opt_ PULONG DllCharacteristics,
		_In_ PUNICODE_STRING DllName,
		_Out_ PVOID* DllHandle);

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
	NTSYSAPI NTSTATUS NTAPI LdrGetDllPath(
		_In_  PCWSTR DllName,
		_In_  ULONG  Flags, // LOAD_LIBRARY_SEARCH_*
		_Out_ PWSTR* DllPath,
		_Out_ PWSTR* SearchPaths);

	// https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
	NTSYSAPI PLDR_FAILURE_DATA NTAPI LdrGetFailureData(VOID);

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
	NTSYSAPI NTSTATUS NTAPI LdrGetKnownDllSectionHandle(
		_In_ PCWSTR DllName,
		_In_ BOOLEAN KnownDlls32,
		_Out_ PHANDLE Section);

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
	NTSYSAPI NTSTATUS NTAPI LdrGetProcedureAddress(
		_In_ PVOID DllHandle,
		_In_opt_ PANSI_STRING ProcedureName,
		_In_opt_ ULONG ProcedureNumber,
		_Out_ PVOID* ProcedureAddress);

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
	NTSYSAPI NTSTATUS NTAPI LdrGetProcedureAddressEx(
		_In_ PVOID DllHandle,
		_In_opt_ PANSI_STRING ProcedureName,
		_In_opt_ ULONG ProcedureNumber,
		_Out_ PVOID* ProcedureAddress,
		_In_ ULONG Flags);

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
	NTSYSAPI NTSTATUS NTAPI LdrGetProcedureAddressForCaller(
		_In_ PVOID DllHandle,
		_In_opt_ PANSI_STRING ProcedureName,
		_In_opt_ ULONG ProcedureNumber,
		_Out_ PVOID* ProcedureAddress,
		_In_ ULONG Flags,
		_In_ PVOID* Callback);

	// See also https://learn.microsoft.com/en-us/windows/win32/api/enclaveapi/nf-enclaveapi-initializeenclave
	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
	NTSYSAPI NTSTATUS NTAPI LdrInitializeEnclave(
		_In_ HANDLE ProcessHandle,
		_In_ PVOID BaseAddress,
		_In_reads_bytes_(EnclaveInformationLength) PVOID EnclaveInformation,
		_In_ ULONG EnclaveInformationLength,
		_Out_ PULONG EnclaveError);

	// Not invoked from any other function in NTDLL.DLL
	// Some obscure information in https://vrodxda.hatenablog.com/entry/2019/09/18/085454 (no prototype)
	// http://www.nynaeve.net/Code/LdrInitializeThunk.c
	NTSYSAPI VOID NTAPI LdrInitializeThunk(
		_In_ PCONTEXT Context,
		_In_ PVOID NtDllBaseAddress);

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
	NTSYSAPI BOOLEAN NTAPI LdrIsModuleSxsRedirected(
		_In_ PVOID DllHandle);

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
	NTSYSAPI NTSTATUS NTAPI LdrLoadAlternateResourceModule(
		_In_ PVOID DllHandle,
		_Out_ PVOID* ResourceDllBase,
		_Out_opt_ ULONG_PTR* ResourceOffset,
		_In_ ULONG Flags);

	// https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntldr.h#L1010
	NTSYSAPI NTSTATUS NTAPI LdrLoadAlternateResourceModuleEx(
		_In_ PVOID DllHandle,
		_In_ LANGID LanguageId,
		_Out_ PVOID* ResourceDllBase,
		_Out_opt_ ULONG_PTR* ResourceOffset,
		_In_ ULONG Flags);

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
	NTSYSAPI NTSTATUS NTAPI LdrLoadDll(
		_In_opt_ PCWSTR DllPath,
		_In_opt_ PULONG DllCharacteristics,
		_In_ PUNICODE_STRING DllName,
		_Out_ PVOID* DllHandle);

	// See also https://learn.microsoft.com/en-us/windows/win32/api/enclaveapi/nf-enclaveapi-loadenclaveimagew
	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
	NTSYSAPI NTSTATUS NTAPI LdrLoadEnclaveModule(
		_In_ PVOID BaseAddress,
		_In_opt_ PCWSTR DllPath,
		_In_ PUNICODE_STRING DllName);

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
	NTSYSAPI NTSTATUS NTAPI LdrLockLoaderLock(
		_In_ ULONG Flags,
		_Out_opt_ ULONG* Disposition,
		_Out_opt_ PVOID* Cookie);

	// Reversed. Implemented by LdrpProcessInitializationComplete
	NTSYSAPI VOID NTAPI LdrProcessInitializationComplete(VOID);

	// https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
	NTSYSAPI PIMAGE_BASE_RELOCATION NTAPI LdrProcessRelocationBlock(
		_In_ ULONG_PTR VA,
		_In_ ULONG SizeOfBlock,
		_In_ PUSHORT NextOffset,
		_In_ LONG_PTR Diff);

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
	NTSYSAPI PIMAGE_BASE_RELOCATION NTAPI LdrProcessRelocationBlockEx(
		_In_ ULONG Machine, // IMAGE_FILE_MACHINE_AMD64|IMAGE_FILE_MACHINE_ARM|IMAGE_FILE_MACHINE_THUMB|IMAGE_FILE_MACHINE_ARMNT
		_In_ ULONG_PTR VA,
		_In_ ULONG SizeOfBlock,
		_In_ PUSHORT NextOffset,
		_In_ LONG_PTR Diff);

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
	NTSYSAPI NTSTATUS NTAPI LdrQueryModuleServiceTags(
		_In_ PVOID DllHandle,
		_Out_writes_(*BufferSize) PULONG ServiceTagBuffer,
		_Inout_ PULONG BufferSize);

	//https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi2/nf-libloaderapi2-queryoptionaldelayloadedapi
	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
	NTSYSAPI NTSTATUS NTAPI LdrQueryOptionalDelayLoadedAPI(
		_In_ PVOID ParentModuleBase,
		_In_ PCSTR DllName,
		_In_ PCSTR ProcedureName,
		_Reserved_ ULONG Flags);

	// https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
	NTSYSAPI NTSTATUS NTAPI LdrQueryProcessModuleInformation(
		_In_opt_ PRTL_PROCESS_MODULES ModuleInformation,
		_In_opt_ ULONG Size,
		_Out_ PULONG ReturnedSize);

	// https://learn.microsoft.com/en-us/windows/win32/devnotes/ldrregisterdllnotification
	NTSYSAPI NTSTATUS NTAPI LdrRegisterDllNotification(
		_In_ ULONG Flags,
		_In_ PLDR_DLL_NOTIFICATION_FUNCTION NotificationFunction,
		_In_opt_ PVOID Context,
		_Out_ PVOID* Cookie);

	// https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-removedlldirectory
	NTSYSAPI NTSTATUS NTAPI LdrRemoveDllDirectory(
		_In_ DLL_DIRECTORY_COOKIE Cookie);

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
	NTSYSAPI NTSTATUS NTAPI LdrRemoveLoadAsDataTable(
		_In_ PVOID InitModule,
		_Out_opt_ PVOID* BaseModule,
		_Out_opt_ PSIZE_T Size,
		_In_ ULONG Flags);

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
	NTSYSAPI NTSTATUS NTAPI LdrResFindResource(
		_In_ PVOID DllHandle,
		_In_ ULONG_PTR Type,
		_In_ ULONG_PTR Name,
		_In_ ULONG_PTR Language,
		_Out_opt_ PVOID* ResourceBuffer,
		_Out_opt_ PULONG ResourceLength,
		_Out_writes_bytes_opt_(CultureNameLength) PVOID CultureName, // WCHAR buffer[6]
		_Out_opt_ PULONG CultureNameLength,
		_In_ ULONG Flags);

	// https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
	NTSYSAPI NTSTATUS NTAPI LdrResFindResourceDirectory(
		_In_ PVOID DllHandle,
		_In_ ULONG_PTR Type,
		_In_ ULONG_PTR Name,
		_Out_opt_ PIMAGE_RESOURCE_DIRECTORY* ResourceDirectory,
		_Out_writes_bytes_opt_(CultureNameLength) PVOID CultureName, // WCHAR buffer[6]
		_Out_opt_ PULONG CultureNameLength,
		_In_ ULONG Flags);

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
	NTSYSAPI NTSTATUS NTAPI LdrResGetRCConfig(
		_In_ PVOID DllHandle,
		_In_opt_ SIZE_T Length,
		_Out_writes_bytes_opt_(Length) PVOID Config,
		_In_ ULONG Flags,
		_In_ BOOLEAN AlternateResource); // LdrLoadAlternateResourceModule

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
	NTSYSAPI NTSTATUS NTAPI LdrResRelease(
		_In_ PVOID DllHandle,
		_In_opt_ ULONG_PTR CultureNameOrId, // MAKEINTRESOURCE
		_In_ ULONG Flags);

	// https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntldr.h#L905
	NTSYSAPI NTSTATUS NTAPI LdrResSearchResource(
		_In_ PVOID DllHandle,
		_In_ PLDR_RESOURCE_INFO ResourceInfo,
		_In_ ULONG Level,
		_In_ ULONG Flags,
		_Out_opt_ PVOID* ResourceBuffer,
		_Out_opt_ PSIZE_T ResourceLength,
		_Out_writes_bytes_opt_(CultureNameLength) PVOID CultureName, // WCHAR buffer[6]
		_Out_opt_ PULONG CultureNameLength);

	// https://learn.microsoft.com/en-us/windows/win32/devnotes/resolvedelayloadedapi
	// https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
	NTSYSAPI PVOID NTAPI LdrResolveDelayLoadedAPI(
		_In_ PVOID ParentModuleBase,
		_In_ PCIMAGE_DELAYLOAD_DESCRIPTOR DelayloadDescriptor,
		_In_opt_ PDELAYLOAD_FAILURE_DLL_CALLBACK FailureDllHook,
		_In_opt_ PDELAYLOAD_FAILURE_SYSTEM_ROUTINE FailureSystemHook, // kernel32.DelayLoadFailureHook
		_Out_ PIMAGE_THUNK_DATA ThunkAddress,
		_Reserved_ ULONG Flags);

	// https://learn.microsoft.com/en-us/windows/win32/devnotes/resolvedelayloadsfromdll
	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
	NTSYSAPI NTSTATUS NTAPI LdrResolveDelayLoadsFromDll(
		_In_ PVOID ParentModuleBase,
		_In_ PCSTR TargetDllName,
		_Reserved_ ULONG Flags);

	// Reversed
	NTSYSAPI NTSTATUS NTAPI LdrRscIsTypeExist(
		PSTR1 pStr1,
		// Either a pointer to a string or a resource identifier (<= 0x100000)
		wchar_t* nameOrResourceId,
		__int64 UNUSED,
		PDWORD pFlags); // Flags

	// https://doxygen.reactos.org/d7/d55/ldrapi_8c.html
	NTSYSAPI NTSTATUS NTAPI LdrSetAppCompatDllRedirectionCallback(
		_In_ ULONG Flags,
		_In_ PLDR_APP_COMPAT_DLL_REDIRECTION_CALLBACK_FUNCTION CallbackFunction,
		_In_opt_ PVOID CallbackData);

	// https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-setdefaultdlldirectories
	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
	NTSYSAPI NTSTATUS NTAPI LdrSetDefaultDllDirectories(
		_In_ ULONG DirectoryFlags);

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
	NTSYSAPI NTSTATUS NTAPI LdrSetDllDirectory(
		_In_ PUNICODE_STRING DllDirectory);

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
	NTSYSAPI VOID NTAPI LdrSetDllManifestProber(
		_In_ PVOID Routine);

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
	NTSYSAPI NTSTATUS NTAPI LdrSetImplicitPathOptions(
		_In_ ULONG ImplicitPathOptions);

	// Reversed. Not invoked from inside NTDLL.DLL
	NTSYSAPI NTSTATUS NTAPI LdrSetMUICacheType(
		_In_ DWORD cacheType);

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
	_Analysis_noreturn_ __declspec(noreturn) NTSYSAPI VOID NTAPI LdrShutdownProcess(VOID);

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
	_Analysis_noreturn_ __declspec(noreturn) NTSYSAPI VOID NTAPI LdrShutdownThread(VOID);

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
	NTSYSAPI PUNICODE_STRING NTAPI LdrStandardizeSystemPath(
		_In_ PUNICODE_STRING SystemPath);

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
	NTSYSAPI PS_SYSTEM_DLL_INIT_BLOCK LdrSystemDllInitBlock;

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
	NTSYSAPI BOOLEAN NTAPI LdrUnloadAlternateResourceModule(
		_In_ PVOID DllHandle);

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
	NTSYSAPI BOOLEAN NTAPI LdrUnloadAlternateResourceModuleEx(
		_In_ PVOID DllHandle,
		_In_ ULONG Flags);
	
	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
	NTSYSAPI NTSTATUS NTAPI LdrUnloadDll(
		_In_ PVOID DllHandle);

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
	NTSYSAPI NTSTATUS NTAPI LdrUnlockLoaderLock(
		_In_ ULONG Flags,
		_In_opt_ PVOID Cookie);

	// https://learn.microsoft.com/en-us/windows/win32/devnotes/ldrunregisterdllnotification
	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
	NTSYSAPI NTSTATUS NTAPI LdrUnregisterDllNotification(
		_In_ PVOID Cookie);

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
	NTSYSAPI NTSTATUS NTAPI LdrUpdatePackageSearchPath(
		_In_ PCWSTR SearchPath);

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
	NTSYSAPI NTSTATUS NTAPI LdrVerifyImageMatchesChecksum(
		_In_ HANDLE ImageFileHandle,
		_In_opt_ PLDR_IMPORT_MODULE_CALLBACK ImportCallbackRoutine,
		_In_ PVOID ImportCallbackParameter,
		_Out_opt_ PUSHORT ImageCharacteristics);

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
	NTSYSAPI NTSTATUS NTAPI LdrVerifyImageMatchesChecksumEx(
		_In_ HANDLE ImageFileHandle,
		_Inout_ PLDR_VERIFY_IMAGE_INFO VerifyInfo);

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
	NTSYSAPI VOID NTAPI LdrpResGetMappingSize(
		_In_ PVOID BaseAddress,
		_Out_ PSIZE_T Size,
		_In_ ULONG Flags,
		_In_ BOOLEAN GetFileSizeFromLoadAsDataTable);

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
	NTSYSAPI NTSTATUS NTAPI LdrpResGetResourceDirectory(
		_In_ PVOID DllHandle,
		_In_ SIZE_T Size,
		_In_ ULONG Flags,
		_Out_opt_ PIMAGE_RESOURCE_DIRECTORY* ResourceDirectory,
		_Out_ PIMAGE_NT_HEADERS* OutHeaders);

#ifdef __cplusplus
}
#endif

#endif // _NTLOADER_
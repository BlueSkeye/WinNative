#pragma once

#ifndef _NTLOADER_
#define _NTLOADER_

#include "NtCommonDefs.h"

extern "C" {

	// UNRESOLVED FUNCTIONS

	// Not invoked from any other function in NTDLL.DLL
	//LdrInitShimEngineDynamic

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
	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
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

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
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

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
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

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
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

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
	NTSYSAPI NTSTATUS NTAPI LdrQueryProcessModuleInformation(
		_In_opt_ PRTL_PROCESS_MODULES ModuleInformation,
		_In_opt_ ULONG Size,
		_Out_ PULONG ReturnedSize);

	//https://learn.microsoft.com/en-us/windows/win32/devnotes/ldrregisterdllnotification
	NTSYSAPI NTSTATUS NTAPI LdrRegisterDllNotification(
		_In_ ULONG Flags,
		_In_ PLDR_DLL_NOTIFICATION_FUNCTION NotificationFunction,
		_In_opt_ PVOID Context,
		_Out_ PVOID* Cookie);

	//https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-removedlldirectory
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

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
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

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
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
	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
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

	//https://doxygen.reactos.org/d7/d55/ldrapi_8c.html
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
	_Analysis_noreturn_ DECLSPEC_NORETURN NTSYSAPI VOID NTAPI LdrShutdownProcess(VOID);

	//https://raw.githubusercontent.com/winsiderss/phnt/refs/heads/master/ntldr.h
	_Analysis_noreturn_ DECLSPEC_NORETURN NTSYSAPI VOID NTAPI LdrShutdownThread(VOID);

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

}

#endif // _NTLOADER_
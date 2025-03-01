#pragma once

#ifndef _NTLOADER_
#define _NTLOADER_

#include "NtCommonDefs.h"

extern "C" {

	//LdrAccessResource
	//LdrAddDllDirectory
	//LdrAddLoadAsDataTable
	//LdrAddRefDll
	//LdrAppxHandleIntegrityFailure
	//LdrCallEnclave
	//LdrControlFlowGuardEnforced
	//LdrCreateEnclave
	//LdrDeleteEnclave
	//LdrDisableThreadCalloutsForDll
	//LdrEnumResources
	//LdrEnumerateLoadedModules
	//LdrFastFailInLoaderCallout
	//LdrFindEntryForAddress
	//LdrFindResourceDirectory_U
	//LdrFindResourceEx_U
	//LdrFindResource_U
	//LdrFlushAlternateResourceModules
	//LdrGetDllDirectory
	//LdrGetDllFullName
	//LdrGetDllHandle
	//LdrGetDllHandleByMapping
	//LdrGetDllHandleByName
	//LdrGetDllHandleEx
	//LdrGetDllPath
	//LdrGetFailureData
	//LdrGetKnownDllSectionHandle
	//LdrGetProcedureAddress
	//LdrGetProcedureAddressEx
	//LdrGetProcedureAddressForCaller
	//LdrInitShimEngineDynamic
	//LdrInitializeEnclave
	//LdrInitializeThunk
	//LdrIsModuleSxsRedirected
	//LdrLoadAlternateResourceModule
	//LdrLoadAlternateResourceModuleEx
	//LdrLoadDll
	//LdrLoadEnclaveModule
	//LdrLockLoaderLock
	//LdrProcessInitializationComplete
	//LdrProcessRelocationBlock
	//LdrProcessRelocationBlockEx
	//LdrQueryModuleServiceTags
	//LdrQueryOptionalDelayLoadedAPI
	//LdrQueryProcessModuleInformation
	//LdrRegisterDllNotification
	//LdrRemoveDllDirectory
	//LdrRemoveLoadAsDataTable
	//LdrResFindResource
	//LdrResFindResourceDirectory
	//LdrResGetRCConfig
	//LdrResRelease
	//LdrResSearchResource
	//LdrResolveDelayLoadedAPI
	//LdrResolveDelayLoadsFromDll
	//LdrRscIsTypeExist
	//LdrSetAppCompatDllRedirectionCallback
	//LdrSetDefaultDllDirectories
	//LdrSetDllDirectory
	//LdrSetDllManifestProber
	//LdrSetImplicitPathOptions
	//LdrSetMUICacheType
	//LdrShutdownProcess
	//LdrShutdownThread
	//LdrStandardizeSystemPath
	//LdrSystemDllInitBlock
	//LdrUnloadAlternateResourceModule
	//LdrUnloadAlternateResourceModuleEx
	//LdrUnloadDll
	//LdrUnlockLoaderLock
	//LdrUnregisterDllNotification
	//LdrUpdatePackageSearchPath
	//LdrVerifyImageMatchesChecksum
	//LdrVerifyImageMatchesChecksumEx
	//LdrpResGetMappingSize
	//LdrpResGetResourceDirectory

}

#endif // _NTLOADER_
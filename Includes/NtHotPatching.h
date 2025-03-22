#pragma once

#ifndef _NTHOTPATCHING_
#define _NTHOTPATCHING_

#include "NtCommonDefs.h"
#include "NtAccessRights.h"

extern "C" {

	const ULONG SECURITY_MAX_SID_SIZE = (ULONG)68;

	// https://github.com/winsiderss/systeminformer/blob/d144a06c86e2c7278018f170bff9058b996c8432/phnt/include/ntexapi.h#L7129C1-L7133C48
	typedef struct _HOT_PATCH_IMAGE_INFO {
		ULONG CheckSum;
		ULONG TimeDateStamp;
	} HOT_PATCH_IMAGE_INFO, * PHOT_PATCH_IMAGE_INFO;

	// https://github.com/winsiderss/systeminformer/blob/d144a06c86e2c7278018f170bff9058b996c8432/phnt/include/ntexapi.h#L7135C1-L7145C62
	typedef struct _MANAGE_HOT_PATCH_LOAD_PATCH {
		ULONG Version;
		UNICODE_STRING PatchPath;
		union {
			SID Sid;
			UCHAR Buffer[SECURITY_MAX_SID_SIZE];
		} UserSid;
		HOT_PATCH_IMAGE_INFO BaseInfo;
	} MANAGE_HOT_PATCH_LOAD_PATCH, * PMANAGE_HOT_PATCH_LOAD_PATCH;

	// https://github.com/winsiderss/systeminformer/blob/d144a06c86e2c7278018f170bff9058b996c8432/phnt/include/ntexapi.h#L7147C1-L7156C66
	typedef struct _MANAGE_HOT_PATCH_UNLOAD_PATCH {
		ULONG Version;
		HOT_PATCH_IMAGE_INFO BaseInfo;
		union {
			SID Sid;
			UCHAR Buffer[SECURITY_MAX_SID_SIZE];
		} UserSid;
	} MANAGE_HOT_PATCH_UNLOAD_PATCH, * PMANAGE_HOT_PATCH_UNLOAD_PATCH;

	// https://github.com/winsiderss/systeminformer/blob/d144a06c86e2c7278018f170bff9058b996c8432/phnt/include/ntexapi.h#L7158C1-L7169C68
	typedef struct _MANAGE_HOT_PATCH_QUERY_PATCHES {
		ULONG Version;
		union {
			SID Sid;
			UCHAR Buffer[SECURITY_MAX_SID_SIZE];
		} UserSid;
		ULONG PatchCount;
		PUNICODE_STRING PatchPathStrings;
		PHOT_PATCH_IMAGE_INFO BaseInfos;
	} MANAGE_HOT_PATCH_QUERY_PATCHES, * PMANAGE_HOT_PATCH_QUERY_PATCHES;

	// https://github.com/winsiderss/systeminformer/blob/d144a06c86e2c7278018f170bff9058b996c8432/phnt/include/ntexapi.h#L7171C1-L7179C82
	typedef struct _MANAGE_HOT_PATCH_QUERY_ACTIVE_PATCHES {
		ULONG Version;
		HANDLE ProcessHandle;
		ULONG PatchCount;
		PUNICODE_STRING PatchPathStrings;
		PHOT_PATCH_IMAGE_INFO BaseInfos;
		PULONG PatchSequenceNumbers;
	} MANAGE_HOT_PATCH_QUERY_ACTIVE_PATCHES, * PMANAGE_HOT_PATCH_QUERY_ACTIVE_PATCHES;

	// https://github.com/winsiderss/systeminformer/blob/d144a06c86e2c7278018f170bff9058b996c8432/phnt/include/ntexapi.h#L7181C1-L7197C76
	typedef struct _MANAGE_HOT_PATCH_APPLY_IMAGE_PATCH {
		ULONG Version;
		union {
			struct {
				ULONG ApplyReversePatches : 1;
				ULONG ApplyForwardPatches : 1;
				ULONG Spare : 29;
			} DUMMYSTRUCTNAME;
			ULONG AllFlags;
		};
		HANDLE ProcessHandle;
		PVOID BaseImageAddress;
		PVOID PatchImageAddress;
	} MANAGE_HOT_PATCH_APPLY_IMAGE_PATCH, * PMANAGE_HOT_PATCH_APPLY_IMAGE_PATCH;

	// https://github.com/winsiderss/systeminformer/blob/d144a06c86e2c7278018f170bff9058b996c8432/phnt/include/ntexapi.h#L7199C1-L7206C78
	typedef struct _MANAGE_HOT_PATCH_QUERY_SINGLE_PATCH {
		ULONG Version;
		HANDLE ProcessHandle;
		PVOID BaseAddress;
		ULONG Flags;
		UNICODE_STRING PatchPathString;
	} MANAGE_HOT_PATCH_QUERY_SINGLE_PATCH, * PMANAGE_HOT_PATCH_QUERY_SINGLE_PATCH;
	
	// https://github.com/winsiderss/systeminformer/blob/d144a06c86e2c7278018f170bff9058b996c8432/phnt/include/ntexapi.h#L7208C1-L7212C68
	typedef struct _MANAGE_HOT_PATCH_CHECK_ENABLED {
		ULONG Version;
		ULONG Flags;
	} MANAGE_HOT_PATCH_CHECK_ENABLED, * PMANAGE_HOT_PATCH_CHECK_ENABLED;

	typedef struct _MANAGE_HOT_PATCH_CREATE_PATCH_SECTION {
		ULONG Version;
		ULONG Flags;
		ACCESS_MASK DesiredAccess;
		ULONG PageProtection;
		ULONG AllocationAttributes;
		PVOID BaseImageAddress;
		HANDLE SectionHandle;
	} MANAGE_HOT_PATCH_CREATE_PATCH_SECTION, * PMANAGE_HOT_PATCH_CREATE_PATCH_SECTION;

	// https://github.com/winsiderss/systeminformer/blob/d144a06c86e2c7278018f170bff9058b996c8432/phnt/include/ntexapi.h#L7113
	typedef enum _HOT_PATCH_INFORMATION_CLASS {
		ManageHotPatchLoadPatch = 0, // MANAGE_HOT_PATCH_LOAD_PATCH
		ManageHotPatchUnloadPatch = 1, // MANAGE_HOT_PATCH_UNLOAD_PATCH
		ManageHotPatchQueryPatches = 2, // MANAGE_HOT_PATCH_QUERY_PATCHES
		ManageHotPatchLoadPatchForUser = 3, // MANAGE_HOT_PATCH_LOAD_PATCH
		ManageHotPatchUnloadPatchForUser = 4, // MANAGE_HOT_PATCH_UNLOAD_PATCH
		ManageHotPatchQueryPatchesForUser = 5, // MANAGE_HOT_PATCH_QUERY_PATCHES
		ManageHotPatchQueryActivePatches = 6, // MANAGE_HOT_PATCH_QUERY_ACTIVE_PATCHES
		ManageHotPatchApplyImagePatch = 7, // MANAGE_HOT_PATCH_APPLY_IMAGE_PATCH
		ManageHotPatchQuerySinglePatch = 8, // MANAGE_HOT_PATCH_QUERY_SINGLE_PATCH
		ManageHotPatchCheckEnabled = 9, // MANAGE_HOT_PATCH_CHECK_ENABLED
		ManageHotPatchCreatePatchSection = 10, // MANAGE_HOT_PATCH_CREATE_PATCH_SECTION
		ManageHotPatchMax
	} HOT_PATCH_INFORMATION_CLASS;

	// ============================ functions ============================
	
	// https://signal-labs.com/windows-hotpatching-amp-process-injection/
	// https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/SystemServices/struct.IMAGE_HOT_PATCH_INFO.html
	// https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_load_config_directory64
	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSAPI NTSTATUS NTAPI NtManageHotPatch(
		_In_ HOT_PATCH_INFORMATION_CLASS HotPatchClass,
		_In_ PVOID PatchData,
		_In_ ULONG Length,
		_Out_ PULONG ReturnedLength);
	//ZwManageHotPatch

}

#endif // _NTHOTPATCHING_
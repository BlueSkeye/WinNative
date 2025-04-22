#pragma once

#ifndef _NTCONTEXTS_
#define _NTCONTEXTS_

#include "NtCommonDefs.h"
#include "NtContext.h"
#include "NtPebTeb.h"

#ifdef __cplusplus
extern "C" {
#endif

	// NO UNRESOLVED FUNCTIONS

	typedef struct _COMPATIBILITY_CONTEXT_ELEMENT COMPATIBILITY_CONTEXT_ELEMENT,
		* PCOMPATIBILITY_CONTEXT_ELEMENT;

	// https://github.com/wine-mirror/wine/blob/6298b0cab2086ae61f46b284d22c420dfbb2b44e/dlls/ntdll/actctx.c#L530
	enum assembly_type {
		APPLICATION_MANIFEST,
		ASSEMBLY_MANIFEST,
		ASSEMBLY_SHARED_MANIFEST,
	};

	// https://github.com/wine-mirror/wine/blob/6298b0cab2086ae61f46b284d22c420dfbb2b44e/include/winnt.h#L6387C1-L6392C37
	typedef enum {
		ACTCTX_COMPATIBILITY_ELEMENT_TYPE_UNKNOWN = 0,
		ACTCTX_COMPATIBILITY_ELEMENT_TYPE_OS,
		ACTCTX_COMPATIBILITY_ELEMENT_TYPE_MITIGATION,
		ACTCTX_COMPATIBILITY_ELEMENT_TYPE_MAXVERSIONTESTED
	} ACTCTX_COMPATIBILITY_ELEMENT_TYPE;

	// https://github.com/wine-mirror/wine/blob/6298b0cab2086ae61f46b284d22c420dfbb2b44e/include/winnt.h#L6407C1-L6413C30
	typedef enum {
		ACTCTX_RUN_LEVEL_UNSPECIFIED = 0,
		ACTCTX_RUN_LEVEL_AS_INVOKER,
		ACTCTX_RUN_LEVEL_HIGHEST_AVAILABLE,
		ACTCTX_RUN_LEVEL_REQUIRE_ADMIN,
		ACTCTX_RUN_LEVEL_NUMBERS
	} ACTCTX_REQUESTED_RUN_LEVEL;

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

	typedef struct _ACTIVATION_CONTEXT_QUERY_INDEX {
		DWORD ulAssemblyIndex;
		DWORD ulFileIndexInAssembly;
	} ACTIVATION_CONTEXT_QUERY_INDEX, * PACTIVATION_CONTEXT_QUERY_INDEX;

	// https://github.com/wine-mirror/wine/blob/6298b0cab2086ae61f46b284d22c420dfbb2b44e/dlls/ntdll/actctx.c#L129
	struct assembly_version {
		USHORT major;
		USHORT minor;
		USHORT build;
		USHORT revision;
	};

	// https://github.com/wine-mirror/wine/blob/6298b0cab2086ae61f46b284d22c420dfbb2b44e/dlls/ntdll/actctx.c#L137
	struct assembly_identity {
		WCHAR* name;
		WCHAR* arch;
		WCHAR* public_key;
		WCHAR* language;
		WCHAR* type;
		struct assembly_version version;
		BOOL optional;
		BOOL delayed;
	};

	// https://github.com/wine-mirror/wine/blob/6298b0cab2086ae61f46b284d22c420dfbb2b44e/dlls/ntdll/actctx.c#L123
	struct file_info {
		ULONG type;
		WCHAR* info;
	};

	// https://github.com/wine-mirror/wine/blob/6298b0cab2086ae61f46b284d22c420dfbb2b44e/dlls/ntdll/actctx.c#L446
	struct progids {
		WCHAR** progids;
		unsigned int num;
		unsigned int allocated;
	};

	// https://github.com/wine-mirror/wine/blob/6298b0cab2086ae61f46b284d22c420dfbb2b44e/dlls/ntdll/actctx.c#L453C1-L513C3
	struct entity
	{
		DWORD kind;
		union {
			struct {
				WCHAR* tlbid;
				WCHAR* helpdir;
				WORD flags;
				WORD major;
				WORD minor;
			} typelib;
			struct {
				WCHAR* clsid;
				WCHAR* tlbid;
				WCHAR* progid;
				WCHAR* name;    /* clrClass: class name */
				WCHAR* version; /* clrClass: CLR runtime version */
				DWORD model;
				DWORD miscstatus;
				DWORD miscstatuscontent;
				DWORD miscstatusthumbnail;
				DWORD miscstatusicon;
				DWORD miscstatusdocprint;
				struct progids progids;
			} comclass;
			struct {
				WCHAR* iid;
				WCHAR* base;
				WCHAR* tlib;
				WCHAR* name;
				WCHAR* ps32; /* only stored for 'comInterfaceExternalProxyStub' */
				DWORD mask;
				ULONG nummethods;
			} ifaceps;
			struct {
				WCHAR* name;
				BOOL versioned;
			} Class;
			struct {
				WCHAR* name;
				WCHAR* clsid;
				WCHAR* version;
			} clrsurrogate;
			struct {
				WCHAR* name;
				WCHAR* value;
				WCHAR* ns;
			} settings;
			struct {
				WCHAR* name;
				DWORD threading_model;
			} activatable_class;
		} u;
	};

	// https://github.com/wine-mirror/wine/blob/6298b0cab2086ae61f46b284d22c420dfbb2b44e/dlls/ntdll/actctx.c#L515
	struct entity_array {
		struct entity* base;
		unsigned int num;
		unsigned int allocated;
	};

	// https://github.com/wine-mirror/wine/blob/6298b0cab2086ae61f46b284d22c420dfbb2b44e/dlls/ntdll/actctx.c#L522
	struct dll_redirect {
		WCHAR* name;
		WCHAR* load_from;
		WCHAR* hash;
		struct entity_array entities;
	};
	
	// https://github.com/wine-mirror/wine/blob/6298b0cab2086ae61f46b284d22c420dfbb2b44e/include/winnt.h#L6394C1-L6398C66
	struct _COMPATIBILITY_CONTEXT_ELEMENT {
		GUID Id;
		ACTCTX_COMPATIBILITY_ELEMENT_TYPE Type;
		ULONGLONG MaxVersionTested;
	};

	// https://github.com/wine-mirror/wine/blob/6298b0cab2086ae61f46b284d22c420dfbb2b44e/dlls/ntdll/actctx.c#L537
	struct assembly {
		enum assembly_type type;
		struct assembly_identity id;
		struct file_info manifest;
		WCHAR* directory;
		BOOL no_inherit;
		struct dll_redirect* dlls;
		unsigned int num_dlls;
		unsigned int allocated_dlls;
		struct entity_array entities;
		COMPATIBILITY_CONTEXT_ELEMENT* compat_contexts;
		ULONG num_compat_contexts;
		ACTCTX_REQUESTED_RUN_LEVEL run_level;
		ULONG ui_access;
	};
	
	// https://github.com/wine-mirror/wine/blob/6298b0cab2086ae61f46b284d22c420dfbb2b44e/dlls/ntdll/actctx.c#L149
	struct strsection_header {
		DWORD magic;
		ULONG size;
		DWORD unk1[3];
		ULONG count;
		ULONG index_offset;
		DWORD unk2[2];
		ULONG global_offset;
		ULONG global_len;
	};
	
	// https://github.com/wine-mirror/wine/blob/6298b0cab2086ae61f46b284d22c420dfbb2b44e/dlls/ntdll/actctx.c#L171
	struct guidsection_header {
		DWORD magic;
		ULONG size;
		DWORD unk[3];
		ULONG count;
		ULONG index_offset;
		DWORD unk2;
		ULONG names_offset;
		ULONG names_len;
	};

	// =========================== functions ===========================
	//https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/actctx.c
	NTSYSAPI NTSTATUS NTAPI RtlActivateActivationContext(
		_In_ ULONG Flags,
		_In_ HANDLE Handle,
		_Out_ PULONG_PTR Cookie);

	// https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/actctx.c
	NTSTATUS NTAPI RtlActivateActivationContextEx(
		_In_ ULONG Flags,
		_In_ TEB* Teb,
		_In_ HANDLE Handle,
		_Out_ PULONG_PTR Cookie);

	//https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/actctx.c
	NTSYSAPI void NTAPI RtlAddRefActivationContext(
		_In_ HANDLE handle);

	//https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/actctx.c
	NTSYSAPI NTSTATUS NTAPI RtlCreateActivationContext(
		PHANDLE handle,
		LPCVOID ptr);

	//https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/actctx.c
	NTSYSAPI VOID NTAPI RtlDeactivateActivationContext(
		_In_ ULONG Flags,
		_In_ ULONG_PTR cookie);

	//https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/actctx.c
	NTSYSAPI NTSTATUS NTAPI RtlFindActivationContextSectionGuid(
		_In_ ULONG Flags,
		LPCGUID extguid,
		ULONG section_kind,
		LPCGUID guid,
		PVOID ptr);

	// https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/actctx.c
	NTSYSAPI NTSTATUS NTAPI RtlFindActivationContextSectionString(
		_In_ ULONG Flags,
		LPCGUID guid,
		ULONG section_kind,
		LPCUNICODE_STRING section_name,
		PVOID ptr);

	// https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/actctx.c
	NTSYSAPI VOID NTAPI RtlFreeActivationContextStack(
		_In_ PACTIVATION_CONTEXT_STACK actctx_stack);

	//https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/actctx.c
	NTSYSAPI void NTAPI RtlFreeThreadActivationContextStack(VOID);

	// https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/actctx.c
	NTSYSAPI NTSTATUS NTAPI RtlGetActiveActivationContext(
		_Out_ PHANDLE handle);

	// https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/actctx.c
	NTSYSAPI BOOLEAN NTAPI RtlIsActivationContextActive(
		_In_ HANDLE handle);

	//https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/actctx.c
	NTSYSAPI NTSTATUS NTAPI RtlQueryActivationContextApplicationSettings(
		DWORD Flags,
		HANDLE handle,
		const PWCHAR ns,
		const PWCHAR settings,
		PWCHAR buffer,
		SIZE_T size,
		_Out_ PSIZE_T written);

	//https://github.com/winsiderss/systeminformer/blob/06f8fd943b3e05baa42e2fd1f45246caf8d7ff95/phnt/include/ntrtl.h#L4066
	NTSYSAPI NTSTATUS NTAPI RtlQueryInformationActivationContext(
		_In_ ULONG Flags,
		_In_ PACTIVATION_CONTEXT Handle,
		_In_opt_ PACTIVATION_CONTEXT_QUERY_INDEX SubinstanceIndex,
		_In_ ACTIVATION_CONTEXT_INFO_CLASS Class,
		_Out_writes_bytes_(ActivationContextInformationLength) PVOID ActivationContextInformation,
		_In_ SIZE_T ActivationContextInformationLength,
		_Out_ PSIZE_T retlen);

	//https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/ntrtl.h#L3908
	NTSYSAPI void NTAPI RtlReleaseActivationContext(
		_In_ PACTIVATION_CONTEXT ActivationContext);

	// https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/actctx.c
	NTSYSAPI NTSTATUS NTAPI RtlZombifyActivationContext(
		_In_ HANDLE handle);

#ifdef __cplusplus
}
#endif

#endif // _NTCONTEXTS_
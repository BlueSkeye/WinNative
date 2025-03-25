#pragma once

#ifndef _NTCONTEXTS_
#define _NTCONTEXTS_

#include "NtCommonDefs.h"
#include "NtContext.h"
#include "NtPebTeb.h"

extern "C" {

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


	// https://github.com/wine-mirror/wine/blob/6298b0cab2086ae61f46b284d22c420dfbb2b44e/dlls/ntdll/actctx.c#L566
	struct _ACTIVATION_CONTEXT {
		ULONG magic;
		LONG ref_count;
		struct file_info config;
		struct file_info appdir;
		struct assembly* assemblies;
		unsigned int num_assemblies;
		unsigned int allocated_assemblies;
		/* section data */
		DWORD sections;
		struct strsection_header* wndclass_section;
		struct strsection_header* dllredirect_section;
		struct strsection_header* progid_section;
		struct strsection_header* activatable_class_section;
		struct guidsection_header* tlib_section;
		struct guidsection_header* comserver_section;
		struct guidsection_header* ifaceps_section;
		struct guidsection_header* clrsurrogate_section;
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
		const PVOID ptr);

	//https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/actctx.c
	NTSYSAPI VOID NTAPI RtlDeactivateActivationContext(
		_In_ ULONG Flags,
		_In_ ULONG_PTR cookie);

	//https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/actctx.c
	NTSYSAPI NTSTATUS NTAPI RtlFindActivationContextSectionGuid(
		_In_ ULONG Flags,
		const PGUID extguid,
		ULONG section_kind,
		const PGUID guid,
		PVOID ptr);

	// https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/actctx.c
	NTSYSAPI NTSTATUS NTAPI RtlFindActivationContextSectionString(
		_In_ ULONG Flags,
		const PGUID guid,
		ULONG section_kind,
		const PUNICODE_STRING section_name,
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

	//https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/actctx.c
	NTSYSAPI NTSTATUS NTAPI RtlQueryInformationActivationContext(
		_In_ ULONG Flags,
		_In_ HANDLE Handle,
		PVOID Subinst,
		_In_ ULONG Class,
		_In_ PVOID Buffer,
		_In_ SIZE_T Bufsize,
		_Out_ PSIZE_T retlen);

	//https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/actctx.c
	NTSYSAPI void NTAPI RtlReleaseActivationContext(
		_In_ HANDLE handle);

	// https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/actctx.c
	NTSYSAPI NTSTATUS NTAPI RtlZombifyActivationContext(
		_In_ HANDLE handle);

}

#endif // _NTCONTEXTS_
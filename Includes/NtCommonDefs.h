#pragma once

#ifndef _NTCOMMONDEFS_
#define _NTCOMMONDEFS_

#ifdef SAL_AWARE
#include <sal.h>
#else
#define _Field_size_bytes_part_opt_(X, Y)
#define _Null_terminated_
#define _NullNull_terminated_
#endif

#define WIN32
// This will prevent minwindef.h to include winnt.h
#define NT_INCLUDED
// ... however we have to define a couple of things

#define ANYSIZE_ARRAY 1
#define CONST const
#define POINTER_64 __ptr64
#define UNALIGNED __unaligned
#define VOID void

// Forward declarations
typedef struct _SID_IDENTIFIER_AUTHORITY* PSID_IDENTIFIER_AUTHORITY;
typedef struct _UNICODE_STRING* PUNICODE_STRING;

// Intrinsic types aliases
typedef int errno_t;
typedef void* LPVOID;
typedef const void *LPCVOID;
typedef int BOOL, * PBOOL;
typedef unsigned char BYTE;
typedef char CHAR, CCHAR;
typedef short CSHORT; 
typedef int DWORD, *PDWORD;
typedef unsigned __int64 ULONG64, UINT64, * PULONG64;
typedef unsigned __int64 DWORD64, * PDWORD64;
typedef void* HANDLE, * PHANDLE;
typedef __int64 INT_PTR, * PINT_PTR;
typedef long LONG, * PLONG;
typedef __int64 INT64, LONGLONG, LONG64, * PLONG64, QWORD;
typedef __int64 LONG_PTR, * PLONG_PTR;
typedef signed __int64 int64_t;
typedef short SHORT, * PSHORT;
typedef unsigned char UCHAR, * PUCHAR;
typedef unsigned int uint32_t, UINT, UINT32;
typedef unsigned __int64 uint64_t, DWORD64, UINT_PTR, * PUINT_PTR;
typedef unsigned long ULONG, * PULONG;
typedef unsigned __int64 ULONGLONG, *PULONGLONG;
typedef unsigned __int64 ULONG_PTR, * PULONG_PTR;
typedef unsigned char UINT8, * PUINT8;
typedef unsigned short UINT16, *PUINT16, USHORT, * PUSHORT;
typedef wchar_t WCHAR;    // wc,   16-bit UNICODE character
typedef short WORD;

// More derived types.
typedef BYTE BOOLEAN, *PBOOLEAN, *PBYTE;
typedef DWORD INT32, LCID, *PLCID;
typedef ULONG CLONG, LOGICAL; 
typedef LONG NTSTATUS, *PNTSTATUS;
typedef VOID* PVOID, ** PPVOID;
typedef void* POINTER_64 PVOID64;
typedef const VOID* PCVOID;
typedef ULONGLONG REGHANDLE, * PREGHANDLE;
typedef __int64 intptr_t;
typedef USHORT LANGID;

#define __int3264   __int64
#ifndef FALSE
#define FALSE               0
#endif
#ifndef TRUE
#define TRUE                1
#endif

#define MAX_PATH 260

// Including some basic types
#define DECLARE_HANDLE(name) struct name##__; typedef struct name##__ *name
typedef size_t SIZE_T, * PSIZE_T;

typedef _Null_terminated_ CHAR* LPCH, * LPSTR, * NPSTR, * PCH, * PCHAR, * PSTR, * PSZ;
typedef _Null_terminated_ CONST char *LPCCH, * LPCSTR, * PCCH, * PCSTR, * PCSZ;

typedef WCHAR* PWCHAR, * LPWCH, * PWCH;
typedef CONST WCHAR* LPCWCH, * PCWCH;

typedef _Null_terminated_ WCHAR* NWPSTR, * LPWSTR, * PWSTR;
typedef _Null_terminated_ PWSTR* PZPWSTR;
typedef _Null_terminated_ CONST PWSTR* PCZPWSTR;
typedef _Null_terminated_ WCHAR UNALIGNED* LPUWSTR, * PUWSTR;
typedef _Null_terminated_ CONST WCHAR* LPCWSTR, * PCWSTR;
typedef _Null_terminated_ PCWSTR* PZPCWSTR;
typedef _Null_terminated_ CONST PCWSTR* PCZPCWSTR;
typedef _Null_terminated_ CONST WCHAR UNALIGNED* LPCUWSTR, * PCUWSTR;

typedef _NullNull_terminated_ WCHAR* PZZWSTR;
typedef _NullNull_terminated_ CONST WCHAR* PCZZWSTR;
typedef _NullNull_terminated_ WCHAR UNALIGNED* PUZZWSTR;
typedef _NullNull_terminated_ CONST WCHAR UNALIGNED* PCUZZWSTR;

typedef  WCHAR* PNZWCH;
typedef  CONST WCHAR* PCNZWCH;
typedef  WCHAR UNALIGNED* PUNZWCH;
typedef  CONST WCHAR UNALIGNED* PCUNZWCH;

typedef CONST WCHAR* LPCWCHAR, * PCWCHAR;
typedef CONST WCHAR UNALIGNED* LPCUWCHAR, * PCUWCHAR;

#define NTSYSAPI __declspec(dllimport)
#define NTSYSCALLAPI __declspec(dllimport)
#define NTAPI __stdcall

typedef INT_PTR(__stdcall* FARPROC)();

typedef enum _EVENT_TYPE {
    NotificationEvent,
    SynchronizationEvent
} EVENT_TYPE;

typedef struct _GUID {
    unsigned long  Data1;
    unsigned short Data2;
    unsigned short Data3;
    unsigned char  Data4[8];
} GUID;
typedef GUID * PGUID, * LPGUID, REFGUID;
typedef const GUID * LPCGUID;

typedef union _LARGE_INTEGER {
    struct {
        ULONG LowPart;
        LONG HighPart;
    } DUMMYSTRUCTNAME;
    struct {
        ULONG LowPart;
        LONG HighPart;
    } u;
    LONGLONG QuadPart;
} LARGE_INTEGER, *PLARGE_INTEGER;

typedef union _ULARGE_INTEGER {
    struct {
        ULONG LowPart;
        ULONG HighPart;
    } DUMMYSTRUCTNAME;
    struct {
        ULONG LowPart;
        ULONG HighPart;
    } u;
    ULONGLONG QuadPart;
} ULARGE_INTEGER;

typedef struct _LIST_ENTRY {
    struct _LIST_ENTRY* Flink;
    struct _LIST_ENTRY* Blink;
} LIST_ENTRY, * PLIST_ENTRY, PRLIST_ENTRY;

// From winnt.h
typedef struct __declspec(align(16)) _SLIST_ENTRY {
    struct _SLIST_ENTRY* Next;
} SLIST_ENTRY, * PSLIST_ENTRY;

// From winnt.h
typedef union __declspec(align(16)) _SLIST_HEADER {
    struct {
        // original struct
        ULONGLONG Alignment;
        ULONGLONG Region;
    } DUMMYSTRUCTNAME;
    struct {
        // x64 16-byte header
        ULONGLONG Depth : 16;
        ULONGLONG Sequence : 48;
        ULONGLONG Reserved : 4;
        ULONGLONG NextEntry : 60; // last 4 bits are always 0's
    } HeaderX64;
} SLIST_HEADER, * PSLIST_HEADER;

typedef struct _SINGLE_LIST_ENTRY {
    struct _SINGLE_LIST_ENTRY* Next;
} SINGLE_LIST_ENTRY, * PSINGLE_LIST_ENTRY;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _SID_IDENTIFIER_AUTHORITY {
    UCHAR Value[6];
} SID_IDENTIFIER_AUTHORITY;

typedef struct _SID {
    BYTE Revision;
    BYTE SubAuthorityCount;
    SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
    /* [size_is] */ ULONG SubAuthority[1];
} SID, *PSID;

typedef struct _STRING {
    USHORT Length;
    USHORT MaximumLength;
    _Field_size_bytes_part_opt_(MaximumLength, Length) PCHAR Buffer;
} STRING;
typedef STRING ANSI_STRING, CANSI_STRING, OEM_STRING, UTF8_STRING, *PSTRING;
typedef PSTRING PANSI_STRING, PCANSI_STRING, POEM_STRING, PUTF8_STRING;
typedef CONST STRING* PCOEM_STRING;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING;
typedef const UNICODE_STRING* PCUNICODE_STRING;

// https://doxygen.reactos.org/d6/d6b/struct__CLIENT__ID.html
typedef struct _CLIENT_ID {
    HANDLE 	UniqueProcess;
    HANDLE 	UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

// From winnt.h
typedef enum _SECURITY_IMPERSONATION_LEVEL {
    SecurityAnonymous,
    SecurityIdentification,
    SecurityImpersonation,
    SecurityDelegation
} SECURITY_IMPERSONATION_LEVEL, * PSECURITY_IMPERSONATION_LEVEL;

// From winnt.h
typedef BOOLEAN SECURITY_CONTEXT_TRACKING_MODE, * PSECURITY_CONTEXT_TRACKING_MODE;

// From winnt.h
typedef struct _SECURITY_QUALITY_OF_SERVICE {
    DWORD Length;
    SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
    SECURITY_CONTEXT_TRACKING_MODE ContextTrackingMode;
    BOOLEAN EffectiveOnly;
} SECURITY_QUALITY_OF_SERVICE, * PSECURITY_QUALITY_OF_SERVICE;

// From wtypebase.h
typedef struct _SECURITY_ATTRIBUTES {
    DWORD nLength;
    LPVOID lpSecurityDescriptor;
    BOOL bInheritHandle;
} SECURITY_ATTRIBUTES, *PSECURITY_ATTRIBUTES;

// From winnt.h
typedef struct _LUID {
    DWORD LowPart;
    LONG HighPart;
} LUID, * PLUID;

// From winnt.h
typedef struct _LUID_AND_ATTRIBUTES {
    LUID Luid;
    DWORD Attributes;
} LUID_AND_ATTRIBUTES, * PLUID_AND_ATTRIBUTES;
typedef LUID_AND_ATTRIBUTES LUID_AND_ATTRIBUTES_ARRAY[ANYSIZE_ARRAY];
typedef LUID_AND_ATTRIBUTES_ARRAY* PLUID_AND_ATTRIBUTES_ARRAY;

typedef PVOID PSECURITY_DESCRIPTOR;

typedef struct _RTL_SPLAY_LINKS RTL_SPLAY_LINKS, * PRTL_SPLAY_LINKS;

// https://processhacker.sourceforge.io/doc/struct___r_t_l___s_p_l_a_y___l_i_n_k_s.html
struct _RTL_SPLAY_LINKS {
    struct _RTL_SPLAY_LINKS* Parent;
    struct _RTL_SPLAY_LINKS* LeftChild;
    struct _RTL_SPLAY_LINKS* RightChild;
};

// From wtypesbase.h
typedef struct _ACL {
    UCHAR AclRevision;
    UCHAR Sbz1;
    USHORT AclSize;
    USHORT AceCount;
    USHORT Sbz2;
} ACL, *PACL;

typedef ULONG_PTR KAFFINITY;

// From ntdef.h
typedef struct _GROUP_AFFINITY {
    KAFFINITY Mask;
    USHORT Group;
    USHORT Reserved[3];
} GROUP_AFFINITY, * PGROUP_AFFINITY;

typedef struct _RTL_CONDITION_VARIABLE {
    PVOID Ptr;
} RTL_CONDITION_VARIABLE, * PRTL_CONDITION_VARIABLE;

typedef struct _RTL_SRWLOCK {
    PVOID Ptr;
} RTL_SRWLOCK, * PRTL_SRWLOCK;

// https://github.com/x-tinkerer/WRK/blob/e2e25706c766e1f93b3e55ab95601e72860f74d9/public/sdk/inc/ntrtlstringandbuffer.h#L114
typedef struct _RTL_BUFFER {
    PUCHAR Buffer;
    PUCHAR StaticBuffer;
    SIZE_T Size;
    SIZE_T StaticSize;
    SIZE_T ReservedForAllocatedSize; // for future doubling
    PVOID ReservedForIMalloc; // for future pluggable growth
} RTL_BUFFER, * PRTL_BUFFER;

// https://github.com/x-tinkerer/WRK/blob/e2e25706c766e1f93b3e55ab95601e72860f74d9/public/sdk/inc/ntrtlstringandbuffer.h#L249
typedef struct _RTL_UNICODE_STRING_BUFFER {
    UNICODE_STRING String;
    RTL_BUFFER ByteBuffer;
    UCHAR MinimumStaticBufferForTerminalNul[sizeof(WCHAR)];
} RTL_UNICODE_STRING_BUFFER, * PRTL_UNICODE_STRING_BUFFER;

// From ntdef.h
// Structure to represent a system wide processor number. It contains a
// group number and relative processor number within the group.
typedef struct _PROCESSOR_NUMBER {
    USHORT Group;
    UCHAR Number;
    UCHAR Reserved;
} PROCESSOR_NUMBER, * PPROCESSOR_NUMBER;

// https://learn.microsoft.com/fr-fr/windows-hardware/drivers/kernel/eprocess#rtl_bitmap
typedef struct _RTL_BITMAP {
    // opaque
} RTL_BITMAP, * PRTL_BITMAP;


// https://github.com/winsiderss/systeminformer/blob/21b740464f0d1f738d49542e13d68e6dbb7f76d2/phnt/include/ntpebteb.h#L822C1-L829C56
/* The TEB_ACTIVE_FRAME_CONTEXT structure is used to store information about an active frame context. */
typedef struct _TEB_ACTIVE_FRAME_CONTEXT {
    ULONG Flags;
    PCSTR FrameName;
} TEB_ACTIVE_FRAME_CONTEXT, * PTEB_ACTIVE_FRAME_CONTEXT;

// https://github.com/winsiderss/systeminformer/blob/21b740464f0d1f738d49542e13d68e6dbb7f76d2/phnt/include/ntpebteb.h#L842C1-L851C1
/* The TEB_ACTIVE_FRAME structure is used to store information about an active frame. */
typedef struct _TEB_ACTIVE_FRAME {
    ULONG Flags;
    struct _TEB_ACTIVE_FRAME* Previous;
    PTEB_ACTIVE_FRAME_CONTEXT Context;
} TEB_ACTIVE_FRAME, * PTEB_ACTIVE_FRAME;

// https://github.com/winsiderss/systeminformer/blob/fb60c2a4494de6f27ffdfefc85364d5b357a2ffa/phnt/include/phnt_ntdef.h#L369C1-L375C1
typedef enum _NT_PRODUCT_TYPE {
    NtProductWinNt = 1,
    NtProductLanManNt,
    NtProductServer
} NT_PRODUCT_TYPE, * PNT_PRODUCT_TYPE;

// https://github.com/winsiderss/systeminformer/blob/fb60c2a4494de6f27ffdfefc85364d5b357a2ffa/phnt/include/phnt_ntdef.h#L422C1-L427C32
typedef struct _KSYSTEM_TIME {
    ULONG LowPart;
    LONG High1Time;
    LONG High2Time;
} KSYSTEM_TIME, * PKSYSTEM_TIME;

// From winnt.h
typedef struct _RTL_CRITICAL_SECTION  RTL_CRITICAL_SECTION, * PRTL_CRITICAL_SECTION;
typedef struct _RTL_CRITICAL_SECTION_DEBUG {
    WORD Type;
    WORD CreatorBackTraceIndex;
    PRTL_CRITICAL_SECTION CriticalSection;
    LIST_ENTRY ProcessLocksList;
    DWORD EntryCount;
    DWORD ContentionCount;
    DWORD Flags;
    WORD CreatorBackTraceIndexHigh;
    WORD Identifier;
} RTL_CRITICAL_SECTION_DEBUG, * PRTL_CRITICAL_SECTION_DEBUG, RTL_RESOURCE_DEBUG, * PRTL_RESOURCE_DEBUG;

#ifndef _VA_LIST
#define _VA_LIST char*
#endif
typedef _VA_LIST va_list;

// Define some specificiation strings to prevent compilation errors.
#define __drv_aliasesMem
#define _Frees_ptr_
#define _Frees_ptr_opt_
#define DECLSPEC_ALLOCATOR __declspec(allocator)
#define DECLSPEC_NOALIAS __declspec(noalias)
#define DECLSPEC_RESTRICT __declspec(restrict)

#endif // _NTCOMMONDEFS_
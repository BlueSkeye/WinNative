#pragma once

#ifndef _NTCOMMONDEFS_
#define _NTCOMMONDEFS_

#include <sal.h>

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
typedef char CHAR;
typedef short CSHORT; 
typedef int DWORD, *PDWORD;
typedef unsigned __int64 ULONG64, UINT64, * PULONG64;
typedef unsigned __int64 DWORD64, * PDWORD64;
typedef void* HANDLE, * PHANDLE;
typedef __int64 INT_PTR, * PINT_PTR;
typedef long LONG, * PLONG;
typedef __int64 LONGLONG, QWORD;
typedef __int64 LONG_PTR, * PLONG_PTR;
typedef short SHORT, * PSHORT;
typedef unsigned char UCHAR, * PUCHAR;
typedef unsigned __int64 DWORD64, UINT_PTR, * PUINT_PTR;
typedef unsigned long ULONG, * PULONG;
typedef unsigned __int64 ULONGLONG, *PULONGLONG;
typedef unsigned __int64 ULONG_PTR, * PULONG_PTR;
typedef unsigned short USHORT, * PUSHORT;
typedef wchar_t WCHAR;    // wc,   16-bit UNICODE character
typedef short WORD;

// More derived types.
typedef BYTE BOOLEAN, *PBOOLEAN;
typedef DWORD LCID, *PLCID;
typedef ULONG CLONG, LOGICAL; 
typedef LONG NTSTATUS;
typedef VOID* PVOID, ** PPVOID;
typedef void* POINTER_64 PVOID64;
typedef const VOID* PCVOID;
typedef ULONGLONG REGHANDLE, * PREGHANDLE;
typedef __int64 intptr_t;

#define __int3264   __int64
#ifndef FALSE
#define FALSE               0
#endif
#ifndef TRUE
#define TRUE                1
#endif

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

typedef struct _LIST_ENTRY {
    struct _LIST_ENTRY* Flink;
    struct _LIST_ENTRY* Blink;
} LIST_ENTRY, * PLIST_ENTRY, PRLIST_ENTRY;

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
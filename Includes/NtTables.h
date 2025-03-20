#pragma once

#ifndef _NTTABLES_
#define _NTTABLES_

#include "NtCommonDefs.h"

extern "C" {

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16

	typedef struct _IMAGE_DATA_DIRECTORY IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;
	typedef struct _IMAGE_FILE_HEADER IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;
	typedef struct _IMAGE_NT_HEADERS64 IMAGE_NT_HEADERS64, * PIMAGE_NT_HEADERS64;
	typedef struct _IMAGE_OPTIONAL_HEADER64  IMAGE_OPTIONAL_HEADER64, * PIMAGE_OPTIONAL_HEADER64;
	typedef struct _RTL_AVL_TABLE RTL_AVL_TABLE, * PRTL_AVL_TABLE;
	typedef struct _RTL_BALANCED_NODE RTL_BALANCED_NODE, * PRTL_BALANCED_NODE;
	typedef struct _RTL_BALANCED_LINKS RTL_BALANCED_LINKS, *PRTL_BALANCED_LINKS;
	typedef struct _RTL_DYNAMIC_HASH_TABLE_CONTEXT RTL_DYNAMIC_HASH_TABLE_CONTEXT,
		* PRTL_DYNAMIC_HASH_TABLE_CONTEXT;
	typedef struct _RTL_DYNAMIC_HASH_TABLE_ENUMERATOR RTL_DYNAMIC_HASH_TABLE_ENUMERATOR,
		* PRTL_DYNAMIC_HASH_TABLE_ENUMERATOR;
	typedef struct _RTL_DYNAMIC_HASH_TABLE_ENTRY RTL_DYNAMIC_HASH_TABLE_ENTRY,
		* PRTL_DYNAMIC_HASH_TABLE_ENTRY;
	typedef struct _RTL_GENERIC_TABLE RTL_GENERIC_TABLE, * PRTL_GENERIC_TABLE;
	typedef struct _RTL_HANDLE_TABLE* PRTL_HANDLE_TABLE;
	typedef struct _RTL_HANDLE_TABLE_ENTRY* PRTL_HANDLE_TABLE_ENTRY;
	typedef struct _RTL_RB_TREE RTL_RB_TREE, * PRTL_RB_TREE;
	typedef struct _RTL_SPLAY_LINKS RTL_SPLAY_LINKS, * PRTL_SPLAY_LINKS;


	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html#ad7ef1aa11ee7738aac70bb450a9a8f51
	typedef enum _RTL_GENERIC_COMPARE_RESULTS {
		GenericLessThan,
		GenericGreaterThan,
		GenericEqual
	} RTL_GENERIC_COMPARE_RESULTS, *PRTL_GENERIC_COMPARE_RESULTS;

	typedef _Function_class_(GET_RUNTIME_FUNCTION_CALLBACK) PRUNTIME_FUNCTION
		GET_RUNTIME_FUNCTION_CALLBACK(
			_In_ DWORD64 ControlPc,
			_In_opt_ PVOID Context);
	typedef GET_RUNTIME_FUNCTION_CALLBACK* PGET_RUNTIME_FUNCTION_CALLBACK;
	typedef PVOID(NTAPI* PRTL_AVL_ALLOCATE_ROUTINE) (
		__in PRTL_AVL_TABLE Table,
		__in CLONG  ByteSize);
	typedef VOID(NTAPI* PRTL_AVL_FREE_ROUTINE) (
		__in PRTL_AVL_TABLE Table,
		__in PVOID Buffer);
	typedef NTSTATUS(NTAPI* PRTL_AVL_MATCH_FUNCTION)(
		_In_ PRTL_AVL_TABLE Table,
		_In_ PVOID UserData,
		_In_ PVOID MatchData);
	typedef RTL_GENERIC_COMPARE_RESULTS(NTAPI* PRTL_AVL_COMPARE_ROUTINE) (
		__in PRTL_AVL_TABLE Table,
		__in PVOID FirstStruct,
		__in PVOID SecondStruct);
	typedef PVOID(NTAPI* PRTL_GENERIC_ALLOCATE_ROUTINE)(
		_In_ struct _RTL_GENERIC_TABLE* Table,
		_In_ CLONG ByteSize);
	typedef RTL_GENERIC_COMPARE_RESULTS(NTAPI* PRTL_GENERIC_COMPARE_ROUTINE)(
		_In_ PRTL_GENERIC_TABLE Table);
	typedef VOID(NTAPI* PRTL_GENERIC_FREE_ROUTINE)(
		_In_ struct _RTL_GENERIC_TABLE* Table,
		_In_ _Post_invalid_ PVOID Buffer);

	typedef enum _TABLE_SEARCH_RESULT {
		TableEmptyTree,
		TableFoundNode,
		TableInsertAsLeft,
		TableInsertAsRight
	} TABLE_SEARCH_RESULT, *PTABLE_SEARCH_RESULT;

	struct _IMAGE_DATA_DIRECTORY {
		DWORD VirtualAddress;
		DWORD Size;
	};

	// https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_file_header
	struct _IMAGE_FILE_HEADER {
		WORD  Machine;
		WORD  NumberOfSections;
		DWORD TimeDateStamp;
		DWORD PointerToSymbolTable;
		DWORD NumberOfSymbols;
		WORD  SizeOfOptionalHeader;
		WORD  Characteristics;
	};

	// https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header64
	struct _IMAGE_OPTIONAL_HEADER64 {
		WORD                 Magic;
		BYTE                 MajorLinkerVersion;
		BYTE                 MinorLinkerVersion;
		DWORD                SizeOfCode;
		DWORD                SizeOfInitializedData;
		DWORD                SizeOfUninitializedData;
		DWORD                AddressOfEntryPoint;
		DWORD                BaseOfCode;
		ULONGLONG            ImageBase;
		DWORD                SectionAlignment;
		DWORD                FileAlignment;
		WORD                 MajorOperatingSystemVersion;
		WORD                 MinorOperatingSystemVersion;
		WORD                 MajorImageVersion;
		WORD                 MinorImageVersion;
		WORD                 MajorSubsystemVersion;
		WORD                 MinorSubsystemVersion;
		DWORD                Win32VersionValue;
		DWORD                SizeOfImage;
		DWORD                SizeOfHeaders;
		DWORD                CheckSum;
		WORD                 Subsystem;
		WORD                 DllCharacteristics;
		ULONGLONG            SizeOfStackReserve;
		ULONGLONG            SizeOfStackCommit;
		ULONGLONG            SizeOfHeapReserve;
		ULONGLONG            SizeOfHeapCommit;
		DWORD                LoaderFlags;
		DWORD                NumberOfRvaAndSizes;
		IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
	};

	// https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_nt_headers64
	struct _IMAGE_NT_HEADERS64 {
		DWORD Signature;
		IMAGE_FILE_HEADER FileHeader;
		IMAGE_OPTIONAL_HEADER64 OptionalHeader;
	};

	// https://processhacker.sourceforge.io/doc/struct___r_t_l___b_a_l_a_n_c_e_d___n_o_d_e.html
	struct _RTL_BALANCED_NODE {
		union {
			PRTL_BALANCED_NODE Children[2];
			struct {
				PRTL_BALANCED_NODE Left;
				PRTL_BALANCED_NODE Right;
			} DUMMYSTRUCTNAME;
		};
		union {
			UCHAR Red : 1;
			UCHAR Balance : 2;
			ULONG_PTR ParentValue;
		} DUMMYUNIONNAME;
	};

	struct _RTL_BALANCED_LINKS {
		struct _RTL_BALANCED_LINKS* Parent;
		struct _RTL_BALANCED_LINKS* LeftChild;
		struct _RTL_BALANCED_LINKS* RightChild;
		CHAR Balance;
		UCHAR Reserved[3];
	};

	// https://processhacker.sourceforge.io/doc/struct___r_t_l___a_v_l___t_a_b_l_e.html
	struct _RTL_AVL_TABLE {
		RTL_BALANCED_LINKS BalancedRoot;
		PVOID OrderedPointer;
		ULONG WhichOrderedElement;
		ULONG NumberGenericTableElements;
		ULONG DepthOfTree;
		PRTL_BALANCED_LINKS RestartKey;
		ULONG DeleteCount;
		PRTL_AVL_COMPARE_ROUTINE CompareRoutine;
		PRTL_AVL_ALLOCATE_ROUTINE AllocateRoutine;
		PRTL_AVL_FREE_ROUTINE FreeRoutine;
		PVOID TableContext;
	};

	typedef struct _RTL_DYNAMIC_HASH_TABLE {
		ULONG Flags;
		ULONG Shift;
		ULONG TableSize;
		ULONG Pivot;
		ULONG DivisorMask;
		ULONG NumEntries;
		ULONG NonEmptyBuckets;
		ULONG NumEnumerators;
		PVOID Directory;
	} RTL_DYNAMIC_HASH_TABLE, * PRTL_DYNAMIC_HASH_TABLE;

	// https://processhacker.sourceforge.io/doc/struct___r_t_l___d_y_n_a_m_i_c___h_a_s_h___t_a_b_l_e___c_o_n_t_e_x_t.html
	struct _RTL_DYNAMIC_HASH_TABLE_CONTEXT {
		PLIST_ENTRY ChainHead;
		PLIST_ENTRY PrevLinkage;
		ULONG_PTR Signature;
	};

	// https://processhacker.sourceforge.io/doc/struct___r_t_l___d_y_n_a_m_i_c___h_a_s_h___t_a_b_l_e___e_n_t_r_y.html
	struct _RTL_DYNAMIC_HASH_TABLE_ENTRY {
		LIST_ENTRY Linkage;
		ULONG_PTR Signature;
	};

	// https://processhacker.sourceforge.io/doc/struct___r_t_l___d_y_n_a_m_i_c___h_a_s_h___t_a_b_l_e___e_n_u_m_e_r_a_t_o_r.html
	struct _RTL_DYNAMIC_HASH_TABLE_ENUMERATOR {
		RTL_DYNAMIC_HASH_TABLE_ENTRY HashEntry;
		PLIST_ENTRY ChainHead;
		ULONG BucketIndex;
	};

	// https://processhacker.sourceforge.io/doc/struct___r_t_l___g_e_n_e_r_i_c___t_a_b_l_e.html
	struct _RTL_GENERIC_TABLE {
		PRTL_SPLAY_LINKS TableRoot;
		LIST_ENTRY InsertOrderList;
		PLIST_ENTRY OrderedPointer;
		ULONG WhichOrderedElement;
		ULONG NumberGenericTableElements;
		PRTL_GENERIC_COMPARE_ROUTINE CompareRoutine;
		PRTL_GENERIC_ALLOCATE_ROUTINE AllocateRoutine;
		PRTL_GENERIC_FREE_ROUTINE FreeRoutine;
		PVOID TableContext;
	};

	// https://processhacker.sourceforge.io/doc/struct___r_t_l___h_a_n_d_l_e___t_a_b_l_e.html
	struct _RTL_HANDLE_TABLE {
		ULONG MaximumNumberOfHandles;
		ULONG SizeOfHandleTableEntry;
		ULONG Reserved[2];
		PRTL_HANDLE_TABLE_ENTRY FreeHandles;
		PRTL_HANDLE_TABLE_ENTRY CommittedHandles;
		PRTL_HANDLE_TABLE_ENTRY UnCommittedHandles;
		PRTL_HANDLE_TABLE_ENTRY MaxReservedHandles;
	};

	// https://processhacker.sourceforge.io/doc/struct___r_t_l___h_a_n_d_l_e___t_a_b_l_e___e_n_t_r_y.html
	struct _RTL_HANDLE_TABLE_ENTRY {
		union {
			ULONG Flags;
			PRTL_HANDLE_TABLE_ENTRY NextFree;
		};
	};

	// https://processhacker.sourceforge.io/doc/struct___r_t_l___s_p_l_a_y___l_i_n_k_s.html
	struct _RTL_SPLAY_LINKS {
		struct _RTL_SPLAY_LINKS* Parent;
		struct _RTL_SPLAY_LINKS* LeftChild;
		struct _RTL_SPLAY_LINKS* RightChild;
	};

	// ======================== functions ========================
	// https://learn.microsoft.com/fr-fr/windows/win32/api/winnt/nf-winnt-rtladdfunctiontable
	NTSYSAPI BOOLEAN NTAPI RtlAddFunctionTable(
		_In_ PRUNTIME_FUNCTION FunctionTable,
		_In_ DWORD             EntryCount,
		_In_ DWORD64           BaseAddress);

	// https://learn.microsoft.com/fr-fr/windows/win32/api/winnt/nf-winnt-rtladdgrowablefunctiontable
	NTSYSAPI DWORD NTAPI RtlAddGrowableFunctionTable(
		_Out_ PVOID* DynamicTable,
		PRUNTIME_FUNCTION FunctionTable,
		_In_  DWORD             EntryCount,
		_In_  DWORD             MaximumEntryCount,
		_In_  ULONG_PTR         RangeBase,
		_In_  ULONG_PTR         RangeEnd);

	// https://github.com/mic101/windows/blob/master/WRK-v1.2/base/ntos/rtl/imagedir.c
	NTSYSAPI PVOID NTAPI RtlAddressInSectionTable(
		_In_ PIMAGE_NT_HEADERS64 NtHeaders,
		_In_ PVOID Base,
		_In_ ULONG Address);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI NTSTATUS NTAPI RtlComputeImportTableHash(
		_In_ HANDLE hFile,
		_Out_writes_bytes_(16) PCHAR Hash,
		_In_ ULONG ImportTableHashRevision);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html#a45d5646d40fe2acf29e8137ca6b93795
	NTSYSAPI BOOLEAN NTAPI RtlContractHashTable(
		_In_ PRTL_DYNAMIC_HASH_TABLE HashTable);


	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html#a45d5646d40fe2acf29e8137ca6b93795
	_Must_inspect_result_ NTSYSAPI BOOLEAN NTAPI RtlCreateHashTable(
		_Inout_ _When_(*HashTable == NULL, __drv_allocatesMem(Mem)) PRTL_DYNAMIC_HASH_TABLE* HashTable,
		_In_ ULONG Shift,
		_In_ _Reserved_ ULONG Flags);

	// https://github.com/tpn/tracer/blob/master/SALExamples.h
	// https://microsoft.github.io/windows-docs-rs/doc/windows/Wdk/System/SystemServices/fn.RtlCreateHashTableEx.html
	_Must_inspect_result_ _Success_(return != 0) NTSYSAPI BOOLEAN NTAPI RtlCreateHashTableEx(
		_Inout_ _When_(NULL == *HashTable, _At_(*HashTable, __drv_allocatesMem(Mem)))
			PRTL_DYNAMIC_HASH_TABLE* HashTable,
		_In_ ULONG InitialSize,
		_In_ ULONG Shift,
		_Reserved_ ULONG Flags);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html#a45d5646d40fe2acf29e8137ca6b93795
	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	NTSYSAPI PRTL_SPLAY_LINKS NTAPI RtlDelete(
		PRTL_SPLAY_LINKS links);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html#a45d5646d40fe2acf29e8137ca6b93795
	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	NTSYSAPI BOOLEAN NTAPI RtlDeleteElementGenericTable(
		_In_ PRTL_GENERIC_TABLE table,
		_In_ PVOID value);

	//https://processhacker.sourceforge.io/doc/ntrtl_8h.html#a45d5646d40fe2acf29e8137ca6b93795
	NTSYSAPI BOOLEAN NTAPI RtlDeleteElementGenericTableAvl(
		_In_ PRTL_AVL_TABLE Table,
		_In_ PVOID Buffer);

	// https://github.com/ANSSI-FR/ADCP-libdev/blob/master/Include/CacheAvlTable.h
	NTSYSAPI VOID NTAPI RtlDeleteElementGenericTableAvlEx(
		_In_ PRTL_AVL_TABLE Table,
		_In_ PVOID NodeOrParent);

	// https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-rtldeletefunctiontable
	NTSYSAPI BOOLEAN NTAPI RtlDeleteFunctionTable(
		_In_ PRUNTIME_FUNCTION FunctionTable);

	//https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-rtldeletegrowablefunctiontable
	NTSYSAPI VOID RtlDeleteGrowableFunctionTable(
		_In_ PVOID DynamicTable);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html#a45d5646d40fe2acf29e8137ca6b93795
	NTSYSAPI VOID NTAPI RtlDeleteHashTable(
		_In_ PRTL_DYNAMIC_HASH_TABLE HashTable);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html#a45d5646d40fe2acf29e8137ca6b93795
	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	NTSYSAPI VOID NTAPI RtlDeleteNoSplay(
		_In_ PRTL_SPLAY_LINKS links,
		_Inout_ PRTL_SPLAY_LINKS* root);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI NTSTATUS NTAPI RtlDestroyHandleTable(
		_Inout_ PRTL_HANDLE_TABLE HandleTable);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html#a45d5646d40fe2acf29e8137ca6b93795
	NTSYSAPI VOID NTAPI RtlEndEnumerationHashTable(
		_In_ PRTL_DYNAMIC_HASH_TABLE HashTable,
		_Inout_ PRTL_DYNAMIC_HASH_TABLE_ENUMERATOR Enumerator);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html#a45d5646d40fe2acf29e8137ca6b93795
	// Reversed. Empty function immediately returning.
	NTSYSAPI VOID NTAPI RtlEndStrongEnumerationHashTable(
		_In_ PRTL_DYNAMIC_HASH_TABLE HashTable,
		_Inout_ PRTL_DYNAMIC_HASH_TABLE_ENUMERATOR Enumerator);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html#a45d5646d40fe2acf29e8137ca6b93795
	NTSYSAPI VOID NTAPI RtlEndWeakEnumerationHashTable(
		_In_ PRTL_DYNAMIC_HASH_TABLE HashTable,
		_Inout_ PRTL_DYNAMIC_HASH_TABLE_ENUMERATOR Enumerator);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html#a45d5646d40fe2acf29e8137ca6b93795
	_Must_inspect_result_ NTSYSAPI PRTL_DYNAMIC_HASH_TABLE_ENTRY NTAPI RtlEnumerateEntryHashTable(
		_In_ PRTL_DYNAMIC_HASH_TABLE HashTable,
		_Inout_ PRTL_DYNAMIC_HASH_TABLE_ENUMERATOR Enumerator);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html#a45d5646d40fe2acf29e8137ca6b93795
	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	_Check_return_ NTSYSAPI PVOID NTAPI RtlEnumerateGenericTable(
		_In_ PRTL_GENERIC_TABLE table,
		_In_ BOOLEAN restart);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html#a45d5646d40fe2acf29e8137ca6b93795
	_Check_return_ NTSYSAPI PVOID NTAPI RtlEnumerateGenericTableAvl(
		_In_ PRTL_AVL_TABLE Table,
		_In_ BOOLEAN Restart);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html#a45d5646d40fe2acf29e8137ca6b93795
	_Check_return_ NTSYSAPI PVOID NTAPI RtlEnumerateGenericTableLikeADirectory(
		_In_ PRTL_AVL_TABLE Table,
		_In_opt_ PRTL_AVL_MATCH_FUNCTION MatchFunction,
		_In_opt_ PVOID MatchData,
		_In_ ULONG NextFlag,
		_Inout_ PVOID* RestartKey,
		_Inout_ PULONG DeleteCount,
		_In_ PVOID Buffer);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html#a45d5646d40fe2acf29e8137ca6b93795
	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	_Check_return_ NTSYSAPI PVOID NTAPI RtlEnumerateGenericTableWithoutSplaying(
		_In_ PRTL_GENERIC_TABLE table,
		_Inout_ PVOID* previous);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html#a45d5646d40fe2acf29e8137ca6b93795
	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	NTSYSAPI PVOID NTAPI RtlEnumerateGenericTableWithoutSplayingAvl(
		_In_ PRTL_AVL_TABLE Table,
		_Inout_ PVOID* RestartKey);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html#a45d5646d40fe2acf29e8137ca6b93795
	NTSYSAPI BOOLEAN NTAPI RtlExpandHashTable(
		_In_ PRTL_DYNAMIC_HASH_TABLE HashTable);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html#a45d5646d40fe2acf29e8137ca6b93795
	_Check_return_ NTSYSAPI PVOID NTAPI RtlGetElementGenericTable(
		_In_ PRTL_GENERIC_TABLE Table,
		_In_ ULONG Index);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html#a45d5646d40fe2acf29e8137ca6b93795
	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	_Check_return_ NTSYSAPI PVOID NTAPI RtlGetElementGenericTableAvl(
		_In_ PRTL_AVL_TABLE Table,
		_In_ ULONG Index);

	// https://learn.microsoft.com/en-us/windows/win32/devnotes/rtlgetfunctiontablelisthead
	NTSYSAPI PLIST_ENTRY NTAPI RtlGetFunctionTableListHead(VOID);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html#a45d5646d40fe2acf29e8137ca6b93795
	_Must_inspect_result_ NTSYSAPI PRTL_DYNAMIC_HASH_TABLE_ENTRY NTAPI RtlGetNextEntryHashTable(
		_In_ PRTL_DYNAMIC_HASH_TABLE HashTable,
		_In_ PRTL_DYNAMIC_HASH_TABLE_CONTEXT Context);

	// https://learn.microsoft.com/fr-fr/windows/win32/api/winnt/nf-winnt-rtlgrowfunctiontable
	NTSYSAPI VOID NTAPI RtlGrowFunctionTable(
		PVOID DynamicTable,
		_In_ DWORD NewEntryCount);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html#a45d5646d40fe2acf29e8137ca6b93795
	NTSYSAPI BOOLEAN NTAPI RtlInitEnumerationHashTable(
		_In_ PRTL_DYNAMIC_HASH_TABLE HashTable,
		_Out_ PRTL_DYNAMIC_HASH_TABLE_ENUMERATOR Enumerator);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html#a45d5646d40fe2acf29e8137ca6b93795
	NTSYSAPI BOOLEAN NTAPI RtlInitStrongEnumerationHashTable(
		_In_ PRTL_DYNAMIC_HASH_TABLE HashTable,
		_Out_ PRTL_DYNAMIC_HASH_TABLE_ENUMERATOR Enumerator);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html#a45d5646d40fe2acf29e8137ca6b93795
	NTSYSAPI BOOLEAN NTAPI RtlInitWeakEnumerationHashTable(
		_In_ PRTL_DYNAMIC_HASH_TABLE HashTable,
		_Out_ PRTL_DYNAMIC_HASH_TABLE_ENUMERATOR Enumerator);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html#a45d5646d40fe2acf29e8137ca6b93795
	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	NTSYSAPI VOID NTAPI RtlInitializeGenericTable(
		_Out_ PRTL_GENERIC_TABLE table,
		_In_ PRTL_GENERIC_COMPARE_ROUTINE compare,
		_In_ PRTL_GENERIC_ALLOCATE_ROUTINE allocate,
		_In_ PRTL_GENERIC_FREE_ROUTINE free,
		_In_ PVOID context);

	// https://learn.microsoft.com/fr-fr/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlinitializegenerictableavl
	NTSYSAPI VOID NTAPI RtlInitializeGenericTableAvl(
		PRTL_AVL_TABLE table,
		PRTL_AVL_COMPARE_ROUTINE compare,
		PRTL_AVL_ALLOCATE_ROUTINE allocate,
		PRTL_AVL_FREE_ROUTINE free,
		PVOID context);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI VOID NTAPI RtlInitializeHandleTable(
		_In_ ULONG MaximumNumberOfHandles,
		_In_ ULONG SizeOfHandleTableEntry,
		_Out_ PRTL_HANDLE_TABLE HandleTable);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html#a45d5646d40fe2acf29e8137ca6b93795
	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	NTSYSAPI PVOID NTAPI RtlInsertElementGenericTable(
		_In_ PRTL_GENERIC_TABLE table,
		_In_reads_bytes_(BufferSize) PVOID value,
		_In_ CLONG BufferSize,
		_Out_opt_ PBOOLEAN new_element);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	NTSYSAPI VOID NTAPI RtlInsertElementGenericTableAvl(
		PRTL_AVL_TABLE table,
		PVOID buffer,
		ULONG size,
		PBOOL element);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html#a45d5646d40fe2acf29e8137ca6b93795
	NTSYSAPI PVOID NTAPI RtlInsertElementGenericTableFull(
		_In_ PRTL_GENERIC_TABLE Table,
		_In_reads_bytes_(BufferSize) PVOID Buffer,
		_In_ CLONG BufferSize,
		_Out_opt_ PBOOLEAN NewElement,
		_In_ PVOID NodeOrParent,
		_In_ TABLE_SEARCH_RESULT SearchResult);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html#a45d5646d40fe2acf29e8137ca6b93795
	NTSYSAPI PVOID NTAPI RtlInsertElementGenericTableFullAvl(
		_In_ PRTL_AVL_TABLE Table,
		_In_reads_bytes_(BufferSize) PVOID Buffer,
		_In_ CLONG BufferSize,
		_Out_opt_ PBOOLEAN NewElement,
		_In_ PVOID NodeOrParent,
		_In_ TABLE_SEARCH_RESULT SearchResult);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html#a45d5646d40fe2acf29e8137ca6b93795
	NTSYSAPI BOOLEAN NTAPI RtlInsertEntryHashTable(
		_In_ PRTL_DYNAMIC_HASH_TABLE HashTable,
		_In_ PRTL_DYNAMIC_HASH_TABLE_ENTRY Entry,
		_In_ ULONG_PTR Signature,
		_Inout_opt_ PRTL_DYNAMIC_HASH_TABLE_CONTEXT Context);

	// https://learn.microsoft.com/fr-fr/windows/win32/api/winnt/nf-winnt-rtlinstallfunctiontablecallback
	NTSYSAPI BOOLEAN NTAPI RtlInstallFunctionTableCallback(
		_In_ DWORD64                        TableIdentifier,
		_In_ DWORD64                        BaseAddress,
		_In_ DWORD                          Length,
		_In_ PGET_RUNTIME_FUNCTION_CALLBACK Callback,
		_In_ PVOID                          Context,
		_In_ PCWSTR                         OutOfProcessCallbackDll);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html#a45d5646d40fe2acf29e8137ca6b93795
	//https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	NTSYSAPI BOOLEAN NTAPI RtlIsGenericTableEmpty(
		_In_ PRTL_GENERIC_TABLE table);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html#a45d5646d40fe2acf29e8137ca6b93795
	_Check_return_ NTSYSAPI BOOLEAN NTAPI RtlIsGenericTableEmptyAvl(
		_In_ PRTL_AVL_TABLE Table);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html#a45d5646d40fe2acf29e8137ca6b93795
	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	_Check_return_ NTSYSAPI PVOID NTAPI RtlLookupElementGenericTable(
		_In_ PRTL_GENERIC_TABLE Table,
		_In_ PVOID Value);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	NTSYSAPI PVOID NTAPI RtlLookupElementGenericTableAvl(
		PRTL_AVL_TABLE table,
		PVOID buffer);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html#a45d5646d40fe2acf29e8137ca6b93795
	NTSYSAPI PVOID NTAPI RtlLookupElementGenericTableFull(
		_In_ PRTL_GENERIC_TABLE Table,
		_In_ PVOID Buffer,
		_Out_ PVOID* NodeOrParent,
		_Out_ TABLE_SEARCH_RESULT* SearchResult);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html#a45d5646d40fe2acf29e8137ca6b93795
	NTSYSAPI PVOID NTAPI RtlLookupElementGenericTableFullAvl(
		_In_ PRTL_AVL_TABLE Table,
		_In_ PVOID Buffer,
		_Out_ PVOID* NodeOrParent,
		_Out_ TABLE_SEARCH_RESULT* SearchResult);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html#a45d5646d40fe2acf29e8137ca6b93795
	_Must_inspect_result_ NTSYSAPI PRTL_DYNAMIC_HASH_TABLE_ENTRY NTAPI RtlLookupEntryHashTable(
		_In_ PRTL_DYNAMIC_HASH_TABLE HashTable,
		_In_ ULONG_PTR Signature,
		_Out_opt_ PRTL_DYNAMIC_HASH_TABLE_CONTEXT Context);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html#a45d5646d40fe2acf29e8137ca6b93795
	_Check_return_ NTSYSAPI PVOID NTAPI RtlLookupFirstMatchingElementGenericTableAvl(
		_In_ PRTL_AVL_TABLE Table,
		_In_ PVOID Buffer,
		_Out_ PVOID* RestartKey);

	// https://reactos.org/wiki/Techwiki:SEH64
	// http://uninformed.org/index.cgi?v=8&a=2&p=20 -> PsInvertedFunctionTable
	// http://uninformed.org/index.cgi?v=6&a=1&p=16 -> Interception of PsInvertedFunctionTable
	// https://github.com/mic101/windows/blob/master/WRK-v1.2/base/ntos/rtl/lookup.c
	// https://doxygen.reactos.org/d8/d2f/unwind_8c.html
	NTSYSAPI PRUNTIME_FUNCTION NTAPI RtlLookupFunctionTable(
		_In_ DWORD64 ControlPc,
		_Out_ PVOID* ImageBase,
		_Out_ PULONG SizeOfTable);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html#a45d5646d40fe2acf29e8137ca6b93795
	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	NTSYSAPI ULONG NTAPI RtlNumberGenericTableElements(
		_In_ PRTL_GENERIC_TABLE table);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html#a45d5646d40fe2acf29e8137ca6b93795
	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	NTSYSAPI ULONG NTAPI RtlNumberGenericTableElementsAvl(
		PRTL_AVL_TABLE table);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html#a45d5646d40fe2acf29e8137ca6b93795
	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	NTSYSAPI VOID NTAPI RtlRbInsertNodeEx(
		_In_ PRTL_RB_TREE tree,
		_In_opt_ PRTL_BALANCED_NODE parent,
		_In_ BOOLEAN right,
		_Out_ PRTL_BALANCED_NODE node);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html#a45d5646d40fe2acf29e8137ca6b93795
	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	NTSYSAPI VOID NTAPI RtlRbRemoveNode(
		_In_ PRTL_RB_TREE tree,
		_In_ PRTL_BALANCED_NODE node);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html#a45d5646d40fe2acf29e8137ca6b93795
	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	NTSYSAPI PRTL_SPLAY_LINKS NTAPI RtlRealPredecessor(
		_In_ PRTL_SPLAY_LINKS links);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html#a45d5646d40fe2acf29e8137ca6b93795
	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	NTSYSAPI PRTL_SPLAY_LINKS NTAPI RtlRealSuccessor(
		_In_ PRTL_SPLAY_LINKS links);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html#a45d5646d40fe2acf29e8137ca6b93795
	NTSYSAPI BOOLEAN NTAPI RtlRemoveEntryHashTable(
		_In_ PRTL_DYNAMIC_HASH_TABLE HashTable,
		_In_ PRTL_DYNAMIC_HASH_TABLE_ENTRY Entry,
		_Inout_opt_ PRTL_DYNAMIC_HASH_TABLE_CONTEXT Context);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html#a45d5646d40fe2acf29e8137ca6b93795
	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	NTSYSAPI PRTL_SPLAY_LINKS NTAPI RtlSplay(
		_Inout_ PRTL_SPLAY_LINKS links);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html#a45d5646d40fe2acf29e8137ca6b93795
	_Must_inspect_result_ NTSYSAPI PRTL_DYNAMIC_HASH_TABLE_ENTRY NTAPI RtlStronglyEnumerateEntryHashTable(
		_In_ PRTL_DYNAMIC_HASH_TABLE HashTable,
		_Inout_ PRTL_DYNAMIC_HASH_TABLE_ENUMERATOR Enumerator);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html#a45d5646d40fe2acf29e8137ca6b93795
	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	NTSYSAPI PRTL_SPLAY_LINKS NTAPI RtlSubtreePredecessor(
		_In_ PRTL_SPLAY_LINKS links);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html#a45d5646d40fe2acf29e8137ca6b93795
	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	NTSYSAPI PRTL_SPLAY_LINKS NTAPI RtlSubtreeSuccessor(
		_In_ PRTL_SPLAY_LINKS links);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html#a45d5646d40fe2acf29e8137ca6b93795
	_Must_inspect_result_ NTSYSAPI PRTL_DYNAMIC_HASH_TABLE_ENTRY NTAPI RtlWeaklyEnumerateEntryHashTable(
		_In_ PRTL_DYNAMIC_HASH_TABLE HashTable,
		_Inout_ PRTL_DYNAMIC_HASH_TABLE_ENUMERATOR Enumerator);
}

#endif // _NTTABLES_
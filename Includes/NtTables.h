#pragma once

#ifndef _NTTABLES_
#define _NTTABLES_

#include "NtCommonDefs.h"

extern "C" {
	
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
		IN PIMAGE_NT_HEADERS NtHeaders,
		IN PVOID Base,
		IN ULONG Address);

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
	NTSYSAPI PRTL_SPLAY_LINKS WINAPI RtlDelete(
		PRTL_SPLAY_LINKS links);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html#a45d5646d40fe2acf29e8137ca6b93795
	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	NTSYSAPI BOOLEAN WINAPI RtlDeleteElementGenericTable(
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
	NTSYSAPI VOID WINAPI RtlDeleteNoSplay(
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
	_Check_return_ NTSYSAPI PVOID WINAPI RtlEnumerateGenericTable(
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
	_Check_return_ NTSYSAPI PVOID WINAPI RtlEnumerateGenericTableWithoutSplaying(
		_In_ PRTL_GENERIC_TABLE table,
		_Inout_ PVOID* previous);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html#a45d5646d40fe2acf29e8137ca6b93795
	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	NTSYSAPI PVOID WINAPI RtlEnumerateGenericTableWithoutSplayingAvl(
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
	typedef RTL_GENERIC_COMPARE_RESULTS(NTAPI* PRTL_GENERIC_COMPARE_ROUTINE)(
		_In_ struct _RTL_GENERIC_TABLE* Table);
	NTSYSAPI VOID WINAPI RtlInitializeGenericTable(
		_Out_ PRTL_GENERIC_TABLE table,
		_In_ PRTL_GENERIC_COMPARE_ROUTINE compare,
		_In_ PRTL_GENERIC_ALLOCATE_ROUTINE allocate,
		_In_ PRTL_GENERIC_FREE_ROUTINE free,
		_In_ PVOID context);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	NTSYSAPI VOID WINAPI RtlInitializeGenericTableAvl(
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
	NTSYSAPI PVOID WINAPI RtlInsertElementGenericTable(
		_In_ PRTL_GENERIC_TABLE table,
		_In_reads_bytes_(BufferSize) PVOID value,
		_In_ CLONG BufferSize,
		_Out_opt_ PBOOLEAN new_element);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	NTSYSAPI VOID WINAPI RtlInsertElementGenericTableAvl(
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
	NTSYSAPI BOOLEAN WINAPI RtlIsGenericTableEmpty(
		_In_ PRTL_GENERIC_TABLE table);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html#a45d5646d40fe2acf29e8137ca6b93795
	_Check_return_ NTSYSAPI BOOLEAN NTAPI RtlIsGenericTableEmptyAvl(
		_In_ PRTL_AVL_TABLE Table);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html#a45d5646d40fe2acf29e8137ca6b93795
	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	_Check_return_ NTSYSAPI PVOID WINAPI RtlLookupElementGenericTable(
		_In_ PRTL_GENERIC_TABLE Table,
		_In_ PVOID Value);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	NTSYSAPI PVOID WINAPI RtlLookupElementGenericTableAvl(
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
	NTSYSAPI ULONG WINAPI RtlNumberGenericTableElements(
		_In_ PRTL_GENERIC_TABLE table);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html#a45d5646d40fe2acf29e8137ca6b93795
	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	NTSYSAPI ULONG WINAPI RtlNumberGenericTableElementsAvl(
		PRTL_AVL_TABLE table);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html#a45d5646d40fe2acf29e8137ca6b93795
	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	NTSYSAPI VOID WINAPI RtlRbInsertNodeEx(
		_In_ PRTL_RB_TREE tree,
		_In_opt_ PRTL_BALANCED_NODE parent,
		_In_ BOOLEAN right,
		_Out_ PRTL_BALANCED_NODE node);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html#a45d5646d40fe2acf29e8137ca6b93795
	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	NTSYSAPI VOID WINAPI RtlRbRemoveNode(
		_In_ PRTL_RB_TREE tree,
		_In_ PRTL_BALANCED_NODE node);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html#a45d5646d40fe2acf29e8137ca6b93795
	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	NTSYSAPI PRTL_SPLAY_LINKS WINAPI RtlRealPredecessor(
		_In_ PRTL_SPLAY_LINKS links);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html#a45d5646d40fe2acf29e8137ca6b93795
	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	NTSYSAPI PRTL_SPLAY_LINKS WINAPI RtlRealSuccessor(
		_In_ PRTL_SPLAY_LINKS links);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html#a45d5646d40fe2acf29e8137ca6b93795
	NTSYSAPI BOOLEAN NTAPI RtlRemoveEntryHashTable(
		_In_ PRTL_DYNAMIC_HASH_TABLE HashTable,
		_In_ PRTL_DYNAMIC_HASH_TABLE_ENTRY Entry,
		_Inout_opt_ PRTL_DYNAMIC_HASH_TABLE_CONTEXT Context);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html#a45d5646d40fe2acf29e8137ca6b93795
	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	NTSYSAPI PRTL_SPLAY_LINKS WINAPI RtlSplay(
		_Inout_ PRTL_SPLAY_LINKS links);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html#a45d5646d40fe2acf29e8137ca6b93795
	_Must_inspect_result_ NTSYSAPI PRTL_DYNAMIC_HASH_TABLE_ENTRY NTAPI RtlStronglyEnumerateEntryHashTable(
		_In_ PRTL_DYNAMIC_HASH_TABLE HashTable,
		_Inout_ PRTL_DYNAMIC_HASH_TABLE_ENUMERATOR Enumerator);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html#a45d5646d40fe2acf29e8137ca6b93795
	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	NTSYSAPI PRTL_SPLAY_LINKS WINAPI RtlSubtreePredecessor(
		_In_ PRTL_SPLAY_LINKS links);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html#a45d5646d40fe2acf29e8137ca6b93795
	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	NTSYSAPI PRTL_SPLAY_LINKS WINAPI RtlSubtreeSuccessor(
		_In_ PRTL_SPLAY_LINKS links);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html#a45d5646d40fe2acf29e8137ca6b93795
	_Must_inspect_result_ NTSYSAPI PRTL_DYNAMIC_HASH_TABLE_ENTRY NTAPI RtlWeaklyEnumerateEntryHashTable(
		_In_ PRTL_DYNAMIC_HASH_TABLE HashTable,
		_Inout_ PRTL_DYNAMIC_HASH_TABLE_ENUMERATOR Enumerator);
}

#endif // _NTTABLES_
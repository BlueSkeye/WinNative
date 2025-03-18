#pragma once

#ifndef _NTSTRINGS_
#define _NTSTRINGS_

#include "NtCommonDefs.h"

extern "C" {

	// NO UNRESOLVED FUNCTIONS

	// https://learn.microsoft.com/en-us/previous-versions/windows/hardware/kernel/ff561132(v=vs.85)
	NTSYSAPI WCHAR NTAPI RtlAnsiCharToUnicodeChar(
		_Inout_ PUCHAR* SourceCharacter);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlansistringtounicodesize
	NTSYSAPI ULONG NTAPI RtlAnsiStringToUnicodeSize(
		PANSI_STRING AnsiString);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlansistringtounicodestring
	// See winterl.h
	NTSYSAPI NTSTATUS RtlAnsiStringToUnicodeString(
		[in, out] PUNICODE_STRING DestinationString,
		_In_      PCANSI_STRING   SourceString,
		_In_      BOOLEAN         AllocateDestinationString);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI NTSTATUS NTAPI RtlAppendAsciizToString(
		_In_ PSTRING Destination,
		_In_opt_ PSTR Source);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlappendstringtostring
	NTSYSAPI NTSTATUS RtlAppendStringToString(
		[in, out] PSTRING      Destination,
		_In_      const STRING* Source);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlansistringtounicodestring
	NTSYSAPI NTSTATUS RtlAnsiStringToUnicodeString(
		[in, out] PUNICODE_STRING DestinationString,
		_In_      PCANSI_STRING   SourceString,
		_In_      BOOLEAN         AllocateDestinationString);

	//https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlappendunicodetostring
	NTSYSAPI NTSTATUS RtlAppendUnicodeToString(
		[in, out]      PUNICODE_STRING Destination,
		_In_opt_ PCWSTR          Source);

	// https://learn.microsoft.com/fr-fr/windows/win32/api/winternl/nf-winternl-rtlchartointeger
	// See winterl.h
	NTSTATUS RtlCharToInteger(
		_In_           PCSZ   String,
		_In_opt_ ULONG  Base,
		_Out_          PULONG Value);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	_Must_inspect_result_ NTSYSAPI LONG NTAPI RtlCompareString(
		_In_ PSTRING String1,
		_In_ PSTRING String2,
		_In_ BOOLEAN CaseInSensitive);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlcompareunicodestring
	NTSYSAPI LONG RtlCompareUnicodeString(
		_In_ PCUNICODE_STRING String1,
		_In_ PCUNICODE_STRING String2,
		_In_ BOOLEAN          CaseInSensitive);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	_Must_inspect_result_ NTSYSAPI LONG NTAPI RtlCompareUnicodeStrings(
		_In_reads_(String1Length) PWCH String1,
		_In_ SIZE_T String1Length,
		_In_reads_(String2Length) PWCH String2,
		_In_ SIZE_T String2Length,
		_In_ BOOLEAN CaseInSensitive);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI VOID NTAPI RtlCopyString(
		_In_ PSTRING DestinationString,
		_In_opt_ PSTRING SourceString);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlcopyunicodestring
	NTSYSAPI VOID RtlCopyUnicodeString(
		[in, out]      PUNICODE_STRING  DestinationString,
		_In_opt_ PCUNICODE_STRING SourceString);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlcreateunicodestring
	NTSYSAPI BOOLEAN RtlCreateUnicodeString(
		_Out_ PUNICODE_STRING DestinationString,
		_In_  PCWSTR          SourceString);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI BOOLEAN NTAPI RtlCreateUnicodeStringFromAsciiz(
		_Out_ PUNICODE_STRING DestinationString,
		_In_ PSTR SourceString);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtldowncaseunicodechar
	NTSYSAPI WCHAR RtlDowncaseUnicodeChar(
		_In_ WCHAR SourceCharacter);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtldowncaseunicodestring
	NTSYSAPI NTSTATUS RtlDowncaseUnicodeString(
		PUNICODE_STRING  DestinationString,
		_In_ PCUNICODE_STRING SourceString,
		_In_ BOOLEAN          AllocateDestinationString);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI NTSTATUS NTAPI RtlDuplicateUnicodeString(
		_In_ ULONG Flags,
		_In_ PUNICODE_STRING StringIn,
		_Out_ PUNICODE_STRING StringOut);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlequalstring
	NTSYSAPI BOOLEAN RtlEqualString(
		_In_ const STRING* String1,
		_In_ const STRING* String2,
		_In_ BOOLEAN      CaseInSensitive);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlequalunicodestring
	NTSYSAPI BOOLEAN RtlEqualUnicodeString(
		_In_ PCUNICODE_STRING String1,
		_In_ PCUNICODE_STRING String2,
		_In_ BOOLEAN          CaseInSensitive);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI VOID NTAPI RtlEraseUnicodeString(
		_Inout_ PUNICODE_STRING String);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI NTSTATUS NTAPI RtlFindCharInUnicodeString(
		_In_ ULONG 	Flags,
		_In_ PUNICODE_STRING StringToSearch,
		_In_ PUNICODE_STRING CharSet,
		_Out_ PUSHORT NonInclusivePrefixLength);

	// https://gitee.com/AbstractFactory/NativeLib-R/blob/master/ntrtl.h
	_Must_inspect_result_ NTSYSAPI PWCHAR NTAPI RtlFindUnicodeSubstring(
		_In_ PUNICODE_STRING FullString,
		_In_ PUNICODE_STRING SearchString,
		_In_ BOOLEAN CaseInSensitive);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlfreeansistring
	// See winterl.h
	NTSYSAPI VOID RtlFreeAnsiString(
		[in, out] PANSI_STRING AnsiString);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlfreeoemstring
	// See winterl.h
	NTSYSAPI VOID RtlFreeOemString(
		[in, out] POEM_STRING OemString);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlfreeunicodestring
	// See winterl.h
	NTSYSAPI VOID RtlFreeUnicodeString(
		[in, out] PUNICODE_STRING UnicodeString);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlfreeutf8string
	NTSYSAPI VOID RtlFreeUTF8String(
		PUTF8_STRING utf8String);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI NTSTATUS NTAPI RtlGUIDFromString(
		_In_ PUNICODE_STRING GuidString,
		_Out_ PGUID Guid);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlhashunicodestring
	NTSYSAPI NTSTATUS RtlHashUnicodeString(
		_In_  PCUNICODE_STRING String,
		_In_  BOOLEAN          CaseInSensitive,
		_In_  ULONG            HashAlgorithm,
		_Out_ PULONG           HashValue);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlinitansistring
	// See winterl.h
	NTSYSAPI VOID RtlInitAnsiString(
		_Out_ PANSI_STRING DestinationString,
		_In_opt_ __drv_aliasesMem PCSZ SourceString);

	// https://source.winehq.org/WineAPI/RtlInitAnsiStringEx.html
	// See winterl.h
	NTSYSAPI NTSTATUS NTAPI RtlInitAnsiStringEx(
		_Out_ PANSI_STRING Destinationstring,
		_In_ PCSZ SourceString);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlinitstring
	// See winterl.h
	NTSYSAPI VOID RtlInitString(
		_Out_ PSTRING DestinationString,
		_In_opt_ __drv_aliasesMem PCSZ SourceString);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlinitstringex
	// See winterl.h
	NTSYSAPI NTSTATUS RtlInitStringEx(
		_Out_ PSTRING DestinationString,
		_In_opt_ __drv_aliasesMem PCSZ SourceString);

	//https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlinitutf8string
	NTSYSAPI VOID NTAPI RtlInitUTF8String(
		PUTF8_STRING DestinationString,
		__drv_aliasesMem PCSZ SourceString);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlinitutf8stringex
	NTSYSAPI NTSTATUS RtlInitUTF8StringEx(
		PUTF8_STRING          DestinationString,
		__drv_aliasesMem PCSZ SourceString);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlinitunicodestring
	// See winterl.h
	// See wdm.h
	NTSYSAPI VOID NTAPI RtlInitUnicodeString(
		_Out_ PUNICODE_STRING DestinationString,
		_In_opt_z_ __drv_aliasesMem PCWSTR SourceString);

	// See wdm.h
	NTSYSAPI NTSTATUS NTAPI RtlInitUnicodeStringEx(
		_Out_ PUNICODE_STRING DestinationString,
		_In_opt_z_ __drv_aliasesMem PCWSTR SourceString);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlint64tounicodestring
	NTSYSAPI NTSTATUS RtlInt64ToUnicodeString(
		_In_           ULONGLONG       Value,
		_In_opt_ ULONG           Base,
		[in, out]      PUNICODE_STRING String);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI NTSTATUS NTAPI RtlIntegerToChar(
		_In_ ULONG Value,
		_In_opt_ ULONG Base,
		_In_ LONG OutputLength,
		_Out_ PSTR String);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlintegertounicodestring
	NTSYSAPI NTSTATUS RtlIntegerToUnicodeString(
		_In_           ULONG           Value,
		_In_opt_ ULONG           Base,
		[in, out]      PUNICODE_STRING String);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI NTSTATUS NTAPI RtlIsNormalizedString(
		_In_ ULONG 	NormForm,
		_In_ PCWSTR 	SourceString,
		_In_ LONG 	SourceStringLength,
		_Out_ PBOOLEAN 	Normalized);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI BOOLEAN NTAPI RtlIsTextUnicode(
		_In_ PVOID Buffer,
		_In_ ULONG Size,
		_Inout_opt_ PULONG Result);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI NTSTATUS NTAPI RtlLargeIntegerToChar(
		_In_ PLARGE_INTEGER Value,
		_In_opt_ ULONG Base,
		_In_ LONG OutputLength,
		_Out_ PSTR String);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L6433
	NTSYSAPI NTSTATUS NTAPI RtlLoadString(
		_In_ PVOID DllHandle,
		_In_ ULONG StringId,
		_In_opt_ PCWSTR StringLanguage,
		_In_ ULONG Flags,
		_Out_ PCWSTR* ReturnString,
		_Out_opt_ PUSHORT ReturnStringLen,
		_Out_writes_(ReturnLanguageLen) PWSTR ReturnLanguageName,
		_Inout_opt_ PULONG ReturnLanguageLen);

	// https://github.com/x-tinkerer/WRK/blob/master/public/sdk/inc/ntrtlstringandbuffer.h
	NTSYSAPI NTSTATUS NTAPI RtlMultiAppendUnicodeStringBuffer(
		OUT PRTL_UNICODE_STRING_BUFFER  Destination,
		IN  ULONG                       NumberOfSources,
		IN  const UNICODE_STRING* SourceArray);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlmultibytetounicoden
	NTSYSAPI NTSTATUS RtlMultiByteToUnicodeN(
		_Out_           PWCH       UnicodeString,
		_In_            ULONG      MaxBytesInUnicodeString,
		[out, optional] PULONG     BytesInUnicodeString,
		_In_            const CHAR* MultiByteString,
		_In_            ULONG      BytesInMultiByteString);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlmultibytetounicodesize
	NTSYSAPI NTSTATUS RtlMultiByteToUnicodeSize(
		_Out_ PULONG     BytesInUnicodeString,
		_In_  const CHAR* MultiByteString,
		_In_  ULONG      BytesInMultiByteString);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI NTSTATUS NTAPI RtlNormalizeString(
		_In_ ULONG NormForm,
		_In_ PCWSTR SourceString,
		_In_ LONG SourceStringLength,
		_Out_writes_to_(*DestinationStringLength, *DestinationStringLength) PWSTR DestinationString,
		_Inout_ PLONG DestinationStringLength);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtloemstringtounicodestring
	NTSYSAPI NTSTATUS RtlOemStringToUnicodeString(
		_Inout_ PUNICODE_STRING DestinationString,
		_In_ PCOEM_STRING SourceString,
		_In_ BOOLEAN AllocateDestinationString);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtloemtounicoden
	NTSYSAPI NTSTATUS RtlOemToUnicodeN(
		_Out_           PWCH   UnicodeString,
		_In_            ULONG  MaxBytesInUnicodeString,
		[out, optional] PULONG BytesInUnicodeString,
		_In_            PCCH   OemString,
		_In_            ULONG  BytesInOemString);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI BOOLEAN NTAPI RtlPrefixString(
		_In_ PSTRING String1,
		_In_ PSTRING String2,
		_In_ BOOLEAN CaseInSensitive);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlprefixunicodestring
	NTSYSAPI BOOLEAN RtlPrefixUnicodeString(
		_In_ PCUNICODE_STRING String1,
		_In_ PCUNICODE_STRING String2,
		_In_ BOOLEAN          CaseInSensitive);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI VOID NTAPI RtlRunDecodeUnicodeString(
		_In_ UCHAR Seed,
		_In_ PUNICODE_STRING String);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI VOID NTAPI RtlRunEncodeUnicodeString(
		_Inout_ PUCHAR Seed,
		_In_ PUNICODE_STRING String);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlstringfromguid
	NTSYSAPI NTSTATUS RtlStringFromGUID(
		_In_  REFGUID         Guid,
		_Out_ PUNICODE_STRING GuidString);

	//https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L2370
	NTSYSAPI NTSTATUS NTAPI RtlStringFromGUIDEx(
		_In_ PGUID Guid,
		_Inout_ PUNICODE_STRING GuidString,
		_In_ BOOLEAN AllocateGuidString);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI WCHAR NTAPI RtlUpcaseUnicodeChar(
		_In_ WCHAR SourceCharacter);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI NTSTATUS NTAPI RtlUpcaseUnicodeStringToAnsiString(
		_Inout_ PANSI_STRING DestinationString,
		_In_ PUNICODE_STRING SourceString,
		_In_ BOOLEAN AllocateDestinationString);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlutf8stringtounicodestring
	NTSYSAPI NTSTATUS RtlUTF8StringToUnicodeString(
		PUNICODE_STRING DestinationString,
		PUTF8_STRING    SourceString,
		BOOLEAN         AllocateDestinationString);

	//https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlutf8tounicoden
	NTSYSAPI NTSTATUS RtlUTF8ToUnicodeN(
		[out, optional] PWSTR  UnicodeStringDestination,
		_In_            ULONG  UnicodeStringMaxByteCount,
		_Out_           PULONG UnicodeStringActualByteCount,
		_In_            PCCH   UTF8StringSource,
		_In_            ULONG  UTF8StringByteCount);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlunicodestringtoansisize
	NTSYSAPI void NTAPI RtlUnicodeStringToAnsiSize(
		_In_  STRING);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlunicodestringtoansistring
	// See winterl.h
	NTSYSAPI NTSTATUS NTAPI RtlUnicodeStringToAnsiString(
		[in, out] PANSI_STRING     DestinationString,
		_In_      PCUNICODE_STRING SourceString,
		_In_      BOOLEAN          AllocateDestinationString);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlunicodestringtocountedoemstring
	NTSYSAPI NTSTATUS RtlUnicodeStringToCountedOemString(
		POEM_STRING      DestinationString,
		_In_ PCUNICODE_STRING SourceString,
		_In_ BOOLEAN          AllocateDestinationString);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlunicodestringtoansistring
	NTSYSAPI NTSTATUS RtlUnicodeStringToAnsiString(
		[in, out] PANSI_STRING     DestinationString,
		_In_      PCUNICODE_STRING SourceString,
		_In_      BOOLEAN          AllocateDestinationString);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlxunicodestringtooemsize
#define RtlUnicodeStringToOemSize RtlUnicodeStringToAnsiSize /* Alias */
#define RtlxUnicodeStringToAnsiSize RtlUnicodeStringToAnsiSize /* Alias */
#define RtlxUnicodeStringToOemSize RtlUnicodeStringToAnsiSize /* Alias */
	NTSYSAPI ULONG NTAPI RtlUnicodeStringToAnsiSize(
		PCUNICODE_STRING UnicodeString);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlunicodestringtooemstring
	// See winterl.h
	NTSYSAPI NTSTATUS NTAPI RtlUnicodeStringToOemString(
		_Out_ POEM_STRING      DestinationString,
		_In_  PCUNICODE_STRING SourceString,
		_In_  BOOLEAN          AllocateDestinationString);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlunicodestringtoutf8string
	NTSYSAPI NTSTATUS RtlUnicodeStringToUTF8String(
		PUTF8_STRING     DestinationString,
		PCUNICODE_STRING SourceString,
		BOOLEAN          AllocateDestinationString);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlunicodetocustomcpn
	NTSYSAPI NTSTATUS RtlUnicodeToCustomCPN(
		PCPTABLEINFO CustomCP,
		PCH          CustomCPString,
		ULONG        MaxBytesInCustomCPString,
		PULONG       BytesInCustomCPString,
		PWCH         UnicodeString,
		ULONG        BytesInUnicodeString);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlunicodetomultibyten
	NTSYSAPI NTSTATUS RtlUnicodeToMultiByteN(
		_Out_           PCHAR  MultiByteString,
		_In_            ULONG  MaxBytesInMultiByteString,
		[out, optional] PULONG BytesInMultiByteString,
		_In_            PCWCH  UnicodeString,
		_In_            ULONG  BytesInUnicodeString);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlunicodetomultibytesize
	// See winterl.h
	NTSYSAPI NTSTATUS NTAPI RtlUnicodeToMultiByteSize(
		_Out_ PULONG BytesInMultiByteString,
		_In_  PWCH   UnicodeString,
		_In_  ULONG  BytesInUnicodeString);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlunicodetooemn
	NTSYSAPI NTSTATUS RtlUnicodeToOemN(
		_Out_           PCHAR  OemString,
		_In_            ULONG  MaxBytesInOemString,
		[out, optional] PULONG BytesInOemString,
		_In_            PCWCH  UnicodeString,
		_In_            ULONG  BytesInUnicodeString);

	//https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlunicodetoutf8n
	NTSYSAPI NTSTATUS RtlUnicodeToUTF8N(
		_Out_ PCHAR  UTF8StringDestination,
		_In_  ULONG  UTF8StringMaxByteCount,
		_Out_ PULONG UTF8StringActualByteCount,
		_In_  PCWCH  UnicodeStringSource,
		_In_  ULONG  UnicodeStringByteCount);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlupcaseunicodestring
	NTSYSAPI NTSTATUS RtlUpcaseUnicodeString(
		[in, out] PUNICODE_STRING  DestinationString,
		_In_      PCUNICODE_STRING SourceString,
		_In_      BOOLEAN          AllocateDestinationString);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlupcaseunicodestringtocountedoemstring
	NTSYSAPI NTSTATUS RtlUpcaseUnicodeStringToCountedOemString(
		POEM_STRING      DestinationString,
		_In_ PCUNICODE_STRING SourceString,
		_In_ BOOLEAN          AllocateDestinationString);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlupcaseunicodestringtooemstring
	NTSYSAPI NTSTATUS RtlUpcaseUnicodeStringToOemString(
		POEM_STRING      DestinationString,
		_In_ PCUNICODE_STRING SourceString,
		_In_ BOOLEAN          AllocateDestinationString);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlupcaseunicodetocustomcpn
	NTSYSAPI NTSTATUS RtlUpcaseUnicodeToCustomCPN(
		PCPTABLEINFO CustomCP,
		PCH          CustomCPString,
		ULONG        MaxBytesInCustomCPString,
		PULONG       BytesInCustomCPString,
		PWCH         UnicodeString,
		ULONG        BytesInUnicodeString);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlupcaseunicodetomultibyten
	NTSYSAPI NTSTATUS RtlUpcaseUnicodeToMultiByteN(
		_Out_           PCHAR  MultiByteString,
		_In_            ULONG  MaxBytesInMultiByteString,
		[out, optional] PULONG BytesInMultiByteString,
		_In_            PCWCH  UnicodeString,
		_In_            ULONG  BytesInUnicodeString);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlupcaseunicodetooemn
	NTSYSAPI NTSTATUS RtlUpcaseUnicodeToOemN(
		_Out_           PCHAR  OemString,
		_In_            ULONG  MaxBytesInOemString,
		[out, optional] PULONG BytesInOemString,
		_In_            PCWCH  UnicodeString,
		_In_            ULONG  BytesInUnicodeString);

	//https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlupperchar
	NTSYSAPI CHAR RtlUpperChar(
		_In_ CHAR Character);

	//https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlupperstring
	NTSYSAPI VOID RtlUpperString(
		[in, out] PSTRING      DestinationString,
		_In_      const STRING* SourceString);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI NTSTATUS NTAPI RtlValidateUnicodeString(
		_In_ ULONG Flags,
		_In_ PUNICODE_STRING String);

	//https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L1942
	NTSYSAPI ULONG NTAPI RtlxAnsiStringToUnicodeSize(
		_In_ PCANSI_STRING AnsiString);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlxoemstringtounicodesize
	NTSYSAPI ULONG RtlxOemStringToUnicodeSize(
		PCOEM_STRING OemString);

}

#endif
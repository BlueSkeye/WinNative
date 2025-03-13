#pragma once

#ifndef _NTDLL_
#define _NTDLL_

#include "NTCRuntime.h"
#include "NtAtoms.h"
#include "NtDebugging.h"
#include "NtDevices.h"
#include "NtEnvironment.h"
#include "NtEvents.h"
#include "NtFile.h"
#include "NtIo.h"
#include "NtLocalProcedureCalls.h"
#include "NtMemory.h"
#include "NtNotification.h"
#include "NtObjects.h"
#include "NtPartition.h"
#include "NtRegisry.h"
#include "NtRuntimeLib.h"
#include "NtSection.h"
#include "NtSecurity.h"
#include "NtTime.h"
#include "NtTransaction.h"

extern "C"
{

	// UNRESOLVED FUNCTIONS

	// Theese three functions are quite intricated. Actually the exported addresses are just in the
	// middle of the RtlInterlockedPopEntrySList function itself. They are most certainly used for
	// handling some intricate use cases where the "pop entry" is not so interlocked because the
	// operation has been preempted and initial acquired lock may have been released !!! requiring
	// some kind of "restart".
	//ExpInterlockedPopEntrySListEnd
	//ExpInterlockedPopEntrySListFault
	//ExpInterlockedPopEntrySListResume

	//RtlActivateActivationContextUnsafeFast

	//ShipAssert
	//ShipAssertGetBufferInfo
	//ShipAssertMsgA
	//ShipAssertMsgW

	// END OF UNRESOLVED FUNCTIONS

	// https://processhacker.sourceforge.io/doc/ntlpcapi_8h.html
	NTSYSAPI NTSTATUS NTAPI AlpcAdjustCompletionListConcurrencyCount(
		_In_ HANDLE PortHandle,
		_In_ ULONG ConcurrencyCount);

	// https://processhacker.sourceforge.io/doc/ntlpcapi_8h.html
	NTSYSAPI VOID NTAPI AlpcFreeCompletionListMessage(
		_Inout_ PVOID CompletionList,
		_In_ PPORT_MESSAGE Message);

	// https://processhacker.sourceforge.io/doc/ntlpcapi_8h.html
	NTSYSAPI VOID NTAPI AlpcGetCompletionListLastMessageInformation(
		_In_ PVOID CompletionList,
		_Out_ PULONG LastMessageId,
		_Out_ PULONG LastCallbackId);

	// https://processhacker.sourceforge.io/doc/ntlpcapi_8h.html
	NTSYSAPI PALPC_MESSAGE_ATTRIBUTES NTAPI AlpcGetCompletionListMessageAttributes(
		_In_ PVOID CompletionList,
		_In_ PPORT_MESSAGE Message);

	// https://processhacker.sourceforge.io/doc/ntlpcapi_8h.html
	NTSYSAPI ULONG NTAPI AlpcGetHeaderSize(
		_In_ ULONG Flags);

	// https://processhacker.sourceforge.io/doc/ntlpcapi_8h.html
	NTSYSAPI PVOID NTAPI AlpcGetMessageAttribute(
		_In_ PALPC_MESSAGE_ATTRIBUTES 	Buffer,
		_In_ ULONG 	AttributeFlag);

	// https://processhacker.sourceforge.io/doc/ntlpcapi_8h.html
	NTSYSAPI PPORT_MESSAGE NTAPI AlpcGetMessageFromCompletionList(
		_In_ PVOID CompletionList,
		_Out_opt_ PALPC_MESSAGE_ATTRIBUTES* MessageAttributes);

	// https://processhacker.sourceforge.io/doc/ntlpcapi_8h.html
	NTSYSAPI ULONG NTAPI AlpcGetOutstandingCompletionListMessageCount(
		_In_ PVOID CompletionList);

	// https://processhacker.sourceforge.io/doc/ntlpcapi_8h.html
	NTSYSAPI NTSTATUS NTAPI AlpcInitializeMessageAttribute(
		_In_ ULONG 	AttributeFlags,
		_Out_opt_ PALPC_MESSAGE_ATTRIBUTES 	Buffer,
		_In_ ULONG 	BufferSize,
		_Out_ PULONG 	RequiredBufferSize);
		
	// https://processhacker.sourceforge.io/doc/ntlpcapi_8h.html
	NTSYSAPI ULONG NTAPI AlpcMaxAllowedMessageLength(VOID);

	// https://processhacker.sourceforge.io/doc/ntlpcapi_8h.html
	NTSYSAPI NTSTATUS NTAPI AlpcRegisterCompletionList(
		_In_ HANDLE 	PortHandle,
		_Out_ PALPC_COMPLETION_LIST_HEADER 	Buffer,
		_In_ ULONG 	Size,
		_In_ ULONG 	ConcurrencyCount,
		_In_ ULONG 	AttributeFlags);

	// https://processhacker.sourceforge.io/doc/ntlpcapi_8h.html
	NTSYSAPI BOOLEAN NTAPI AlpcRegisterCompletionListWorkerThread(
		_Inout_ PVOID CompletionList);

	// https://processhacker.sourceforge.io/doc/ntlpcapi_8h.html
	NTSYSAPI NTSTATUS NTAPI AlpcRundownCompletionList(
		_In_ HANDLE PortHandle);
		
	// https://processhacker.sourceforge.io/doc/ntlpcapi_8h.html
	NTSYSAPI NTSTATUS NTAPI AlpcUnregisterCompletionList(
		_In_ HANDLE PortHandle);

	// https://processhacker.sourceforge.io/doc/ntlpcapi_8h.html
	NTSYSAPI BOOLEAN NTAPI AlpcUnregisterCompletionListWorkerThread(
		_Inout_ PVOID CompletionList);

	// https://www.sstic.org/media/SSTIC2019/SSTIC-actes/dll_shell_game_and_other_misdirections/SSTIC2019-Article-dll_shell_game_and_other_misdirections-georges.pdf
	// https://learn.microsoft.com/en-us/windows/win32/sysinfo/apisetqueryapisetpresence
	NTSYSAPI BOOL WINAPI ApiSetQueryApiSetPresence(
		_In_  PCUNICODE_STRING Namespace,
		_Out_ PBOOLEAN         Present);

	//https://learn.microsoft.com/en-us/windows/win32/sysinfo/apisetqueryapisetpresenceex
	NTSYSAPI BOOL WINAPI ApiSetQueryApiSetPresenceEx(
		_In_ PCUNICODE_STRING Namespace,
		_Out_ PBOOLEAN IsInSchema,
		_Out_ PBOOLEAN Present);

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtAllocateUuids(
		_Out_ PLARGE_INTEGER UuidLastTimeAllocated,
		_Out_ PULONG UuidDeltaTime,
		_Out_ PULONG UuidSequenceNumber,
		_Out_ PUCHAR UuidSeed);
	//ZwAllocateUuids

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtCallbackReturn(
		_In_opt_ PVOID Result,
		_In_ ULONG ResultLength,
		_In_ NTSTATUS Status);
	//ZwCallbackReturn

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntclose
	NTSYSAPI NTSTATUS NTAPI NtClose(
		_In_ HANDLE Handle);
	// ZwClose

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSAPI NTSTATUS NTAPI NtDirectGraphicsCall(
		ULONG Unknown,
		ULONG Unknown,
		ULONG Unknown,
		ULONG Unknown,
		ULONG Unknown);
	//ZwDirectGraphicsCall

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtDisplayString(
		_In_ PUNICODE_STRING Message);
	//ZwDisplayString

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtDrawText(
		_In_ PUNICODE_STRING Text);
	//ZwDrawText

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSAPI NTSTATUS NTAPI NtFlushInstallUILanguage(
		_In_ ULONG InstallUILanguage,
		_In_ ULONG SetComittedFlag);
	//ZwFlushInstallUILanguage

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtGetMUIRegistryInfo(
		_In_ ULONG Flags,
		_Inout_ PULONG BufferLength,
		_Out_ PVOID Buffer);
	//ZwGetMUIRegistryInfo

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtGetTickCount();

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtIsUILanguageComitted();
	//ZwIsUILanguageComitted

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtLockProductActivationKeys(
		_In_ PULONG ProductBuild,
		_In_ PULONG SafeMode);
	//ZwLockProductActivationKeys

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtManageHotPatch(
		_In_ HOT_PATCH_INFORMATION_CLASS HotPatchClass,
		_In_ PVOID PatchData,
		_In_ ULONG Length,
		_Out_ PULONG ReturnedLength);
	//ZwManageHotPatch

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtMapCMFModule(
		_In_ ULONG What,
		_In_ ULONG Index,
		_Out_opt_ PULONG CacheIndexOut,
		_Out_opt_ PULONG CacheFlagsOut,
		_Out_opt_ PULONG ViewSizeOut,
		_Out_opt_ PPVOID BaseAddress);
	//ZwMapCMFModule

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtNotifyChangeSession(
		_In_ HANDLE Session,
		_In_ ULONG IoStateSequence,
		_In_ PVOID Reserved,
		_In_ ULONG Action,
		_In_ IO_SESSION_STATE IoState,
		_In_ IO_SESSION_STATE IoState2,
		_In_ PVOID Buffer,
		_In_ ULONG BufferSize);
	//ZwNotifyChangeSession

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtOpenSession(
		_Out_ PHANDLE SessionHandle,
		_In_ ACCESS_MASK DesiredAccess,
		_In_ POBJECT_ATTRIBUTES ObjectAttributes);
	//ZwOpenSession

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtQueryLicenseValue(
		_In_ PUNICODE_STRING Name,
		_Out_opt_ PULONG Type,
		_Out_ PVOID Buffer,
		_In_ ULONG Length,
		_Out_ PULONG ReturnedLength);
	//ZwQueryLicenseValue

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtRevertContainerImpersonation();
	//ZwRevertContainerImpersonation

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtSetLdtEntries(
		_In_ ULONG Selector1,
		_In_ ULONG LdtEntry1L,
		_In_ ULONG LdtEntry1H,
		_In_ ULONG Selector2,
		_In_ ULONG LdtEntry2L,
		_In_ ULONG LdtEntry2H);
	//ZwSetLdtEntries
	
	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSAPI NTSTATUS NTAPI NtSetUuidSeed(
		_In_ PUCHAR UuidSeed);
	//ZwSetUuidSeed

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSAPI NTSTATUS NTAPI NtShutdownSystem(
		_In_ SHUTDOWN_ACTION Action);
	//ZwShutdownSystem

	// https://learn.microsoft.com/fr-fr/windows/win32/api/winuser/nf-winuser-defwindowproca
	// Forwarded from USER32:DefWindowProcA
	NTSYSAPI LRESULT NTAPI NtdllDefWindowProc_A(
		[in] HWND   hWnd,
		[in] UINT   Msg,
		[in] WPARAM wParam,
		[in] LPARAM lParam);

	// https://learn.microsoft.com/fr-fr/windows/win32/api/winuser/nf-winuser-defwindowprocw
	NTSYSAPI LRESULT NTAPI NtdllDefWindowProc_W(
		[in] HWND   hWnd,
		[in] UINT   Msg,
		[in] WPARAM wParam,
		[in] LPARAM lParam);

	// https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-defdlgproca
	// Forwarded from USER32:DefDlgProcA
	NTSYSAPI LRESULT NTAPI NtdllDialogWndProc_A(
		[in] HWND   hDlg,
		[in] UINT   Msg,
		[in] WPARAM wParam,
		[in] LPARAM lParam);

	// https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-defdlgprocw
	// Forwarded from USER32:DefDlgProcW
	NTSYSAPI LRESULT NTAPI NtdllDialogWndProc_W(
		[in] HWND   hDlg,
		[in] UINT   Msg,
		[in] WPARAM wParam,
		[in] LPARAM lParam);

	// https://doxygen.reactos.org/dc/d65/rxact_8c.html
	NTSYSAPI NTSTATUS NTAPI RtlAbortRXact(
		PRXACT_CONTEXT Context);

	// Reversed
	NTSYSAPI NTSTATUS NTAPI RtlAcquirePebLock();

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI VOID NTAPI RtlReleaseSRWLockExclusive(
		_Inout_ PRTL_SRWLOCK SRWLock);

	//https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI BOOLEAN NTAPI RtlAcquireResourceExclusive(
		_Inout_ PRTL_RESOURCE Resource,
		_In_ BOOLEAN Wait);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI BOOLEAN NTAPI RtlAcquireResourceShared(
		_Inout_ PRTL_RESOURCE Resource,
		_In_ BOOLEAN Wait);

	//https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI VOID NTAPI RtlAcquireSRWLockExclusive(
		_Inout_ PRTL_SRWLOCK SRWLock);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI VOID NTAPI RtlAcquireSRWLockShared(
		_Inout_ PRTL_SRWLOCK SRWLock);

	// https://doxygen.reactos.org/dc/d65/rxact_8c.html
	NTSYSAPI NTSTATUS NTAPI RtlAddActionToRXact(
		PRXACT_CONTEXT Context,
		ULONG ActionType,
		PUNICODE_STRING KeyName,
		ULONG ValueType,
		PVOID ValueData,
		ULONG ValueDataSize);

	//RtlAddAttributeActionToRXact
	NTSYSAPI NTSTATUS NTAPI RtlAddAttributeActionToRXact(
		PRXACT_CONTEXT Context,
		ULONG ActionType,
		PUNICODE_STRING KeyName,
		HANDLE KeyHandle,
		PUNICODE_STRING ValueName,
		ULONG ValueType,
		PVOID ValueData,
		ULONG ValueDataSize);
	
	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI PRTL_HANDLE_TABLE_ENTRY NTAPI RtlAllocateHandle(
		_In_ PRTL_HANDLE_TABLE HandleTable,
		_Out_opt_ PULONG HandleIndex);

	// https://undoc.airesoft.co.uk/ntdll.dll/RtlAppendPathElement.php
	NTSYSAPI NTSTATUS WINAPI RtlAppendPathElement(
		ULONG flags,
		PRTL_UNICODE_STRING_BUFFER pStrBuffer,
		PCUNICODE_STRING pAddend);

	// https://doxygen.reactos.org/d2/d94/appverifier_8c.html
	NTSYSAPI VOID NTAPI RtlApplicationVerifierStop(
		_In_ ULONG_PTR Code,
		_In_ PCSTR Message,
		_In_ PVOID Value1,
		_In_ PCSTR Description1,
		_In_ PVOID Value2,
		_In_ PCSTR Description2,
		_In_ PVOID Value3,
		_In_ PCSTR Description3,
		_In_ PVOID Value4,
		_In_ PCSTR Description4);

	// https://doxygen.reactos.org/dc/d65/rxact_8c.html
	NTSYSAPI NTSTATUS NTAPI RtlApplyRXact(
		PRXACT_CONTEXT Context);

	// https://doxygen.reactos.org/dc/d65/rxact_8c.html
	NTSYSAPI NTSTATUS NTAPI RtlApplyRXactNoFlush(
		PRXACT_CONTEXT Context);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlarebitsclear
	NTSYSAPI BOOLEAN RtlAreBitsClear(
		[in] PRTL_BITMAP BitMapHeader,
		[in] ULONG       StartingIndex,
		[in] ULONG       Length);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlarebitsset
	NTSYSAPI BOOLEAN RtlAreBitsSet(
		[in] PRTL_BITMAP BitMapHeader,
		[in] ULONG       StartingIndex,
		[in] ULONG       Length);

	// Reversed
	NTSYSAPI BOOLEAN NTAPI RtlAreLongPathsEnabled(VOID);
	
	// https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/shared/ntrtl_x/rtl_barrier.htm
	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI BOOLEAN NTAPI RtlBarrier(
		_Inout_ PRTL_BARRIER Barrier,
		_In_ ULONG Flags);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI BOOLEAN NTAPI RtlBarrierForDelete(
		_Inout_ PRTL_BARRIER Barrier,
		_In_ ULONG Flags);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L10109C1-L10116C7
	NTSYSAPI NTSTATUS NTAPI RtlCapabilityCheck(
		_In_opt_ HANDLE TokenHandle,
		_In_ PUNICODE_STRING CapabilityName,
		_Out_ PBOOLEAN HasCapability);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlcapturecontext
	NTSYSAPI VOID RtlCaptureContext(
		[out] PCONTEXT ContextRecord);

	// Guessed
	// https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/Diagnostics/Debug/fn.RtlCaptureContext2.html
	NTSYSAPI VOID RtlCaptureContext2(
		[out] PCONTEXT ContextRecord);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlcapturestackbacktrace
	NTSYSAPI USHORT RtlCaptureStackBackTrace(
		[in]            ULONG  FramesToSkip,
		[in]            ULONG  FramesToCapture,
		[out]           PVOID* BackTrace,
		[out, optional] PULONG BackTraceHash);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L10720C1-L10727C1
	NTSYSAPI NTSTATUS NTAPI RtlCheckBootStatusIntegrity(
		_In_ HANDLE FileHandle,
		_Out_ PBOOLEAN Verified);

	// https://github.com/reactos/reactos/blob/master/sdk/lib/rtl/critical.c
	NTSYSAPI VOID NTAPI RtlCheckForOrphanedCriticalSections(
		HANDLE ThreadHandle);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L10771C1-L10777C1
	NTSYSAPI NTSTATUS NTAPI RtlCheckPortableOperatingSystem(
		_Out_ PBOOLEAN IsPortable); // VOID

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlcheckregistrykey
	NTSYSAPI NTSTATUS RtlCheckRegistryKey(
		[in] ULONG RelativeTo,
		[in] PWSTR Path);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L10086C1-L10093C1
	NTSYSAPI NTSTATUS NTAPI RtlCheckSandboxedToken(
		_In_opt_ HANDLE TokenHandle,
		_Out_ PBOOLEAN IsSandboxed);

	// https://github.com/winsiderss/phnt/blob/master/ntrtl.h
	NTSYSAPI NTSTATUS NTAPI RtlCheckTokenMembership(
		_In_opt_ HANDLE TokenHandle,
		_In_ PSID SidToCheck,
		_Out_ PBOOLEAN IsMember);

	// https://github.com/winsiderss/phnt/blob/master/ntrtl.h
	NTSYSAPI NTSTATUS NTAPI RtlCheckTokenMembershipEx(
		_In_opt_ HANDLE TokenHandle,
		_In_ PSID SidToCheck,
		_In_ ULONG Flags, // CTMF_VALID_FLAGS
		_Out_ PBOOLEAN IsMember);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L10097
	NTSYSAPI NTSTATUS NTAPI RtlCheckTokenCapability(
		_In_opt_ HANDLE TokenHandle,
		_In_ PSID CapabilitySidToCheck,
		_Out_ PBOOLEAN HasCapability);

	// https://ntdoc.m417z.com/rtlcleanupteblanglists
	NTSYSAPI VOID NTAPI RtlCleanUpTEBLangLists(VOID);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlclearallbits
	NTSYSAPI VOID RtlClearAllBits(
		[in] PRTL_BITMAP BitMapHeader);

	// https://github.com/winsiderss/phnt/blob/master/ntrtl.h
	NTSYSAPI VOID NTAPI RtlClearAllBitsEx(
		_In_ PRTL_BITMAP_EX BitMapHeader);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlclearbit
	NTSYSAPI VOID RtlClearBit(
		[in] PRTL_BITMAP BitMapHeader,
		[in] ULONG       BitNumber);

	// https://github.com/winsiderss/phnt/blob/master/ntrtl.h
	NTSYSAPI VOID NTAPI RtlClearBitEx(
		_In_ PRTL_BITMAP_EX BitMapHeader,
		_In_range_(< , BitMapHeader->SizeOfBitMap) ULONG64 BitNumber);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlclearbits
	NTSYSAPI VOID RtlClearBits(
		[in] PRTL_BITMAP BitMapHeader,
		[in] ULONG       StartingIndex,
		[in] ULONG       NumberToClear);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlcmdecodememioresource
	NTSYSAPI ULONGLONG RtlCmDecodeMemIoResource(
		[in]            PCM_PARTIAL_RESOURCE_DESCRIPTOR Descriptor,
		[out, optional] PULONGLONG                      Start);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlcmencodememioresource
	NTSYSAPI NTSTATUS RtlCmEncodeMemIoResource(
		[in] PCM_PARTIAL_RESOURCE_DESCRIPTOR Descriptor,
		[in] UCHAR                           Type,
		[in] ULONGLONG                       Length,
		[in] ULONGLONG                       Start);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L6279C1-L6286C1
	NTSYSAPI PVOID NTAPI RtlCommitDebugInfo(
		_Inout_ PRTL_DEBUG_INFORMATION Buffer,
		_In_ SIZE_T Size);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI LONG NTAPI RtlCompareAltitudes(
		_In_ PUNICODE_STRING Altitude1,
		_In_ PUNICODE_STRING Altitude2);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlcompressbuffer
	NTSYSAPI NT_RTL_COMPRESS_API NTSTATUS RtlCompressBuffer(
		[in]  USHORT CompressionFormatAndEngine,
		[in]  PUCHAR UncompressedBuffer,
		[in]  ULONG  UncompressedBufferSize,
		[out] PUCHAR CompressedBuffer,
		[in]  ULONG  CompressedBufferSize,
		[in]  ULONG  UncompressedChunkSize,
		[out] PULONG FinalCompressedSize,
		[in]  PVOID  WorkSpace);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	NTSYSAPI DWORD WINAPI RtlComputeCrc32(
		DWORD dwInitial,
		const PBYTE pData,
		INT iLen);

	//https://doxygen.reactos.org/d8/dd5/ndk_2rtlfuncs_8h.html#affe1add420874a2869fbd93ddf8913fb
	NTSYSAPI NTSTATUS NTAPI RtlComputePrivatizedDllName_U(
		_In_ PUNICODE_STRING 	DllName,
		_Inout_ PUNICODE_STRING 	RealName,
		_Inout_ PUNICODE_STRING 	LocalName);

	// https://github.com/xmoezzz/NativeLib-R/blob/master/ntsmss.h
	NTSYSAPI NTSTATUS NTAPI RtlConnectToSm(
		_In_ PUNICODE_STRING ApiPortName,
		_In_ HANDLE ApiPortHandle,
		_In_ DWORD ProcessImageType,
		_Out_ PHANDLE SmssConnection);

	// https://doxygen.reactos.org/d6/d28/sdk_2lib_2rtl_2nls_8c.html
	NTSYSAPI NTSTATUS NTAPI RtlConsoleMultiByteToUnicodeN(
		OUT PWCHAR UnicodeString,
		IN ULONG UnicodeSize,
		OUT PULONG ResultSize,
		IN PCSTR MbString,
		IN ULONG MbSize,
		OUT PULONG Unknown);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	NTSYSAPI DWORD WINAPI RtlConvertDeviceFamilyInfoToString(
		PDWORD device_family_size,
		PDWORD device_form_size,
		WCHAR* device_family,
		WCHAR* device_form);

	//https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI VOID NTAPI RtlConvertExclusiveToShared(
		_Inout_ PRTL_RESOURCE Resource);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI NTSTATUS NTAPI RtlConvertLCIDToString(
		_In_ LCID LcidValue,
		_In_ ULONG Base,
		_In_ ULONG Padding,
		_Out_writes_(Size) PWSTR pResultBuf,
		_In_ ULONG Size);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI VOID NTAPI RtlConvertSharedToExclusive(
		_Inout_ PRTL_RESOURCE Resource);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L1256C1-L1261C7
	NTSYSAPI BOOLEAN NTAPI RtlConvertSRWLockExclusiveToShared(
		_Inout_ PRTL_SRWLOCK SRWLock);

	// https://github.com/winsiderss/phnt/blob/master/ntrtl.h
	NTSYSAPI VOID NTAPI RtlCopyBitMap(
		_In_ PRTL_BITMAP Source,
		_In_ PRTL_BITMAP Destination,
		_In_range_(0, Destination->SizeOfBitMap - 1) ULONG TargetBit);

	// https://github.com/winsiderss/phnt/blob/master/ntrtl.h
	NTSYSAPI NTSTATUS NTAPI RtlCopyContext(
		_Inout_ PCONTEXT Context,
		_In_ ULONG ContextFlags,
		_Out_ PCONTEXT Source);

	// https://github.com/winsiderss/phnt/blob/master/ntrtl.h
	NTSYSAPI NTSTATUS NTAPI RtlCopyExtendedContext(
		_Out_ PCONTEXT_EX Destination,
		_In_ ULONG ContextFlags,
		_In_ PCONTEXT_EX Source);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlcopyluid
	NTSYSAPI VOID RtlCopyLuid(
		[out] PLUID DestinationLuid,
		[in]  PLUID SourceLuid);

	// https://github.com/winsiderss/phnt/blob/master/ntrtl.h
	NTSYSAPI VOID NTAPI RtlCopyLuidAndAttributesArray(
		_In_ ULONG Count,
		_In_ PLUID_AND_ATTRIBUTES Src,
		_In_ PLUID_AND_ATTRIBUTES Dest);

	// https://github.com/winsiderss/phnt/blob/master/ntrtl.h
	NTSYSAPI ULONG NTAPI RtlCrc32(
		_In_reads_bytes_(Size) const void* Buffer,
		_In_ size_t Size,
		_In_ ULONG InitialCrc);

	// https://github.com/winsiderss/phnt/blob/master/ntrtl.h
	NTSYSAPI ULONGLONG NTAPI RtlCrc64(
		_In_reads_bytes_(Size) const void* Buffer,
		_In_ size_t Size,
		_In_ ULONGLONG InitialCrc);

	// https://github.com/winsiderss/phnt/blob/master/ntrtl.h
	NTSYSAPI NTSTATUS NTAPI RtlCreateEnvironment(
		_In_ BOOLEAN CloneCurrentEnvironment,
		_Out_ PVOID* Environment);

	// https://github.com/winsiderss/phnt/blob/master/ntrtl.h
	NTSYSAPI NTSTATUS NTAPI RtlCreateEnvironmentEx(
		_In_opt_ PVOID SourceEnvironment,
		_Out_ PVOID* Environment,
		_In_ ULONG Flags);

	// https://github.com/winsiderss/phnt/blob/master/ntrtl.h
	NTSYSAPI PRTL_DEBUG_INFORMATION NTAPI RtlCreateQueryDebugBuffer(
		_In_opt_ ULONG MaximumCommit,
		_In_ BOOLEAN UseEventPair);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlcreateregistrykey
	NTSYSAPI NTSTATUS RtlCreateRegistryKey(
		[in] ULONG RelativeTo,
		[in] PWSTR Path);

	//https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlcreatesystemvolumeinformationfolder
	NTSYSAPI NTSTATUS RtlCreateSystemVolumeInformationFolder(
		[in] PCUNICODE_STRING VolumeRootPath);

	// https://github.com/winsiderss/phnt/blob/master/ntrtl.h
	NTSYSAPI NTSTATUS NTAPI RtlCreateUserSecurityObject(
		_In_ PRTL_ACE_DATA AceData,
		_In_ ULONG AceCount,
		_In_ PSID OwnerSid,
		_In_ PSID GroupSid,
		_In_ BOOLEAN IsDirectoryObject,
		_In_ PGENERIC_MAPPING GenericMapping,
		_Out_ PSECURITY_DESCRIPTOR* NewSecurityDescriptor);

	// https://github.com/winsiderss/phnt/blob/master/ntrtl.h
	NTSYSAPI NTSTATUS NTAPI RtlCreateUserStack(
		_In_opt_ SIZE_T CommittedStackSize,
		_In_opt_ SIZE_T MaximumStackSize,
		_In_opt_ ULONG_PTR ZeroBits,
		_In_ SIZE_T PageSize,
		_In_ ULONG_PTR ReserveAlignment,
		_Out_ PINITIAL_TEB InitialTeb);

	//https://github.com/winsiderss/phnt/blob/master/ntrtl.h
	NTSYSAPI NTSTATUS NTAPI RtlCreateUserThread(
		_In_ HANDLE ProcessHandle,
		_In_opt_ PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
		_In_ BOOLEAN CreateSuspended,
		_In_opt_ ULONG ZeroBits,
		_In_opt_ SIZE_T MaximumStackSize,
		_In_opt_ SIZE_T CommittedStackSize,
		_In_ PUSER_THREAD_START_ROUTINE StartAddress,
		_In_opt_ PVOID Parameter,
		_Out_opt_ PHANDLE ThreadHandle,
		_Out_opt_ PCLIENT_ID ClientId);

	// https://github.com/winsiderss/phnt/blob/master/ntrtl.h
	NTSYSAPI BOOLEAN NTAPI RtlCultureNameToLCID(
		_In_ PUNICODE_STRING String,
		_Out_ PLCID Lcid);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlcustomcptounicoden
	NTSYSAPI NTSTATUS RtlCustomCPToUnicodeN(
		PCPTABLEINFO CustomCP,
		PWCH         UnicodeString,
		ULONG        MaxBytesInUnicodeString,
		PULONG       BytesInUnicodeString,
		PCH          CustomCPString,
		ULONG        BytesInCustomCPString);

	// https://github.com/winsiderss/phnt/blob/master/ntrtl.h
	NTSYSAPI VOID NTAPI RtlDeCommitDebugInfo(
		_Inout_ PRTL_DEBUG_INFORMATION Buffer,
		_In_ PVOID p,
		_In_ SIZE_T Size);

	// https://github.com/reactos/reactos/blob/0089017d54a601ed317e885576471a73f96ad56c/sdk/include/ndk/rtlfuncs.h#L4104C1-L4109C3
	NTSYSAPI PRTL_ACTIVATION_CONTEXT_STACK_FRAME FASTCALL RtlDeactivateActivationContextUnsafeFast(
		_In_ PRTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME_EXTENDED Frame);

	// https://learn.microsoft.com/en-us/previous-versions/bb432242(v=vs.85)
	NTSYSAPI PVOID NTAPI RtlDecodePointer(
		_In_ PVOID Ptr);

	// https://learn.microsoft.com/en-us/previous-versions/dn877133(v=vs.85)
	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L9349C1-L9356C7
	NTSYSAPI NTSTATUS NTAPI RtlDecodeRemotePointer(
		_In_ HANDLE ProcessHandle,
		_In_ PVOID Pointer,
		_Out_ PVOID* DecodedPointer);

	// https://learn.microsoft.com/en-us/previous-versions/bb432243(v=vs.85)
	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L9330C1-L9335C7
	NTSYSAPI PVOID NTAPI RtlDecodeSystemPointer(
		_In_ PVOID Ptr);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtldecompressbuffer
	NTSYSAPI NT_RTL_COMPRESS_API NTSTATUS RtlDecompressBuffer(
		[in]  USHORT CompressionFormat,
		[out] PUCHAR UncompressedBuffer,
		[in]  ULONG  UncompressedBufferSize,
		[in]  PUCHAR CompressedBuffer,
		[in]  ULONG  CompressedBufferSize,
		[out] PULONG FinalUncompressedSize);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtldecompressbufferex
	NTSYSAPI NT_RTL_COMPRESS_API NTSTATUS RtlDecompressBufferEx(
		[in]  USHORT CompressionFormat,
		[out] PUCHAR UncompressedBuffer,
		[in]  ULONG  UncompressedBufferSize,
		[in]  PUCHAR CompressedBuffer,
		[in]  ULONG  CompressedBufferSize,
		[out] PULONG FinalUncompressedSize,
		[in]  PVOID  WorkSpace);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtldecompressfragment
	NTSYSAPI NT_RTL_COMPRESS_API NTSTATUS RtlDecompressFragment(
		[in]  USHORT CompressionFormat,
		[out] PUCHAR UncompressedFragment,
		[in]  ULONG  UncompressedFragmentSize,
		[in]  PUCHAR CompressedBuffer,
		[in]  ULONG  CompressedBufferSize,
		[in]  ULONG  FragmentOffset,
		[out] PULONG FinalUncompressedSize,
		[in]  PVOID  WorkSpace);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L8518C1-L8523C7
	NTSYSAPI NTSTATUS NTAPI RtlDefaultNpAcl(
		_Out_ PACL* Acl);

	//https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI NTSTATUS NTAPI RtlDeleteBarrier(
		_In_ PRTL_BARRIER Barrier);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L1006C1-L1011C7
	NTSYSAPI NTSTATUS NTAPI RtlDeleteCriticalSection(
		_Inout_ PRTL_CRITICAL_SECTION CriticalSection);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtldeleteregistryvalue
	NTSYSAPI NTSTATUS RtlDeleteRegistryValue(
		[in] ULONG  RelativeTo,
		[in] PCWSTR Path,
		[in] PCWSTR ValueName);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L1127C1-L1132C7
	NTSYSAPI VOID NTAPI RtlDeleteResource(
		_Inout_ PRTL_RESOURCE Resource);

	// https://github.com/rpodgorny/wine/blob/master/dlls/ntdll/threadpool.c
	NTSYSAPI NTSTATUS WINAPI RtlDeregisterWait(
		_In_ HANDLE WaitHandle);

	// https://github.com/rpodgorny/wine/blob/master/dlls/ntdll/threadpool.c
	NTSYSAPI NTSTATUS WINAPI RtlDeregisterWaitEx(
		_In_ HANDLE WaitHandle,
		_In_opt_ HANDLE CompletionEvent);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L4368
	NTSYSAPI NTSTATUS NTAPI RtlDestroyEnvironment(
		_In_ _Post_invalid_ PVOID Environment);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L6269C1-L6274C7
	NTSYSAPI NTSTATUS NTAPI RtlDestroyQueryDebugBuffer(
		_In_ PRTL_DEBUG_INFORMATION Buffer);

	// https://googleprojectzero.blogspot.com/2016/02/the-definitive-guide-on-win32-to-nt.html
	typedef enum _RTL_PATH_TYPE
	{
		RtlPathTypeUnknown,
		RtlPathTypeUncAbsolute,
		RtlPathTypeDriveAbsolute,
		RtlPathTypeDriveRelative,
		RtlPathTypeRooted,
		RtlPathTypeRelative,
		RtlPathTypeLocalDevice,
		RtlPathTypeRootLocalDevice
	} RTL_PATH_TYPE, *PRTL_PATH_TYPE;
	NTSYSAPI RTL_PATH_TYPE NTAPI RtlDetermineDosPathNameType_U(
		_In_ PCWSTR Path);

	//RtlDisableThreadProfiling
	NTSYSAPI NTSTATUS NTAPI RtlDisableThreadProfiling(
		_In_ PVOID PerformanceDataHandle);
	
	// https://learn.microsoft.com/en-us/windows/win32/devnotes/rtldllshutdowninprogress
	NTSYSAPI BOOLEAN NTAPI RtlDllShutdownInProgress(VOID);

	// https://doxygen.reactos.org/df/d18/sdk_2lib_2rtl_2unicode_8c.html
	// See also https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-dnshostnametocomputernamew
	NTSYSAPI NTSTATUS NTAPI RtlDnsHostNameToComputerName(
		_In_ PUNICODE_STRING ComputerName,
		_Out_opt_ PUNICODE_STRING DnsHostName,
		_In_ BOOLEAN AllocateComputerNameString);

	//https://learn.microsoft.com/fr-fr/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtldrainnonvolatileflush
	NTSYSAPI NTSTATUS NTAPI RtlDrainNonVolatileFlush(
		[in] PVOID NvToken);

	// https://doxygen.reactos.org/de/df0/sdk_2lib_2rtl_2resource_8c.html
	NTSYSAPI VOID NTAPI RtlDumpResource(
		PRTL_RESOURCE Resource);

	// https://raw.githubusercontent.com/hfiref0x/KDU/master/Source/Shared/ntos/ntos.h
	NTSYSAPI VOID NTAPI RtlEnableEarlyCriticalSectionEventCreation(VOID);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI NTSTATUS NTAPI RtlEnableThreadProfiling(
		_In_ HANDLE ThreadHandle,
		_In_ ULONG Flags,
		_In_ ULONG64 HardwareCounters,
		_Out_ PVOID* PerformanceDataHandle);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	NTSYSAPI PVOID WINAPI RtlEncodePointer(PVOID ptr);

	// https://i.blackhat.com/USA-19/Thursday/us-19-Kotler-Process-Injection-Techniques-Gotta-Catch-Them-All-wp.pdf
	NTSYSAPI NTSTATUS RtlEncodeRemotePointer(
		_In_ HANDLE ProcessHandle,
		_In_ PVOID ptr,
		_Out_ PVOID* encoded_ptr);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI PVOID NTAPI RtlEncodeSystemPointer(_In_ PVOID Ptr);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L1014C1-L1019C7
	NTSYSAPI NTSTATUS NTAPI RtlEnterCriticalSection(
		_Inout_ PRTL_CRITICAL_SECTION CriticalSection);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI BOOLEAN NTAPI RtlEqualComputerName(
		_In_ PUNICODE_STRING String1,
		_In_ PUNICODE_STRING String2);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI BOOLEAN NTAPI RtlEqualDomainName(
		_In_ PUNICODE_STRING String1,
		_In_ PUNICODE_STRING String2);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlequalluid
	NTSYSAPI VOID NTAPI RtlEqualLuid(
		_In_ __int64 L1,
		_In_ __int64 L2);

	// https://github.com/winsiderss/systeminformer/blob/bc71c2c1962be178e13cd0f84f63348f468a0701/phnt/include/ntexapi.h#L1373
	typedef ULONG WNF_CHANGE_STAMP, * PWNF_CHANGE_STAMP;
	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L11296
	_Must_inspect_result_ NTSYSAPI BOOLEAN NTAPI RtlEqualWnfChangeStamps(
		_In_ WNF_CHANGE_STAMP ChangeStamp1,
		_In_ WNF_CHANGE_STAMP ChangeStamp2);

	// https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-executeumsthread
	// As of Windows 11, user-mode scheduling is not supported. All calls fail with the error
	// ERROR_NOT_SUPPORTED.
	NTSYSAPI NTSTATUS NTAPI RtlExecuteUmsThread(
		_Inout_ PUMS_CONTEXT UmsThread);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI NTSTATUS NTAPI RtlExpandEnvironmentStrings(
		_In_opt_ PVOID Environment,
		_In_reads_(SrcLength) PWSTR Src,
		_In_ SIZE_T SrcLength,
		_Out_writes_(DstLength) PWSTR Dst,
		_In_ SIZE_T DstLength,
		_Out_opt_ PSIZE_T ReturnLength);
	
	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI NTSTATUS NTAPI RtlExpandEnvironmentStrings_U(
		_In_opt_ PVOID Environment,
		_In_ PUNICODE_STRING Source,
		_Out_ PUNICODE_STRING Destination,
		_Out_opt_ PULONG ReturnedLength);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlextendcorrelationvector
	NTSYSAPI NTSTATUS RtlExtendCorrelationVector(
		[in, out] PCORRELATION_VECTOR CorrelationVector);

	// https://microsoft.github.io/windows-docs-rs/doc/windows/Wdk/System/SystemServices/fn.RtlExtractBitMap.html
	NTSYSAPI VOID NTAPI RtlExtractBitMap(
		_In_ PRTL_BITMAP source,
		_In_ PRTL_BITMAP destination,
		_In_ ULONG targetbit,
		_In_ ULONG numberofbits);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlfindclearbits
	NTSYSAPI ULONG RtlFindClearBits(
		[in] PRTL_BITMAP BitMapHeader,
		[in] ULONG       NumberToFind,
		[in] ULONG       HintIndex);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlfindclearbitsandset
	NTSYSAPI ULONG RtlFindClearBitsAndSet(
		[in] PRTL_BITMAP BitMapHeader,
		[in] ULONG       NumberToFind,
		[in] ULONG       HintIndex);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlfindclearruns
	NTSYSAPI ULONG RtlFindClearRuns(
		[in]  PRTL_BITMAP     BitMapHeader,
		[out] PRTL_BITMAP_RUN RunArray,
		[in]  ULONG           SizeOfRunArray,
		[in]  BOOLEAN         LocateLongestRuns);

	// https://doxygen.reactos.org/de/df5/xdk_2rtlfuncs_8h_source.html
	NTSYSAPI NTSTATUS NTAPI RtlFindClosestEncodableLength(
		_In_ ULONGLONG SourceLength,
		_Out_ PULONGLONG TargetLength);

	// https://github.com/ionescu007/lxss/blob/master/lxdrv/ntosp.h
	NTSYSAPI PVOID NTAPI RtlFindExportedRoutineByName(
		_In_ PVOID ImageBase,
		_In_ PCCH RoutineNam);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlfindlastbackwardrunclear
	NTSYSAPI ULONG RtlFindLastBackwardRunClear(
		[in]  PRTL_BITMAP BitMapHeader,
		[in]  ULONG       FromIndex,
		[out] PULONG      StartingRunIndex);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlfindleastsignificantbit
	NTSYSAPI CCHAR RtlFindLeastSignificantBit(
		[in] ULONGLONG Set);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlfindlongestrunclear
	NTSYSAPI ULONG RtlFindLongestRunClear(
		[in]  PRTL_BITMAP BitMapHeader,
		[out] PULONG      StartingIndex);

	// https://doxygen.reactos.org/de/d70/sdk_2lib_2rtl_2message_8c.html
	NTSYSAPI NTSTATUS NTAPI RtlFindMessage(
		IN PVOID BaseAddress,
		IN ULONG Type,
		IN ULONG Language,
		IN ULONG MessageId,
		OUT PMESSAGE_RESOURCE_ENTRY* MessageResourceEntry);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlfindmostsignificantbit
	NTSYSAPI CCHAR RtlFindMostSignificantBit(
		[in] ULONGLONG Set);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlfindnextforwardrunclear
	NTSYSAPI ULONG RtlFindNextForwardRunClear(
		[in]  PRTL_BITMAP BitMapHeader,
		[in]  ULONG       FromIndex,
		[out] PULONG      StartingRunIndex);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlfindsetbits
	NTSYSAPI ULONG RtlFindSetBits(
		[in] PRTL_BITMAP BitMapHeader,
		[in] ULONG       NumberToFind,
		[in] ULONG       HintIndex);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlfindsetbitsandclear
	NTSYSAPI ULONG RtlFindSetBitsAndClear(
		[in] PRTL_BITMAP BitMapHeader,
		[in] ULONG       NumberToFind,
		[in] ULONG       HintIndex);

	// https://jabber-tools.github.io/google_cognitive_apis/doc/0.1.5/ntapi/ntrtl/fn.RtlFindClearBitsAndSet.html
	NTSYSAPI ULONG NTAPI RtlFindClearBitsAndSet(
		_In_ PRTL_BITMAP BitMapHeader,
		_In_ ULONG NumberToFind,
		_In_ ULONG HintIndex);

	//https://learn.microsoft.com/fr-fr/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlfindsetbits
	NTSYSAPI ULONG NTAPI RtlFindSetBits(
		[in] PRTL_BITMAP BitMapHeader,
		[in] ULONG       NumberToFind,
		[in] ULONG       HintIndex);

	//https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-rtlfirstentryslist
	NTSYSAPI PSLIST_ENTRY NTAPI RtlFirstEntrySList(
		[in] const SLIST_HEADER* ListHead);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L10227C1-L10234C1
	NTSYSAPI NTSTATUS NTAPI RtlFlsAlloc(
		_In_ PFLS_CALLBACK_FUNCTION Callback,
		_Out_ PULONG FlsIndex);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L10245C1-L10251C1
	NTSYSAPI NTSTATUS NTAPI RtlFlsFree(
		_In_ ULONG FlsIndex);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L10253C1-L10260C1
	NTSYSAPI NTSTATUS NTAPI RtlFlsGetValue(
		_In_ ULONG FlsIndex,
		_Out_ PVOID* FlsData);
	
	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L10268C1-L10275C1
	NTSYSAPI NTSTATUS NTAPI RtlFlsSetValue(
		_In_ ULONG FlsIndex,
		_In_ PVOID FlsData);

	// https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/rtl/regutil/formatcurrentuserkeypath.htm?ta=8.199996948242188&tx=91,109,113;90,103&ts=0,217
	NTSYSAPI NTSTATUS RtlFormatCurrentUserKeyPath(
		UNICODE_STRING* CurrentUserKeyPath);

	// https://doxygen.reactos.org/de/d70/sdk_2lib_2rtl_2message_8c.html
	NTSYSAPI NTSTATUS NTAPI RtlFormatMessage(
		IN PWSTR Message,
		IN ULONG MaxWidth OPTIONAL,
		IN BOOLEAN IgnoreInserts,
		IN BOOLEAN ArgumentsAreAnsi,
		IN BOOLEAN ArgumentsAreAnArray,
		IN va_list* Arguments,
		OUT PWSTR Buffer,
		IN ULONG BufferSize,
		OUT PULONG ReturnLength OPTIONAL);

	// https://doxygen.reactos.org/de/d70/sdk_2lib_2rtl_2message_8c.html
	NTSYSAPI NTSTATUS NTAPI RtlFormatMessageEx(
		IN PWSTR Message,
		IN ULONG MaxWidth OPTIONAL,
		IN BOOLEAN IgnoreInserts,
		IN BOOLEAN ArgumentsAreAnsi,
		IN BOOLEAN ArgumentsAreAnArray,
		IN va_list* Arguments,
		OUT PWSTR Buffer,
		IN ULONG BufferSize,
		OUT PULONG ReturnLength OPTIONAL,
		IN ULONG Flags);
	
	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI BOOLEAN NTAPI RtlFreeHandle(
		_In_ PRTL_HANDLE_TABLE HandleTable,
		_In_ PRTL_HANDLE_TABLE_ENTRY Handle);

//RtlFreeUserFiberShadowStack

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L3426C1-L3431C7
	NTSYSAPI NTSTATUS NTAPI RtlFreeUserStack(
		_In_ PVOID AllocationBase);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlgenerate8dot3name
	NTSYSAPI NTSTATUS RtlGenerate8dot3Name(
		[in]      PCUNICODE_STRING       Name,
		[in]      BOOLEAN                AllowExtendedCharacters,
		[in, out] PGENERATE_NAME_CONTEXT Context,
		[in, out] PUNICODE_STRING        Name8dot3);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L10008C1-L10013C7
	NTSYSAPI ULONG NTAPI RtlGetActiveConsoleId(VOID);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L10062C1-L10070C7
	NTSYSAPI NTSTATUS NTAPI RtlGetAppContainerNamedObjectPath(
		_In_opt_ HANDLE TokenHandle,
		_In_opt_ PSID AppContainerSid,
		_In_ BOOLEAN RelativePath,
		_Out_ PUNICODE_STRING ObjectPath); // RtlFreeUnicodeString

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L10075C1-L10081C7
	NTSYSAPI NTSTATUS NTAPI RtlGetAppContainerParent(
		_In_ PSID AppContainerSid,
		_Out_ PSID* AppContainerSidParent); // RtlFreeSid

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L9431C1-L9437C7
	NTSYSAPI VOID NTAPI RtlGetCallersAddress(
		// Use the intrinsic _ReturnAddress instead.
		_Out_ PVOID* CallersAddress,
		_Out_ PVOID* CallersCaller);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlgetcompressionworkspacesize
	NT_RTL_COMPRESS_API NTSTATUS RtlGetCompressionWorkSpaceSize(
		[in]  USHORT CompressionFormatAndEngine,
		[out] PULONG CompressBufferWorkSpaceSize,
		[out] PULONG CompressFragmentWorkSpaceSize);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L1051C1-L1056C7
	NTSYSAPI ULONG NTAPI RtlGetCriticalSectionRecursionCount(
		_In_ PRTL_CRITICAL_SECTION CriticalSection);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L4570C1-L4577C1
	NTSYSAPI ULONG NTAPI RtlGetCurrentDirectory_U(
		_In_ ULONG BufferLength,
		_Out_writes_bytes_(BufferLength) PWSTR Buffer);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/process.c
	NTSYSAPI PEB* WINAPI RtlGetCurrentPeb(VOID);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	NTSYSAPI void WINAPI RtlGetCurrentProcessorNumberEx(
		_Out_ PROCESSOR_NUMBER* processor);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L9984C1-L9989C7
	NTSYSAPI ULONG NTAPI RtlGetCurrentServiceSessionId(VOID);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	HANDLE WINAPI RtlGetCurrentTransaction(void);

//RtlGetCurrentUmsThread

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	void WINAPI RtlGetDeviceFamilyInfoEnum(ULONGLONG* version, DWORD* family, DWORD* form);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlgetenabledextendedfeatures
	NTSYSAPI ULONG64 RtlGetEnabledExtendedFeatures(
		[in] ULONG64 FeatureMask);

	// https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/loader.c
	NTSYSAPI NTSTATUS WINAPI RtlGetExePath(
		PCWSTR name,
		PWSTR* path);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L3549C1-L3556C1
	NTSYSAPI NTSTATUS NTAPI RtlGetExtendedContextLength(
		_In_ ULONG ContextFlags,
		_Out_ PULONG ContextLength);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L3557C1-L3565C1
	NTSYSAPI NTSTATUS NTAPI RtlGetExtendedContextLength2(
		_In_ ULONG ContextFlags,
		_Out_ PULONG ContextLength,
		_In_ ULONG64 EnabledExtendedFeatures); // RtlGetEnabledExtendedFeatures(-1)

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L3566C1-L3572C1
	NTSYSAPI ULONG64 NTAPI RtlGetExtendedFeaturesMask(
		_In_ PCONTEXT_EX ContextEx);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L9409C1-L9415C1
	NTSYSAPI PTEB_ACTIVE_FRAME NTAPI RtlGetFrame(VOID);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L6467C1-L6473C1
	NTSYSAPI NTSTATUS NTAPI RtlGetLastNtStatus(VOID);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L6474C1-L6480C1
	NTSYSAPI LONG NTAPI RtlGetLastWin32Error(VOID);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L9249C1-L9258C1
	NTSYSAPI NTSTATUS NTAPI RtlGetNativeSystemInformation(
		_In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
		_In_ PVOID NativeSystemInformation,
		_In_ ULONG InformationLength,
		_Out_opt_ PULONG ReturnLength);

//RtlGetNextUmsListItem

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L8865C1-L8871C1
	NTSYSAPI ULONG NTAPI RtlGetNtGlobalFlags(VOID);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L8873C1-L8879C1
	NTSYSAPI BOOLEAN NTAPI RtlGetNtProductType(
		_Out_ PNT_PRODUCT_TYPE NtProductType);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L4945C1-L4950C7
	NTSYSAPI PWSTR NTAPI RtlGetNtSystemRoot(VOID);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L8851C1-L8858C7
	NTSYSAPI VOID NTAPI RtlGetNtVersionNumbers(
		_Out_opt_ PULONG NtMajorVersion,
		_Out_opt_ PULONG NtMinorVersion,
		_Out_opt_ PULONG NtBuildNumber);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L2786C1-L2795C1
	NTSYSAPI NTSTATUS NTAPI RtlGetParentLocaleName(
		_In_ PCWSTR LocaleName,
		_Inout_ PUNICODE_STRING ParentLocaleName,
		_In_ ULONG Flags,
		_In_ BOOLEAN AllocateDestinationString);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlgetpersistedstatelocation
	NTSYSAPI NTSTATUS RtlGetPersistedStateLocation(
		_In_ PCWSTR SourceID,
		_In_opt_ PCWSTR CustomValue,
		_In_opt_ PCWSTR DefaultPath,
		_In_ STATE_LOCATION_TYPE StateLocationType,
		_In_ PWCHAR TargetPath,
		_In_ ULONG BufferLengthIn,
		_Out_opt_ PULONG BufferLengthOut);

	// https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getproductinfo
	// From Kernel32 to Imports from api-ms-win-core-sysinfo-l1-2-0.dll:__imp_GetProductInfo
	NTSYSAPI BOOL NTAPI RtlGetProductInfo(
		[in]  DWORD  dwOSMajorVersion,
		[in]  DWORD  dwOSMinorVersion,
		[in]  DWORD  dwSpMajorVersion,
		[in]  DWORD  dwSpMinorVersion,
		[out] PDWORD pdwReturnedProductType);

//RtlGetReturnAddressHijackTarget

	// https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/loader.c
	NTSYSAPI NTSTATUS NTAPI RtlGetSearchPath(
		_Out_ PWSTR* path);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L10586C1-L10593C1
	NTSYSAPI NTSTATUS NTAPI RtlGetSessionProperties(
		_In_ ULONG SessionId,
		_Out_ PULONG SharedUserSessionId);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L10706C1-L10717C1
	NTSYSAPI NTSTATUS NTAPI RtlGetSetBootStatusData(
		_In_ HANDLE FileHandle,
		_In_ BOOLEAN Read,
		_In_ RTL_BSD_ITEM_TYPE DataClass,
		_In_ PVOID Buffer,
		_In_ ULONG BufferSize,
		_Out_opt_ PULONG ReturnLength);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L8882C1-L8887C7
	NTSYSAPI ULONG NTAPI RtlGetSuiteMask(VOID);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L10747C1-L10756C1
	NTSYSAPI NTSTATUS NTAPI RtlGetSystemBootStatus(
		_In_ RTL_BSD_ITEM_TYPE BootStatusInformationClass,
		_Out_ PVOID DataBuffer,
		_In_ ULONG DataLength,
		_Out_opt_ PULONG ReturnLength);

//RtlGetSystemBootStatusEx

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L2870C1-L2880C1
	NTSYSAPI NTSTATUS NTAPI RtlGetSystemPreferredUILanguages(
		_In_ ULONG Flags, // MUI_LANGUAGE_NAME
		_In_opt_ PCWSTR LocaleName,
		_Out_ PULONG NumberOfLanguages,
		_Out_writes_opt_(*ReturnLength) PZZWSTR Languages,
		_Inout_ PULONG ReturnLength);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L6506C1-L6512C1
	NTSYSAPI ULONG NTAPI RtlGetThreadErrorMode(VOID);

//RtlGetThreadLangIdByIndex
	
	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L2848C1-L2857C1
	NTSYSAPI NTSTATUS NTAPI RtlGetThreadPreferredUILanguages(
		_In_ ULONG Flags, // MUI_LANGUAGE_NAME
		_Out_ PULONG NumberOfLanguages,
		_Out_writes_opt_(*ReturnLength) PZZWSTR Languages,
		_Inout_ PULONG ReturnLength);

//RtlGetThreadWorkOnBehalfTicket

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L10050C1-L10057C7
	NTSYSAPI NTSTATUS NTAPI RtlGetTokenNamedObjectPath(
		_In_ HANDLE TokenHandle,
		_In_opt_ PSID Sid,
		_Out_ PUNICODE_STRING ObjectPath); // RtlFreeUnicodeString

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L2903C1-L2913C1
	NTSYSAPI NTSTATUS NTAPI RtlGetUILanguageInfo(
		_In_ ULONG Flags,
		_In_ PCZZWSTR Languages,
		_Out_writes_opt_(*NumberOfFallbackLanguages) PZZWSTR FallbackLanguages,
		_Inout_opt_ PULONG NumberOfFallbackLanguages,
		_Out_ PULONG Attributes);

//RtlGetUmsCompletionListEvent
	
	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI VOID NTAPI RtlGetUnloadEventTraceEx(
		_Out_ PULONG* ElementSize,
		_Out_ PULONG* ElementCount,
		_Out_ PVOID* EventTrace);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L9600C1-L9607C7
	NTSYSAPI PRTL_UNLOAD_EVENT_TRACE NTAPI RtlGetUnloadEventTraceEx(
		_Out_ PULONG* ElementSize,
		_Out_ PULONG* ElementCount,
		_Out_ PVOID* EventTrace); // works across all processes

	//RtlGetUserPreferredUILanguages
	NTSYSAPI NTSTATUS NTAPI RtlGetUserPreferredUILanguages(
		_In_ ULONG Flags, // MUI_LANGUAGE_NAME
		_In_opt_ PCWSTR LocaleName,
		_Out_ PULONG NumberOfLanguages,
		_Out_writes_opt_(*ReturnLength) PZZWSTR Languages,
		_Inout_ PULONG ReturnLength);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlgetversion
	NTSYSAPI NTSTATUS RtlGetVersion(
		[out] PRTL_OSVERSIONINFOW lpVersionInformation);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L4151C1-L4159C1
	NTSYSAPI NTSTATUS NTAPI RtlGuardCheckLongJumpTarget(
		_In_ PVOID PcValue,
		_In_ BOOL IsFastFail,
		_Out_ PBOOL IsLongJumpTarget);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L2399C1-L2409C1
	NTSYSAPI NTSTATUS NTAPI RtlIdnToAscii(
		_In_ ULONG Flags,
		_In_ PCWSTR SourceString,
		_In_ LONG SourceStringLength,
		_Out_writes_to_(*DestinationStringLength, *DestinationStringLength) PWSTR DestinationString,
		_Inout_ PLONG DestinationStringLength);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L2421C1-L2431C1
	NTSYSAPI NTSTATUS NTAPI RtlIdnToNameprepUnicode(
		_In_ ULONG Flags,
		_In_ PCWSTR SourceString,
		_In_ LONG SourceStringLength,
		_Out_writes_to_(*DestinationStringLength, *DestinationStringLength) PWSTR DestinationString,
		_Inout_ PLONG DestinationStringLength);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L2410C1-L2420C1
	NTSYSAPI NTSTATUS NTAPI RtlIdnToUnicode(
		_In_ ULONG Flags,
		_In_ PCWSTR SourceString,
		_In_ LONG SourceStringLength,
		_Out_writes_to_(*DestinationStringLength, *DestinationStringLength) PWSTR DestinationString,
		_Inout_ PLONG DestinationStringLength);

	// https://doxygen.reactos.org/df/da2/sdk_2lib_2rtl_2image_8c.html
	NTSYSAPI PVOID NTAPI RtlImageDirectoryEntryToData(
		PVOID BaseAddress,
		BOOLEAN MappedAsImage,
		USHORT Directory,
		PULONG Size);

	// https://github.com/mic101/windows/blob/master/WRK-v1.2/base/ntos/rtl/rtlnthdr.c
	NTSYSAPI PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(
		_In_ PVOID Base);

	// https://github.com/mic101/windows/blob/master/WRK-v1.2/base/ntos/rtl/rtlnthdr.c
	NTSYSAPI NTSTATUS NTAPI RtlImageNtHeaderEx(
		_In_ ULONG Flags,
		_In_ PVOID Base,
		_In_ ULONG64 Size,
		_Out_ PIMAGE_NT_HEADERS* OutHeaders);

	// https://doxygen.reactos.org/df/da2/sdk_2lib_2rtl_2image_8c.html
	NTSYSAPI PIMAGE_SECTION_HEADER NTAPI RtlImageRvaToSection(
		PIMAGE_NT_HEADERS NtHeader,
		PVOID BaseAddress,
		ULONG Rva);

	// https://doxygen.reactos.org/df/da2/sdk_2lib_2rtl_2image_8c.html
	NTSYSAPI PVOID NTAPI RtlImageRvaToVa(
		PIMAGE_NT_HEADERS NtHeader,
		PVOID BaseAddress,
		ULONG Rva,
		PIMAGE_SECTION_HEADER* SectionHeader);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlincrementcorrelationvector
	NTSYSAPI NTSTATUS RtlIncrementCorrelationVector(
		[in, out] PCORRELATION_VECTOR CorrelationVector);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI NTSTATUS NTAPI RtlInitBarrier(
		_Out_ PRTL_BARRIER Barrier,
		_In_ ULONG TotalThreads,
		_In_ ULONG SpinCount);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlinitcodepagetable
	NTSYSAPI VOID RtlInitCodePageTable(
		PUSHORT      TableBase,
		PCPTABLEINFO CodePageTable);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI VOID NTAPI RtlInitNlsTables(
		_In_ PUSHORT 	AnsiNlsBase,
		_In_ PUSHORT 	OemNlsBase,
		_In_ PUSHORT 	LanguageNlsBase,
		_Out_ PNLSTABLEINFO 	TableInfo);

	//https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlinitializebitmap
	NTSYSAPI VOID RtlInitializeBitMap(
		[out] PRTL_BITMAP BitMapHeader,
		[in]  __drv_aliasesMem PULONG BitMapBuffer,
		[in]  ULONG SizeOfBitMap);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L7315C1-L7323C1
	NTSYSAPI VOID NTAPI RtlInitializeBitMapEx(
		_Out_ PRTL_BITMAP_EX BitMapHeader,
		_In_ PULONG64 BitMapBuffer,
		_In_ ULONG64 SizeOfBitMap);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI VOID NTAPI RtlInitializeConditionVariable(
		_Out_ PRTL_CONDITION_VARIABLE ConditionVariable);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI VOID NTAPI RtlInitializeContext(
		_In_ HANDLE Process,
		_Out_ PCONTEXT Context,
		_In_opt_ PVOID Parameter,
		_In_opt_ PVOID InitialPc,
		_In_opt_ PVOID InitialSp);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlinitializecorrelationvector
	NTSYSAPI NTSTATUS RtlInitializeCorrelationVector(
		[in, out] PCORRELATION_VECTOR CorrelationVector,
		[in]      int                 Version,
		[in]      const GUID* Guid);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI NTSTATUS NTAPI RtlInitializeCriticalSection(
		_Out_ PRTL_CRITICAL_SECTION CriticalSection);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI NTSTATUS NTAPI RtlInitializeCriticalSectionAndSpinCount(
		_Inout_ PRTL_CRITICAL_SECTION CriticalSection,
		_In_ ULONG SpinCount);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L997C1-L1005C1
	NTSYSAPI NTSTATUS NTAPI RtlInitializeCriticalSectionEx(
		_Out_ PRTL_CRITICAL_SECTION CriticalSection,
		_In_ ULONG SpinCount,
		_In_ ULONG Flags);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L3512C1-L3520C1
	NTSYSAPI NTSTATUS NTAPI RtlInitializeExtendedContext(
		_Out_ PCONTEXT Context,
		_In_ ULONG ContextFlags,
		_Out_ PCONTEXT_EX* ContextEx);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L3521C1-L3530C1
	NTSYSAPI NTSTATUS NTAPI RtlInitializeExtendedContext2(
		_Out_ PCONTEXT Context,
		_In_ ULONG ContextFlags,
		_Out_ PCONTEXT_EX* ContextEx,
		_In_ ULONG64 EnabledExtendedFeatures); // RtlGetEnabledExtendedFeatures(-1)

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	NTSTATUS WINAPI RtlInitializeNtUserPfn(const void* client_procsA, ULONG procsA_size,
		const void* client_procsW, ULONG procsW_size,
		const void* client_workers, ULONG workers_size);

//RtlInitializeRXact
	
	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI VOID NTAPI RtlInitializeResource(
		_Out_ PRTL_RESOURCE Resource);

	// https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-rtlinitializeslisthead
	NTSYSAPI VOID RtlInitializeSListHead(
		[in] PSLIST_HEADER ListHead);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI VOID NTAPI RtlInitializeSRWLock(
		_Out_ PRTL_SRWLOCK SRWLock);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI VOID NTAPI RtlInterlockedClearBitRun(
		_In_ PRTL_BITMAP BitMapHeader,
		_In_range_(0, BitMapHeader->SizeOfBitMap - NumberToClear) ULONG StartingIndex,
		_In_range_(0, BitMapHeader->SizeOfBitMap - StartingIndex) ULONG NumberToClear);

	//https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-rtlinterlockedflushslist
	NTSYSAPI PSLIST_ENTRY NTAPI RtlInterlockedFlushSList(
		[in] PSLIST_HEADER ListHead);

	// https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-rtlinterlockedpopentryslist
	NTSYSAPI PSLIST_ENTRY NTAPI RtlInterlockedPopEntrySList(
		[in] PSLIST_HEADER ListHead);

	// https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-rtlinterlockedpushentryslist
	NTSYSAPI PSLIST_ENTRY NTAPI RtlInterlockedPushEntrySList(
		[in] PSLIST_HEADER                 ListHead,
		[in] __drv_aliasesMem PSLIST_ENTRY ListEntry);
	
	// https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/sync.c
	NTSYSAPI PSLIST_ENTRY FASTCALL NTAPI RtlInterlockedPushListSList(
		_Inout_ PSLIST_HEADER SListHead,
		_Inout_ __drv_aliasesMem PSLIST_ENTRY List,
		_Inout_ PSLIST_ENTRY ListEnd,
		_In_ ULONG Count);
	
	// https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/sync.c
	NTSYSAPI PSLIST_ENTRY WINAPI RtlInterlockedPushListSListEx(
		PSLIST_HEADER list,
		PSLIST_ENTRY first,
		PSLIST_ENTRY last,
		ULONG count);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI VOID NTAPI RtlInterlockedSetBitRun(
		_In_ PRTL_BITMAP BitMapHeader,
		_In_range_(0, BitMapHeader->SizeOfBitMap - NumberToSet) ULONG StartingIndex,
		_In_range_(0, BitMapHeader->SizeOfBitMap - StartingIndex) ULONG NumberToSet);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtliodecodememioresource
	NTSYSAPI ULONGLONG RtlIoDecodeMemIoResource(
		[in]            PIO_RESOURCE_DESCRIPTOR Descriptor,
		[out, optional] PULONGLONG              Alignment,
		[out, optional] PULONGLONG              MinimumAddress,
		[out, optional] PULONGLONG              MaximumAddress);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlioencodememioresource
	NTSYSAPI NTSTATUS RtlIoEncodeMemIoResource(
		[in] PIO_RESOURCE_DESCRIPTOR Descriptor,
		[in] UCHAR                   Type,
		[in] ULONGLONG               Length,
		[in] ULONGLONG               Alignment,
		[in] ULONGLONG               MinimumAddress,
		[in] ULONGLONG               MaximumAddress);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI LOGICAL NTAPI RtlIsCriticalSectionLocked(
		_In_ PRTL_CRITICAL_SECTION CriticalSection);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI LOGICAL NTAPI RtlIsCriticalSectionLockedByThread(
		_In_ PRTL_CRITICAL_SECTION CriticalSection);

	// Reversed
	NTSYSAPI BOOL NTAPI RtlIsCurrentThread(
		_In_ HANDLE hThread);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L3403
	NTSYSAPI BOOLEAN NTAPI RtlIsCurrentThreadAttachExempt(VOID);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI ULONG NTAPI RtlIsDosDeviceName_U(
		_In_ PWSTR DosFileName);

	// Reversed
	// See also https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-kuser_shared_data
	NTSYSAPI BOOL NTAPI RtlIsMultiSessionSku(VOID);

	// https://codemachine.com/downloads/win10.1607/ntddk.h
	_IRQL_requires_max_(PASSIVE_LEVEL)
	_Must_inspect_result_ NTSYSAPI BOOLEAN NTAPI RtlIsMultiUsersInSessionSku(VOID);

	// https://microsoft.github.io/windows-docs-rs/doc/windows/Wdk/System/SystemServices/fn.RtlIsMultiSessionSku.html
	NTSYSAPI BOOL NTAPI RtlIsMultiSessionSku(VOID);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L10160
	NTSYSAPI BOOLEAN NTAPI RtlIsParentOfChildAppContainer(
		_In_ PSID ParentAppContainerSid,
		_In_ PSID ChildAppContainerSid);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlispartialplaceholder
	NTSYSAPI BOOLEAN RtlIsPartialPlaceholder(
		[in] ULONG FileAttributes,
		[in] ULONG ReparseTag);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI BOOLEAN NTAPI RtlIsThreadWithinLoaderCallout(VOID);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlisstateseparationenabled
	NTSYSAPI BOOLEAN RtlIsStateSeparationEnabled();

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html#ad6df589c370b58b02583177842bb98ea
	NTSYSAPI BOOLEAN NTAPI RtlIsThreadWithinLoaderCallout(VOID);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI BOOLEAN NTAPI RtlIsValidHandle(
		_In_ PRTL_HANDLE_TABLE HandleTable,
		_In_ PRTL_HANDLE_TABLE_ENTRY Handle);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI BOOLEAN NTAPI RtlIsValidIndexHandle(
		_In_ PRTL_HANDLE_TABLE HandleTable,
		_In_ ULONG HandleIndex,
		_Out_ PRTL_HANDLE_TABLE_ENTRY* Handle);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI BOOLEAN NTAPI RtlIsValidLocaleName(
		_In_ PWSTR LocaleName,
		_In_ ULONG Flags);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI BOOLEAN NTAPI RtlLCIDToCultureName(
		_In_ LCID Lcid,
		_Inout_ PUNICODE_STRING String);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI NTSTATUS NTAPI RtlLcidToLocaleName(
		_In_ LCID lcid,
		_Inout_ PUNICODE_STRING LocaleName,
		_In_ ULONG Flags,
		_In_ BOOLEAN AllocateDestinationString);
	
	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI NTSTATUS NTAPI RtlLeaveCriticalSection(
		_Inout_ PRTL_CRITICAL_SECTION CriticalSection);
		
	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI NTSTATUS NTAPI RtlLocaleNameToLcid(
		_In_ PWSTR LocaleName,
		_Out_ PLCID lcid,
		_In_ ULONG Flags);

	// https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/exception.c
	NTSYSAPI PVOID NTAPI RtlLocateExtendedFeature(
		PCONTEXT_EX context_ex,
		ULONG feature_id,
		PULONG length);

	// https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/exception.c
	NTSYSAPI PVOID NTAPI RtlLocateExtendedFeature2(
		PCONTEXT_EX context_ex,
		ULONG feature_id,
		PXSTATE_CONFIGURATION xstate_config,
		ULONG* length);

	// https://windows-internals.com/cet-on-windows/
	NTSYSAPI PCONTEXT NTAPI RtlLocateLegacyContext(
		_In_ PCONTEXT_EX ContextEx,
		_Out_opt_ PULONG Length);

	// https://doxygen.reactos.org/de/d93/sdk_2lib_2rtl_2bootdata_8c.html
	NTSYSAPI NTSTATUS NTAPI RtlLockBootStatusData(
		_Out_ PHANDLE FileHandle);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI NTSTATUS NTAPI RtlLockCurrentThread(VOID);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI NTSTATUS NTAPI RtlLockModuleSection(
		_In_ PVOID Address);

	// https://github.com/mic101/windows/blob/master/WRK-v1.2/base/ntos/rtl/stktrace.c
	NTSYSAPI USHORT NTAPI RtlLogStackBackTrace(VOID);

	// https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-rtllookupfunctionentry
	NTSYSAPI PRUNTIME_FUNCTION RtlLookupFunctionEntry(
		[in]  DWORD64               ControlPc,
		[out] PDWORD64              ImageBase,
		[out] PUNWIND_HISTORY_TABLE HistoryTable);

	// https://doxygen.reactos.org/de/ddc/sdk_2lib_2rtl_2error_8c.html
	NTSYSAPI NTSTATUS NTAPI RtlMapSecurityErrorToNtStatus(
		IN ULONG SecurityError);

	// https://github.com/thebookisclosed/ViVe/blob/master/ViVe/NativeMethods.Ntdll.cs#L99
	NTSYSAPI NTSTATUS NTAPI RtlNotifyFeatureUsage(
		_Inout_ RTL_FEATURE_USAGE_REPORT report);

	// https://doxygen.reactos.org/d3/d5a/RtlNtPathNameToDosPathName_8c_source.html
	NTSYSAPI NTSTATUS NTAPI RtlNtPathNameToDosPathName(
		ULONG Flags,
		PRTL_UNICODE_STRING_BUFFER Path,
		PULONG Type,
		PULONG Unknown4);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlntstatustodoserror
	// See winternl.h
	NTSYSAPI ULONG NTAPI RtlNtStatusToDosError(
		[in] NTSTATUS Status);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlntstatustodoserrornoteb
	NTSYSAPI ULONG RtlNtStatusToDosErrorNoTeb(
		[in] NTSTATUS Status);

	// Reversed
	NTSYSAPI PCWSTR RtlNtdllName;

	// https://doxygen.reactos.org/db/d90/sdk_2lib_2rtl_2bitmap_8c.html
	NTSYSAPI BITMAP_INDEX NTAPI RtlNumberOfClearBits(
		_In_ PRTL_BITMAP BitMapHeader);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlnumberofclearbits
	NTSYSAPI ULONG RtlNumberOfClearBits(
		[in] PRTL_BITMAP BitMapHeader);

	//RtlNumberOfClearBitsInRange
	NTSYSAPI UINT NTAPI RtlNumberOfClearBitsInRange(
		PRTL_BITMAP bitmapheader,
		UINT startingindex,
		UINT length);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlnumberofsetbits
	NTSYSAPI ULONG RtlNumberOfSetBits(
		[in] PRTL_BITMAP BitMapHeader);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlnumberofsetbits
	NTSYSAPI ULONG NTAPI RtlNumberOfSetBits(
		[in] PRTL_BITMAP BitMapHeader);

	// Reversed. Based on call from RtlNumberOfClearBitsInRange
	NTSYSAPI UINT NTAPI RtlNumberOfSetBitsInRange(
		_In_ PRTL_BITMAP BitMapHeader);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlnumberofsetbitsulongptr
	NTSYSAPI ULONG RtlNumberOfSetBitsUlongPtr(
		[in] ULONG_PTR Target);

	// https://doxygen.reactos.org/d5/dc9/sdk_2lib_2rtl_2registry_8c.html
	NTSYSAPI NTSTATUS NTAPI RtlOpenCurrentUser(
		IN ACCESS_MASK DesiredAccess,
		OUT PHANDLE KeyHandle);

	//RtlOsDeploymentState
	NTSYSAPI OS_DEPLOYEMENT_STATE_VALUES NTAPI RtlOsDeploymentState(
		_In_ ULONG 	Flags);

	// https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/thread.c
	NTSYSAPI void WINAPI RtlPopFrame(
		PTEB_ACTIVE_FRAME frame);

	// https://ntquery.wordpress.com/2014/03/29/anti-debug-fiber-local-storage-fls/#more-18
	NTSYSCALLAPI NTSTATUS NTAPI RtlProcessFlsData(
		PRTL_UNKNOWN_FLS_DATA Buffer);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L11330C1-L11339C7
	NTSYSAPI NTSTATUS NTAPI RtlPublishWnfStateData(
		_In_ WNF_STATE_NAME StateName,
		_In_opt_ PCWNF_TYPE_ID TypeId,
		_In_reads_bytes_opt_(Length) const VOID* Buffer,
		_In_opt_ ULONG Length,
		_In_opt_ const VOID* ExplicitScope);

	// https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/thread.c
	NTSYSAPI VOID WINAPI RtlPushFrame(TEB_ACTIVE_FRAME* frame);

	// https://docs.rs/phnt/latest/phnt/ffi/fn.RtlPublishWnfStateData.html
	NTSYSAPI NTSTATUS NTAPI RtlPublishWnfStateData(
		WNF_STATE_NAME StateName,
		PCWNF_TYPE_ID TypeId,
		_In_ PBYTE Buffer,
		_In_ ULONG Length,
		PBYTE ExplicitScope);

	//RtlQueryCriticalSectionOwner
	NTSYSAPI HANDLE NTAPI RtlQueryCriticalSectionOwner(
		_In_ HANDLE EventHandle);

	// https://learn.microsoft.com/fr-fr/windows/win32/api/winnt/nf-winnt-rtlquerydepthslist
	NTSYSAPI WORD RtlQueryDepthSList(
		[in] PSLIST_HEADER ListHead);
	
	// https://undoc.airesoft.co.uk/ntdll.dll/RtlQueryElevationFlags.php
	NTSYSAPI NTSTATUS NTAPI RtlQueryElevationFlags(
		PDWORD pFlags);

	// Reversed. Based on invocation of RtlQueryEnvironmentVariable_U
	NTSYSAPI NTSTATUS NTAPI RtlQueryEnvironmentVariable(
		PWSTR Environment,
		PWSTR Name,
		UINT NameLength,
		PWSTR Value);

	// https://docs.rs/ntapi/latest/ntapi/ntrtl/fn.RtlQueryEnvironmentVariable_U.html
	NTSYSAPI NTSTSATUS NTAPI RtlQueryEnvironmentVariable_U(
		PVOID Environment,
		PUNICODE_STRING Name,
		PUNICODE_STRING Value);

	// https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntrtl.h
	NTSYSAPI NTSTATUS NTAPI RtlQueryFeatureConfiguration(
		_In_ RTL_FEATURE_ID FeatureId,
		_In_ RTL_FEATURE_CONFIGURATION_TYPE ConfigurationType,
		_Out_ PRTL_FEATURE_CHANGE_STAMP ChangeStamp,
		_Out_ PRTL_FEATURE_CONFIGURATION FeatureConfiguration);

	// https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntrtl.h
	NTSYSAPI RTL_FEATURE_CHANGE_STAMP NTAPI RtlQueryFeatureConfigurationChangeStamp(VOID);

	// https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntrtl.h
	NTSYSAPI NTSTATUS NTAPI RtlQueryFeatureUsageNotificationSubscriptions(
		_Out_writes_(*SubscriptionCount) PRTL_FEATURE_USAGE_SUBSCRIPTION_DETAILS Subscriptions,
		_Inout_ PSIZE_T SubscriptionCount);

	// https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntrtl.h
	NTSYSAPI NTSTATUS NTAPI RtlQueryImageMitigationPolicy(
		_In_opt_ PCWSTR ImagePath, // NULL for system-wide defaults
		_In_ IMAGE_MITIGATION_POLICY Policy,
		_In_ ULONG Flags,
		_Inout_ PVOID Buffer,
		_In_ ULONG BufferSize);

	// https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntrtl.h
	NTSYSAPI NTSTATUS NTAPI RtlQueryInformationActiveActivationContext(
		_In_ ACTIVATION_CONTEXT_INFO_CLASS ActivationContextInformationClass,
		_Out_writes_bytes_(ActivationContextInformationLength) PVOID ActivationContextInformation,
		_In_ SIZE_T ActivationContextInformationLength,
		_Out_opt_ PSIZE_T ReturnLength);

	// https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/rtl/ldrreloc/querymoduleinformation.htm
	NTSYSAPI NTSTATUS NTAPI RtlQueryModuleInformation(
		PULONG InformationLength,
		ULONG SizePerModule,
		PVOID InformationBuffer);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L10487
	NTSYSAPI NTSTATUS NTAPI RtlQueryPackageClaims(
		_In_ HANDLE TokenHandle,
		_Out_writes_bytes_to_opt_(*PackageSize, *PackageSize) PWSTR PackageFullName,
		_Inout_opt_ PSIZE_T PackageSize,
		_Out_writes_bytes_to_opt_(*AppIdSize, *AppIdSize) PWSTR AppId,
		_Inout_opt_ PSIZE_T AppIdSize,
		_Out_opt_ PGUID DynamicId,
		_Out_opt_ PPS_PKG_CLAIM PkgClaim,
		_Out_opt_ PULONG64 AttributesPresent);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlquerypackageidentity
	NTSYSAPI NTSTATUS RtlQueryPackageIdentity(
		PVOID    TokenObject,
		PWSTR    PackageFullName,
		PSIZE_T  PackageSize,
		PWSTR    AppId,
		PSIZE_T  AppIdSize,
		PBOOLEAN Packaged);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlquerypackageidentityex
	NTSYSAPI NTSTATUS RtlQueryPackageIdentityEx(
		PVOID    TokenObject,
		PWSTR    PackageFullName,
		PSIZE_T  PackageSize,
		PWSTR    AppId,
		PSIZE_T  AppIdSize,
		LPGUID   DynamicId,
		PULONG64 Flags);

	// https://learn.microsoft.com/en-us/windows/win32/api/profileapi/nf-profileapi-queryperformancecounter
	NTSYSAPI BOOL NTAPI RtlQueryPerformanceCounter(
		[out] PLARGE_INTEGER lpPerformanceCount);

	// https://learn.microsoft.com/en-us/windows/win32/api/profileapi/nf-profileapi-queryperformancefrequency
	NTSYSAPI BOOL NTAPI QueryPerformanceFrequency(
		[out] PLARGE_INTEGER lpFrequency);

	// https://github.com/winsiderss/phnt/blob/48759c9b5916a359df706789f71053e49b528a18/ntrtl.h#L10535C1-L10542C1
	NTSYSAPI NTSTATUS NTAPI RtlQueryProtectedPolicy(
		_In_ PGUID PolicyGuid,
		_Out_ PULONG_PTR PolicyValue);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlqueryregistryvaluewithfallback
	NTSYSAPI NTSTATUS RtlQueryRegistryValueWithFallback(
		[in]  HANDLE          PrimaryHandle,
		[in]  HANDLE          FallbackHandle,
		[in]  PUNICODE_STRING ValueName,
		[in]  ULONG           ValueLength,
		[Out] PULONG          ValueType,
		[out] PVOID           ValueData,
		[out] PULONG          ResultLength);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues
	NTSYSAPI NTSTATUS RtlQueryRegistryValues(
		[in]           ULONG                     RelativeTo,
		[in]           PCWSTR                    Path,
		[in, out]      PRTL_QUERY_REGISTRY_TABLE QueryTable,
		[in, optional] PVOID                     Context,
		[in, optional] PVOID                     Environment);

	//RtlQueryRegistryValuesEx
	NTSYSAPI NTSTATUS NTAPI RtlQueryRegistryValuesEx(
			_In_ ULONG RelativeTo,
			_In_ PCWSTR Path,
			_Inout_ _At_(*(*QueryTable).EntryContext, _Pre_unknown_) PRTL_QUERY_REGISTRY_TABLE QueryTable,
			_In_opt_ PVOID Context,
			_In_opt_ PVOID Environment);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlquerythreadplaceholdercompatibilitymode
	NTSYSAPI CHAR RtlQueryThreadPlaceholderCompatibilityMode();

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI NTSTATUS NTAPI RtlQueryThreadProfiling(
		_In_ HANDLE ThreadHandle,
		_Out_ PBOOLEAN Enabled);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L10149
	NTSYSAPI NTSTATUS NTAPI RtlQueryTokenHostIdAsUlong64(
		_In_ HANDLE TokenHandle,
		_Out_ PULONG64 HostId); // (WIN://PKGHOSTID)

	// https://learn.microsoft.com/fr-fr/windows/win32/api/winbase/nf-winbase-queryumsthreadinformation
	// https://www.geoffchappell.com/studies/windows/win32/kernel32/history/names61.htm
    // Based on reversing Kernel32::QueryUmsThreadInformation
	NTSYSAPI BOOL NTAPI RtlQueryUmsThreadInformation(
		PUMS_CONTEXT UmsThread,
		UMS_THREAD_INFO_CLASS UmsThreadInfoClass,
		PVOID UmsThreadInformation,
		ULONG UmsThreadInformationLength,
		PULONG ReturnLength);

	// https://gist.github.com/msmania/472912cd6e9ab067be3211ba3f5f0f9e
	typedef NTSTATUS* (NTAPI pWnfCallback)(
		uint64_t p1,
		void* p2,
		void* p3,
		void* p4,
		void* p5,
		void* p6);
	NTSYSAPI NTSTATUS NTAPI RtlQueryWnfStateData(
		uint32_t*,
		uint64_t,
		pWnfCallback,
		size_t,
		size_t);

	// https://doxygen.reactos.org/d3/dcd/sdk_2lib_2rtl_2amd64_2stubs_8c.html
	NTSYSAPI NTSTATUS NTAPI RtlQueueApcWow64Thread(
		_In_ HANDLE ThreadHandle,
		_In_ PKNORMAL_ROUTINE ApcRoutine,
		_In_opt_ PVOID NormalContext,
		_In_opt_ PVOID SystemArgument1,
		_In_opt_ PVOID SystemArgument2);

	// https://source.winehq.org/WineAPI/RtlQueueWorkItem.html
	NTSYSAPI NTSTATUS NTAPI RtlQueueWorkItem (
		PRTL_WORK_ITEM_ROUTINE function,
		PVOID                  context,
		ULONG                  flags);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlraisecustomsystemeventtrigger
	NTSYSAPI NTSTATUS RtlRaiseCustomSystemEventTrigger(
		[_In_] PCUSTOM_SYSTEM_EVENT_TRIGGER_CONFIG TriggerConfig);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlrandom
	NTSYSAPI ULONG RtlRandom(
		[in, out] PULONG Seed);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlrandomex
	NTSYSAPI ULONG RtlRandomEx(
		[in, out] PULONG Seed);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI NTSTATUS NTAPI RtlReadThreadProfilingData(
		_In_ HANDLE PerformanceDataHandle,
		_In_ ULONG Flags,
		_Out_ PPERFORMANCE_DATA PerformanceData);

	// https://github.com/winsiderss/systeminformer/blob/bc71c2c1962be178e13cd0f84f63348f468a0701/phnt/include/ntrtl.h#L11233C1-L11242C1
	NTSYSAPI NTSTATUS NTAPI RtlRegisterFeatureConfigurationChangeNotification(
		_In_ PRTL_FEATURE_CONFIGURATION_CHANGE_CALLBACK Callback,
		_In_opt_ PVOID Context,
		_In_opt_ PRTL_FEATURE_CHANGE_STAMP ObservedChangeStamp,
		_Out_ PRTL_FEATURE_CONFIGURATION_CHANGE_REGISTRATION RegistrationHandle);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html#a3971f6c4d689c54c8b8f8b9a7d3a51f9
	NTSYSAPI NTSTATUS NTAPI RtlRegisterThreadWithCsrss(VOID);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html#a3971f6c4d689c54c8b8f8b9a7d3a51f9
	NTSYSAPI NTSTATUS NTAPI RtlRegisterWait(
		_Out_ PHANDLE 	WaitHandle,
		_In_ HANDLE 	Handle,
		_In_ WAITORTIMERCALLBACKFUNC 	Function,
		_In_ PVOID 	Context,
		_In_ ULONG 	Milliseconds,
		_In_ ULONG 	Flags);

	// https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/loader.c
	NTSYSAPI VOID WINAPI RtlReleasePath(
		_In_ PWSTR path);

	// https://github.com/reactos/reactos/blob/master/sdk/include/ndk/rtlfuncs.h#L2819
	NTSYSAPI VOID NTAPI RtlReleasePebLock(VOID);

	// https://github.com/reactos/reactos/blob/master/sdk/include/ndk/rtlfuncs.h#L2819
	NTSYSAPI VOID NTAPI RtlReleaseRelativeName(
		_In_ PRTL_RELATIVE_NAME_U RelativeName);

	// https://doxygen.reactos.org/de/df0/sdk_2lib_2rtl_2resource_8c.html
	NTSYSAPI VOID NTAPI RtlReleaseResource(
		PRTL_RESOURCE Resource);

	// https://github.com/reactos/reactos/blob/master/sdk/include/ndk/rtlfuncs.h#L2819
	NTSYSAPI VOID NTAPI RtlReleaseSRWLockExclusive(
		IN OUT PRTL_SRWLOCK SRWLock);

	// https://github.com/reactos/reactos/blob/master/sdk/include/ndk/rtlfuncs.h#L2819
	NTSYSAPI VOID NTAPI RtlReleaseSRWLockShared(
		IN OUT PRTL_SRWLOCK SRWLock);

	// https://www.alex-ionescu.com/rtlremotecall/
	NTSYSAPI NTSTATUS NTAPI RtlRemoteCall(
		IN HANDLE Process,
		IN HANDLE Thread,
		IN PVOID CallSite,
		IN ULONG ArgumentCount,
		IN PULONG Arguments,
		IN BOOLEAN PassContext,
		IN BOOLEAN AlreadySuspended);

	// https://github.com/winsiderss/phnt/blob/master/ntrtl.h
	NTSYSAPI ULONG NTAPI RtlReplaceSystemDirectoryInPath(
		_Inout_ PUNICODE_STRING Destination,
		_In_ USHORT Machine, // IMAGE_FILE_MACHINE_I386
		_In_ USHORT TargetMachine, // IMAGE_FILE_MACHINE_TARGET_HOST
		_In_ BOOLEAN IncludePathSeperator);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	NTSYSAPI NTSTATUS WINAPI RtlResetNtUserPfn(void);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI VOID NTAPI RtlResetRtlTranslations(
		_In_ PNLSTABLEINFO TableInfo);

	// https://github.com/winsiderss/phnt/blob/master/ntrtl.h
	NTSYSAPI NTSTATUS NTAPI RtlRestoreBootStatusDefaults(
		_In_ HANDLE FileHandle);

	// https://github.com/winsiderss/phnt/blob/master/ntrtl.h
	NTSYSAPI VOID NTAPI RtlRestoreContext(
		_In_ PCONTEXT ContextRecord,
		_In_opt_ struct _EXCEPTION_RECORD* ExceptionRecord);

	// https://github.com/winsiderss/phnt/blob/master/ntrtl.h
	NTSYSAPI VOID NTAPI RtlRestoreLastWin32Error(
		_In_ LONG Win32Error);

	// https://github.com/winsiderss/phnt/blob/master/ntrtl.h
	NTSYSAPI NTSTATUS NTAPI RtlRestoreSystemBootStatusDefaults(VOID);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	NTSYSAPI NTSTATUS WINAPI RtlRetrieveNtUserPfn(const void** client_procsA,
		const void** client_procsW,
		const void** client_workers);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlrunoncebegininitialize
	NTSYSAPI NTSTATUS RtlRunOnceBeginInitialize(
		[in, out] PRTL_RUN_ONCE RunOnce,
		[in]      ULONG         Flags,
		[out]     PVOID* Context);

	// http://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlrunoncecomplete
	NTSYSAPI NTSTATUS RtlRunOnceComplete(
		[in, out]      PRTL_RUN_ONCE RunOnce,
		[in]           ULONG         Flags,
		[in, optional] PVOID         Context);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlrunonceexecuteonce
	NTSYSAPI NTSTATUS RtlRunOnceExecuteOnce(
		PRTL_RUN_ONCE         RunOnce,
		PRTL_RUN_ONCE_INIT_FN InitFn,
		PVOID                 Parameter,
		PVOID* Context);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlrunonceinitialize
	NTSYSAPI VOID RtlRunOnceInitialize(
		[out] PRTL_RUN_ONCE RunOnce);

	// https://github.com/xmoezzz/NativeLib-R/blob/master/ntsmss.h
	NTSYSAPI NTSTATUS NTAPI RtlSendMsgToSm(
		_In_ HANDLE ApiPortHandle,
		_In_ PPORT_MESSAGE MessageData);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlsetallbits
	NTSYSAPI VOID RtlSetAllBits(
		[in] PRTL_BITMAP BitMapHeader);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlsetbit
	NTSYSAPI VOID RtlSetBit(
		[in] PRTL_BITMAP BitMapHeader,
		[in] ULONG       BitNumber);

	// https://github.com/winsiderss/phnt/blob/master/ntrtl.h
	NTSYSAPI VOID NTAPI RtlSetBitEx(
		_In_ PRTL_BITMAP_EX BitMapHeader,
		_In_range_(< , BitMapHeader->SizeOfBitMap) ULONG64 BitNumber);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlsetbits
	NTSYSAPI VOID RtlSetBits(
		[in] PRTL_BITMAP BitMapHeader,
		[in] ULONG       StartingIndex,
		[in] ULONG       NumberToSet);

	// https://github.com/winsiderss/phnt/blob/master/ntrtl.h
	NTSYSAPI ULONG NTAPI RtlSetCriticalSectionSpinCount(
		_Inout_ PRTL_CRITICAL_SECTION CriticalSection,
		_In_ ULONG SpinCount);

	// https://github.com/winsiderss/phnt/blob/master/ntrtl.h
	NTSYSAPI NTSTATUS NTAPI RtlSetCurrentDirectory_U(
		_In_ PUNICODE_STRING PathName);

	// https://github.com/winsiderss/phnt/blob/master/ntrtl.h
	NTSYSAPI NTSTATUS NTAPI RtlSetCurrentEnvironment(
		_In_ PVOID Environment,
		_Out_opt_ PVOID* PreviousEnvironment);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	BOOL WINAPI RtlSetCurrentTransaction(HANDLE new_transaction);

	// https://github.com/winsiderss/phnt/blob/master/ntrtl.h
	NTSYSAPI NTSTATUS NTAPI RtlSetEnvironmentStrings(
		_In_ PCWSTR NewEnvironment,
		_In_ SIZE_T NewEnvironmentSize);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L4385
	NTSYSAPI NTSTATUS NTAPI RtlSetEnvironmentVar(
		_Inout_opt_ PVOID* Environment,
		_In_reads_(NameLength) PCWSTR Name,
		_In_ SIZE_T NameLength,
		_In_reads_(ValueLength) PCWSTR Value,
		_In_opt_ SIZE_T ValueLength);

	// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FEnvironment%2FRtlSetEnvironmentVariable.html
	NTSYSAPI NTSTATUS NTAPI RtlSetEnvironmentVariable(
		IN OUT PVOID* Environment OPTIONAL,
		IN PUNICODE_STRING      VariableName,
		IN PUNICODE_STRING      VariableValue);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L3590C1-L3596C7
	NTSYSAPI VOID NTAPI RtlSetExtendedFeaturesMask(
		_In_ PCONTEXT_EX ContextEx,
		_In_ ULONG64 FeatureMask);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L11118C1-L11126C7
	NTSYSAPI NTSTATUS NTAPI RtlSetFeatureConfigurations(
		_In_opt_ PRTL_FEATURE_CHANGE_STAMP PreviousChangeStamp,
		_In_ RTL_FEATURE_CONFIGURATION_TYPE ConfigurationType,
		_In_reads_(ConfigurationUpdateCount) PRTL_FEATURE_CONFIGURATION_UPDATE ConfigurationUpdates,
		_In_ SIZE_T ConfigurationUpdateCount);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L9951C1-L9961C1
	NTSYSAPI NTSTATUS NTAPI RtlSetImageMitigationPolicy(
		_In_opt_ PCWSTR ImagePath, // NULL for system-wide defaults
		_In_ IMAGE_MITIGATION_POLICY Policy,
		_In_ ULONG Flags,
		_Inout_ PVOID Buffer,
		_In_ ULONG BufferSize);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L8932C1-L8939C7
	NTSYSAPI NTSTATUS NTAPI RtlSetIoCompletionCallback(
		_In_ HANDLE FileHandle,
		_In_ APC_CALLBACK_FUNCTION CompletionProc,
		_In_ ULONG Flags);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L6488C1-L6493C7
	NTSYSAPI VOID NTAPI RtlSetLastWin32Error(
		_In_ LONG Win32Error);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L6481C1-L6486C7
	NTSYSAPI VOID NTAPI RtlSetLastWin32ErrorAndNtStatusFromNtStatus(
		_In_ NTSTATUS Status);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L10779C1-L10784C7
	NTSYSAPI NTSTATUS NTAPI RtlSetPortableOperatingSystem(
		_In_ BOOLEAN IsPortable);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L10544C1-L10551C7
	NTSYSAPI NTSTATUS NTAPI RtlSetProtectedPolicy(
		_In_ PGUID PolicyGuid,
		_In_ ULONG_PTR PolicyValue,
		_Out_ PULONG_PTR OldPolicyValue);

	// https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/loader.c
	NTSYSAPI NTSTATUS NTAPI RtlSetSearchPathMode(
		ULONG flags);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L10758C1-L10766C7
	NTSYSAPI NTSTATUS NTAPI RtlSetSystemBootStatus(
		_In_ RTL_BSD_ITEM_TYPE BootStatusInformationClass,
		_In_ PVOID DataBuffer,
		_In_ ULONG DataLength,
		_Out_opt_ PULONG ReturnLength);

//RtlSetSystemBootStatusEx

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L6513C1-L6519C7
	NTSYSAPI NTSTATUS NTAPI RtlSetThreadErrorMode(
		_In_ ULONG NewMode,
		_Out_opt_ PULONG OldMode);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L3316C1-L3323C7
	NTSYSAPI NTSTATUS STDAPIVCALLTYPE RtlSetThreadIsCritical(
		_In_ BOOLEAN NewValue,
		_Out_opt_ PBOOLEAN OldValue,
		_In_ BOOLEAN CheckFlag);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlsetthreadplaceholdercompatibilitymode
	NTSYSAPI CHAR RtlSetThreadPlaceholderCompatibilityMode(
		_In_ CHAR Mode);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L8955C1-L8961C7
	NTSYSAPI NTSTATUS NTAPI RtlSetThreadPoolStartFunc(
		_In_ PRTL_START_POOL_THREAD StartPoolThread,
		_In_ PRTL_EXIT_POOL_THREAD ExitPoolThread);

//RtlSetThreadPreferredUILanguages
//RtlSetThreadPreferredUILanguages2
	
	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L3326C1-L3331C7
	NTSYSAPI PVOID NTAPI RtlSetThreadSubProcessTag(
		_In_ PVOID SubProcessTag);

//RtlSetThreadWorkOnBehalfTicket
//RtlSetUmsThreadInformation

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L1326C1-L1333C7
	NTSYSAPI NTSTATUS NTAPI RtlSleepConditionVariableCS(
		_Inout_ PRTL_CONDITION_VARIABLE ConditionVariable,
		_Inout_ PRTL_CRITICAL_SECTION CriticalSection,
		_In_opt_ PLARGE_INTEGER Timeout);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L1326C1-L1333C7
	NTSYSAPI NTSTATUS NTAPI RtlSleepConditionVariableSRW(
		_Inout_ PRTL_CONDITION_VARIABLE ConditionVariable,
		_Inout_ PRTL_SRWLOCK SRWLock,
		_In_opt_ PLARGE_INTEGER Timeout,
		_In_ ULONG Flags);

//RtlStartRXact
	
	// https://github.com/winsiderss/systeminformer/blob/bc71c2c1962be178e13cd0f84f63348f468a0701/phnt/include/ntrtl.h#L11252C1-L11258C7
	NTSYSAPI NTSTATUS NTAPI RtlSubscribeForFeatureUsageNotification(
		_In_reads_(SubscriptionCount) PRTL_FEATURE_USAGE_SUBSCRIPTION_DETAILS SubscriptionDetails,
		_In_ SIZE_T SubscriptionCount);

	// https://gist.github.com/msmania/472912cd6e9ab067be3211ba3f5f0f9e
	NTSYSAPI NTSTATUS NTAPI RtlSubscribeWnfStateChangeNotification(
		void*,
		uint64_t,
		uint32_t,
		pWnfCallback,
		size_t,
		size_t,
		size_t,
		size_t);

//RtlSwitchedVVI
//RtlTestAndPublishWnfStateData

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtltestbit
	NTSYSAPI BOOLEAN RtlTestBit(
		[in] PRTL_BITMAP BitMapHeader,
		[in] ULONG       BitNumber);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L7325C1-L7332C7
	_Check_return_ NTSYSAPI BOOLEAN NTAPI RtlTestBitEx(
		_In_ PRTL_BITMAP_EX BitMapHeader,
		_In_range_(< , BitMapHeader->SizeOfBitMap) ULONG64 BitNumber);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L3342C1-L3348C7
	NTSYSAPI BOOLEAN NTAPI RtlTestProtectedAccess(
		_In_ PS_PROTECTION Source,
		_In_ PS_PROTECTION Target);

//RtlTraceDatabaseAdd
//RtlTraceDatabaseCreate
//RtlTraceDatabaseDestroy
//RtlTraceDatabaseEnumerate
//RtlTraceDatabaseFind
//RtlTraceDatabaseLock
//RtlTraceDatabaseUnlock
//RtlTraceDatabaseValidate

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L2952C1-L2957C7
	NTSYSAPI LOGICAL NTAPI RtlTryAcquirePebLock(VOID);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L1227C1-L1233C7
	_When_(return != 0, _Acquires_exclusive_lock_(*SRWLock)) NTSYSAPI BOOLEAN NTAPI
		RtlTryAcquireSRWLockExclusive(
			_Inout_ PRTL_SRWLOCK SRWLock);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L1236C1-L1242C7
	_When_(return != 0, _Acquires_shared_lock_(*SRWLock)) NTSYSAPI BOOLEAN NTAPI
		RtlTryAcquireSRWLockShared(
			_Inout_ PRTL_SRWLOCK SRWLock);

//RtlTryConvertSRWLockSharedToExclusiveOrRelease

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L1029C1-L1035C7
	_When_(return != 0, _Acquires_exclusive_lock_(*CriticalSection)) NTSYSAPI LOGICAL NTAPI
		RtlTryEnterCriticalSection(
			_Inout_ PRTL_CRITICAL_SECTION CriticalSection);

//RtlUdiv128
//RtlUmsThreadYield

	// https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-rtluniform
	// See winterl.h
	NTSYSAPI ULONG NTAPI RtlUniform(
		_Inout_ PULONG Seed);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L10698C1-L10703C7
	NTSYSAPI NTSTATUS NTAPI RtlUnlockBootStatusData(
		_In_ HANDLE FileHandle);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI NTSTATUS NTAPI RtlUnlockCurrentThread(VOID);

	// https://processhacker.sourceforge.io/doc/ntrtl_8h.html
	NTSYSAPI NTSTATUS NTAPI RtlUnlockModuleSection(
		_In_ PVOID Address);

	// https://github.com/winsiderss/systeminformer/blob/bc71c2c1962be178e13cd0f84f63348f468a0701/phnt/include/ntrtl.h#L11244C1-L11249C7
	NTSYSAPI NTSTATUS NTAPI RtlUnregisterFeatureConfigurationChangeNotification(
		_In_ RTL_FEATURE_CONFIGURATION_CHANGE_REGISTRATION RegistrationHandle);

	// https://github.com/winsiderss/systeminformer/blob/bc71c2c1962be178e13cd0f84f63348f468a0701/phnt/include/ntrtl.h#L11261C1-L11267C7
	NTSYSAPI NTSTATUS NTAPI RtlUnsubscribeFromFeatureUsageNotifications(
		_In_reads_(SubscriptionCount) PRTL_FEATURE_USAGE_SUBSCRIPTION_DETAILS SubscriptionDetails,
		_In_ SIZE_T SubscriptionCount);

//RtlUnsubscribeWnfNotificationWaitForCompletion
//RtlUnsubscribeWnfNotificationWithCompletionCallback

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L11355C1-L11360C7
	NTSYSAPI NTSTATUS NTAPI RtlUnsubscribeWnfStateChangeNotification(
		_In_ PWNF_USER_CALLBACK Callback);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L3258C1-L3264C1
	NTSYSAPI VOID NTAPI RtlUpdateClonedCriticalSection(
		_Inout_ PRTL_CRITICAL_SECTION CriticalSection);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L3266C1-L3273C1
	NTSYSAPI VOID NTAPI RtlUpdateClonedSRWLock(
		_Inout_ PRTL_SRWLOCK SRWLock,
		_In_ LOGICAL Shared); // TRUE to set to shared acquire

//RtlUserFiberStart
	
	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L8963C1-L8970C1
	NTSYSAPI VOID NTAPI RtlUserThreadStart(
		_In_ PTHREAD_START_ROUTINE Function,
		_In_ PVOID Parameter);

	//https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlvalidatecorrelationvector
	NTSYSAPI NTSTATUS RtlValidateCorrelationVector(
		PCORRELATION_VECTOR Vector);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlverifyversioninfo
	NTSYSAPI NTSTATUS RtlVerifyVersionInfo(
		[in] PRTL_OSVERSIONINFOEXW VersionInfo,
		[in] ULONG                 TypeMask,
		[in] ULONGLONG             ConditionMask);

//RtlVirtualUnwind
//RtlWaitForWnfMetaNotification
	
	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L1416C1-L1425C1
	NTSYSAPI NTSTATUS NTAPI RtlWaitOnAddress(
		_In_reads_bytes_(AddressSize) volatile VOID * Address,
		_In_reads_bytes_(AddressSize) PVOID CompareAddress,
		_In_ SIZE_T AddressSize,
		_In_opt_ PLARGE_INTEGER Timeout);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L1426C1-L1432C1
	NTSYSAPI VOID NTAPI RtlWakeAddressAll(
		_In_ PVOID Address);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L1433C1-L1439C1
	NTSYSAPI VOID NTAPI RtlWakeAddressAllNoFence(
		_In_ PVOID Address);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L1440C1-L1446C1
	NTSYSAPI VOID NTAPI RtlWakeAddressSingle(
		_In_ PVOID Address);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L1447C1-L1453C1
	NTSYSAPI VOID NTAPI RtlWakeAddressSingleNoFence(
		_In_ PVOID Address);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L1355C1-L1361C1
	NTSYSAPI VOID NTAPI RtlWakeAllConditionVariable(
		_Inout_ PRTL_CONDITION_VARIABLE ConditionVariable);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L1347
	// winbase:WakeConditionVariable
	NTSYSAPI VOID NTAPI RtlWakeConditionVariable(
		_Inout_ PRTL_CONDITION_VARIABLE ConditionVariable);

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L9421C1-L9429C1
	NTSYSAPI ULONG NTAPI RtlWalkFrameChain(
		_Out_writes_(Count - (Flags >> RTL_STACK_WALKING_MODE_FRAMES_TO_SKIP_SHIFT)) PVOID* Callers,
		_In_ ULONG Count,
		_In_ ULONG Flags);

//RtlWnfCompareChangeStamp

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L11362C1-L11368C1
	NTSYSAPI NTSTATUS NTAPI RtlWnfDllUnloadCallback(
		_In_ PVOID DllBase);

//RtlWow64CallFunction64

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/process.c
	NTSYSAPI NTSTATUS WINAPI RtlWow64EnableFsRedirection(BOOLEAN enable);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/process.c
	NTSYSAPI NTSTATUS WINAPI RtlWow64EnableFsRedirectionEx(ULONG disable, ULONG* old_value);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/process.c
	NTSYSAPI NTSTATUS WINAPI RtlWow64GetCpuAreaInfo(WOW64_CPURESERVED* cpu, ULONG reserved, WOW64_CPU_AREA_INFO* info);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/process.c
	NTSYSAPI NTSTATUS WINAPI RtlWow64GetCurrentCpuArea(USHORT* machine, void** context, void** context_ex);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/process.c
	NTSYSAPI USHORT WINAPI RtlWow64GetCurrentMachine(void);

//RtlWow64GetEquivalentMachineCHPE

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/process.c
	NTSYSAPI NTSTATUS WINAPI RtlWow64GetThreadContext(HANDLE handle, WOW64_CONTEXT* context);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/process.c
	NTSYSAPI NTSTATUS WINAPI RtlWow64GetThreadSelectorEntry(HANDLE handle, THREAD_DESCRIPTOR_INFORMATION* info,
		ULONG size, ULONG* retlen);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/process.c
	NTSYSAPI NTSTATUS WINAPI RtlWow64IsWowGuestMachineSupported(USHORT machine, BOOLEAN* supported);

//RtlWow64LogMessageInEventLogger

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/process.c
	NTSYSAPI CROSS_PROCESS_WORK_ENTRY* WINAPI RtlWow64PopAllCrossProcessWorkFromWorkList(CROSS_PROCESS_WORK_HDR* list, BOOLEAN* flush);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/process.c
	NTSYSAPI CROSS_PROCESS_WORK_ENTRY* WINAPI RtlWow64PopCrossProcessWorkFromFreeList(CROSS_PROCESS_WORK_HDR* list);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/process.c
	NTSYSAPI BOOLEAN WINAPI RtlWow64PushCrossProcessWorkOntoFreeList(CROSS_PROCESS_WORK_HDR* list, CROSS_PROCESS_WORK_ENTRY* entry);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/process.c
	NTSYSAPI BOOLEAN WINAPI RtlWow64PushCrossProcessWorkOntoWorkList(CROSS_PROCESS_WORK_HDR* list, CROSS_PROCESS_WORK_ENTRY* entry, void** unknown);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/process.c
	NTSYSAPI BOOLEAN WINAPI RtlWow64RequestCrossProcessHeavyFlush(CROSS_PROCESS_WORK_HDR* list);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/process.c
	NTSYSAPI NTSTATUS WINAPI RtlWow64SetThreadContext(HANDLE handle, const WOW64_CONTEXT* context);

//RtlWow64SuspendThread

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlwriteregistryvalue
	NTSYSAPI NTSTATUS RtlWriteRegistryValue(
		[in]           ULONG  RelativeTo,
		[in]           PCWSTR Path,
		[in]           PCWSTR ValueName,
		[in]           ULONG  ValueType,
		[in, optional] PVOID  ValueData,
		[in]           ULONG  ValueLength);

//RtlpApplyLengthFunction
//RtlpCleanupRegistryKeys
//RtlpConvertAbsoluteToRelativeSecurityAttribute
//RtlpConvertCultureNamesToLCIDs
//RtlpConvertLCIDsToCultureNames
//RtlpConvertRelativeToAbsoluteSecurityAttribute
//RtlpEnsureBufferSize
//RtlpExecuteUmsThread
//RtlpGetDeviceFamilyInfoEnum
//RtlpGetLCIDFromLangInfoNode
//RtlpGetNameFromLangInfoNode

	// https://github.com/winsiderss/systeminformer/blob/8ebcd34e13f623eff4d0edaf8550c5d7a0601180/phnt/include/ntrtl.h#L2882C1-L2889C1
	NTSYSAPI NTSTATUS NTAPI RtlpGetSystemDefaultUILanguage(
		_Out_ LANGID DefaultUILanguageId,
		_Inout_ PLCID Lcid);

//RtlpGetUserOrMachineUILanguage4NLS
//RtlpInitializeLangRegistryInfo
//RtlpIsQualifiedLanguage
//RtlpLoadMachineUIByPolicy
//RtlpLoadUserUIByPolicy
//RtlpMergeSecurityAttributeInformation
//RtlpMuiFreeLangRegistryInfo
//RtlpMuiRegCreateRegistryInfo
//RtlpMuiRegFreeRegistryInfo
//RtlpMuiRegLoadRegistryInfo
//RtlpNotOwnerCriticalSection
//RtlpNtCreateKey
//RtlpNtEnumerateSubKey
//RtlpNtMakeTemporaryKey
//RtlpNtOpenKey
//RtlpNtSetValueKey
//RtlpQueryDefaultUILanguage
//RtlpRefreshCachedUILanguage
//RtlpSetInstallLanguage
//RtlpSetPreferredUILanguages
//RtlpSetUserPreferredUILanguages
//RtlpUmsExecuteYieldThreadEnd
//RtlpUmsThreadYield
//RtlpUnWaitCriticalSection
//RtlpVerifyAndCommitUILanguageSettings

	// Reversed. Empty function always returning 0. Arguments unknown may not be VOID.
	NTSYSAPI NTSTATUS NTAPI RtlpWaitForCriticalSection(VOID);

//RtlpWow64CtxFromAmd64
//RtlpWow64GetContextOnAmd64
//RtlpWow64SetContextOnAmd64

	// https://undoc.airesoft.co.uk/ntdll.dll/SbExecuteProcedure.php
	NTSYSAPI PVOID WINAPI SbExecuteProcedure(
		ULONG signature,
		ULONG unk,
		const SWITCHBRANCH_SCENARIO_TABLE* pScenarioTable,
		ULONG scenarioIndex,
		PVOID pCtx);

	// https://undoc.airesoft.co.uk/ntdll.dll/SbSelectProcedure.php
	NTSYSAPI FARPROC WINAPI SbSelectProcedure(
		ULONG signature,
		ULONG unk,
		const SWITCHBRANCH_SCENARIO_TABLE* pScenarioTable,
		ULONG scenarioIndex);

//VerSetConditionMask
//WerReportSQMEvent

}

#endif
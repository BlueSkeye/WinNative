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

	//https://www.geoffchappell.com/studies/windows/win32/ntdll/api/csrutil/allocatecapturebuffer.htm
	NTSYSAPI PVOID WINAPI CsrAllocateCaptureBuffer(
		ULONG MaxMessagePointers,
		ULONG Size);

	//https://www.geoffchappell.com/studies/windows/win32/ntdll/api/csrutil/allocatemessagepointer.htm
	NTSYSAPI ULONG WINAPI CsrAllocateMessagePointer(
		PVOID CaptureBuffer,
		ULONG Size,
		PVOID* Pointer);

	//https://www.geoffchappell.com/studies/windows/win32/ntdll/api/csrutil/capturemessagebuffer.htm
	NTSYSAPI ULONG WINAPI CsrCaptureMessageBuffer(
		PVOID CaptureBuffer,
		PVOID Data,
		ULONG Size,
		PVOID* Pointer);

	//CsrCaptureMessageMultiUnicodeStringsInPlace
//CsrCaptureMessageString
//CsrCaptureTimeout

	//https://www.geoffchappell.com/studies/windows/win32/ntdll/api/csrutil/clientcallserver.htm
	NTSYSAPI NTSTATUS WINAPI CsrClientCallServer(
		CSR_API_MSG* ApiMsg,
		PVOID CaptureBuffer,
		ULONG ApiNumber,
		LONG ApiMessageDataSize);

	//CsrClientConnectToServer
//CsrFreeCaptureBuffer
//CsrGetProcessId
//CsrIdentifyAlertableThread
//CsrSetPriorityClass
//CsrVerifyRegion


//EvtIntReportAuthzEventAndSourceAsync
//EvtIntReportEventAndSourceAsync
//ExpInterlockedPopEntrySListEnd
//ExpInterlockedPopEntrySListFault
//ExpInterlockedPopEntrySListResume
//KiRaiseUserExceptionDispatcher
//KiUserApcDispatcher
//KiUserCallbackDispatcher
//KiUserExceptionDispatcher
//KiUserInvertedFunctionTable


//NlsAnsiCodePage
//NlsMbCodePageTag
//NlsMbOemCodePageTag

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtAllocateUuids(
		_Out_ PLARGE_INTEGER UuidLastTimeAllocated,
		_Out_ PULONG UuidDeltaTime,
		_Out_ PULONG UuidSequenceNumber,
		_Out_ PUCHAR UuidSeed);
	//ZwAllocateUuids

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtCallEnclave(
		_In_ PVOID Function,
		_In_ PVOID Parameter,
		_In_ BOOLEAN WaitForThread,
		_Out_opt_ PVOID* Result);
	//ZwCallEnclave

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtCallbackReturn(
		_In_opt_ PVOID Result,
		_In_ ULONG ResultLength,
		_In_ NTSTATUS Status);
	//ZwCallbackReturn

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntclose
	// See winternl.h
	// NtClose
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

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtTerminateEnclave(
		_In_ PVOID BaseAddress,
		_In_ BOOLEAN WaitForThread);
	//ZwTerminateEnclave

//NtdllDefWindowProc_A
//NtdllDefWindowProc_W
//NtdllDialogWndProc_A
//NtdllDialogWndProc_W

//PfxFindPrefix
//PfxInitialize
//PfxInsertPrefix
//PfxRemovePrefix

//PssNtCaptureSnapshot
//PssNtDuplicateSnapshot
//PssNtFreeRemoteSnapshot
//PssNtFreeSnapshot
//PssNtFreeWalkMarker
//PssNtQuerySnapshot
//PssNtValidateDescriptor
//PssNtWalkSnapshot
//RtlAbortRXact
	
	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlabsolutetoselfrelativesd
	NTSYSAPI NTSTATUS RtlAbsoluteToSelfRelativeSD(
		[in]      PSECURITY_DESCRIPTOR AbsoluteSecurityDescriptor,
		[out]     PSECURITY_DESCRIPTOR SelfRelativeSecurityDescriptor,
		[in, out] PULONG               BufferLength);

	//RtlAcquirePebLock
//RtlAcquirePrivilege
//RtlAcquireReleaseSRWLockExclusive
//RtlAcquireResourceExclusive
//RtlAcquireResourceShared
//RtlAcquireSRWLockExclusive
//RtlAcquireSRWLockShared
//RtlActivateActivationContext
//RtlActivateActivationContextEx
//RtlActivateActivationContextUnsafeFast

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtladdaccessallowedace
	NTSYSAPI NTSTATUS RtlAddAccessAllowedAce(
		[in, out] PACL        Acl,
		[in]      ULONG       AceRevision,
		[in]      ACCESS_MASK AccessMask,
		[in]      PSID        Sid);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtladdaccessallowedaceex
	NTSYSAPI NTSTATUS RtlAddAccessAllowedAceEx(
		[in, out] PACL        Acl,
		[in]      ULONG       AceRevision,
		[in]      ULONG       AceFlags,
		[in]      ACCESS_MASK AccessMask,
		[in]      PSID        Sid);

//RtlAddAccessAllowedObjectAce
//RtlAddAccessDeniedAce
//RtlAddAccessDeniedAceEx
//RtlAddAccessDeniedObjectAce
//RtlAddAccessFilterAce

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtladdace
	NTSYSAPI NTSTATUS RtlAddAce(
		[in, out] PACL  Acl,
		[in]      ULONG AceRevision,
		[in]      ULONG StartingAceIndex,
		[in]      PVOID AceList,
		[in]      ULONG AceListLength);

//RtlAddActionToRXact
//RtlAddAttributeActionToRXact
//RtlAddAuditAccessAce
//RtlAddAuditAccessAceEx
//RtlAddAuditAccessObjectAce
//RtlAddCompoundAce
//RtlAddFunctionTable
//RtlAddGrowableFunctionTable
//RtlAddIntegrityLabelToBoundaryDescriptor
//RtlAddMandatoryAce
//RtlAddProcessTrustLabelAce
//RtlAddRefActivationContext
//RtlAddRefMemoryStream
//RtlAddResourceAttributeAce
//RtlAddSIDToBoundaryDescriptor
//RtlAddScopedPolicyIDAce
//RtlAddVectoredContinueHandler
//RtlAddVectoredExceptionHandler
//RtlAddressInSectionTable

	// https://github.com/Uri3n/Thread-Pool-Injection-PoC/blob/main/include/FunctionPtrs.hpp
	NTSYSAPI NTSTATUS NTAPI RtlAdjustPrivilege(
		_In_ ULONG Privilege,
		_In_ BOOLEAN Enable,
		_In_ BOOLEAN Client,
		_Out_ PBOOLEAN WasEnabled);

//RtlAllocateActivationContextStack

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlallocateandinitializesid
	NTSYSAPI NTSTATUS RtlAllocateAndInitializeSid(
		PSID_IDENTIFIER_AUTHORITY IdentifierAuthority,
		UCHAR                     SubAuthorityCount,
		ULONG                     SubAuthority0,
		ULONG                     SubAuthority1,
		ULONG                     SubAuthority2,
		ULONG                     SubAuthority3,
		ULONG                     SubAuthority4,
		ULONG                     SubAuthority5,
		ULONG                     SubAuthority6,
		ULONG                     SubAuthority7,
		PSID* Sid);

//RtlAllocateAndInitializeSidEx
//RtlAllocateHandle

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlallocateheap
	NTSYSAPI PVOID RtlAllocateHeap(
		[in]           PVOID  HeapHandle,
		[in, optional] ULONG  Flags,
		[in]           SIZE_T Size);

//RtlAllocateMemoryBlockLookaside
//RtlAllocateMemoryZone
//RtlAllocateWnfSerializationGroup
//RtlAnsiCharToUnicodeChar

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlansistringtounicodesize
	NTSYSAPI ULONG NTAPI RtlAnsiStringToUnicodeSize(
      PANSI_STRING AnsiString );

// See winterl.h
// RtlAnsiStringToUnicodeString

//RtlAppendAsciizToString
//RtlAppendPathElement

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlappendstringtostring
	NTSYSAPI NTSTATUS RtlAppendStringToString(
		[in, out] PSTRING      Destination,
		[in]      const STRING* Source);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlansistringtounicodestring
	NTSYSAPI NTSTATUS RtlAnsiStringToUnicodeString(
		[in, out] PUNICODE_STRING DestinationString,
		[in]      PCANSI_STRING   SourceString,
		[in]      BOOLEAN         AllocateDestinationString);

	//https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlappendunicodetostring
	NTSYSAPI NTSTATUS RtlAppendUnicodeToString(
		[in, out]      PUNICODE_STRING Destination,
		[in, optional] PCWSTR          Source);

//RtlApplicationVerifierStop
//RtlApplyRXact
//RtlApplyRXactNoFlush
//RtlAreAllAccessesGranted
//RtlAreAnyAccessesGranted

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlarebitsclear
	NTSYSAPI BOOLEAN RtlAreBitsClear(
		[in] PRTL_BITMAP BitMapHeader,
		[in] ULONG       StartingIndex,
		[in] ULONG       Length);

//RtlAreBitsClearEx

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlarebitsset
	NTSYSAPI BOOLEAN RtlAreBitsSet(
		[in] PRTL_BITMAP BitMapHeader,
		[in] ULONG       StartingIndex,
		[in] ULONG       Length);

	//RtlAreLongPathsEnabled

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	void WINAPI RtlAssert(void* assertion, void* filename, ULONG linenumber, char* message);

//RtlAvlInsertNodeEx
//RtlAvlRemoveNode
//RtlBarrier
//RtlBarrierForDelete
//RtlCallEnclaveReturn
//RtlCancelTimer
//RtlCanonicalizeDomainName
//RtlCapabilityCheck
//RtlCapabilityCheckForSingleSessionSku

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlcapturecontext
	NTSYSAPI VOID RtlCaptureContext(
		[out] PCONTEXT ContextRecord);

//RtlCaptureContext2
	
	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlcapturestackbacktrace
	NTSYSAPI USHORT RtlCaptureStackBackTrace(
		[in]            ULONG  FramesToSkip,
		[in]            ULONG  FramesToCapture,
		[out]           PVOID* BackTrace,
		[out, optional] PULONG BackTraceHash);
	
	// See winterl.h
	// RtlCharToInteger

	//RtlCheckBootStatusIntegrity
//RtlCheckForOrphanedCriticalSections
//RtlCheckPortableOperatingSystem

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlcheckregistrykey
	NTSYSAPI NTSTATUS RtlCheckRegistryKey(
		[in] ULONG RelativeTo,
		[in] PWSTR Path);

//RtlCheckSandboxedToken
//RtlCheckSystemBootStatusIntegrity
//RtlCheckTokenCapability
//RtlCheckTokenMembership
//RtlCheckTokenMembershipEx
//RtlCleanUpTEBLangLists

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlclearallbits
	NTSYSAPI VOID RtlClearAllBits(
		[in] PRTL_BITMAP BitMapHeader);

	//RtlClearAllBitsEx

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlclearbit
	NTSYSAPI VOID RtlClearBit(
		[in] PRTL_BITMAP BitMapHeader,
		[in] ULONG       BitNumber);

	//RtlClearBitEx

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlclearbits
	NTSYSAPI VOID RtlClearBits(
		[in] PRTL_BITMAP BitMapHeader,
		[in] ULONG       StartingIndex,
		[in] ULONG       NumberToClear);

	//RtlClearBitsEx
//RtlClearThreadWorkOnBehalfTicket
//RtlCloneMemoryStream
//RtlCloneUserProcess

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

	//RtlCommitDebugInfo
//RtlCommitMemoryStream
//RtlCompactHeap
//RtlCompareAltitudes

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlcomparememory
	NTSYSAPI SIZE_T RtlCompareMemory(
		[in] const VOID* Source1,
		[in] const VOID* Source2,
		[in] SIZE_T     Length);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlcomparememoryulong
	NTSYSAPI SIZE_T RtlCompareMemoryUlong(
		[in] PVOID  Source,
		[in] SIZE_T Length,
		[in] ULONG  Pattern);

//RtlCompareString

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlcompareunicodestring
	NTSYSAPI LONG RtlCompareUnicodeString(
		[in] PCUNICODE_STRING String1,
		[in] PCUNICODE_STRING String2,
		[in] BOOLEAN          CaseInSensitive);

//RtlCompareUnicodeStrings
//RtlCompleteProcessCloning

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlcompressbuffer
	NT_RTL_COMPRESS_API NTSTATUS RtlCompressBuffer(
		[in]  USHORT CompressionFormatAndEngine,
		[in]  PUCHAR UncompressedBuffer,
		[in]  ULONG  UncompressedBufferSize,
		[out] PUCHAR CompressedBuffer,
		[in]  ULONG  CompressedBufferSize,
		[in]  ULONG  UncompressedChunkSize,
		[out] PULONG FinalCompressedSize,
		[in]  PVOID  WorkSpace);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	DWORD WINAPI RtlComputeCrc32(DWORD dwInitial, const BYTE* pData, INT iLen);

	//RtlComputeImportTableHash
//RtlComputePrivatizedDllName_U
//RtlConnectToSm
//RtlConsoleMultiByteToUnicodeN
//RtlConstructCrossVmEventPath
//RtlConstructCrossVmMutexPath
//RtlContractHashTable

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	DWORD WINAPI RtlConvertDeviceFamilyInfoToString(DWORD* device_family_size, DWORD* device_form_size,
		WCHAR* device_family, WCHAR* device_form);

//RtlConvertExclusiveToShared
//RtlConvertLCIDToString
//RtlConvertSRWLockExclusiveToShared
//RtlConvertSharedToExclusive

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlconvertsidtounicodestring
	// See winterl.h
	// RtlConvertSidToUnicodeString

//RtlConvertToAutoInheritSecurityObject
//RtlCopyBitMap
//RtlCopyContext
//RtlCopyExtendedContext

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlcopyluid
	NTSYSAPI VOID RtlCopyLuid(
		[out] PLUID DestinationLuid,
		[in]  PLUID SourceLuid);

//RtlCopyLuidAndAttributesArray
//RtlCopyMappedMemory

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlcopymemory
	void RtlCopyMemory(
		void* Destination,
		const void* Source,
		size_t      Length);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlcopymemorynontemporal
	NTSYSAPI VOID RtlCopyMemoryNonTemporal(
		VOID* Destination,
		const VOID* Source,
		SIZE_T     Length);

	//RtlCopyMemoryStreamTo
//RtlCopyOutOfProcessMemoryStreamTo
//RtlCopySecurityDescriptor

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlcopysid
	NTSYSAPI NTSTATUS RtlCopySid(
		[in] ULONG DestinationSidLength,
		[in] PSID  DestinationSid,
		[in] PSID  SourceSid);

//RtlCopySidAndAttributesArray
//RtlCopyString

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlcopyunicodestring
	NTSYSAPI VOID RtlCopyUnicodeString(
		[in, out]      PUNICODE_STRING  DestinationString,
		[in, optional] PCUNICODE_STRING SourceString);

//RtlCrc32
//RtlCrc64

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlcreateacl
	NTSYSAPI NTSTATUS RtlCreateAcl(
		[out] PACL  Acl,
		[in]  ULONG AclLength,
		ULONG AclRevision);

//RtlCreateActivationContext
//RtlCreateAndSetSD
//RtlCreateBoundaryDescriptor
//RtlCreateEnvironment
//RtlCreateEnvironmentEx
//RtlCreateHashTable
//RtlCreateHashTableEx

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlcreateheap
	NTSYSAPI PVOID RtlCreateHeap(
		[in]           ULONG                Flags,
		[in, optional] PVOID                HeapBase,
		[in, optional] SIZE_T               ReserveSize,
		[in, optional] SIZE_T               CommitSize,
		[in, optional] PVOID                Lock,
		[in, optional] PRTL_HEAP_PARAMETERS Parameters);

//RtlCreateMemoryBlockLookaside
//RtlCreateMemoryZone
//RtlCreateProcessParameters
//RtlCreateProcessParametersEx
//RtlCreateProcessParametersWithTemplate
//RtlCreateProcessReflection
//RtlCreateQueryDebugBuffer

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlcreateregistrykey
	NTSYSAPI NTSTATUS RtlCreateRegistryKey(
		[in] ULONG RelativeTo,
		[in] PWSTR Path);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlcreatesecuritydescriptor
	NTSYSAPI NTSTATUS RtlCreateSecurityDescriptor(
		[out] PSECURITY_DESCRIPTOR SecurityDescriptor,
		[in]  ULONG                Revision);

	//RtlCreateServiceSid
//RtlCreateSystemVolumeInformationFolder
//RtlCreateTagHeap
//RtlCreateTimer
//RtlCreateTimerQueue
//RtlCreateUmsCompletionList
//RtlCreateUmsThreadContext

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlcreateunicodestring
	NTSYSAPI BOOLEAN RtlCreateUnicodeString(
		[out] PUNICODE_STRING DestinationString,
		[in]  PCWSTR          SourceString);

//RtlCreateUnicodeStringFromAsciiz
//RtlCreateUserFiberShadowStack

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/process.c
	NTSTATUS WINAPI RtlCreateUserProcess(UNICODE_STRING* path, ULONG attributes,
		RTL_USER_PROCESS_PARAMETERS* params,
		SECURITY_DESCRIPTOR* process_descr,
		SECURITY_DESCRIPTOR* thread_descr,
		HANDLE parent, BOOLEAN inherit, HANDLE debug, HANDLE token,
		RTL_USER_PROCESS_INFORMATION* info);

//RtlCreateUserProcessEx
//RtlCreateUserSecurityObject
//RtlCreateUserStack
//RtlCreateUserThread
//RtlCreateVirtualAccountSid
//RtlCultureNameToLCID

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlcustomcptounicoden
	NTSYSAPI NTSTATUS RtlCustomCPToUnicodeN(
		PCPTABLEINFO CustomCP,
		PWCH         UnicodeString,
		ULONG        MaxBytesInUnicodeString,
		PULONG       BytesInUnicodeString,
		PCH          CustomCPString,
		ULONG        BytesInCustomCPString);

//RtlCutoverTimeToSystemTime
//RtlDeCommitDebugInfo
//RtlDeNormalizeProcessParams
//RtlDeactivateActivationContext
//RtlDeactivateActivationContextUnsafeFast
//RtlDebugPrintTimes
//RtlDecodePointer
//RtlDecodeRemotePointer
//RtlDecodeSystemPointer

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtldecompressbuffer
	NT_RTL_COMPRESS_API NTSTATUS RtlDecompressBuffer(
		[in]  USHORT CompressionFormat,
		[out] PUCHAR UncompressedBuffer,
		[in]  ULONG  UncompressedBufferSize,
		[in]  PUCHAR CompressedBuffer,
		[in]  ULONG  CompressedBufferSize,
		[out] PULONG FinalUncompressedSize);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtldecompressbufferex
	NT_RTL_COMPRESS_API NTSTATUS RtlDecompressBufferEx(
		[in]  USHORT CompressionFormat,
		[out] PUCHAR UncompressedBuffer,
		[in]  ULONG  UncompressedBufferSize,
		[in]  PUCHAR CompressedBuffer,
		[in]  ULONG  CompressedBufferSize,
		[out] PULONG FinalUncompressedSize,
		[in]  PVOID  WorkSpace);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtldecompressfragment
	NT_RTL_COMPRESS_API NTSTATUS RtlDecompressFragment(
		[in]  USHORT CompressionFormat,
		[out] PUCHAR UncompressedFragment,
		[in]  ULONG  UncompressedFragmentSize,
		[in]  PUCHAR CompressedBuffer,
		[in]  ULONG  CompressedBufferSize,
		[in]  ULONG  FragmentOffset,
		[out] PULONG FinalUncompressedSize,
		[in]  PVOID  WorkSpace);

//RtlDefaultNpAcl

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	RTL_SPLAY_LINKS* WINAPI RtlDelete(RTL_SPLAY_LINKS* links);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtldeleteace
	NTSYSAPI NTSTATUS RtlDeleteAce(
		[in, out] PACL  Acl,
		[in]      ULONG AceIndex);

//RtlDeleteBarrier
//RtlDeleteBoundaryDescriptor
//RtlDeleteCriticalSection

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	BOOLEAN WINAPI RtlDeleteElementGenericTable(RTL_GENERIC_TABLE* table, void* value);

//RtlDeleteElementGenericTableAvl
//RtlDeleteElementGenericTableAvlEx
//RtlDeleteFunctionTable
//RtlDeleteGrowableFunctionTable
//RtlDeleteHashTable

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	void WINAPI RtlDeleteNoSplay(RTL_SPLAY_LINKS* links, RTL_SPLAY_LINKS** root);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtldeleteregistryvalue
	NTSYSAPI NTSTATUS RtlDeleteRegistryValue(
		[in] ULONG  RelativeTo,
		[in] PCWSTR Path,
		[in] PCWSTR ValueName);

	//RtlDeleteResource
//RtlDeleteSecurityObject
//RtlDeleteTimer
//RtlDeleteTimerQueue
//RtlDeleteTimerQueueEx
//RtlDeleteUmsCompletionList
//RtlDeleteUmsThreadContext
//RtlDequeueUmsCompletionListItems
//RtlDeregisterSecureMemoryCacheCallback
//RtlDeregisterWait
//RtlDeregisterWaitEx
//RtlDeriveCapabilitySidsFromName
//RtlDestroyEnvironment
//RtlDestroyHandleTable

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtldestroyheap
	NTSYSAPI PVOID RtlDestroyHeap(
		[in] PVOID HeapHandle);

//RtlDestroyMemoryBlockLookaside
//RtlDestroyMemoryZone
//RtlDestroyProcessParameters
//RtlDestroyQueryDebugBuffer
//RtlDetectHeapLeaks
//RtlDetermineDosPathNameType_U
//RtlDisableThreadProfiling
//RtlDisownModuleHeapAllocation
//RtlDllShutdownInProgress
//RtlDnsHostNameToComputerName

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtldowncaseunicodechar
	NTSYSAPI WCHAR RtlDowncaseUnicodeChar(
		[in] WCHAR SourceCharacter);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtldowncaseunicodestring
	NTSYSAPI NTSTATUS RtlDowncaseUnicodeString(
		PUNICODE_STRING  DestinationString,
		[in] PCUNICODE_STRING SourceString,
		[in] BOOLEAN          AllocateDestinationString);

//RtlDrainNonVolatileFlush
//RtlDumpResource
//RtlDuplicateUnicodeString
//RtlEnableEarlyCriticalSectionEventCreation
//RtlEnableThreadProfiling
//RtlEnclaveCallDispatch
//RtlEnclaveCallDispatchReturn

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	PVOID WINAPI RtlEncodePointer(PVOID ptr);

//RtlEncodeRemotePointer
//RtlEncodeSystemPointer
//RtlEndEnumerationHashTable
//RtlEndStrongEnumerationHashTable
//RtlEndWeakEnumerationHashTable
//RtlEnterCriticalSection
//RtlEnterUmsSchedulingMode
//RtlEnumProcessHeaps
//RtlEnumerateEntryHashTable

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	void* WINAPI RtlEnumerateGenericTable(RTL_GENERIC_TABLE* table, BOOLEAN restart);

//RtlEnumerateGenericTableAvl
//RtlEnumerateGenericTableLikeADirectory

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	void* WINAPI RtlEnumerateGenericTableWithoutSplaying(RTL_GENERIC_TABLE* table, PVOID* previous);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	void* WINAPI RtlEnumerateGenericTableWithoutSplayingAvl(RTL_AVL_TABLE* table, PVOID* previous);

	//RtlEqualComputerName

	//RtlEqualDomainName

	//RtlEqualLuid

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlequalprefixsid
	NTSYSAPI BOOLEAN RtlEqualPrefixSid(
		[in] PSID Sid1,
		[in] PSID Sid2);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlequalsid
	NTSYSAPI BOOLEAN RtlEqualSid(
		[in] PSID Sid1,
		[in] PSID Sid2);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlequalstring
	NTSYSAPI BOOLEAN RtlEqualString(
		[in] const STRING* String1,
		[in] const STRING* String2,
		[in] BOOLEAN      CaseInSensitive);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlequalunicodestring
	NTSYSAPI BOOLEAN RtlEqualUnicodeString(
		[in] PCUNICODE_STRING String1,
		[in] PCUNICODE_STRING String2,
		[in] BOOLEAN          CaseInSensitive);

	//RtlEqualWnfChangeStamps
//RtlEraseUnicodeString
//RtlEthernetAddressToStringA
//RtlEthernetAddressToStringW
//RtlEthernetStringToAddressA
//RtlEthernetStringToAddressW
//RtlExecuteUmsThread
//RtlExitUserProcess
//RtlExitUserThread
//RtlExpandEnvironmentStrings
//RtlExpandEnvironmentStrings_U
//RtlExpandHashTable

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlextendcorrelationvector
	NTSYSAPI NTSTATUS RtlExtendCorrelationVector(
		[in, out] PCORRELATION_VECTOR CorrelationVector);

//RtlExtendMemoryBlockLookaside
//RtlExtendMemoryZone
//RtlExtractBitMap
//RtlFillMemory

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlfillmemorynontemporal
	NTSYSAPI VOID RtlFillMemoryNonTemporal(
		VOID* Destination,
		SIZE_T      Length,
		const UCHAR Value);

//RtlFillNonVolatileMemory
//RtlFinalReleaseOutOfProcessMemoryStream
//RtlFindAceByType
//RtlFindActivationContextSectionGuid
//RtlFindActivationContextSectionString
//RtlFindCharInUnicodeString

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

//RtlFindClearBitsEx

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlfindclearruns
	NTSYSAPI ULONG RtlFindClearRuns(
		[in]  PRTL_BITMAP     BitMapHeader,
		[out] PRTL_BITMAP_RUN RunArray,
		[in]  ULONG           SizeOfRunArray,
		[in]  BOOLEAN         LocateLongestRuns);

//RtlFindClosestEncodableLength
//RtlFindExportedRoutineByName

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

	//RtlFindMessage

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

//RtlFindSetBitsAndClearEx
//RtlFindSetBitsEx
//RtlFindUnicodeSubstring
//RtlFirstEntrySList
//RtlFirstFreeAce
//RtlFlsAlloc
//RtlFlsFree
//RtlFlsGetValue
//RtlFlsSetValue
//RtlFlushHeaps
//RtlFlushNonVolatileMemory
//RtlFlushNonVolatileMemoryRanges
//RtlFlushSecureMemoryCache

	// https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/rtl/regutil/formatcurrentuserkeypath.htm?ta=8.199996948242188&tx=91,109,113;90,103&ts=0,217
	NTSYSAPI NTSTATUS RtlFormatCurrentUserKeyPath(
		UNICODE_STRING* CurrentUserKeyPath);

//RtlFormatMessage
//RtlFormatMessageEx
//RtlFreeActivationContextStack

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlfreeansistring
	// See winterl.h
	// RtlFreeAnsiString

//RtlFreeHandle

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlfreeheap
	NTSYSAPI LOGICAL RtlFreeHeap(
		[in]           PVOID                 HeapHandle,
		[in, optional] ULONG                 Flags,
		_Frees_ptr_opt_ PVOID BaseAddress);

//RtlFreeMemoryBlockLookaside
//RtlFreeNonVolatileToken

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlfreeoemstring
	// See winterl.h
	// RtlFreeOemString

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlfreesid
	NTSYSAPI PVOID RtlFreeSid(
		PSID Sid);

//RtlFreeThreadActivationContextStack

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlfreeunicodestring
	// See winterl.h
	// RtlFreeUnicodeString

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlfreeutf8string
	NTSYSAPI VOID RtlFreeUTF8String(
		PUTF8_STRING utf8String);

//RtlFreeUserFiberShadowStack
//RtlFreeUserStack
//RtlGUIDFromString

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlgenerate8dot3name
	NTSYSAPI NTSTATUS RtlGenerate8dot3Name(
		[in]      PCUNICODE_STRING       Name,
		[in]      BOOLEAN                AllowExtendedCharacters,
		[in, out] PGENERATE_NAME_CONTEXT Context,
		[in, out] PUNICODE_STRING        Name8dot3);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlgetace
	NTSYSAPI NTSTATUS RtlGetAce(
		[in]  PACL  Acl,
		[in]  ULONG AceIndex,
		[out] PVOID* Ace);

	//RtlGetActiveActivationContext
//RtlGetActiveConsoleId
//RtlGetAppContainerNamedObjectPath
//RtlGetAppContainerParent
//RtlGetAppContainerSidType
//RtlGetCallersAddress

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlgetcompressionworkspacesize
	NT_RTL_COMPRESS_API NTSTATUS RtlGetCompressionWorkSpaceSize(
		[in]  USHORT CompressionFormatAndEngine,
		[out] PULONG CompressBufferWorkSpaceSize,
		[out] PULONG CompressFragmentWorkSpaceSize);

//RtlGetConsoleSessionForegroundProcessId
//RtlGetControlSecurityDescriptor
//RtlGetCriticalSectionRecursionCount
//RtlGetCurrentDirectory_U

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/process.c
	PEB* WINAPI RtlGetCurrentPeb(void);

//RtlGetCurrentProcessorNumber

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	void WINAPI RtlGetCurrentProcessorNumberEx(PROCESSOR_NUMBER* processor);

//RtlGetCurrentServiceSessionId

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	HANDLE WINAPI RtlGetCurrentTransaction(void);

//RtlGetCurrentUmsThread
	
	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlgetdaclsecuritydescriptor
	NTSYSAPI NTSTATUS RtlGetDaclSecurityDescriptor(
		[in]  PSECURITY_DESCRIPTOR SecurityDescriptor,
		[out] PBOOLEAN             DaclPresent,
		[out] PACL* Dacl,
		[out] PBOOLEAN             DaclDefaulted);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	void WINAPI RtlGetDeviceFamilyInfoEnum(ULONGLONG* version, DWORD* family, DWORD* form);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	void* WINAPI RtlGetElementGenericTable(RTL_GENERIC_TABLE* table, ULONG index);

	//RtlGetElementGenericTableAvl

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlgetenabledextendedfeatures
	NTSYSAPI ULONG64 RtlGetEnabledExtendedFeatures(
		[in] ULONG64 FeatureMask);

//RtlGetExePath
//RtlGetExtendedContextLength
//RtlGetExtendedContextLength2
//RtlGetExtendedFeaturesMask
//RtlGetFrame
//RtlGetFunctionTableListHead

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlgetgroupsecuritydescriptor
	NTSYSAPI NTSTATUS RtlGetGroupSecurityDescriptor(
		[in]  PSECURITY_DESCRIPTOR SecurityDescriptor,
		[out] PSID* Group,
		[out] PBOOLEAN             GroupDefaulted);

//RtlGetInterruptTimePrecise
//RtlGetLastNtStatus
//RtlGetLastWin32Error
//RtlGetMultiTimePrecise
//RtlGetNativeSystemInformation
//RtlGetNextEntryHashTable
//RtlGetNextUmsListItem
//RtlGetNonVolatileToken
//RtlGetNtGlobalFlags
//RtlGetNtProductType
//RtlGetNtSystemRoot
//RtlGetNtVersionNumbers

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlgetownersecuritydescriptor
	NTSYSAPI NTSTATUS RtlGetOwnerSecurityDescriptor(
		[in]  PSECURITY_DESCRIPTOR SecurityDescriptor,
		[out] PSID* Owner,
		[out] PBOOLEAN             OwnerDefaulted);
//RtlGetParentLocaleName

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlgetpersistedstatelocation
	NTSYSAPI NTSTATUS RtlGetPersistedStateLocation(
		[_In_]      PCWSTR              SourceID,
		[_In_opt_]  PCWSTR              CustomValue,
		[_In_opt_]  PCWSTR              DefaultPath,
		[_In_]      STATE_LOCATION_TYPE StateLocationType,
		[_In_]      PWCHAR              TargetPath,
		[_In_]      ULONG               BufferLengthIn,
		[_Out_opt_] PULONG              BufferLengthOut);

//RtlGetProcessHeaps
//RtlGetProcessPreferredUILanguages
//RtlGetProductInfo
//RtlGetReturnAddressHijackTarget

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlgetsaclsecuritydescriptor
	NTSYSAPI NTSTATUS RtlGetSaclSecurityDescriptor(
		[in]  PSECURITY_DESCRIPTOR SecurityDescriptor,
		[out] PBOOLEAN             SaclPresent,
		[out] PACL* Sacl,
		[out] PBOOLEAN             SaclDefaulted);

	//RtlGetSearchPath
//RtlGetSecurityDescriptorRMControl
//RtlGetSessionProperties
//RtlGetSetBootStatusData
//RtlGetSuiteMask
//RtlGetSystemBootStatus
//RtlGetSystemBootStatusEx
//RtlGetSystemPreferredUILanguages
//RtlGetSystemTimeAndBias
//RtlGetSystemTimePrecise
//RtlGetThreadErrorMode
//RtlGetThreadLangIdByIndex
//RtlGetThreadPreferredUILanguages
//RtlGetThreadWorkOnBehalfTicket
//RtlGetTokenNamedObjectPath
//RtlGetUILanguageInfo
//RtlGetUmsCompletionListEvent
//RtlGetUnloadEventTrace
//RtlGetUnloadEventTraceEx
//RtlGetUserInfoHeap
//RtlGetUserPreferredUILanguages

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlgetversion
	NTSYSAPI NTSTATUS RtlGetVersion(
		[out] PRTL_OSVERSIONINFOW lpVersionInformation);

//RtlGrowFunctionTable
//RtlGuardCheckLongJumpTarget

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlhashunicodestring
	NTSYSAPI NTSTATUS RtlHashUnicodeString(
		[in]  PCUNICODE_STRING String,
		[in]  BOOLEAN          CaseInSensitive,
		[in]  ULONG            HashAlgorithm,
		[out] PULONG           HashValue);

//RtlHeapTrkInitialize

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlidentifierauthoritysid
	NTSYSAPI PSID_IDENTIFIER_AUTHORITY RtlIdentifierAuthoritySid(
		PSID Sid);

	//RtlIdnToAscii
//RtlIdnToNameprepUnicode
//RtlIdnToUnicode
//RtlImageDirectoryEntryToData
//RtlImageNtHeader
//RtlImageNtHeaderEx
//RtlImageRvaToSection
//RtlImageRvaToVa
//RtlImpersonateSelf
//RtlImpersonateSelfEx

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlincrementcorrelationvector
	NTSYSAPI NTSTATUS RtlIncrementCorrelationVector(
		[in, out] PCORRELATION_VECTOR CorrelationVector);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlinitansistring
	// See winterl.h
	// RtlInitAnsiString

//// See winterl.h
//// RtlInitAnsiStringEx
//RtlInitBarrier

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlinitcodepagetable
	NTSYSAPI VOID RtlInitCodePageTable(
		PUSHORT      TableBase,
		PCPTABLEINFO CodePageTable);

//RtlInitEnumerationHashTable
//RtlInitMemoryStream
//RtlInitNlsTables
//RtlInitOutOfProcessMemoryStream

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlinitstring
	// See winterl.h
	// RtlInitString

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlinitstringex
	// See winterl.h
	// RtlInitStringEx

//RtlInitStrongEnumerationHashTable
//RtlInitUTF8String

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

//RtlInitWeakEnumerationHashTable
//RtlInitializeBitMap
//RtlInitializeBitMapEx
//RtlInitializeConditionVariable
//RtlInitializeContext

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlinitializecorrelationvector
	NTSYSAPI NTSTATUS RtlInitializeCorrelationVector(
		[in, out] PCORRELATION_VECTOR CorrelationVector,
		[in]      int                 Version,
		[in]      const GUID* Guid);

//RtlInitializeCriticalSection
//RtlInitializeCriticalSectionAndSpinCount
//RtlInitializeCriticalSectionEx
//RtlInitializeExtendedContext
//RtlInitializeExtendedContext2

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	void WINAPI RtlInitializeGenericTable(RTL_GENERIC_TABLE* table, PRTL_GENERIC_COMPARE_ROUTINE compare,
		PRTL_GENERIC_ALLOCATE_ROUTINE allocate, PRTL_GENERIC_FREE_ROUTINE free,
		void* context);
	

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	void WINAPI RtlInitializeGenericTableAvl(PRTL_AVL_TABLE table, PRTL_AVL_COMPARE_ROUTINE compare,
		PRTL_AVL_ALLOCATE_ROUTINE allocate, PRTL_AVL_FREE_ROUTINE free, void* context);
	
	//RtlInitializeHandleTable

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	NTSTATUS WINAPI RtlInitializeNtUserPfn(const void* client_procsA, ULONG procsA_size,
		const void* client_procsW, ULONG procsW_size,
		const void* client_workers, ULONG workers_size);

//RtlInitializeRXact
//RtlInitializeResource
//RtlInitializeSListHead
//RtlInitializeSRWLock

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlinitializesid
	NTSYSAPI NTSTATUS RtlInitializeSid(
		[out] PSID                      Sid,
		[in]  PSID_IDENTIFIER_AUTHORITY IdentifierAuthority,
		[in]  UCHAR                     SubAuthorityCount);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlinitializesidex
	NTSYSAPI NTSTATUS RtlInitializeSidEx(
		[out] PSID                      Sid,
		[in]  PSID_IDENTIFIER_AUTHORITY IdentifierAuthority,
		[in]  UCHAR                     SubAuthorityCount,
		...);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	void* WINAPI RtlInsertElementGenericTable(RTL_GENERIC_TABLE* table, void* value, CLONG size, BOOLEAN* new_element);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	void WINAPI RtlInsertElementGenericTableAvl(PRTL_AVL_TABLE table, void* buffer, ULONG size, BOOL* element);

	//RtlInsertElementGenericTableFull
//RtlInsertElementGenericTableFullAvl
//RtlInsertEntryHashTable
//RtlInstallFunctionTableCallback

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlint64tounicodestring
	NTSYSAPI NTSTATUS RtlInt64ToUnicodeString(
		[in]           ULONGLONG       Value,
		[in, optional] ULONG           Base,
		[in, out]      PUNICODE_STRING String);

//RtlIntegerToChar

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlintegertounicodestring
	NTSYSAPI NTSTATUS RtlIntegerToUnicodeString(
		[in]           ULONG           Value,
		[in, optional] ULONG           Base,
		[in, out]      PUNICODE_STRING String);

//RtlInterlockedClearBitRun
//RtlInterlockedFlushSList
//RtlInterlockedPopEntrySList
//RtlInterlockedPushEntrySList
//RtlInterlockedPushListSList
//RtlInterlockedPushListSListEx
//RtlInterlockedSetBitRun

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

//RtlIpv4AddressToStringA
//RtlIpv4AddressToStringExA
//RtlIpv4AddressToStringExW
//RtlIpv4AddressToStringW
//RtlIpv4StringToAddressA
//RtlIpv4StringToAddressExA
//RtlIpv4StringToAddressExW
//RtlIpv4StringToAddressW
//RtlIpv6AddressToStringA
//RtlIpv6AddressToStringExA
//RtlIpv6AddressToStringExW
//RtlIpv6AddressToStringW
//RtlIpv6StringToAddressA
//RtlIpv6StringToAddressExA
//RtlIpv6StringToAddressExW
//RtlIpv6StringToAddressW
//RtlIsActivationContextActive
//RtlIsCapabilitySid
//RtlIsCriticalSectionLocked
//RtlIsCriticalSectionLockedByThread

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/process.c
	BOOLEAN WINAPI RtlIsCurrentProcess(HANDLE handle);

//RtlIsCurrentThread
//RtlIsCurrentThreadAttachExempt
//RtlIsDosDeviceName_U
//RtlIsElevatedRid

	//https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	BOOLEAN WINAPI RtlIsGenericTableEmpty(RTL_GENERIC_TABLE* table);

//RtlIsGenericTableEmptyAvl
//RtlIsMultiSessionSku
//RtlIsMultiUsersInSessionSku
//RtlIsNonEmptyDirectoryReparsePointAllowed
//RtlIsNormalizedString
//RtlIsPackageSid
//RtlIsParentOfChildAppContainer

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlispartialplaceholder
	NTSYSAPI BOOLEAN RtlIsPartialPlaceholder(
		[in] ULONG FileAttributes,
		[in] ULONG ReparseTag);

//RtlIsProcessorFeaturePresent

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlisstateseparationenabled
	NTSYSAPI BOOLEAN RtlIsStateSeparationEnabled();

//RtlIsTextUnicode
//RtlIsThreadWithinLoaderCallout
//RtlIsUntrustedObject
//RtlIsValidHandle
//RtlIsValidIndexHandle
//RtlIsValidLocaleName
//RtlIsValidProcessTrustLabelSid

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtliszeromemory
	NTSYSAPI BOOLEAN RtlIsZeroMemory(
		PVOID  Buffer,
		SIZE_T Length);

//RtlKnownExceptionFilter
//RtlLCIDToCultureName
//RtlLargeIntegerToChar
//RtlLcidToLocaleName
//RtlLeaveCriticalSection

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtllengthrequiredsid
	NTSYSAPI ULONG RtlLengthRequiredSid(
		[in] ULONG SubAuthorityCount);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtllengthsecuritydescriptor
	NTSYSAPI ULONG RtlLengthSecurityDescriptor(
		[in] PSECURITY_DESCRIPTOR SecurityDescriptor);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtllengthsid
	NTSYSAPI ULONG RtlLengthSid(
		[in] PSID Sid);

//RtlLengthSidAsUnicodeString
//RtlLoadString
//RtlLocaleNameToLcid
//// See winternl.h
//// RtlLocalTimeToSystemTime
//RtlLocateExtendedFeature
//RtlLocateExtendedFeature2
//RtlLocateLegacyContext
//RtlLockBootStatusData
//RtlLockCurrentThread
//RtlLockHeap
//RtlLockMemoryBlockLookaside
//RtlLockMemoryStreamRegion
//RtlLockMemoryZone
//RtlLockModuleSection
//RtlLogStackBackTrace

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	void* WINAPI RtlLookupElementGenericTable(RTL_GENERIC_TABLE* table, void* value);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	void* WINAPI RtlLookupElementGenericTableAvl(PRTL_AVL_TABLE table, void* buffer);

	//RtlLookupElementGenericTableFull
//RtlLookupElementGenericTableFullAvl
//RtlLookupEntryHashTable
//RtlLookupFirstMatchingElementGenericTableAvl
//RtlLookupFunctionEntry
//RtlLookupFunctionTable
//RtlMakeSelfRelativeSD

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlmapgenericmask
	NTSYSAPI VOID RtlMapGenericMask(
		[in, out] PACCESS_MASK          AccessMask,
		[in]      const GENERIC_MAPPING* GenericMapping);

//RtlMapSecurityErrorToNtStatus

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlmovememory
	void RtlMoveMemory(
		void* Destination,
		const void* Source,
		size_t      Length);

//RtlMultiAppendUnicodeStringBuffer

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlmultibytetounicoden
	NTSYSAPI NTSTATUS RtlMultiByteToUnicodeN(
		[out]           PWCH       UnicodeString,
		[in]            ULONG      MaxBytesInUnicodeString,
		[out, optional] PULONG     BytesInUnicodeString,
		[in]            const CHAR* MultiByteString,
		[in]            ULONG      BytesInMultiByteString);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlmultibytetounicodesize
	NTSYSAPI NTSTATUS RtlMultiByteToUnicodeSize(
		[out] PULONG     BytesInUnicodeString,
		[in]  const CHAR* MultiByteString,
		[in]  ULONG      BytesInMultiByteString);

	//RtlMultipleAllocateHeap
//RtlMultipleFreeHeap
//RtlNewInstanceSecurityObject
//RtlNewSecurityGrantedAccess
//RtlNewSecurityObject
//RtlNewSecurityObjectEx
//RtlNewSecurityObjectWithMultipleInheritance
//RtlNormalizeProcessParams

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlnormalizesecuritydescriptor
	NTSYSAPI BOOLEAN RtlNormalizeSecurityDescriptor(
		PSECURITY_DESCRIPTOR* SecurityDescriptor,
		ULONG                SecurityDescriptorLength,
		PSECURITY_DESCRIPTOR* NewSecurityDescriptor,
		PULONG               NewSecurityDescriptorLength,
		BOOLEAN              CheckOnly);

//RtlNormalizeString
//RtlNotifyFeatureUsage
//RtlNtPathNameToDosPathName

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlntstatustodoserror
	// See winternl.h
	// RtlNtStatusToDosError

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlntstatustodoserrornoteb
	NTSYSAPI ULONG RtlNtStatusToDosErrorNoTeb(
		[in] NTSTATUS Status);

//RtlNtdllName

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	ULONG WINAPI RtlNumberGenericTableElements(RTL_GENERIC_TABLE* table);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	ULONG WINAPI RtlNumberGenericTableElementsAvl(RTL_AVL_TABLE* table);

	//RtlNumberOfClearBits

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlnumberofclearbits
	NTSYSAPI ULONG RtlNumberOfClearBits(
		[in] PRTL_BITMAP BitMapHeader);

	//RtlNumberOfClearBitsInRange

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlnumberofsetbits
	NTSYSAPI ULONG RtlNumberOfSetBits(
		[in] PRTL_BITMAP BitMapHeader);

	//RtlNumberOfSetBitsEx
//RtlNumberOfSetBitsInRange

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlnumberofsetbitsulongptr
	NTSYSAPI ULONG RtlNumberOfSetBitsUlongPtr(
		[in] ULONG_PTR Target);

//RtlOemStringToUnicodeSize

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtloemstringtounicodestring
	NTSYSAPI NTSTATUS RtlOemStringToUnicodeString(
		PUNICODE_STRING DestinationString,
		[in] PCOEM_STRING    SourceString,
		[in] BOOLEAN         AllocateDestinationString);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtloemtounicoden
	NTSYSAPI NTSTATUS RtlOemToUnicodeN(
		[out]           PWCH   UnicodeString,
		[in]            ULONG  MaxBytesInUnicodeString,
		[out, optional] PULONG BytesInUnicodeString,
		[in]            PCCH   OemString,
		[in]            ULONG  BytesInOemString);

	//RtlOpenCurrentUser
//RtlOsDeploymentState
//RtlOwnerAcesPresent
//RtlPopFrame
//RtlPrefixString

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlprefixunicodestring
	NTSYSAPI BOOLEAN RtlPrefixUnicodeString(
		[in] PCUNICODE_STRING String1,
		[in] PCUNICODE_STRING String2,
		[in] BOOLEAN          CaseInSensitive);

//RtlPrepareForProcessCloning
//RtlProcessFlsData
//RtlProtectHeap
//RtlPublishWnfStateData
//RtlPushFrame
//RtlQueryActivationContextApplicationSettings
//RtlQueryAllFeatureConfigurations
//RtlQueryCriticalSectionOwner
//RtlQueryDepthSList
//RtlQueryDynamicTimeZoneInformation
//RtlQueryElevationFlags
//RtlQueryEnvironmentVariable
//RtlQueryEnvironmentVariable_U
//RtlQueryFeatureConfiguration
//RtlQueryFeatureConfigurationChangeStamp
//RtlQueryFeatureUsageNotificationSubscriptions
//RtlQueryHeapInformation
//RtlQueryImageMitigationPolicy
//RtlQueryInformationAcl
//RtlQueryInformationActivationContext
//RtlQueryInformationActiveActivationContext
//RtlQueryInterfaceMemoryStream
//RtlQueryModuleInformation
//RtlQueryPackageClaims

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

	//RtlQueryPerformanceCounter
//RtlQueryPerformanceFrequency
//RtlQueryProcessBackTraceInformation
//RtlQueryProcessDebugInformation
//RtlQueryProcessHeapInformation
//RtlQueryProcessLockInformation

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlqueryprocessplaceholdercompatibilitymode
	NTSYSAPI CHAR RtlQueryProcessPlaceholderCompatibilityMode();

	//RtlQueryProtectedPolicy

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
//RtlQueryResourcePolicy
//RtlQuerySecurityObject
//RtlQueryTagHeap

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlquerythreadplaceholdercompatibilitymode
	NTSYSAPI CHAR RtlQueryThreadPlaceholderCompatibilityMode();

//RtlQueryThreadProfiling
//RtlQueryTimeZoneInformation
//RtlQueryTokenHostIdAsUlong64
//RtlQueryUmsThreadInformation
//RtlQueryUnbiasedInterruptTime
//RtlQueryValidationRunlevel
//RtlQueryWnfMetaNotification
//RtlQueryWnfStateData
//RtlQueryWnfStateDataWithExplicitScope
//RtlQueueApcWow64Thread
//RtlQueueWorkItem

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlraisecustomsystemeventtrigger
	NTSTATUS RtlRaiseCustomSystemEventTrigger(
		[_In_] PCUSTOM_SYSTEM_EVENT_TRIGGER_CONFIG TriggerConfig);

//RtlRaiseException
//RtlRaiseExceptionForReturnAddressHijack
//RtlRaiseNoncontinuableException
//RtlRaiseStatus

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlrandom
	NTSYSAPI ULONG RtlRandom(
		[in, out] PULONG Seed);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlrandomex
	NTSYSAPI ULONG RtlRandomEx(
		[in, out] PULONG Seed);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	void WINAPI RtlRbInsertNodeEx(RTL_RB_TREE* tree, RTL_BALANCED_NODE* parent, BOOLEAN right, RTL_BALANCED_NODE* node);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	void WINAPI RtlRbRemoveNode(RTL_RB_TREE* tree, RTL_BALANCED_NODE* node);

	//RtlReAllocateHeap
//RtlReadMemoryStream
//RtlReadOutOfProcessMemoryStream
//RtlReadThreadProfilingData

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	RTL_SPLAY_LINKS* WINAPI RtlRealPredecessor(RTL_SPLAY_LINKS* links);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	RTL_SPLAY_LINKS* WINAPI RtlRealSuccessor(RTL_SPLAY_LINKS* links);

	//RtlRegisterFeatureConfigurationChangeNotification
//RtlRegisterForWnfMetaNotification
//RtlRegisterSecureMemoryCacheCallback
//RtlRegisterThreadWithCsrss
//RtlRegisterWait
//RtlReleaseActivationContext
//RtlReleaseMemoryStream
//RtlReleasePath
//RtlReleasePebLock
//RtlReleasePrivilege
//RtlReleaseRelativeName
//RtlReleaseResource
//RtlReleaseSRWLockExclusive
//RtlReleaseSRWLockShared
//RtlRemoteCall
//RtlRemoveEntryHashTable
//RtlRemovePrivileges
//RtlRemoveVectoredContinueHandler
//RtlRemoveVectoredExceptionHandler
//RtlReplaceSidInSd
//RtlReplaceSystemDirectoryInPath
//RtlReportException
//RtlReportExceptionEx
//RtlReportSilentProcessExit
//RtlReportSqmEscalation
//RtlResetMemoryBlockLookaside
//RtlResetMemoryZone

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	//RtlResetNtUserPfn
	NTSTATUS WINAPI RtlResetNtUserPfn(void);

//RtlResetRtlTranslations
//RtlRestoreBootStatusDefaults
//RtlRestoreContext
//RtlRestoreLastWin32Error
//RtlRestoreSystemBootStatusDefaults
//RtlRestoreThreadPreferredUILanguages

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	//RtlRetrieveNtUserPfn
	NTSTATUS WINAPI RtlRetrieveNtUserPfn(const void** client_procsA,
		const void** client_procsW,
		const void** client_workers);

//RtlRevertMemoryStream
//RtlRunDecodeUnicodeString
//RtlRunEncodeUnicodeString

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

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlsecondssince1970totime
	NTSYSAPI VOID RtlSecondsSince1970ToTime(
		[in]  ULONG          ElapsedSeconds,
		[out] PLARGE_INTEGER Time);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlsecondssince1980totime
	NTSYSAPI VOID RtlSecondsSince1980ToTime(
		[in]  ULONG          ElapsedSeconds,
		[out] PLARGE_INTEGER Time);

//RtlSeekMemoryStream

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlselfrelativetoabsolutesd
	NTSYSAPI NTSTATUS RtlSelfRelativeToAbsoluteSD(
		[in]      PSECURITY_DESCRIPTOR SelfRelativeSecurityDescriptor,
		[out]     PSECURITY_DESCRIPTOR AbsoluteSecurityDescriptor,
		[in, out] PULONG               AbsoluteSecurityDescriptorSize,
		[out]     PACL                 Dacl,
		[in, out] PULONG               DaclSize,
		[out]     PACL                 Sacl,
		[in, out] PULONG               SaclSize,
		[out]     PSID                 Owner,
		[in, out] PULONG               OwnerSize,
		[out]     PSID                 PrimaryGroup,
		[in, out] PULONG               PrimaryGroupSize);

//RtlSelfRelativeToAbsoluteSD2
//RtlSendMsgToSm

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlsetallbits
	NTSYSAPI VOID RtlSetAllBits(
		[in] PRTL_BITMAP BitMapHeader);

//RtlSetAllBitsEx
//RtlSetAttributesSecurityDescriptor

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlsetbit
	NTSYSAPI VOID RtlSetBit(
		[in] PRTL_BITMAP BitMapHeader,
		[in] ULONG       BitNumber);

//RtlSetBitEx

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlsetbits
	NTSYSAPI VOID RtlSetBits(
		[in] PRTL_BITMAP BitMapHeader,
		[in] ULONG       StartingIndex,
		[in] ULONG       NumberToSet);

//RtlSetBitsEx
//RtlSetControlSecurityDescriptor
//RtlSetCriticalSectionSpinCount
//RtlSetCurrentDirectory_U
//RtlSetCurrentEnvironment

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	BOOL WINAPI RtlSetCurrentTransaction(HANDLE new_transaction);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlsetdaclsecuritydescriptor
	NTSYSAPI NTSTATUS RtlSetDaclSecurityDescriptor(
		[in, out]      PSECURITY_DESCRIPTOR SecurityDescriptor,
		[in]           BOOLEAN              DaclPresent,
		[in, optional] PACL                 Dacl,
		[in, optional] BOOLEAN              DaclDefaulted);

//RtlSetDynamicTimeZoneInformation
//RtlSetEnvironmentStrings
//RtlSetEnvironmentVar
//RtlSetEnvironmentVariable
//RtlSetExtendedFeaturesMask
//RtlSetFeatureConfigurations

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlsetgroupsecuritydescriptor
	NTSYSAPI NTSTATUS RtlSetGroupSecurityDescriptor(
		[in, out]      PSECURITY_DESCRIPTOR SecurityDescriptor,
		[in, optional] PSID                 Group,
		[in, optional] BOOLEAN              GroupDefaulted);

//RtlSetHeapInformation
//RtlSetImageMitigationPolicy
//RtlSetInformationAcl
//RtlSetIoCompletionCallback
//RtlSetLastWin32Error
//RtlSetLastWin32ErrorAndNtStatusFromNtStatus
//RtlSetMemoryStreamSize

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlsetownersecuritydescriptor
	NTSYSAPI NTSTATUS RtlSetOwnerSecurityDescriptor(
		[in, out]      PSECURITY_DESCRIPTOR SecurityDescriptor,
		[in, optional] PSID                 Owner,
		[in, optional] BOOLEAN              OwnerDefaulted);

//RtlSetPortableOperatingSystem
//RtlSetProcessDebugInformation
//RtlSetProcessIsCritical

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlsetprocessplaceholdercompatibilitymode
	NTSYSAPI CHAR RtlSetProcessPlaceholderCompatibilityMode(
		CHAR Mode);

//RtlSetProcessPreferredUILanguages
//RtlSetProtectedPolicy
//RtlSetProxiedProcessId
//RtlSetSaclSecurityDescriptor
//RtlSetSearchPathMode
//RtlSetSecurityDescriptorRMControl
//RtlSetSecurityObject
//RtlSetSecurityObjectEx
//RtlSetSystemBootStatus
//RtlSetSystemBootStatusEx
//RtlSetThreadErrorMode
//RtlSetThreadIsCritical

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlsetthreadplaceholdercompatibilitymode
	NTSYSAPI CHAR RtlSetThreadPlaceholderCompatibilityMode(
		[in] CHAR Mode);

//RtlSetThreadPoolStartFunc
//RtlSetThreadPreferredUILanguages
//RtlSetThreadPreferredUILanguages2
//RtlSetThreadSubProcessTag
//RtlSetThreadWorkOnBehalfTicket
//RtlSetTimeZoneInformation
//RtlSetTimer
//RtlSetUmsThreadInformation
//RtlSetUnhandledExceptionFilter
//RtlSetUserFlagsHeap
//RtlSetUserValueHeap
//RtlSidDominates
//RtlSidDominatesForTrust
//RtlSidEqualLevel
//RtlSidHashInitialize
//RtlSidHashLookup
//RtlSidIsHigherLevel
//RtlSizeHeap
//RtlSleepConditionVariableCS
//RtlSleepConditionVariableSRW

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	RTL_SPLAY_LINKS* WINAPI RtlSplay(RTL_SPLAY_LINKS* links);

//RtlStartRXact
//RtlStatMemoryStream

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlstringfromguid
	NTSYSAPI NTSTATUS RtlStringFromGUID(
		[in]  REFGUID         Guid,
		[out] PUNICODE_STRING GuidString);

//RtlStringFromGUIDEx
//RtlStronglyEnumerateEntryHashTable

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlsubauthoritycountsid
	NTSYSAPI PUCHAR RtlSubAuthorityCountSid(
		PSID Sid);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlsubauthoritysid
	NTSYSAPI PULONG RtlSubAuthoritySid(
		[in] PSID  Sid,
		ULONG SubAuthority);
	
	//RtlSubscribeForFeatureUsageNotification
//RtlSubscribeWnfStateChangeNotification

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	RTL_SPLAY_LINKS* WINAPI RtlSubtreePredecessor(RTL_SPLAY_LINKS* links);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	RTL_SPLAY_LINKS* WINAPI RtlSubtreeSuccessor(RTL_SPLAY_LINKS* links);

	//RtlSwitchedVVI
//RtlSystemTimeToLocalTime
//RtlTestAndPublishWnfStateData

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtltestbit
	NTSYSAPI BOOLEAN RtlTestBit(
		[in] PRTL_BITMAP BitMapHeader,
		[in] ULONG       BitNumber);

//RtlTestBitEx
//RtlTestProtectedAccess

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtltimefieldstotime
	NTSYSAPI BOOLEAN RtlTimeFieldsToTime(
		[in]  PTIME_FIELDS   TimeFields,
		[out] PLARGE_INTEGER Time);

	//RtlTimeToElapsedTimeFields

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtltimetosecondssince1970
	// See winternl.h
	// RtlTimeToSecondsSince1970

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtltimetosecondssince1980
	NTSYSAPI BOOLEAN RtlTimeToSecondsSince1980(
		[in]  PLARGE_INTEGER Time,
		[out] PULONG         ElapsedSeconds);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtltimetotimefields
	NTSYSAPI VOID RtlTimeToTimeFields(
		[in]  PLARGE_INTEGER Time,
		[out] PTIME_FIELDS   TimeFields);

	//RtlTraceDatabaseAdd
//RtlTraceDatabaseCreate
//RtlTraceDatabaseDestroy
//RtlTraceDatabaseEnumerate
//RtlTraceDatabaseFind
//RtlTraceDatabaseLock
//RtlTraceDatabaseUnlock
//RtlTraceDatabaseValidate
//RtlTryAcquirePebLock
//RtlTryAcquireSRWLockExclusive
//RtlTryAcquireSRWLockShared
//RtlTryConvertSRWLockSharedToExclusiveOrRelease
//RtlTryEnterCriticalSection

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlutf8stringtounicodestring
	NTSYSAPI NTSTATUS RtlUTF8StringToUnicodeString(
		PUNICODE_STRING DestinationString,
		PUTF8_STRING    SourceString,
		BOOLEAN         AllocateDestinationString);

	//https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlutf8tounicoden
	NTSYSAPI NTSTATUS RtlUTF8ToUnicodeN(
		[out, optional] PWSTR  UnicodeStringDestination,
		[in]            ULONG  UnicodeStringMaxByteCount,
		[out]           PULONG UnicodeStringActualByteCount,
		[in]            PCCH   UTF8StringSource,
		[in]            ULONG  UTF8StringByteCount);

	//RtlUdiv128
//RtlUmsThreadYield
//RtlUnhandledExceptionFilter
//RtlUnhandledExceptionFilter2

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlunicodestringtoansisize
	void RtlUnicodeStringToAnsiSize(
		[in]  STRING);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlunicodestringtoansistring
	// See winterl.h
	// RtlUnicodeStringToAnsiString

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlunicodestringtocountedoemstring
	NTSYSAPI NTSTATUS RtlUnicodeStringToCountedOemString(
		POEM_STRING      DestinationString,
		[in] PCUNICODE_STRING SourceString,
		[in] BOOLEAN          AllocateDestinationString);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlunicodestringtoansistring
	NTSYSAPI NTSTATUS RtlUnicodeStringToAnsiString(
		[in, out] PANSI_STRING     DestinationString,
		[in]      PCUNICODE_STRING SourceString,
		[in]      BOOLEAN          AllocateDestinationString);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlunicodestringtooemsize
	void RtlUnicodeStringToOemSize(
		STRING);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlunicodestringtooemstring
	// See winterl.h
	// RtlUnicodeStringToOemString

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
		[out]           PCHAR  MultiByteString,
		[in]            ULONG  MaxBytesInMultiByteString,
		[out, optional] PULONG BytesInMultiByteString,
		[in]            PCWCH  UnicodeString,
		[in]            ULONG  BytesInUnicodeString);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlunicodetomultibytesize
	// See winterl.h
	// RtlUnicodeToMultiByteSize

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlunicodetooemn
	NTSYSAPI NTSTATUS RtlUnicodeToOemN(
		[out]           PCHAR  OemString,
		[in]            ULONG  MaxBytesInOemString,
		[out, optional] PULONG BytesInOemString,
		[in]            PCWCH  UnicodeString,
		[in]            ULONG  BytesInUnicodeString);

	//https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlunicodetoutf8n
	NTSYSAPI NTSTATUS RtlUnicodeToUTF8N(
		[out] PCHAR  UTF8StringDestination,
		[in]  ULONG  UTF8StringMaxByteCount,
		[out] PULONG UTF8StringActualByteCount,
		[in]  PCWCH  UnicodeStringSource,
		[in]  ULONG  UnicodeStringByteCount);

	// See winterl.h
	// RtlUniform

	//RtlUnlockBootStatusData
//RtlUnlockCurrentThread
//RtlUnlockHeap
//RtlUnlockMemoryBlockLookaside
//RtlUnlockMemoryStreamRegion
//RtlUnlockMemoryZone
//RtlUnlockModuleSection
//RtlUnregisterFeatureConfigurationChangeNotification
//RtlUnsubscribeFromFeatureUsageNotifications
//RtlUnsubscribeWnfNotificationWaitForCompletion
//RtlUnsubscribeWnfNotificationWithCompletionCallback
//RtlUnsubscribeWnfStateChangeNotification
//RtlUnwind
//RtlUnwindEx
//RtlUpcaseUnicodeChar

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlupcaseunicodestring
	NTSYSAPI NTSTATUS RtlUpcaseUnicodeString(
		[in, out] PUNICODE_STRING  DestinationString,
		[in]      PCUNICODE_STRING SourceString,
		[in]      BOOLEAN          AllocateDestinationString);

//RtlUpcaseUnicodeStringToAnsiString

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlupcaseunicodestringtocountedoemstring
	NTSYSAPI NTSTATUS RtlUpcaseUnicodeStringToCountedOemString(
		POEM_STRING      DestinationString,
		[in] PCUNICODE_STRING SourceString,
		[in] BOOLEAN          AllocateDestinationString);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlupcaseunicodestringtooemstring
	NTSYSAPI NTSTATUS RtlUpcaseUnicodeStringToOemString(
		POEM_STRING      DestinationString,
		[in] PCUNICODE_STRING SourceString,
		[in] BOOLEAN          AllocateDestinationString);

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
		[out]           PCHAR  MultiByteString,
		[in]            ULONG  MaxBytesInMultiByteString,
		[out, optional] PULONG BytesInMultiByteString,
		[in]            PCWCH  UnicodeString,
		[in]            ULONG  BytesInUnicodeString);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlupcaseunicodetooemn
	NTSYSAPI NTSTATUS RtlUpcaseUnicodeToOemN(
		[out]           PCHAR  OemString,
		[in]            ULONG  MaxBytesInOemString,
		[out, optional] PULONG BytesInOemString,
		[in]            PCWCH  UnicodeString,
		[in]            ULONG  BytesInUnicodeString);

	//RtlUpdateClonedCriticalSection
//RtlUpdateClonedSRWLock
//RtlUpdateTimer
	
	//https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlupperchar
	NTSYSAPI CHAR RtlUpperChar(
		[in] CHAR Character);

	//https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlupperstring
	NTSYSAPI VOID RtlUpperString(
		[in, out] PSTRING      DestinationString,
		[in]      const STRING* SourceString);

//RtlUserFiberStart
//RtlUserThreadStart
//RtlValidAcl
//RtlValidProcessProtection
//RtlValidRelativeSecurityDescriptor
//RtlValidSecurityDescriptor
	
	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlvalidsid
	NTSYSAPI BOOLEAN RtlValidSid(
		[in] PSID Sid);

	//https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlvalidatecorrelationvector
	NTSYSAPI NTSTATUS RtlValidateCorrelationVector(
		PCORRELATION_VECTOR Vector);

	//RtlValidateHeap
//RtlValidateProcessHeaps
//RtlValidateUnicodeString

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlverifyversioninfo
	NTSYSAPI NTSTATUS RtlVerifyVersionInfo(
		[in] PRTL_OSVERSIONINFOEXW VersionInfo,
		[in] ULONG                 TypeMask,
		[in] ULONGLONG             ConditionMask);

//RtlVirtualUnwind
//RtlWaitForWnfMetaNotification
//RtlWaitOnAddress
//RtlWakeAddressAll
//RtlWakeAddressAllNoFence
//RtlWakeAddressSingle
//RtlWakeAddressSingleNoFence
//RtlWakeAllConditionVariable
//RtlWakeConditionVariable
//RtlWalkFrameChain
//RtlWalkHeap
//RtlWeaklyEnumerateEntryHashTable
//RtlWerpReportException
//RtlWnfCompareChangeStamp
//RtlWnfDllUnloadCallback
//RtlWow64CallFunction64

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/process.c
	NTSTATUS WINAPI RtlWow64EnableFsRedirection(BOOLEAN enable);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/process.c
	NTSTATUS WINAPI RtlWow64EnableFsRedirectionEx(ULONG disable, ULONG* old_value);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/process.c
	NTSTATUS WINAPI RtlWow64GetCpuAreaInfo(WOW64_CPURESERVED* cpu, ULONG reserved, WOW64_CPU_AREA_INFO* info);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/process.c
	NTSTATUS WINAPI RtlWow64GetCurrentCpuArea(USHORT* machine, void** context, void** context_ex);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/process.c
	USHORT WINAPI RtlWow64GetCurrentMachine(void);

//RtlWow64GetEquivalentMachineCHPE

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/process.c
	NTSTATUS WINAPI RtlWow64GetProcessMachines(HANDLE process, USHORT* current_ret, USHORT* native_ret);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/process.c
	NTSTATUS WINAPI RtlWow64GetSharedInfoProcess(HANDLE process, BOOLEAN* is_wow64, WOW64INFO* info);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/process.c
	NTSTATUS WINAPI RtlWow64GetThreadContext(HANDLE handle, WOW64_CONTEXT* context);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/process.c
	NTSTATUS WINAPI RtlWow64GetThreadSelectorEntry(HANDLE handle, THREAD_DESCRIPTOR_INFORMATION* info,
		ULONG size, ULONG* retlen);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/process.c
	NTSTATUS WINAPI RtlWow64IsWowGuestMachineSupported(USHORT machine, BOOLEAN* supported);

//RtlWow64LogMessageInEventLogger

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/process.c
	CROSS_PROCESS_WORK_ENTRY* WINAPI RtlWow64PopAllCrossProcessWorkFromWorkList(CROSS_PROCESS_WORK_HDR* list, BOOLEAN* flush);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/process.c
	CROSS_PROCESS_WORK_ENTRY* WINAPI RtlWow64PopCrossProcessWorkFromFreeList(CROSS_PROCESS_WORK_HDR* list);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/process.c
	BOOLEAN WINAPI RtlWow64PushCrossProcessWorkOntoFreeList(CROSS_PROCESS_WORK_HDR* list, CROSS_PROCESS_WORK_ENTRY* entry);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/process.c
	BOOLEAN WINAPI RtlWow64PushCrossProcessWorkOntoWorkList(CROSS_PROCESS_WORK_HDR* list, CROSS_PROCESS_WORK_ENTRY* entry, void** unknown);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/process.c
	BOOLEAN WINAPI RtlWow64RequestCrossProcessHeavyFlush(CROSS_PROCESS_WORK_HDR* list);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/process.c
	NTSTATUS WINAPI RtlWow64SetThreadContext(HANDLE handle, const WOW64_CONTEXT* context);

//RtlWow64SuspendProcess
//RtlWow64SuspendThread
//RtlWriteMemoryStream
//RtlWriteNonVolatileMemory

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlwriteregistryvalue
	NTSYSAPI NTSTATUS RtlWriteRegistryValue(
		[in]           ULONG  RelativeTo,
		[in]           PCWSTR Path,
		[in]           PCWSTR ValueName,
		[in]           ULONG  ValueType,
		[in, optional] PVOID  ValueData,
		[in]           ULONG  ValueLength);

//RtlZeroHeap

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlzeromemory
	void RtlZeroMemory(
		void* Destination,
		size_t Length);

//RtlZombifyActivationContext
//RtlpApplyLengthFunction
//RtlpCheckDynamicTimeZoneInformation
//RtlpCleanupRegistryKeys
//RtlpConvertAbsoluteToRelativeSecurityAttribute
//RtlpConvertCultureNamesToLCIDs
//RtlpConvertLCIDsToCultureNames
//RtlpConvertRelativeToAbsoluteSecurityAttribute
//RtlpCreateProcessRegistryInfo
//RtlpEnsureBufferSize
//RtlpExecuteUmsThread
//RtlpFreezeTimeBias
//RtlpGetDeviceFamilyInfoEnum
//RtlpGetLCIDFromLangInfoNode
//RtlpGetNameFromLangInfoNode
//RtlpGetSystemDefaultUILanguage
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
//RtlpQueryProcessDebugInformationFromWow64
//RtlpQueryProcessDebugInformationRemote
//RtlpRefreshCachedUILanguage
//RtlpSetInstallLanguage
//RtlpSetPreferredUILanguages
//RtlpSetUserPreferredUILanguages
//RtlpTimeFieldsToTime
//RtlpTimeToTimeFields
//RtlpUmsExecuteYieldThreadEnd
//RtlpUmsThreadYield
//RtlpUnWaitCriticalSection
//RtlpVerifyAndCommitUILanguageSettings
//RtlpWaitForCriticalSection
//RtlpWow64CtxFromAmd64
//RtlpWow64GetContextOnAmd64
//RtlpWow64SetContextOnAmd64
//RtlxAnsiStringToUnicodeSize

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlxoemstringtounicodesize
	NTSYSAPI ULONG RtlxOemStringToUnicodeSize(
		PCOEM_STRING OemString);

//RtlxUnicodeStringToAnsiSize

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlxunicodestringtooemsize
	NTSYSAPI ULONG RtlxUnicodeStringToOemSize(
		PCUNICODE_STRING UnicodeString);

//SbExecuteProcedure
//SbSelectProcedure
//ShipAssert
//ShipAssertGetBufferInfo
//ShipAssertMsgA
//ShipAssertMsgW


//VerSetConditionMask

//WerReportExceptionWorker
//WerReportSQMEvent

//WinSqmAddToAverageDWORD
//WinSqmAddToStream
//WinSqmAddToStreamEx
//WinSqmCheckEscalationAddToStreamEx
//WinSqmCheckEscalationSetDWORD
//WinSqmCheckEscalationSetDWORD64
//WinSqmCheckEscalationSetString
//WinSqmCommonDatapointDelete
//WinSqmCommonDatapointSetDWORD
//WinSqmCommonDatapointSetDWORD64
//WinSqmCommonDatapointSetStreamEx
//WinSqmCommonDatapointSetString
//WinSqmEndSession
//WinSqmEventEnabled
//WinSqmEventWrite
//WinSqmGetEscalationRuleStatus
//WinSqmGetInstrumentationProperty
//WinSqmIncrementDWORD
//WinSqmIsOptedIn
//WinSqmIsOptedInEx
//WinSqmIsSessionDisabled
//WinSqmSetDWORD
//WinSqmSetDWORD64
//WinSqmSetEscalationInfo
//WinSqmSetIfMaxDWORD
//WinSqmSetIfMinDWORD
//WinSqmSetString
//WinSqmStartSession
//WinSqmStartSessionForPartner
//WinSqmStartSqmOptinListener

}

#endif
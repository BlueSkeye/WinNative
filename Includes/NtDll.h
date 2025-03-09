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

	// https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
	NTSYSCALLAPI NTSTATUS NTAPI NtTerminateEnclave(
		_In_ PVOID BaseAddress,
		_In_ BOOLEAN WaitForThread);
	//ZwTerminateEnclave

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

	//RtlAcquireResourceShared
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

//RtlAllocateActivationContextStack
//RtlAllocateHandle

//RtlAllocateWnfSerializationGroup
//RtlAppendPathElement

//RtlApplicationVerifierStop
//RtlApplyRXact
//RtlApplyRXactNoFlush

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
//RtlCompareAltitudes

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
	DWORD WINAPI RtlComputeCrc32(DWORD dwInitial, const BYTE* pData, INT iLen);

//RtlComputePrivatizedDllName_U
//RtlConnectToSm
//RtlConsoleMultiByteToUnicodeN
//RtlConstructCrossVmEventPath
//RtlConstructCrossVmMutexPath

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	DWORD WINAPI RtlConvertDeviceFamilyInfoToString(DWORD* device_family_size, DWORD* device_form_size,
		WCHAR* device_family, WCHAR* device_form);

//RtlConvertExclusiveToShared
//RtlConvertLCIDToString
//RtlConvertSRWLockExclusiveToShared
//RtlConvertSharedToExclusive

//RtlCopyBitMap
//RtlCopyContext
//RtlCopyExtendedContext

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlcopyluid
	NTSYSAPI VOID RtlCopyLuid(
		[out] PLUID DestinationLuid,
		[in]  PLUID SourceLuid);

//RtlCopyLuidAndAttributesArray

//RtlCrc32
//RtlCrc64
//RtlCreateEnvironment
//RtlCreateEnvironmentEx

//RtlCreateQueryDebugBuffer

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlcreateregistrykey
	NTSYSAPI NTSTATUS RtlCreateRegistryKey(
		[in] ULONG RelativeTo,
		[in] PWSTR Path);

//RtlCreateSystemVolumeInformationFolder
//RtlCreateTimer
//RtlCreateTimerQueue
//RtlCreateUmsCompletionList
//RtlCreateUmsThreadContext

//RtlCreateUserFiberShadowStack

//RtlCreateUserSecurityObject
//RtlCreateUserStack
//RtlCreateUserThread
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

//RtlDeactivateActivationContextUnsafeFast

	// Reversed. Empty function always returning 0. Arguments unknown may not be VOID.
	NTSYSAPI NTSTATUS NTAPI RtlDebugPrintTimes(VOID);

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

//RtlDeleteBarrier
//RtlDeleteCriticalSection

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtldeleteregistryvalue
	NTSYSAPI NTSTATUS RtlDeleteRegistryValue(
		[in] ULONG  RelativeTo,
		[in] PCWSTR Path,
		[in] PCWSTR ValueName);

	//RtlDeleteResource
//RtlDeleteTimer
//RtlDeleteTimerQueue
//RtlDeleteTimerQueueEx
//RtlDeleteUmsCompletionList
//RtlDeleteUmsThreadContext
//RtlDequeueUmsCompletionListItems
//RtlDeregisterWait
//RtlDeregisterWaitEx
//RtlDestroyEnvironment

//RtlDestroyQueryDebugBuffer
//RtlDetermineDosPathNameType_U
//RtlDisableThreadProfiling
//RtlDllShutdownInProgress
//RtlDnsHostNameToComputerName

//RtlDrainNonVolatileFlush
//RtlDumpResource
//RtlEnableEarlyCriticalSectionEventCreation
//RtlEnableThreadProfiling
//RtlEnclaveCallDispatch
//RtlEnclaveCallDispatchReturn

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	PVOID WINAPI RtlEncodePointer(PVOID ptr);

//RtlEncodeRemotePointer
//RtlEncodeSystemPointer
//RtlEnterCriticalSection
//RtlEnterUmsSchedulingMode

	//RtlEqualComputerName

	//RtlEqualDomainName

	//RtlEqualLuid

	//RtlEqualWnfChangeStamps
//RtlEthernetAddressToStringA
//RtlEthernetAddressToStringW
//RtlEthernetStringToAddressA
//RtlEthernetStringToAddressW
//RtlExecuteUmsThread
//RtlExpandEnvironmentStrings
//RtlExpandEnvironmentStrings_U

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlextendcorrelationvector
	NTSYSAPI NTSTATUS RtlExtendCorrelationVector(
		[in, out] PCORRELATION_VECTOR CorrelationVector);

//RtlExtractBitMap

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

//RtlFlsAlloc
//RtlFlsFree
//RtlFlsGetValue
//RtlFlsSetValue

	// https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/rtl/regutil/formatcurrentuserkeypath.htm?ta=8.199996948242188&tx=91,109,113;90,103&ts=0,217
	NTSYSAPI NTSTATUS RtlFormatCurrentUserKeyPath(
		UNICODE_STRING* CurrentUserKeyPath);

//RtlFormatMessage
//RtlFormatMessageEx

//RtlFreeHandle

//RtlFreeUserFiberShadowStack
//RtlFreeUserStack

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlgenerate8dot3name
	NTSYSAPI NTSTATUS RtlGenerate8dot3Name(
		[in]      PCUNICODE_STRING       Name,
		[in]      BOOLEAN                AllowExtendedCharacters,
		[in, out] PGENERATE_NAME_CONTEXT Context,
		[in, out] PUNICODE_STRING        Name8dot3);

	//RtlGetActiveConsoleId
//RtlGetAppContainerNamedObjectPath
//RtlGetAppContainerParent
//RtlGetCallersAddress

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlgetcompressionworkspacesize
	NT_RTL_COMPRESS_API NTSTATUS RtlGetCompressionWorkSpaceSize(
		[in]  USHORT CompressionFormatAndEngine,
		[out] PULONG CompressBufferWorkSpaceSize,
		[out] PULONG CompressFragmentWorkSpaceSize);

//RtlGetCriticalSectionRecursionCount
//RtlGetCurrentDirectory_U

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/process.c
	NTSYSAPI PEB* WINAPI RtlGetCurrentPeb(VOID);

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	NTSYSAPI void WINAPI RtlGetCurrentProcessorNumberEx(
		_Out_ PROCESSOR_NUMBER* processor);

//RtlGetCurrentServiceSessionId

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	HANDLE WINAPI RtlGetCurrentTransaction(void);

//RtlGetCurrentUmsThread

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	void WINAPI RtlGetDeviceFamilyInfoEnum(ULONGLONG* version, DWORD* family, DWORD* form);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlgetenabledextendedfeatures
	NTSYSAPI ULONG64 RtlGetEnabledExtendedFeatures(
		[in] ULONG64 FeatureMask);

//RtlGetExePath
//RtlGetExtendedContextLength
//RtlGetExtendedContextLength2
//RtlGetExtendedFeaturesMask
//RtlGetFrame

//RtlGetInterruptTimePrecise
//RtlGetLastNtStatus
//RtlGetLastWin32Error
//RtlGetMultiTimePrecise
//RtlGetNativeSystemInformation
//RtlGetNextUmsListItem
//RtlGetNtGlobalFlags
//RtlGetNtProductType
//RtlGetNtSystemRoot
//RtlGetNtVersionNumbers
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

//RtlGetProductInfo
//RtlGetReturnAddressHijackTarget

	//RtlGetSearchPath
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
//RtlGetUserPreferredUILanguages

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlgetversion
	NTSYSAPI NTSTATUS RtlGetVersion(
		[out] PRTL_OSVERSIONINFOW lpVersionInformation);

//RtlGuardCheckLongJumpTarget

	//RtlIdnToAscii
//RtlIdnToNameprepUnicode
//RtlIdnToUnicode
//RtlImageDirectoryEntryToData
//RtlImageNtHeader
//RtlImageNtHeaderEx
//RtlImageRvaToSection
//RtlImageRvaToVa

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlincrementcorrelationvector
	NTSYSAPI NTSTATUS RtlIncrementCorrelationVector(
		[in, out] PCORRELATION_VECTOR CorrelationVector);
//RtlInitBarrier

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlinitcodepagetable
	NTSYSAPI VOID RtlInitCodePageTable(
		PUSHORT      TableBase,
		PCPTABLEINFO CodePageTable);

//RtlInitNlsTables

	//https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlinitializebitmap
	NTSYSAPI VOID RtlInitializeBitMap(
		[out] PRTL_BITMAP BitMapHeader,
		[in]  __drv_aliasesMem PULONG BitMapBuffer,
		[in]  ULONG SizeOfBitMap);

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
	NTSTATUS WINAPI RtlInitializeNtUserPfn(const void* client_procsA, ULONG procsA_size,
		const void* client_procsW, ULONG procsW_size,
		const void* client_workers, ULONG workers_size);

//RtlInitializeRXact
//RtlInitializeResource
//RtlInitializeSListHead
//RtlInitializeSRWLock

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

//RtlIsCriticalSectionLocked
//RtlIsCriticalSectionLockedByThread

//RtlIsCurrentThread
//RtlIsCurrentThreadAttachExempt
//RtlIsDosDeviceName_U
//RtlIsElevatedRid
//RtlIsMultiSessionSku
//RtlIsMultiUsersInSessionSku
//RtlIsNonEmptyDirectoryReparsePointAllowed
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
//RtlIsValidHandle
//RtlIsValidIndexHandle
//RtlIsValidLocaleName

//RtlLCIDToCultureName
//RtlLcidToLocaleName
//RtlLeaveCriticalSection

//RtlLocaleNameToLcid
//// See winternl.h
//// RtlLocalTimeToSystemTime
//RtlLocateExtendedFeature
//RtlLocateExtendedFeature2
//RtlLocateLegacyContext
//RtlLockBootStatusData
//RtlLockCurrentThread
//RtlLockModuleSection
//RtlLogStackBackTrace
//RtlLookupFunctionEntry

//RtlMapSecurityErrorToNtStatus

//RtlNotifyFeatureUsage
//RtlNtPathNameToDosPathName

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlntstatustodoserror
	// See winternl.h
	// RtlNtStatusToDosError

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlntstatustodoserrornoteb
	NTSYSAPI ULONG RtlNtStatusToDosErrorNoTeb(
		[in] NTSTATUS Status);

//RtlNtdllName

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

	//RtlOpenCurrentUser
//RtlOsDeploymentState
//RtlPopFrame

//RtlProcessFlsData
//RtlPublishWnfStateData
//RtlPushFrame

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
//RtlQueryImageMitigationPolicy

//RtlQueryInformationActiveActivationContext
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

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlquerythreadplaceholdercompatibilitymode
	NTSYSAPI CHAR RtlQueryThreadPlaceholderCompatibilityMode();

//RtlQueryThreadProfiling
//RtlQueryTimeZoneInformation
//RtlQueryTokenHostIdAsUlong64
//RtlQueryUmsThreadInformation
//RtlQueryUnbiasedInterruptTime
//RtlQueryWnfMetaNotification
//RtlQueryWnfStateData
//RtlQueryWnfStateDataWithExplicitScope
//RtlQueueApcWow64Thread
//RtlQueueWorkItem

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlraisecustomsystemeventtrigger
	NTSTATUS RtlRaiseCustomSystemEventTrigger(
		[_In_] PCUSTOM_SYSTEM_EVENT_TRIGGER_CONFIG TriggerConfig);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlrandom
	NTSYSAPI ULONG RtlRandom(
		[in, out] PULONG Seed);

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlrandomex
	NTSYSAPI ULONG RtlRandomEx(
		[in, out] PULONG Seed);

//RtlReadThreadProfilingData

	//RtlRegisterFeatureConfigurationChangeNotification
//RtlRegisterForWnfMetaNotification
//RtlRegisterThreadWithCsrss
//RtlRegisterWait
//RtlReleasePath
//RtlReleasePebLock
//RtlReleaseRelativeName
//RtlReleaseResource
//RtlReleaseSRWLockExclusive
//RtlReleaseSRWLockShared
//RtlRemoteCall
//RtlReplaceSystemDirectoryInPath
//RtlReportSqmEscalation

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

	//RtlSendMsgToSm

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlsetallbits
	NTSYSAPI VOID RtlSetAllBits(
		[in] PRTL_BITMAP BitMapHeader);

//RtlSetAllBitsEx

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
//RtlSetCriticalSectionSpinCount
//RtlSetCurrentDirectory_U
//RtlSetCurrentEnvironment

	// https://raw.githubusercontent.com/wine-mirror/wine/refs/heads/master/dlls/ntdll/rtl.c
	BOOL WINAPI RtlSetCurrentTransaction(HANDLE new_transaction);

//RtlSetDynamicTimeZoneInformation
//RtlSetEnvironmentStrings
//RtlSetEnvironmentVar
//RtlSetEnvironmentVariable
//RtlSetExtendedFeaturesMask
//RtlSetFeatureConfigurations

//RtlSetImageMitigationPolicy
//RtlSetIoCompletionCallback
//RtlSetLastWin32Error
//RtlSetLastWin32ErrorAndNtStatusFromNtStatus

//RtlSetPortableOperatingSystem
//RtlSetProtectedPolicy
//RtlSetSearchPathMode
//RtlSetSystemBootStatus
//RtlSetSystemBootStatusEx
//RtlSetThreadErrorMode
//RtlSetThreadIsCritical

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlsetthreadplaceholdercompatibilitymode
	NTSYSAPI CHAR RtlSetThreadPlaceholderCompatibilityMode(
		_In_ CHAR Mode);

//RtlSetThreadPoolStartFunc
//RtlSetThreadPreferredUILanguages
//RtlSetThreadPreferredUILanguages2
//RtlSetThreadSubProcessTag
//RtlSetThreadWorkOnBehalfTicket
//RtlSetTimeZoneInformation
//RtlSetTimer
//RtlSetUmsThreadInformation
//RtlSleepConditionVariableCS
//RtlSleepConditionVariableSRW

//RtlStartRXact

	
	//RtlSubscribeForFeatureUsageNotification
//RtlSubscribeWnfStateChangeNotification

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

	//RtlUdiv128
//RtlUmsThreadYield

	// https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-rtluniform
	// See winterl.h
	NTSYSAPI ULONG NTAPI RtlUniform(
		_Inout_ PULONG Seed);

	//RtlUnlockBootStatusData
//RtlUnlockCurrentThread
//RtlUnlockModuleSection
//RtlUnregisterFeatureConfigurationChangeNotification
//RtlUnsubscribeFromFeatureUsageNotifications
//RtlUnsubscribeWnfNotificationWaitForCompletion
//RtlUnsubscribeWnfNotificationWithCompletionCallback
//RtlUnsubscribeWnfStateChangeNotification

	//RtlUpdateClonedCriticalSection
//RtlUpdateClonedSRWLock
//RtlUpdateTimer

//RtlUserFiberStart
//RtlUserThreadStart

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
//RtlWaitOnAddress
//RtlWakeAddressAll
//RtlWakeAddressAllNoFence
//RtlWakeAddressSingle
//RtlWakeAddressSingleNoFence
//RtlWakeAllConditionVariable
//RtlWakeConditionVariable
//RtlWalkFrameChain
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
//RtlpCheckDynamicTimeZoneInformation
//RtlpCleanupRegistryKeys
//RtlpConvertAbsoluteToRelativeSecurityAttribute
//RtlpConvertCultureNamesToLCIDs
//RtlpConvertLCIDsToCultureNames
//RtlpConvertRelativeToAbsoluteSecurityAttribute
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
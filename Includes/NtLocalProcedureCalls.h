#pragma once

#ifndef _NTLOCALPROCEDURECALLS_
#define _NTLOCALPROCEDURECALLS_

#include "NtCommonDefs.h"

extern "C" {

    // NO UNRESOLVED FUNCTION

    // https://github.com/winsiderss/systeminformer/blob/0b59400ca381a9c8681abb07a66d77cc55115e63/phnt/include/ntlpcapi.h#L556C1-L571C31
    typedef enum _ALPC_PORT_INFORMATION_CLASS {
        AlpcBasicInformation, // q: out ALPC_BASIC_INFORMATION
        AlpcPortInformation, // s: in ALPC_PORT_ATTRIBUTES
        AlpcAssociateCompletionPortInformation, // s: in ALPC_PORT_ASSOCIATE_COMPLETION_PORT
        AlpcConnectedSIDInformation, // q: in SID
        AlpcServerInformation, // q: inout ALPC_SERVER_INFORMATION
        AlpcMessageZoneInformation, // s: in ALPC_PORT_MESSAGE_ZONE_INFORMATION
        AlpcRegisterCompletionListInformation, // s: in ALPC_PORT_COMPLETION_LIST_INFORMATION
        AlpcUnregisterCompletionListInformation, // s: VOID
        AlpcAdjustCompletionListConcurrencyCountInformation, // s: in ULONG
        AlpcRegisterCallbackInformation, // s: ALPC_REGISTER_CALLBACK // kernel-mode only
        AlpcCompletionListRundownInformation, // s: VOID // 10
        AlpcWaitForPortReferences,
        AlpcServerSessionInformation // q: ALPC_SERVER_SESSION_INFORMATION // since 19H2
    } ALPC_PORT_INFORMATION_CLASS;

    // https://github.com/winsiderss/systeminformer/blob/0b59400ca381a9c8681abb07a66d77cc55115e63/phnt/include/ntlpcapi.h#L13C1-L44C32
    typedef struct _PORT_MESSAGE {
        union {
            struct {
                CSHORT DataLength;
                CSHORT TotalLength;
            } s1;
            ULONG Length;
        } u1;
        union {
            struct {
                CSHORT Type;
                CSHORT DataInfoOffset;
            } s2;
            ULONG ZeroInit;
        } u2;
        union {
            CLIENT_ID ClientId;
            double DoNotUseThisField;
        };
        ULONG MessageId;
        union {
            SIZE_T ClientViewSize; // only valid for LPC_CONNECTION_REQUEST messages
            ULONG CallbackId; // only valid for LPC_REQUEST messages
        };
    } PORT_MESSAGE, * PPORT_MESSAGE;

    // https://github.com/winsiderss/systeminformer/blob/0b59400ca381a9c8681abb07a66d77cc55115e63/phnt/include/ntlpcapi.h#L92C1-L100C26
    typedef struct _PORT_VIEW {
        ULONG Length;
        HANDLE SectionHandle;
        ULONG SectionOffset;
        SIZE_T ViewSize;
        PVOID ViewBase;
        PVOID ViewRemoteBase;
    } PORT_VIEW, * PPORT_VIEW;

    // https://github.com/winsiderss/systeminformer/blob/0b59400ca381a9c8681abb07a66d77cc55115e63/phnt/include/ntlpcapi.h#L102C1-L107C40
    typedef struct _REMOTE_PORT_VIEW {
        ULONG Length;
        SIZE_T ViewSize;
        PVOID ViewBase;
    } REMOTE_PORT_VIEW, * PREMOTE_PORT_VIEW;

    // https://github.com/winsiderss/systeminformer/blob/0b59400ca381a9c8681abb07a66d77cc55115e63/phnt/include/ntlpcapi.h#L406C1-L421C1
    typedef struct _ALPC_PORT_ATTRIBUTES {
        ULONG Flags;
        SECURITY_QUALITY_OF_SERVICE SecurityQos;
        SIZE_T MaxMessageLength;
        SIZE_T MemoryBandwidth;
        SIZE_T MaxPoolUsage;
        SIZE_T MaxSectionSize;
        SIZE_T MaxViewSize;
        SIZE_T MaxTotalSectionSize;
        ULONG DupObjectTypes;
        ULONG Reserved;
    } ALPC_PORT_ATTRIBUTES, * PALPC_PORT_ATTRIBUTES;

    // https://github.com/winsiderss/systeminformer/blob/0b59400ca381a9c8681abb07a66d77cc55115e63/phnt/include/ntlpcapi.h#L480C1-L487C42
    typedef struct _ALPC_CONTEXT_ATTR {
        PVOID PortContext;
        PVOID MessageContext;
        ULONG Sequence;
        ULONG MessageId;
        ULONG CallbackId;
    } ALPC_CONTEXT_ATTR, * PALPC_CONTEXT_ATTR;

    // https://github.com/winsiderss/systeminformer/blob/0b59400ca381a9c8681abb07a66d77cc55115e63/phnt/include/ntlpcapi.h#L430C1-L434C54
    typedef struct _ALPC_MESSAGE_ATTRIBUTES {
        ULONG AllocatedAttributes;
        ULONG ValidAttributes;
    } ALPC_MESSAGE_ATTRIBUTES, * PALPC_MESSAGE_ATTRIBUTES;

    typedef HANDLE ALPC_HANDLE, * PALPC_HANDLE;

    // https://github.com/winsiderss/systeminformer/blob/0b59400ca381a9c8681abb07a66d77cc55115e63/phnt/include/ntlpcapi.h#L547C1-L554C1
    typedef struct _ALPC_DATA_VIEW_ATTR {
        ULONG Flags;
        ALPC_HANDLE SectionHandle;
        PVOID ViewBase; // must be zero on input
        SIZE_T ViewSize;
    } ALPC_DATA_VIEW_ATTR, * PALPC_DATA_VIEW_ATTR;

    typedef struct _ALPC_SECURITY_ATTR {
        ULONG Flags;
        PSECURITY_QUALITY_OF_SERVICE QoS;
        ALPC_HANDLE ContextHandle; // dbg
    } ALPC_SECURITY_ATTR, * PALPC_SECURITY_ATTR;

    // https://github.com/winsiderss/systeminformer/blob/0b59400ca381a9c8681abb07a66d77cc55115e63/phnt/include/ntlpcapi.h#L637C1-L645C1
    typedef enum _ALPC_MESSAGE_INFORMATION_CLASS {
        AlpcMessageSidInformation, // q: out SID
        AlpcMessageTokenModifiedIdInformation,  // q: out LUID
        AlpcMessageDirectStatusInformation,
        AlpcMessageHandleInformation, // ALPC_MESSAGE_HANDLE_INFORMATION
        MaxAlpcMessageInfoClass
    } ALPC_MESSAGE_INFORMATION_CLASS, * PALPC_MESSAGE_INFORMATION_CLASS;

    // https://github.com/winsiderss/systeminformer/blob/0b59400ca381a9c8681abb07a66d77cc55115e63/phnt/include/ntlpcapi.h#L351C1-L355C26
    typedef enum _PORT_INFORMATION_CLASS {
        PortBasicInformation,
        PortDumpInformation
    } PORT_INFORMATION_CLASS;
    // ============================== functions

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtAcceptConnectPort(
        _Out_ PHANDLE PortHandle,
        _In_opt_ PVOID PortContext,
        _In_ PPORT_MESSAGE ConnectionRequest,
        _In_ BOOLEAN AcceptConnection,
        _Inout_opt_ PPORT_VIEW ServerView,
        _Out_opt_ PREMOTE_PORT_VIEW ClientView);
    //ZwAcceptConnectPort

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtAlpcAcceptConnectPort(
        _Out_ PHANDLE PortHandle,
        _In_ HANDLE ConnectionPortHandle,
        _In_ ULONG Flags,
        _In_ POBJECT_ATTRIBUTES ObjectAttributes,
        _In_ PALPC_PORT_ATTRIBUTES PortAttributes,
        _In_opt_ PVOID PortContext,
        _In_ PPORT_MESSAGE ConnectionRequest,
        _Inout_opt_ PALPC_MESSAGE_ATTRIBUTES ConnectionMessageAttributes,
        _In_ BOOLEAN AcceptConnection);
    //ZwAlpcAcceptConnectPort

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtAlpcCancelMessage(
        _In_ HANDLE PortHandle,
        _In_ ULONG Flags,
        _In_ PALPC_CONTEXT_ATTR MessageContext);
    //ZwAlpcCancelMessage

    // https://github.com/Uri3n/Thread-Pool-Injection-PoC/blob/main/include/FunctionPtrs.hpp
    // https://urien.gitbook.io/diago-lima/a-deep-dive-into-exploiting-windows-thread-pools/attacking-i-o-ports
    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtAlpcConnectPort(
        _Out_ PHANDLE PortHandle,
        _In_ PUNICODE_STRING PortName,
        _In_ POBJECT_ATTRIBUTES ObjectAttributes,
        _In_opt_ PALPC_PORT_ATTRIBUTES PortAttributes,
        _In_ ULONG Flags,
        _In_opt_ PSID RequiredServerSid,
        _Inout_ PPORT_MESSAGE ConnectionMessage,
        _Inout_opt_ PULONG BufferLength,
        _Inout_opt_ PALPC_MESSAGE_ATTRIBUTES OutMessageAttributes,
        _Inout_opt_ PALPC_MESSAGE_ATTRIBUTES InMessageAttributes,
        _In_opt_ PLARGE_INTEGER Timeout);
    //ZwAlpcConnectPort

    // https://github.com/winsiderss/systeminformer/blob/0b59400ca381a9c8681abb07a66d77cc55115e63/phnt/include/ntlpcapi.h#L827C1-L842C7
    NTSYSCALLAPI NTSTATUS NTAPI NtAlpcConnectPortEx(
        _Out_ PHANDLE PortHandle,
        _In_ POBJECT_ATTRIBUTES ConnectionPortObjectAttributes,
        _In_opt_ POBJECT_ATTRIBUTES ClientPortObjectAttributes,
        _In_opt_ PALPC_PORT_ATTRIBUTES PortAttributes,
        _In_ ULONG Flags,
        _In_opt_ PSECURITY_DESCRIPTOR ServerSecurityRequirements,
        _Inout_updates_bytes_to_opt_(*BufferLength, *BufferLength) PPORT_MESSAGE ConnectionMessage,
        _Inout_opt_ PSIZE_T BufferLength,
        _Inout_opt_ PALPC_MESSAGE_ATTRIBUTES OutMessageAttributes,
        _Inout_opt_ PALPC_MESSAGE_ATTRIBUTES InMessageAttributes,
        _In_opt_ PLARGE_INTEGER Timeout);
    //ZwAlpcConnectPortEx

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtAlpcCreatePort(
        _Out_ PHANDLE PortHandle,
        _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
        _In_opt_ PALPC_PORT_ATTRIBUTES PortAttributes);
    //ZwAlpcCreatePort

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtAlpcCreatePortSection(
        _In_ HANDLE PortHandle,
        _In_ ULONG AlpcSectionFlag,
        _In_opt_ HANDLE SectionHandle,
        _In_ ULONG SectionSize,
        _Out_ PHANDLE AlpcSectionHandle,
        _Out_ PULONG ResSize);
    //ZwAlpcCreatePortSection

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtAlpcCreateResourceReserve(
        _In_ HANDLE PortHandle,
        _In_ ULONG Flags,
        _In_ ULONG MessageSize,
        _Out_ PHANDLE ResourceId);
    //ZwAlpcCreateResourceReserve

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtAlpcCreateSectionView(
        _In_ HANDLE PortHandle,
        _Reserved_ ULONG Flags,
        _Inout_ PALPC_DATA_VIEW_ATTR ViewAttributes);
    //ZwAlpcCreateSectionView

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtAlpcCreateSecurityContext(
        _In_ HANDLE PortHandle,
        _In_ ULONG Flags,
        _Inout_ PALPC_SECURITY_ATTR SecurityAttribute);
    //ZwAlpcCreateSecurityContext

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtAlpcDeletePortSection(
        _In_ HANDLE PortHandle,
        _In_ ULONG Flags,
        _In_ HANDLE SectionHandle);
    //ZwAlpcDeletePortSection

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtAlpcDeleteResourceReserve(
        _In_ HANDLE PortHandle,
        _In_ ULONG Flags,
        _In_ HANDLE ResourceHandle);
    //ZwAlpcDeleteResourceReserve

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtAlpcDeleteSectionView(
        _In_ HANDLE PortHandle,
        _In_ ULONG Flags,
        _In_ PVOID ViewBase);
    //ZwAlpcDeleteSectionView

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtAlpcDeleteSecurityContext(
        _In_ HANDLE PortHandle,
        _In_ ULONG Flags,
        _In_ HANDLE ContextHandle);
    //ZwAlpcDeleteSecurityContext

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtAlpcDisconnectPort(
        _In_ HANDLE PortHandle,
        _In_ ULONG Flags);
    //ZwAlpcDisconnectPort

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtAlpcImpersonateClientContainerOfPort(
        _In_ HANDLE PortHandle,
        _In_ PPORT_MESSAGE Message,
        _In_ ULONG Flags);
    //ZwAlpcImpersonateClientContainerOfPort

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtAlpcImpersonateClientOfPort(
        _In_ HANDLE PortHandle,
        _In_ PPORT_MESSAGE PortMessage,
        _In_ PVOID Reserved);
    //ZwAlpcImpersonateClientOfPort

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtAlpcOpenSenderProcess(
        _Out_ PHANDLE ProcessHandle,
        _In_ HANDLE PortHandle,
        _In_ PPORT_MESSAGE PortMessage,
        _In_ ULONG Flags,
        _In_ ACCESS_MASK DesiredAccess,
        _In_ POBJECT_ATTRIBUTES ObjectAttributes);
    //ZwAlpcOpenSenderProcess

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtAlpcOpenSenderThread(
        _Out_ PHANDLE ThreadHandle,
        _In_ HANDLE PortHandle,
        _In_ PPORT_MESSAGE PortMessage,
        _In_ ULONG Flags,
        _In_ ACCESS_MASK DesiredAccess,
        _In_ POBJECT_ATTRIBUTES ObjectAttributes);
    //ZwAlpcOpenSenderThread

    // https://github.com/winsiderss/systeminformer/blob/0b59400ca381a9c8681abb07a66d77cc55115e63/phnt/include/ntlpcapi.h#L680
    NTSYSCALLAPI NTSTATUS NTAPI NtAlpcQueryInformation(
        _In_ HANDLE PortHandle,
        _In_ ALPC_PORT_INFORMATION_CLASS PortInformationClass,
        _Inout_updates_bytes_to_(Length, *ReturnLength)  PVOID PortInformation,
        _In_ ULONG Length,
        _Out_opt_ PULONG ReturnLength);
    //ZwAlpcQueryInformation

    // https://github.com/winsiderss/systeminformer/blob/0b59400ca381a9c8681abb07a66d77cc55115e63/phnt/include/ntlpcapi.h#L788
    NTSYSCALLAPI NTSTATUS NTAPI NtAlpcQueryInformationMessage(
        _In_ HANDLE PortHandle,
        _In_ PPORT_MESSAGE PortMessage,
        _In_ ALPC_MESSAGE_INFORMATION_CLASS MessageInformationClass,
        _Out_writes_bytes_to_opt_(Length, *ReturnLength) PVOID MessageInformation,
        _In_ ULONG Length,
        _Out_opt_ PULONG ReturnLength);

    //ZwAlpcQueryInformationMessage

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtAlpcRevokeSecurityContext(
        _In_ HANDLE PortHandle,
        _In_ ULONG Flags,
        _In_ HANDLE ContextHandle);
    //ZwAlpcRevokeSecurityContext

    // https://github.com/winsiderss/systeminformer/blob/0b59400ca381a9c8681abb07a66d77cc55115e63/phnt/include/ntlpcapi.h#L860
    NTSYSCALLAPI NTSTATUS NTAPI NtAlpcSendWaitReceivePort(
        _In_ HANDLE PortHandle,
        _In_ ULONG SendFlags,
        _In_reads_bytes_opt_(SendMessage->u1.s1.TotalLength) PPORT_MESSAGE SendMessage,
        _Inout_opt_ PVOID InMessageBuffer,
        _Out_writes_bytes_to_opt_(*BufferLength, *BufferLength) PPORT_MESSAGE ReceiveBuffer,
        _Inout_opt_ PULONG ReceiveBufferSize,
        _Inout_opt_ PVOID OutMessageBuffer,
        _In_opt_ PLARGE_INTEGER Timeout);
    //ZwAlpcSendWaitReceivePort

    // https://github.com/Uri3n/Thread-Pool-Injection-PoC/blob/main/include/FunctionPtrs.hpp
    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtAlpcSetInformation(
        _In_ HANDLE PortHandle,
        _In_ ALPC_PORT_INFORMATION_CLASS PortInformationClass,
        _In_ PVOID PortInformation,
        _In_ ULONG Length);
    //ZwAlpcSetInformation

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtCompleteConnectPort(
        _In_ HANDLE PortHandle);
    //ZwCompleteConnectPort

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtConnectPort(
        _Out_ PHANDLE PortHandle,
        _In_ PUNICODE_STRING PortName,
        _In_ PVOID SecurityQos,
        _Inout_opt_ PPORT_VIEW ClientView,
        _Out_opt_ PREMOTE_PORT_VIEW ServerView,
        _Out_opt_ PULONG MaxMsgLength,
        _Inout_opt_ PVOID ConnectionInfo,
        _Inout_opt_ PULONG ConnectionInfoLength);
    //ZwConnectPort

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtCreatePort(
        _Out_ PHANDLE PortHandle,
        _In_ POBJECT_ATTRIBUTES ObjectAttributes,
        _In_ ULONG MaxConnectionInfoLength,
        _In_ ULONG MaxMsgLength,
        _In_ ULONG MaxPoolUsage);
    //ZwCreatePort

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtCreateWaitablePort(
        _Out_ PHANDLE PortHandle,
        _In_ POBJECT_ATTRIBUTES ObjectAttributes,
        _In_ ULONG MaxConnectionInfoLength,
        _In_ ULONG MaxMsgLength,
        _In_ ULONG MaxPoolUsage);
    //ZwCreateWaitablePort

    // https://github.com/winsiderss/systeminformer/blob/0b59400ca381a9c8681abb07a66d77cc55115e63/phnt/include/ntlpcapi.h#L319
    NTSYSCALLAPI NTSTATUS NTAPI NtImpersonateClientOfPort(
        _In_ HANDLE PortHandle,
        _In_ PPORT_MESSAGE Message);
    //ZwImpersonateClientOfPort

    // https://github.com/winsiderss/systeminformer/blob/0b59400ca381a9c8681abb07a66d77cc55115e63/phnt/include/ntlpcapi.h#L234
    NTSYSCALLAPI NTSTATUS NTAPI NtListenPort(
        _In_ HANDLE Handle,
        _Out_ PPORT_MESSAGE ConnectionData);
    //ZwListenPort

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtQueryInformationPort(
        _In_ HANDLE JobHandle,
        _In_ PORT_INFORMATION_CLASS PortInformationClass,
        _Out_writes_bytes_to_(Length, *ReturnLength) PVOID PortInformation,
        _In_ ULONG Length,
        _Out_opt_ PULONG ReturnLength);
    //ZwQueryInformationPort

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtQueryPortInformationProcess();
    //ZwQueryPortInformationProcess

    // https://github.com/winsiderss/systeminformer/blob/0b59400ca381a9c8681abb07a66d77cc55115e63/phnt/include/ntlpcapi.h#L327
    NTSYSCALLAPI NTSTATUS NTAPI NtReadRequestData(
        _In_ HANDLE Handle,
        _In_ PPORT_MESSAGE Request,
        _In_ ULONG Index,
        _Out_writes_bytes_to_(BufferSize, *NumberOfBytesRead) PVOID Buffer,
        _In_ ULONG BufferLength,
        _Out_opt_ PULONG ReturnLength);
    //ZwReadRequestData

    // https://github.com/winsiderss/systeminformer/blob/0b59400ca381a9c8681abb07a66d77cc55115e63/phnt/include/ntlpcapi.h#L282
    NTSYSCALLAPI NTSTATUS NTAPI NtReplyPort(
        _In_ HANDLE PortHandle,
        _In_reads_bytes_(ReplyMessage->u1.s1.TotalLength) PPORT_MESSAGE pMessage);
    //ZwReplyPort

    //https://github.com/winsiderss/systeminformer/blob/0b59400ca381a9c8681abb07a66d77cc55115e63/phnt/include/ntlpcapi.h#L273
    NTSYSCALLAPI NTSTATUS NTAPI NtReplyWaitReceivePort(
        _In_ HANDLE PortHandle,
        _Out_ PHANDLE ReceiveHandle,
        _In_reads_bytes_(RequestMessage->u1.s1.TotalLength) PPORT_MESSAGE RequestMessage,
        _Out_ PPORT_MESSAGE ReplyMessage);
    //ZwReplyWaitReceivePort

    // https://github.com/winsiderss/systeminformer/blob/0b59400ca381a9c8681abb07a66d77cc55115e63/phnt/include/ntlpcapi.h#L308
    NTSYSCALLAPI NTSTATUS NTAPI NtReplyWaitReceivePortEx(
        _In_ HANDLE PortHandle,
        _Out_ PHANDLE ReceiveHandle,
        _In_reads_bytes_opt_(ReplyMessage->u1.s1.TotalLength) PPORT_MESSAGE ReplyMessage,
        _Out_ PPORT_MESSAGE ReceiveMessage,
        _In_ PLARGE_INTEGER Timeout);
    //ZwReplyWaitReceivePortEx

    // https://github.com/winsiderss/systeminformer/blob/0b59400ca381a9c8681abb07a66d77cc55115e63/phnt/include/ntlpcapi.h#L290
    NTSYSCALLAPI NTSTATUS NTAPI NtReplyWaitReplyPort(
        _In_ HANDLE PortHandle,
        _Inout_ PPORT_MESSAGE pMessage);
    //ZwReplyWaitReplyPort

    // https://github.com/winsiderss/systeminformer/blob/0b59400ca381a9c8681abb07a66d77cc55115e63/phnt/include/ntlpcapi.h#L265
    NTSYSCALLAPI NTSTATUS NTAPI NtRequestPort(
        _In_ HANDLE PortHandle,
        _In_reads_bytes_(RequestMessage->u1.s1.TotalLength) PPORT_MESSAGE RequestMessage);
    //ZwRequestPort

    // https://github.com/winsiderss/systeminformer/blob/0b59400ca381a9c8681abb07a66d77cc55115e63/phnt/include/ntlpcapi.h#L273
    NTSYSCALLAPI NTSTATUS NTAPI NtRequestWaitReplyPort(
        _In_ HANDLE PortHandle,
        _In_reads_bytes_(RequestMessage->u1.s1.TotalLength) PPORT_MESSAGE RequestMessage,
        _Out_ PPORT_MESSAGE ReplyMessage);
    //ZwRequestWaitReplyPort

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtSecureConnectPort(
        _Out_ PHANDLE PortHandle,
        _In_ PUNICODE_STRING Name,
        _In_ ULONG QOS,
        _Inout_ PPORT_VIEW pSectionInfo,
        _In_ PSID SecurityInfo,
        _Inout_ PREMOTE_PORT_VIEW pSectionMapInfo,
        _Out_ PULONG MaxMsgLength,
        _Inout_opt_ PVOID ConnectData,
        _Inout_opt_ PULONG ConnectDataLength);
    //ZwSecureConnectPort

    // https://github.com/winsiderss/systeminformer/blob/0b59400ca381a9c8681abb07a66d77cc55115e63/phnt/include/ntlpcapi.h#L339
    NTSYSCALLAPI NTSTATUS NTAPI NtWriteRequestData(
        _In_ HANDLE PortHandle,
        _In_ PPORT_MESSAGE Message,
        _In_ ULONG Index,
        _In_reads_bytes_(BufferSize) PVOID Buffer,
        _In_ ULONG BufferLength,
        _Out_opt_ PULONG ReturnLength);
    //ZwWriteRequestData

}

#endif // _NTLOCALPROCEDURECALLS_
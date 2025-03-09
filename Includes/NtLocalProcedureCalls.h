#pragma once

#ifndef _NTLOCALPROCEDURECALLS_
#define _NTLOCALPROCEDURECALLS_

#include "NtCommonDefs.h"

extern "C" {

    // NO UNRESOLVED FUNCTION

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

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtAlpcConnectPortEx(
        _Out_ PHANDLE PortHandle,
        _In_ PUNICODE_STRING PortName,
        _In_ POBJECT_ATTRIBUTES ObjectAttributes,
        _In_ PALPC_INFO PortInformation,
        _In_ ULONG ConnectionFlags,
        _In_ PSECURITY_DESCRIPTOR pSelfRelativeSD,
        _Inout_ PPORT_MESSAGE ConnectionMessage,
        _Inout_opt_ PULONG BufferLength,
        _Inout_opt_ PALPC_MESSAGE_ATTRIBUTES OutMessageAttributes,
        _Inout_opt_ PALPC_MESSAGE_ATTRIBUTES InMessageAttributes,
        _In_opt_ PLARGE_INTEGER Timeout);
    //ZwAlpcConnectPortEx

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtAlpcCreatePort(
        _Out_ PHANDLE PortHandle,
        _In_ POBJECT_ATTRIBUTES ObjectAttributes,
        _Inout_opt_ PALPC_INFO PortInformation);
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
        HANDLE PortHandle,
        ULONG FlagUnusedMustbeZero,
        PALPC_MESSAGE_VIEW pMessageBuffer);
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

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtAlpcQueryInformation(
        _In_ HANDLE PortHandle,
        _In_ ALPC_PORT_INFORMATION_CLASS PortInformationClass,
        _Out_ PVOID PortInformation,
        _In_ ULONG Length,
        _Out_opt_ PULONG ReturnLength);
    //ZwAlpcQueryInformation

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtAlpcQueryInformationMessage(
        _In_ HANDLE PortHandle,
        _In_ PPORT_MESSAGE PortMessage,
        _In_ ALPC_MESSAGE_INFORMATION_CLASS MessageInformationClass,
        _Out_ PVOID MessageInformation,
        _In_ ULONG Length,
        _Out_opt_ PULONG ReturnLength);
    //ZwAlpcQueryInformationMessage

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtAlpcRevokeSecurityContext(
        _In_ HANDLE PortHandle,
        _In_ ULONG Flags,
        _In_ HANDLE ContextHandle);
    //ZwAlpcRevokeSecurityContext

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtAlpcSendWaitReceivePort(
        _In_ HANDLE PortHandle,
        _In_ ULONG SendFlags,
        _In_opt_ PLPC_MESSAGE SendMessage,
        _Inout_opt_ PVOID InMessageBuffer,
        _Out_opt_ PLPC_MESSAGE ReceiveBuffer,
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

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtImpersonateClientOfPort(
        _In_ HANDLE PortHandle,
        _In_ PLPC_MESSAGE Message);
    //ZwImpersonateClientOfPort

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtListenPort(
        _In_ HANDLE Handle,
        _Out_ PLPC_MESSAGE ConnectionData);
    //ZwListenPort

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtQueryInformationPort(
        _In_ HANDLE JobHandle,
        _In_ PORT_INFORMATION_CLASS PortInformationClass,
        _Out_ PVOID PortInformation,
        _In_ ULONG Length,
        _Out_opt_ PULONG ReturnLength);
    //ZwQueryInformationPort

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtQueryPortInformationProcess();
    //ZwQueryPortInformationProcess

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtReadRequestData(
        _In_ HANDLE Handle,
        _In_ PLPC_MESSAGE Request,
        _In_ ULONG Index,
        _Out_ PVOID Buffer,
        _In_ ULONG BufferLength,
        _Out_opt_ PULONG ReturnLength);
    //ZwReadRequestData

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtReplyPort(
        _In_ HANDLE PortHandle,
        _In_ PLPC_MESSAGE pMessage);
    //ZwReplyPort

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtReplyWaitReceivePort(
        _In_ HANDLE PortHandle,
        _Out_ PHANDLE ReceiveHandle,
        _In_ PLPC_MESSAGE pMessage,
        _Out_ PLPC_MESSAGE pMessage2);
    //ZwReplyWaitReceivePort

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtReplyWaitReceivePortEx(
        _In_ HANDLE PortHandle,
        _Out_ PHANDLE ReceiveHandle,
        _In_ PLPC_MESSAGE pMessage,
        _Out_ PLPC_MESSAGE pMessage2,
        _In_ PLARGE_INTEGER Timeout);
    //ZwReplyWaitReceivePortEx

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtReplyWaitReplyPort(
        _In_ HANDLE PortHandle,
        _Inout_ PLPC_MESSAGE pMessage);
    //ZwReplyWaitReplyPort

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtRequestPort(
        _In_ HANDLE PortHandle,
        _In_ PLPC_MESSAGE RequestMessage);
    //ZwRequestPort

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtRequestWaitReplyPort(
        _In_ HANDLE PortHandle,
        _In_ PLPC_MESSAGE pRequestMessage,
        _Out_ PLPC_MESSAGE pReplyMessage);
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

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtWriteRequestData(
        _In_ HANDLE PortHandle,
        _In_ PLPC_MESSAGE Message,
        _In_ ULONG Index,
        _In_ PVOID Buffer,
        _In_ ULONG BufferLength,
        _Out_opt_ PULONG ReturnLength);
    //ZwWriteRequestData

}

#endif // _NTLOCALPROCEDURECALLS_
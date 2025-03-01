#pragma once

#ifndef _NTENVIRONMENT_
#define _NTENVIRONMENT_

#include "NtCommonDefs.h"

extern "C" {

    // NO UNRESOLVED FUNCTIONS

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtEnumerateSystemEnvironmentValuesEx(
        _In_ ULONG Class,
        _Out_ PVOID Buffer,
        _In_ ULONG BufferLength);
    //ZwEnumerateSystemEnvironmentValuesEx

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI ULONG NTAPI NtGetCurrentProcessorNumber();
    //ZwGetCurrentProcessorNumber

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtGetCurrentProcessorNumberEx(
        _Out_opt_ PULONG ProcNumber);
    //ZwGetCurrentProcessorNumberEx

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtIsSystemResumeAutomatic();
    //ZwIsSystemResumeAutomatic

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtQueryDefaultLocale(
        _In_ BOOLEAN UserProfile,
        _Out_ PLCID DefaultLocaleId);
    //ZwQueryDefaultLocale

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtQueryDefaultUILanguage(
        _Out_ PULONG LanguageId);
    //ZwQueryDefaultUILanguage

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtQueryInstallUILanguage(
        _Out_ PULONG LanguageId);
    //ZwQueryInstallUILanguage

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtQuerySystemEnvironmentValue(
        _In_ PUNICODE_STRING Name,
        _Out_ PWSTR Value,
        _In_ ULONG Length,
        _Out_opt_ PULONG ReturnLength);
    //ZwQuerySystemEnvironmentValue

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtQuerySystemEnvironmentValueEx(
        _In_ PUNICODE_STRING VariableName,
        _In_ PVOID Guid,
        _Out_ PVOID Buffer,
        _Inout_ PULONG BufferLength,
        _Inout_ PULONG Attributes);
    //ZwQuerySystemEnvironmentValueEx

    // See winternl.h
    // https://raw.githubusercontent.com/x64dbg/TitanEngine/refs/heads/x64dbg/TitanEngine/ntdll.h
    NTSYSCALLAPI NTSTATUS NTAPI NtQuerySystemInformation(
        _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
        _Out_opt_ PVOID SystemInformation,
        _In_ ULONG SystemInformationLength,
        _Out_opt_ PULONG ReturnLength);
    // ZwQuerySystemInformation

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtQuerySystemInformationEx(
        _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
        _In_ PULONG QueryType,
        _In_ ULONG Alignment,
        _Out_ PVOID SystemInformation,
        _In_ ULONG Length,
        _Out_opt_ PULONG ReturnLength);
    //ZwQuerySystemInformationEx

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtSetDefaultLocale(
        _In_ BOOLEAN UserProfile,
        _In_ LCID LocaleId);
    //ZwSetDefaultLocale

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtSetDefaultUILanguage(
        _In_ ULONG LanguageId);
    //ZwSetDefaultUILanguage

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtSetSystemEnvironmentValue(
        _In_ PUNICODE_STRING Name,
        _In_ PUNICODE_STRING Value);
    //ZwSetSystemEnvironmentValue

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtSetSystemEnvironmentValueEx(
        _In_ PUNICODE_STRING Name,
        _In_ PVOID Guid,
        _In_ PVOID Buffer,
        _In_ ULONG BufferLength,
        _In_ ULONG Attributes);
    //ZwSetSystemEnvironmentValueEx

    // https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtSetSystemInformation(
        _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
        _In_ PVOID SystemInformation,
        _In_ ULONG Length);
    //ZwSetSystemInformation
}

#endif // _NTENVIRONMENT_
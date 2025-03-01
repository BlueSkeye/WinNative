#pragma once

#ifndef _NTDEVICES_
#define _NTDEVICES_

#include "NtCommonDefs.h"

extern "C" {

    // NO UNRESOLVED FUNCTIONS

    //https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtAddBootEntry(
        _In_ PUNICODE_STRING Name,
        _In_ PUNICODE_STRING Value);
    //ZwAddBootEntry

    //https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtAddDriverEntry(
        _In_ PUNICODE_STRING Name,
        _In_ PUNICODE_STRING Path);
    //ZwAddDriverEntry

    //https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtDeleteBootEntry(
        _In_ PUNICODE_STRING Name);
    //ZwDeleteBootEntry

    //https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtDeleteDriverEntry(
        _In_ PUNICODE_STRING Name);
    //ZwDeleteDriverEntry

    //https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtDisableLastKnownGood();
    //ZwDisableLastKnownGood

    //https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtEnableLastKnownGood();
    //ZwEnableLastKnownGood

    //https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtEnumerateBootEntries(
        _In_ PVOID Buffer,
        _In_ PULONG BufferLength);
    //ZwEnumerateBootEntries

    //https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtEnumerateDriverEntries(
        _In_ PVOID Buffer,
        _In_ PULONG BufferLength);
    //ZwEnumerateDriverEntries

    //https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtGetDevicePowerState(
        _In_ HANDLE DeviceHandle,
        _Out_ PDEVICE_POWER_STATE State);
    //ZwGetDevicePowerState

    //https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtInitiatePowerAction(
        _In_ POWER_ACTION Action,
        _In_ SYSTEM_POWER_STATE State,
        _In_ ULONG Flags,
        _In_ BOOLEAN Asynch); 
    //ZwInitiatePowerAction

    //https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwloaddriver
    NTSYSCALLAPI NTSYSAPI NTSTATUS NtLoadDriver(
        _In_ PUNICODE_STRING DriverName);
    //ZwLoadDriver

    //https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtModifyBootEntry(
        _In_ PBOOT_ENTRY BootEntry);
    //ZwModifyBootEntry

    //https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtModifyDriverEntry(
        _In_ PDRIVER_ENTRY DriverEntry);
    //ZwModifyDriverEntry

    //https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtPlugPlayControl(
        _In_ ULONG Class,
        _Inout_ PVOID Buffer,
        _In_ ULONG BufferSize);
    //ZwPlugPlayControl

    //https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntpowerinformation
    NTSYSCALLAPI NTSTATUS NTAPI NtPowerInformation(
        _In_ POWER_INFORMATION_LEVEL InformationLevel,
        _In_opt_ PVOID InputBuffer,
        _In_ ULONG InputLength,
        _Out_ PVOID OutputBuffer,
        _In_ ULONG OutputLength);
    //ZwPowerInformation

    //https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtQueryBootEntryOrder(
        _In_opt_ PULONG OrderArray,
        _Inout_ PULONG OrderCount);
    //ZwQueryBootEntryOrder

    //https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtQueryBootOptions(
        _Out_opt_ PVOID Buffer,
        _Inout_ PULONG BufferLength);
    //ZwQueryBootOptions

    //https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtQueryDriverEntryOrder(
        _Out_opt_ PULONG OrderArray,
        _Inout_ PULONG OrderCount);
    //ZwQueryDriverEntryOrder

    //https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtReplacePartitionUnit(
        _In_ PUNICODE_STRING TargetInstancePath,
        _In_ PUNICODE_STRING SpareInstancePath,
        _In_ ULONG Flags);
    //ZwReplacePartitionUnit

    //https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtSerializeBoot();
    //ZwSerializeBoot

    //https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtSetBootEntryOrder(
        _In_ PULONG OrderArray,
        _In_ ULONG OrderCount);
    //ZwSetBootEntryOrder

    //https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtSetBootOptions(
        _In_ PVOID Buffer,
        _In_ ULONG BufferLength);
    //ZwSetBootOptions

    //https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtSetDriverEntryOrder(
        _In_ PULONG OrderArray,
        _In_ ULONG OrderCount);
    //ZwSetDriverEntryOrder

    //https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtSetSystemPowerState(
        _In_ POWER_ACTION Action,
        _In_ SYSTEM_POWER_STATE State,
        _In_ ULONG Flags);
    //ZwSetSystemPowerState

    //https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtSetThreadExecutionState(
        _In_ ULONG State,
        _Out_ PULONG PreviousState);
    //ZwSetThreadExecutionState

    //https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtUnloadDriver(
        _In_ PUNICODE_STRING DriverName);
    //ZwUnloadDriver

    //https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSCALLAPI NTSTATUS NTAPI NtVdmControl(
        _In_ ULONG ControlCode,
        _In_ PVOID ControlData);
    //ZwVdmControl
}

#endif // _NTDEVICES_
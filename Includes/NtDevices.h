#pragma once

#ifndef _NTDEVICES_
#define _NTDEVICES_

#include "NtCommonDefs.h"

extern "C" {

    // NO UNRESOLVED FUNCTIONS

    // https://doxygen.reactos.org/d6/d0e/ndk_2iotypes_8h_source.html
    typedef struct _BOOT_ENTRY {
        ULONG Version;
        ULONG Length;
        ULONG Id;
        ULONG Attributes;
        ULONG FriendlyNameOffset;
        ULONG BootFilePathOffset;
        ULONG OsOptionsLength;
        CHAR OsOptions[1];
    } BOOT_ENTRY, * PBOOT_ENTRY;

    // As _EFI_DRIVER_ENTRY in https://doxygen.reactos.org/d6/d0e/ndk_2iotypes_8h_source.html#l01155
    typedef struct _DRIVER_ENTRY {
        ULONG Version;
        ULONG Length;
        ULONG Id;
        ULONG Attributes;
        ULONG FriendlyNameOffset;
        ULONG DriverFilePathOffset;
    } DRIVER_ENTRY, * PDRIVER_ENTRY;

    // https://www.freepascal.org/daily/packages/winunits-jedi/jwawindows/_device_power_state.html
    typedef enum _DEVICE_POWER_STATE {
        PowerDeviceUnspecified,
        PowerDeviceD0,
        PowerDeviceD1,
        PowerDeviceD2,
        PowerDeviceD3,
        PowerDeviceMaximum
    } DEVICE_POWER_STATE, * PDEVICE_POWER_STATE;

    // https://doxygen.reactos.org/d5/d37/ntpoapi_8h.html#aa9a16eb140221e9041bce63f1a38a008
    typedef enum _POWER_ACTION {
        PowerActionNone,
        PowerActionReserved,
        PowerActionSleep,
        PowerActionHibernate,
        PowerActionShutdown,
        PowerActionShutdownReset,
        PowerActionShutdownOff,
        PowerActionWarmEject
    } POWER_ACTION, *PPOWER_ACTION;

    // https://doxygen.reactos.org/d5/d37/ntpoapi_8h_source.html#l00066
    // Had to prefix values to avoid a name collision with SystemPowerInformation also being
    // defined in SYSTEM_INFORMATION_CLASS from NtEnvironment.h
    typedef enum _POWER_INFORMATION_LEVEL {
        PIL_SystemPowerPolicyAc,
        PIL_SystemPowerPolicyDc,
        PIL_VerifySystemPolicyAc,
        PIL_VerifySystemPolicyDc,
        PIL_SystemPowerCapabilities,
        PIL_SystemBatteryState,
        PIL_SystemPowerStateHandler,
        PIL_ProcessorStateHandler,
        PIL_SystemPowerPolicyCurrent,
        PIL_AdministratorPowerPolicy,
        PIL_SystemReserveHiberFile,
        PIL_ProcessorInformation,
        PIL_SystemPowerInformation,
        PIL_ProcessorStateHandler2,
        PIL_LastWakeTime,
        PIL_LastSleepTime,
        PIL_SystemExecutionState,
        PIL_SystemPowerStateNotifyHandler,
        PIL_ProcessorPowerPolicyAc,
        PIL_ProcessorPowerPolicyDc,
        PIL_VerifyProcessorPowerPolicyAc,
        PIL_VerifyProcessorPowerPolicyDc,
        PIL_ProcessorPowerPolicyCurrent,
        PIL_SystemPowerStateLogging,
        PIL_SystemPowerLoggingEntry,
        PIL_SetPowerSettingValue,
        PIL_NotifyUserPowerSetting,
        PIL_PowerInformationLevelUnused0,
        PIL_PowerInformationLevelUnused1,
        PIL_SystemVideoState,
        PIL_TraceApplicationPowerMessage,
        PIL_TraceApplicationPowerMessageEnd,
        PIL_ProcessorPerfStates,
        PIL_ProcessorIdleStates,
        PIL_ProcessorCap,
        PIL_SystemWakeSource,
        PIL_SystemHiberFileInformation,
        PIL_TraceServicePowerMessage,
        PIL_ProcessorLoad,
        PIL_PowerShutdownNotification,
        PIL_MonitorCapabilities,
        PIL_SessionPowerInit,
        PIL_SessionDisplayState,
        PIL_PowerRequestCreate,
        PIL_PowerRequestAction,
        PIL_GetPowerRequestList,
        PIL_ProcessorInformationEx,
        PIL_NotifyUserModeLegacyPowerEvent,
        PIL_GroupPark,
        PIL_ProcessorIdleDomains,
        PIL_WakeTimerList,
        PIL_SystemHiberFileSize,
        PIL_PowerInformationLevelMaximum
    } POWER_INFORMATION_LEVEL;

    // https://www.freepascal.org/daily/packages/winunits-jedi/jwawindows/_system_power_state.html
    typedef enum _SYSTEM_POWER_STATE {
        PowerSystemUnspecified,
        PowerSystemWorking,
        PowerSystemSleeping1,
        PowerSystemSleeping2,
        PowerSystemSleeping3,
        PowerSystemHibernate,
        PowerSystemShutdown,
        PowerSystemMaximum
    } SYSTEM_POWER_STATE, *PSYSTEM_POWER_STATE;

    // =========================== functions =========================== 
    
    //https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSAPI NTSTATUS NTAPI NtAddBootEntry(
        _In_ PUNICODE_STRING Name,
        _In_ PUNICODE_STRING Value);
    //ZwAddBootEntry

    //https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSAPI NTSTATUS NTAPI NtAddDriverEntry(
        _In_ PUNICODE_STRING Name,
        _In_ PUNICODE_STRING Path);
    //ZwAddDriverEntry

    //https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSAPI NTSTATUS NTAPI NtDeleteBootEntry(
        _In_ PUNICODE_STRING Name);
    //ZwDeleteBootEntry

    //https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSAPI NTSTATUS NTAPI NtDeleteDriverEntry(
        _In_ PUNICODE_STRING Name);
    //ZwDeleteDriverEntry

    //https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSAPI NTSTATUS NTAPI NtDisableLastKnownGood();
    //ZwDisableLastKnownGood

    //https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSAPI NTSTATUS NTAPI NtEnableLastKnownGood();
    //ZwEnableLastKnownGood

    //https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSAPI NTSTATUS NTAPI NtEnumerateBootEntries(
        _In_ PVOID Buffer,
        _In_ PULONG BufferLength);
    //ZwEnumerateBootEntries

    //https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSAPI NTSTATUS NTAPI NtEnumerateDriverEntries(
        _In_ PVOID Buffer,
        _In_ PULONG BufferLength);
    //ZwEnumerateDriverEntries

    // https://processhacker.sourceforge.io/doc/ntpoapi_8h.html
    NTSYSAPI NTSTATUS NTAPI NtGetDevicePowerState(
        _In_ HANDLE DeviceHandle,
        _Out_ PDEVICE_POWER_STATE State);
    //ZwGetDevicePowerState

    //https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSAPI NTSTATUS NTAPI NtInitiatePowerAction(
        _In_ POWER_ACTION Action,
        _In_ SYSTEM_POWER_STATE State,
        _In_ ULONG Flags,
        _In_ BOOLEAN Asynch); 
    //ZwInitiatePowerAction

    //https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwloaddriver
    NTSYSAPI NTSTATUS NtLoadDriver(
        _In_ PUNICODE_STRING DriverName);
    //ZwLoadDriver

    //https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSAPI NTSTATUS NTAPI NtModifyBootEntry(
        _In_ PBOOT_ENTRY BootEntry);
    //ZwModifyBootEntry

    //https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSAPI NTSTATUS NTAPI NtModifyDriverEntry(
        _In_ PDRIVER_ENTRY DriverEntry);
    //ZwModifyDriverEntry

    //https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSAPI NTSTATUS NTAPI NtPlugPlayControl(
        _In_ ULONG Class,
        _Inout_ PVOID Buffer,
        _In_ ULONG BufferSize);
    //ZwPlugPlayControl

    //https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntpowerinformation
    NTSYSAPI NTSTATUS NTAPI NtPowerInformation(
        _In_ POWER_INFORMATION_LEVEL InformationLevel,
        _In_opt_ PVOID InputBuffer,
        _In_ ULONG InputLength,
        _Out_ PVOID OutputBuffer,
        _In_ ULONG OutputLength);
    //ZwPowerInformation

    //https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSAPI NTSTATUS NTAPI NtQueryBootEntryOrder(
        _In_opt_ PULONG OrderArray,
        _Inout_ PULONG OrderCount);
    //ZwQueryBootEntryOrder

    //https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSAPI NTSTATUS NTAPI NtQueryBootOptions(
        _Out_opt_ PVOID Buffer,
        _Inout_ PULONG BufferLength);
    //ZwQueryBootOptions

    //https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSAPI NTSTATUS NTAPI NtQueryDriverEntryOrder(
        _Out_opt_ PULONG OrderArray,
        _Inout_ PULONG OrderCount);
    //ZwQueryDriverEntryOrder

    //https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSAPI NTSTATUS NTAPI NtReplacePartitionUnit(
        _In_ PUNICODE_STRING TargetInstancePath,
        _In_ PUNICODE_STRING SpareInstancePath,
        _In_ ULONG Flags);
    //ZwReplacePartitionUnit

    //https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSAPI NTSTATUS NTAPI NtSerializeBoot();
    //ZwSerializeBoot

    //https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSAPI NTSTATUS NTAPI NtSetBootEntryOrder(
        _In_ PULONG OrderArray,
        _In_ ULONG OrderCount);
    //ZwSetBootEntryOrder

    //https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSAPI NTSTATUS NTAPI NtSetBootOptions(
        _In_ PVOID Buffer,
        _In_ ULONG BufferLength);
    //ZwSetBootOptions

    //https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSAPI NTSTATUS NTAPI NtSetDriverEntryOrder(
        _In_ PULONG OrderArray,
        _In_ ULONG OrderCount);
    //ZwSetDriverEntryOrder

    //https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSAPI NTSTATUS NTAPI NtSetSystemPowerState(
        _In_ POWER_ACTION Action,
        _In_ SYSTEM_POWER_STATE State,
        _In_ ULONG Flags);
    //ZwSetSystemPowerState

    //https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSAPI NTSTATUS NTAPI NtSetThreadExecutionState(
        _In_ ULONG State,
        _Out_ PULONG PreviousState);
    //ZwSetThreadExecutionState

    //https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSAPI NTSTATUS NTAPI NtUnloadDriver(
        _In_ PUNICODE_STRING DriverName);
    //ZwUnloadDriver

    //https://raw.githubusercontent.com/rogerorr/NtTrace/refs/heads/main/NtTrace.cfg
    NTSYSAPI NTSTATUS NTAPI NtVdmControl(
        _In_ ULONG ControlCode,
        _In_ PVOID ControlData);
    //ZwVdmControl
}

#endif // _NTDEVICES_
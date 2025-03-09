#pragma once

#ifndef _NTTHREADPOOL_
#define _NTTHREADPOOL_

#include "NtCommonDefs.h"

extern "C" {

	// UNRESOLVED FUNCTIONS

	//TpCallbackIndependent
	//TpCallbackSendPendingAlpcMessage
	//TpDbgDumpHeapUsage

	//TpDisablePoolCallbackChecks

	//TpSetDefaultPoolStackInformation
	//TpSetPoolMaxThreadsSoftLimit
	//TpSetPoolThreadCpuSets
	//TpSetPoolWorkerThreadIdleTimeout
	//TpTimerOutstandingCallbackCount

	// END OF UNRESOLVED FUNCTIONS

	// https://processhacker.sourceforge.io/doc/nttp_8h.html
	NTSYSAPI NTSTATUS NTAPI TpAllocAlpcCompletion(
		_Out_ PTP_ALPC* AlpcReturn,
		_In_ HANDLE AlpcPort,
		_In_ PTP_ALPC_CALLBACK Callback,
		_Inout_opt_ PVOID Context,
		_In_opt_ PTP_CALLBACK_ENVIRON CallbackEnviron);

	// https://processhacker.sourceforge.io/doc/nttp_8h.html
	NTSYSAPI NTSTATUS NTAPI TpAllocAlpcCompletionEx(
		_Out_ PTP_ALPC* AlpcReturn,
		_In_ HANDLE AlpcPort,
		_In_ PTP_ALPC_CALLBACK_EX Callback,
		_Inout_opt_ PVOID Context,
		_In_opt_ PTP_CALLBACK_ENVIRON CallbackEnviron);

	// https://processhacker.sourceforge.io/doc/nttp_8h.html
	NTSYSAPI NTSTATUS NTAPI TpAllocCleanupGroup(
		_Out_ PTP_CLEANUP_GROUP* CleanupGroupReturn);

	// https://processhacker.sourceforge.io/doc/nttp_8h.html
	NTSYSAPI NTSTATUS NTAPI TpAllocIoCompletion(
		_Out_ PTP_IO* IoReturn,
		_In_ HANDLE File,
		_In_ PTP_IO_CALLBACK Callback,
		_Inout_opt_ PVOID Context,
		_In_opt_ PTP_CALLBACK_ENVIRON CallbackEnviron);

	// https://urien.gitbook.io/diago-lima/a-deep-dive-into-exploiting-windows-thread-pools/attacking-i-o-ports
	NTSYSAPI NTSTATUS TpAllocJobNotification(
		_Out_ PFULL_TP_JOB* JobReturn,
		_In_ HANDLE HJob,
		_In_ PVOID Callback,
		_Inout_opt_ PVOID Context,
		_In_opt_ PTP_CALLBACK_ENVIRON CallbackEnviron);

	// https://processhacker.sourceforge.io/doc/nttp_8h.html
	NTSYSAPI NTSTATUS NTAPI TpAllocPool(
		_Out_ PTP_POOL* PoolReturn,
		_Reserved_ PVOID Reserved);

	// https://processhacker.sourceforge.io/doc/nttp_8h.html
	NTSYSAPI NTSTATUS NTAPI TpAllocTimer(
		_Out_ PTP_TIMER* Timer,
		_In_ PTP_TIMER_CALLBACK Callback,
		_Inout_opt_ PVOID Context,
		_In_opt_ PTP_CALLBACK_ENVIRON CallbackEnviron);

	// https://processhacker.sourceforge.io/doc/nttp_8h.html
	NTSYSAPI NTSTATUS NTAPI TpAllocWait(
		_Out_ PTP_WAIT* WaitReturn,
		_In_ PTP_WAIT_CALLBACK Callback,
		_Inout_opt_ PVOID Context,
		_In_opt_ PTP_CALLBACK_ENVIRON CallbackEnviron);

	// https://processhacker.sourceforge.io/doc/nttp_8h.html
	NTSYSAPI NTSTATUS NTAPI TpAllocWork(
		_Out_ PTP_WORK* WorkReturn,
		_In_ PTP_WORK_CALLBACK Callback,
		_Inout_opt_ PVOID Context,
		_In_opt_ PTP_CALLBACK_ENVIRON CallbackEnviron);

	// https://github.com/x64dbg/TitanEngine/blob/x64dbg/TitanEngine/ntdll.h
	NTSYSAPI NTSTATUS NTAPI TpAlpcRegisterCompletionList(
		_Inout_ PTP_ALPC Alpc);

	// https://github.com/x64dbg/TitanEngine/blob/x64dbg/TitanEngine/ntdll.h
	NTSYSAPI NTSTATUS NTAPI TpAlpcUnregisterCompletionList(
			_Inout_ PTP_ALPC Alpc);

	// Reversed. Not invoked from other NTDLL.DLL functions
	NTSYSAPI VOID NTAPI TpCallbackDetectedUnrecoverableError(
		_In_ PVOID unidentified);

	// https://processhacker.sourceforge.io/doc/nttp_8h.html
	NTSYSAPI VOID NTAPI TpCallbackLeaveCriticalSectionOnCompletion(
		_Inout_ PTP_CALLBACK_INSTANCE Instance,
		_Inout_ PRTL_CRITICAL_SECTION CriticalSection);

	// https://processhacker.sourceforge.io/doc/nttp_8h.html
	NTSYSAPI NTSTATUS NTAPI TpCallbackMayRunLong(
		_Inout_ PTP_CALLBACK_INSTANCE Instance);

	// https://processhacker.sourceforge.io/doc/nttp_8h.html
	//NTSYSAPI NTSTATUS NTAPI TpQueryPoolStackInformation(
	//	_In_ PTP_POOL Pool,
	//	_Out_ PTP_POOL_STACK_INFORMATION PoolStackInformation);

	// https://processhacker.sourceforge.io/doc/nttp_8h.html
	NTSYSAPI VOID NTAPI TpCallbackReleaseMutexOnCompletion(
		_Inout_ PTP_CALLBACK_INSTANCE Instance,
		_In_ HANDLE Mutex);

	// https://processhacker.sourceforge.io/doc/nttp_8h.html
	NTSYSAPI VOID NTAPI TpCallbackReleaseSemaphoreOnCompletion(
		_Inout_ PTP_CALLBACK_INSTANCE Instance,
		_In_ HANDLE Semaphore,
		_In_ LONG ReleaseCount);

	// https://processhacker.sourceforge.io/doc/nttp_8h.html
	NTSYSAPI VOID NTAPI TpCallbackSetEventOnCompletion(
		_Inout_ PTP_CALLBACK_INSTANCE Instance,
		_In_ HANDLE Event);

	// https://processhacker.sourceforge.io/doc/nttp_8h.html
	NTSYSAPI VOID NTAPI TpCallbackUnloadDllOnCompletion(
		_Inout_ PTP_CALLBACK_INSTANCE Instance,
		_In_ PVOID DllHandle);

	// https://processhacker.sourceforge.io/doc/nttp_8h.html
	NTSYSAPI VOID NTAPI TpCancelAsyncIoOperation(
		_Inout_ PTP_IO Io);

	// https://processhacker.sourceforge.io/doc/nttp_8h.html
	NTSYSAPI VOID NTAPI TpCaptureCaller(
		_In_ TP_TRACE_TYPE Type);

	// https://processhacker.sourceforge.io/doc/nttp_8h.html
	NTSYSAPI VOID NTAPI TpCheckTerminateWorker(
		_In_ HANDLE Thread);

	// Reversed. Empty function always returning 0. Arguments unknown may not be VOID.
	NTSYSAPI NTSTATUS NTAPI TpDbgSetLogRoutine(VOID);

	// https://processhacker.sourceforge.io/doc/nttp_8h.html
	NTSYSAPI VOID NTAPI TpDisassociateCallback(
		_Inout_ PTP_CALLBACK_INSTANCE Instance);

	// https://processhacker.sourceforge.io/doc/nttp_8h.html
	NTSYSAPI LOGICAL NTAPI TpIsTimerSet(
		_In_ PTP_TIMER Timer);

	// https://processhacker.sourceforge.io/doc/nttp_8h.html
	NTSYSAPI VOID NTAPI TpPostWork(
		_Inout_ PTP_WORK Work);

	// https://processhacker.sourceforge.io/doc/nttp_8h.html
	NTSYSAPI VOID NTAPI TpReleaseAlpcCompletion(
		_Inout_ PTP_ALPC Alpc);

	// https://processhacker.sourceforge.io/doc/nttp_8h.html
	NTSYSAPI VOID NTAPI TpReleaseCleanupGroup(
		_Inout_ PTP_CLEANUP_GROUP CleanupGroup);

	// https://processhacker.sourceforge.io/doc/nttp_8h.html
	NTSYSAPI VOID NTAPI TpReleaseCleanupGroupMembers(
		_Inout_ PTP_CLEANUP_GROUP CleanupGroup,
		_In_ LOGICAL CancelPendingCallbacks,
		_Inout_opt_ PVOID CleanupParameter);

	// https://processhacker.sourceforge.io/doc/nttp_8h.html
	NTSYSAPI VOID NTAPI TpReleaseIoCompletion(
		_Inout_ PTP_IO Io);

	// Reversed. Not invoked from inside NTDLL.DLL
	NTSYSAPI NTSTATUS NTAPI TpReleaseJobNotification(
		_In_ PFULL_TP_JOB Job);

	// https://processhacker.sourceforge.io/doc/nttp_8h.html
	NTSYSAPI VOID NTAPI TpReleasePool(
		_Inout_ PTP_POOL Pool);

	// https://processhacker.sourceforge.io/doc/nttp_8h.html
	NTSYSAPI VOID NTAPI TpReleaseTimer(
		_Inout_ PTP_TIMER Timer);

	// https://processhacker.sourceforge.io/doc/nttp_8h.html
	NTSYSAPI VOID NTAPI TpReleaseWait(
		_Inout_ PTP_WAIT Wait);

	// https://processhacker.sourceforge.io/doc/nttp_8h.html
	NTSYSAPI VOID NTAPI TpReleaseWork(
		_Inout_ PTP_WORK Work);

	// https://processhacker.sourceforge.io/doc/nttp_8h.html
	NTSYSAPI VOID NTAPI TpSetPoolMaxThreads(
		_Inout_ PTP_POOL Pool,
		_In_ LONG MaxThreads);

	// https://processhacker.sourceforge.io/doc/nttp_8h.html
	NTSYSAPI NTSTATUS NTAPI TpSetPoolMinThreads(
		_Inout_ PTP_POOL Pool,
		_In_ LONG MinThreads);

	// https://processhacker.sourceforge.io/doc/nttp_8h.html
	NTSYSAPI NTSTATUS NTAPI TpSetPoolStackInformation(
		_Inout_ PTP_POOL Pool,
		_In_ PTP_POOL_STACK_INFORMATION PoolStackInformation);

	// https://processhacker.sourceforge.io/doc/nttp_8h.html
	NTSYSAPI VOID NTAPI TpSetTimer(
		_Inout_ PTP_TIMER Timer,
		_In_opt_ PLARGE_INTEGER DueTime,
		_In_ LONG Period,
		_In_opt_ LONG WindowLength);

	// https://processhacker.sourceforge.io/doc/nttp_8h.html
	NTSYSAPI VOID NTAPI TpSetWait(
		_Inout_ PTP_WAIT Wait,
		_In_opt_ HANDLE Handle,
		_In_opt_ PLARGE_INTEGER Timeout);

	// https://processhacker.sourceforge.io/doc/nttp_8h.html
	NTSYSAPI NTSTATUS NTAPI TpSimpleTryPost(
		_In_ PTP_SIMPLE_CALLBACK Callback,
		_Inout_opt_ PVOID Context,
		_In_opt_ PTP_CALLBACK_ENVIRON CallbackEnviron);

	// https://github.com/x64dbg/TitanEngine/blob/x64dbg/TitanEngine/ntdll.h
	// https://processhacker.sourceforge.io/doc/nttp_8h.html
	NTSYSAPI VOID NTAPI TpWaitForAlpcCompletion(
		_Inout_ PTP_ALPC Alpc);

	// https://processhacker.sourceforge.io/doc/nttp_8h.html
	NTSYSAPI VOID NTAPI TpStartAsyncIoOperation(
		_Inout_ PTP_IO Io);

	// Reversed. Invoked from LdrShutdownThread.
	NTSYSAPI VOID NTAPI TpTrimPools();

	// https://processhacker.sourceforge.io/doc/nttp_8h.html
	NTSYSAPI VOID NTAPI TpWaitForIoCompletion(
		_Inout_ PTP_IO Io,
		_In_ LOGICAL CancelPendingCallbacks);

	// https://processhacker.sourceforge.io/doc/nttp_8h.html
	NTSYSAPI VOID NTAPI TpWaitForTimer(
		_Inout_ PTP_TIMER Timer,
		_In_ LOGICAL CancelPendingCallbacks);

	// https://processhacker.sourceforge.io/doc/nttp_8h.html
	NTSYSAPI VOID NTAPI TpWaitForWait(
		_Inout_ PTP_WAIT Wait,
		_In_ LOGICAL CancelPendingCallbacks);

	// https://processhacker.sourceforge.io/doc/nttp_8h.html
	NTSYSAPI VOID NTAPI TpWaitForWork(
		_Inout_ PTP_WORK Work,
		_In_ LOGICAL CancelPendingCallbacks);

	// https://raw.githubusercontent.com/hakril/PythonForWindows/refs/heads/master/windows/generated_def/winfuncs.py
	NTSYSAPI NTSTATUS NTAPI TpCallbackSendAlpcMessageOnCompletion(
		HANDLE TpHandle,
		HANDLE PortHandle,
		ULONG Flags,
		PPORT_MESSAGE SendMessage);
	
	//https://docs.rs/phnt/latest/src/phnt/ffi/x86_64_bindgen.rs.html#80957
	NTSYSAPI VOID NTAPI TpReleaseIoCompletion(
		_In_ PTP_IO Io);

	//https://docs.rs/phnt/latest/phnt/ffi/fn.TpSetPoolMaxThreads.html
	NTSYSAPI VOID NTAPI TpSetPoolMaxThreads(
		_In_ PTP_POOL Pool,
		_In_ ULONG MaxThreads);
	
	//https://docs.rs/phnt/latest/phnt/ffi/fn.TpSetPoolThreadBasePriority.html
	NTSYSAPI NTSTATUS NTAPI TpSetPoolThreadBasePriority(
		_In_ PTP_POOL Pool,
		_In_ ULONG BasePriority(: ULONG);
	
	//https://docs.rs/phnt/latest/phnt/ffi/fn.TpSetTimerEx.html
	NTSYSAPI NTSTATUS NTAPI TpSetTimerEx(
		_In_ PTP_TIMER Timer,
		_In_ PLARGE_INTEGER DueTime,
		_In_ ULONG Period,
		_In_ ULONG WindowLength);

	//https://docs.rs/phnt/latest/phnt/ffi/fn.TpSetWaitEx.html
	NTSYSAPI NTSTATUS NTAPI TpSetWaitEx(
		_In_ PTP_WAIT Wait,
		_In_ HANDLE Handle,
		_In_ PLARGE_INTEGER Timeout,
		_In_ PVOID Reserved);

	// Reversed. Not invoked from inside NTDLL.DLL
	NTSYSAPI VOID NTAPI TpWaitForJobNotification(
		_In_ PFULL_TP_JOB Job);

}

#endif // _NTTHREADPOOL_
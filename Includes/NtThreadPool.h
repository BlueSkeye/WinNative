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

	typedef struct _TP_ALPC TP_ALPC, * PTP_ALPC;

	// From winnt.h
	typedef struct _TP_CALLBACK_INSTANCE TP_CALLBACK_INSTANCE, * PTP_CALLBACK_INSTANCE;

	// https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/nttp.h#L15
	typedef VOID(NTAPI* PTP_ALPC_CALLBACK)(
		_Inout_ PTP_CALLBACK_INSTANCE Instance,
		_Inout_opt_ PVOID Context,
		_In_ PTP_ALPC Alpc);

	// From winnt.h
	typedef DWORD TP_VERSION, * PTP_VERSION;
	typedef struct _TP_POOL TP_POOL, * PTP_POOL;
	typedef struct _TP_CLEANUP_GROUP TP_CLEANUP_GROUP, * PTP_CLEANUP_GROUP;
	typedef VOID(NTAPI* PTP_CLEANUP_GROUP_CANCEL_CALLBACK)(
		_Inout_opt_ PVOID ObjectContext,
		_Inout_opt_ PVOID CleanupContext);
	typedef VOID(NTAPI* PTP_SIMPLE_CALLBACK)(
		_Inout_ PTP_CALLBACK_INSTANCE Instance,
		_Inout_opt_ PVOID Context);
	typedef enum _TP_CALLBACK_PRIORITY {
		TP_CALLBACK_PRIORITY_HIGH,
		TP_CALLBACK_PRIORITY_NORMAL,
		TP_CALLBACK_PRIORITY_LOW,
		TP_CALLBACK_PRIORITY_INVALID,
		TP_CALLBACK_PRIORITY_COUNT = TP_CALLBACK_PRIORITY_INVALID
	} TP_CALLBACK_PRIORITY;
	typedef struct _TP_CALLBACK_ENVIRON_V3 {
		TP_VERSION Version;
		PTP_POOL Pool;
		PTP_CLEANUP_GROUP CleanupGroup;
		PTP_CLEANUP_GROUP_CANCEL_CALLBACK CleanupGroupCancelCallback;
		PVOID RaceDll;
		struct _ACTIVATION_CONTEXT* ActivationContext;
		PTP_SIMPLE_CALLBACK FinalizationCallback;
		union {
			DWORD Flags;
			struct {
				DWORD LongFunction : 1;
				DWORD Persistent : 1;
				DWORD Private : 30;
			} s;
		} u;
		TP_CALLBACK_PRIORITY               CallbackPriority;
		DWORD                              Size;
	} TP_CALLBACK_ENVIRON_V3;

	typedef TP_CALLBACK_ENVIRON_V3 TP_CALLBACK_ENVIRON, * PTP_CALLBACK_ENVIRON;
	typedef struct _TP_IO TP_IO, * PTP_IO;

	typedef VOID(NTAPI* PTP_IO_CALLBACK)(
		_Inout_ PTP_CALLBACK_INSTANCE Instance,
		_Inout_opt_ PVOID Context,
		_In_ PVOID ApcContext,
		_In_ PIO_STATUS_BLOCK IoSB,
		_In_ PTP_IO Io);

	// https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/nttp.h#L22
	typedef VOID(NTAPI* PTP_ALPC_CALLBACK_EX)(
		_Inout_ PTP_CALLBACK_INSTANCE Instance,
		_Inout_opt_ PVOID Context,
		_In_ PTP_ALPC Alpc,
		_In_ PVOID ApcContext);

	// From winnt.h
	typedef struct _TP_TIMER TP_TIMER, * PTP_TIMER;

	// From winnt.h
	typedef VOID(NTAPI* PTP_TIMER_CALLBACK)(
		_Inout_ PTP_CALLBACK_INSTANCE Instance,
		_Inout_opt_ PVOID Context,
		_Inout_ PTP_TIMER Timer);

	// From winnt.h
	typedef struct _TP_WAIT TP_WAIT, * PTP_WAIT;

	// From winnt.h
	typedef DWORD TP_WAIT_RESULT;
	typedef VOID(NTAPI* PTP_WAIT_CALLBACK)(
		_Inout_     PTP_CALLBACK_INSTANCE Instance,
		_Inout_opt_ PVOID                 Context,
		_Inout_     PTP_WAIT              Wait,
		_In_        TP_WAIT_RESULT        WaitResult);

	// From winnt.h
	typedef struct _TP_WORK TP_WORK, * PTP_WORK;

	// From winnt.h
	typedef VOID(NTAPI* PTP_WORK_CALLBACK)(
		_Inout_ PTP_CALLBACK_INSTANCE Instance,
		_Inout_opt_ PVOID Context,
		_Inout_ PTP_WORK Work);

	// https://processhacker.sourceforge.io/doc/ntpebteb_8h.html#a1568328a2da2422fe7df18f8069c3cfe
	typedef struct _RTL_CRITICAL_SECTION * PRTL_CRITICAL_SECTION;

	typedef enum _TP_TRACE_TYPE {
		TpTraceThreadPriority,
		TpTraceThreadAffinity,
		MaxTpTraceType
	} TP_TRACE_TYPE;

	// https://github.com/icyguider/Shhhloader/blob/f5f1ed1cf004e49d6d10b5a98038213b467a7d0b/PoolParty.h#L44
	typedef struct _TPP_REFCOUNT {
		volatile INT32 Refcount;
	} TPP_REFCOUNT, * PTPP_REFCOUNT;

	// https://github.com/icyguider/Shhhloader/blob/f5f1ed1cf004e49d6d10b5a98038213b467a7d0b/PoolParty.h#L49
	typedef struct _TPP_CALLER {
		void* ReturnAddress;
	} TPP_CALLER, * PTPP_CALLER;

	// https://github.com/icyguider/Shhhloader/blob/f5f1ed1cf004e49d6d10b5a98038213b467a7d0b/PoolParty.h#L186
	typedef union _TPP_FLAGS_COUNT {
		union {
			UINT64 Count : 60;
			UINT64 Flags : 4;
			INT64 Data;
		} DUMMYUNIONNAME;
	} TPP_FLAGS_COUNT, * PTPP_FLAGS_COUNT;

	// https://github.com/icyguider/Shhhloader/blob/f5f1ed1cf004e49d6d10b5a98038213b467a7d0b/PoolParty.h#L168
	typedef struct _TPP_ITE_WAITER {
		struct _TPP_ITE_WAITER* Next;
		void* ThreadId;
	} TPP_ITE_WAITER, * PTPP_ITE_WAITER;

	// https://github.com/icyguider/Shhhloader/blob/f5f1ed1cf004e49d6d10b5a98038213b467a7d0b/PoolParty.h#L181
	typedef struct _TPP_ITE {
		struct _TPP_ITE_WAITER* First;
	} TPP_ITE, * PTPP_ITE;

	// https://github.com/icyguider/Shhhloader/blob/f5f1ed1cf004e49d6d10b5a98038213b467a7d0b/PoolParty.h#L196
	typedef struct _TPP_BARRIER {
		volatile union _TPP_FLAGS_COUNT Ptr;
		struct _RTL_SRWLOCK WaitLock;
		struct _TPP_ITE WaitList;
	} TPP_BARRIER, * PTPP_BARRIER;

	// https://github.com/icyguider/Shhhloader/blob/f5f1ed1cf004e49d6d10b5a98038213b467a7d0b/PoolParty.h#L202C1-L213C1
	typedef struct _TP_CLEANUP_GROUP {
		struct _TPP_REFCOUNT Refcount;
		INT32 Released;
		struct _RTL_SRWLOCK MemberLock;
		struct _LIST_ENTRY MemberList;
		struct _TPP_BARRIER Barrier;
		struct _RTL_SRWLOCK CleanupLock;
		struct _LIST_ENTRY CleanupList;
	} TP_CLEANUP_GROUP, * PTP_CLEANUP_GROUP;

	// https://github.com/icyguider/Shhhloader/blob/f5f1ed1cf004e49d6d10b5a98038213b467a7d0b/PoolParty.h#L152
	typedef struct _ALPC_WORK_ON_BEHALF_TICKET {
		UINT32 ThreadId;
		UINT32 ThreadCreationTimeLow;
	} ALPC_WORK_ON_BEHALF_TICKET, * PALPC_WORK_ON_BEHALF_TICKET;

	// https://github.com/icyguider/Shhhloader/blob/f5f1ed1cf004e49d6d10b5a98038213b467a7d0b/PoolParty.h#L96
	typedef union _TPP_POOL_QUEUE_STATE {
		union {
			INT64 Exchange;
			struct {
				INT32 RunningThreadGoal : 16;
				UINT32 PendingReleaseCount : 16;
				UINT32 QueueLength;
			} DUMMYSTRUCTNAME;
		} DUMMYUNIONNAME;
	} TPP_POOL_QUEUE_STATE, * PTPP_POOL_QUEUE_STATE;

	// https://github.com/icyguider/Shhhloader/blob/f5f1ed1cf004e49d6d10b5a98038213b467a7d0b/PoolParty.h#L91
	typedef struct _TPP_NUMA_NODE {
		INT32 WorkerCount;
	} TPP_NUMA_NODE, * PTPP_NUMA_NODE;

	// https://github.com/icyguider/Shhhloader/blob/f5f1ed1cf004e49d6d10b5a98038213b467a7d0b/PoolParty.h#L174
	typedef struct _TPP_PH_LINKS {
		_LIST_ENTRY Siblings;
		_LIST_ENTRY Children;
		INT64 Key;
	} TPP_PH_LINKS, * PTPP_PH_LINKS;

	// https://github.com/icyguider/Shhhloader/blob/f5f1ed1cf004e49d6d10b5a98038213b467a7d0b/PoolParty.h#L54C1-L58C1
	typedef struct _TPP_PH {
		struct _TPP_PH_LINKS* Root;
	} TPP_PH, * PTPP_PH;

	// https://github.com/icyguider/Shhhloader/blob/f5f1ed1cf004e49d6d10b5a98038213b467a7d0b/PoolParty.h#L29C1-L34C1
	typedef struct _TP_TASK_CALLBACKS {
		void* ExecuteCallback;
		void* Unposted;
	} TP_TASK_CALLBACKS, * PTP_TASK_CALLBACKS;

	// https://github.com/icyguider/Shhhloader/blob/f5f1ed1cf004e49d6d10b5a98038213b467a7d0b/PoolParty.h#L35
	typedef struct _TP_TASK {
		struct _TP_TASK_CALLBACKS* Callbacks;
		UINT32 NumaNode;
		UINT8 IdealProcessor;
		char Padding_242[3];
		_LIST_ENTRY ListEntry;
	} TP_TASK, * PTP_TASK;

	// https://github.com/icyguider/Shhhloader/blob/f5f1ed1cf004e49d6d10b5a98038213b467a7d0b/PoolParty.h#L59
	typedef struct _TP_DIRECT {
		TP_TASK Task;
		UINT64 Lock;
		LIST_ENTRY IoCompletionInformationList;
		void* Callback;
		UINT32 NumaNode;
		UINT8 IdealProcessor;
		char __PADDING__[3];
	} TP_DIRECT, * PTP_DIRECT;

	// https://github.com/icyguider/Shhhloader/blob/f5f1ed1cf004e49d6d10b5a98038213b467a7d0b/PoolParty.h#L70C1-L80C45
	typedef struct _TPP_TIMER_SUBQUEUE {
		INT64 Expiration;
		TPP_PH WindowStart;
		TPP_PH WindowEnd;
		void* Timer;
		void* TimerPkt;
		TP_DIRECT Direct;
		UINT32 ExpirationWindow;
		INT32 __PADDING__[1];
	} TPP_TIMER_SUBQUEUE, * PTPP_TIMER_SUBQUEUE;

	// https://github.com/icyguider/Shhhloader/blob/f5f1ed1cf004e49d6d10b5a98038213b467a7d0b/PoolParty.h#L82
	typedef struct _TPP_TIMER_QUEUE {
		_RTL_SRWLOCK Lock;
		_TPP_TIMER_SUBQUEUE AbsoluteQueue;
		_TPP_TIMER_SUBQUEUE RelativeQueue;
		INT32 AllocatedTimerCount;
		INT32 __PADDING__[1];
	} TPP_TIMER_QUEUE, * PTPP_TIMER_QUEUE;

	// https://github.com/icyguider/Shhhloader/blob/f5f1ed1cf004e49d6d10b5a98038213b467a7d0b/PoolParty.h#L110
	typedef struct _TPP_QUEUE {
		LIST_ENTRY Queue;
		RTL_SRWLOCK Lock;
	} TPP_QUEUE, * PTPP_QUEUE;

	typedef struct _RTL_CONDITION_VARIABLE {
		PVOID Ptr;
	} RTL_CONDITION_VARIABLE, * PRTL_CONDITION_VARIABLE;

	// https://github.com/icyguider/Shhhloader/blob/f5f1ed1cf004e49d6d10b5a98038213b467a7d0b/PoolParty.h#L116C1-L151C1
	typedef struct _FULL_TP_POOL {
		TPP_REFCOUNT Refcount;
		long Padding_239;
		TPP_POOL_QUEUE_STATE QueueState;
		TPP_QUEUE* TaskQueue[3];
		PTPP_NUMA_NODE NumaNode;
		GROUP_AFFINITY* ProximityInfo;
		void* WorkerFactory;
		void* CompletionPort;
		RTL_SRWLOCK Lock;
		LIST_ENTRY PoolObjectList;
		LIST_ENTRY WorkerList;
		TPP_TIMER_QUEUE TimerQueue;
		RTL_SRWLOCK ShutdownLock;
		UINT8 ShutdownInitiated;
		UINT8 Released;
		UINT16 PoolFlags;
		long Padding_240;
		LIST_ENTRY PoolLinks;
		TPP_CALLER AllocCaller;
		TPP_CALLER ReleaseCaller;
		volatile INT32 AvailableWorkerCount;
		volatile INT32 LongRunningWorkerCount;
		UINT32 LastProcCount;
		volatile INT32 NodeStatus;
		volatile INT32 BindingCount;
		UINT32 CallbackChecksDisabled : 1;
		UINT32 TrimTarget : 11;
		UINT32 TrimmedThrdCount : 11;
		UINT32 SelectedCpuSetCount;
		long Padding_241;
		RTL_CONDITION_VARIABLE TrimComplete;
		LIST_ENTRY TrimmedWorkerList;
	} FULL_TP_POOL, * PFULL_TP_POOL;

	// https://github.com/icyguider/Shhhloader/blob/f5f1ed1cf004e49d6d10b5a98038213b467a7d0b/PoolParty.h#L215
	typedef struct _TPP_CLEANUP_GROUP_MEMBER {
		TPP_REFCOUNT Refcount;
		long Padding_233;
		const struct _TPP_CLEANUP_GROUP_MEMBER_VFUNCS* VFuncs;
		PTP_CLEANUP_GROUP CleanupGroup;
		void* CleanupGroupCancelCallback;
		void* FinalizationCallback;
		LIST_ENTRY CleanupGroupMemberLinks;
		TPP_BARRIER CallbackBarrier;
		union {
			void* Callback;
			void* WorkCallback;
			void* SimpleCallback;
			void* TimerCallback;
			void* WaitCallback;
			void* IoCallback;
			void* AlpcCallback;
			void* AlpcCallbackEx;
			void* JobCallback;
		} DUMMYUNIONNAME;
		void* Context;
		struct _ACTIVATION_CONTEXT* ActivationContext;
		void* SubProcessTag;
		GUID ActivityId;
		ALPC_WORK_ON_BEHALF_TICKET WorkOnBehalfTicket;
		void* RaceDll;
		PFULL_TP_POOL Pool;
		LIST_ENTRY PoolObjectLinks;
		union {
			volatile INT32 Flags;
			UINT32 LongFunction : 1;
			UINT32 Persistent : 1;
			UINT32 UnusedPublic : 14;
			UINT32 Released : 1;
			UINT32 CleanupGroupReleased : 1;
			UINT32 InCleanupGroupCleanupList : 1;
			UINT32 UnusedPrivate : 13;
		};
		long Padding_234;
		TPP_CALLER AllocCaller;
		TPP_CALLER ReleaseCaller;
		TP_CALLBACK_PRIORITY CallbackPriority;
		INT32 __PADDING__[1];
	} TPP_CLEANUP_GROUP_MEMBER, * PTPP_CLEANUP_GROUP_MEMBER;

	// https://github.com/icyguider/Shhhloader/blob/f5f1ed1cf004e49d6d10b5a98038213b467a7d0b/PoolParty.h#L452C1-L464C31
	typedef struct _FULL_TP_JOB {
		struct _TP_DIRECT Direct;
		struct _TPP_CLEANUP_GROUP_MEMBER CleanupGroupMember;
		void* JobHandle;
		union {
			volatile int64_t CompletionState;
			int64_t Rundown : 1;
			int64_t CompletionCount : 63;
		} DUMMYUNIONNAME;
		RTL_SRWLOCK RundownLock;
	} FULL_TP_JOB, * PFULL_TP_JOB;

	// From winnt.h
	typedef struct _TP_POOL_STACK_INFORMATION {
		SIZE_T StackReserve;
		SIZE_T StackCommit;
	}TP_POOL_STACK_INFORMATION, * PTP_POOL_STACK_INFORMATION;

	// ========================== functions ==========================

	// https://processhacker.sourceforge.io/doc/nttp_8h.html
	NTSYSAPI NTSTATUS NTAPI TpAllocAlpcCompletion(
		_Out_ PTP_ALPC* AlpcReturn,
		_In_ HANDLE AlpcPort,
		_In_ PTP_ALPC_CALLBACK Callback,
		_Inout_opt_ PVOID Context,
		_In_opt_ PTP_CALLBACK_ENVIRON CallbackEnviron);

	// https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/nttp.h#L408
	NTSYSAPI NTSTATUS NTAPI TpAllocAlpcCompletionEx(
		_Out_ PTP_ALPC* AlpcReturn,
		_In_ HANDLE AlpcPort,
		_In_ PTP_ALPC_CALLBACK_EX Callback,
		_Inout_opt_ PVOID Context,
		_In_opt_ PTP_CALLBACK_ENVIRON CallbackEnviron);

	// https://processhacker.sourceforge.io/doc/nttp_8h.html
	NTSYSAPI NTSTATUS NTAPI TpAllocCleanupGroup(
		_Out_ PTP_CLEANUP_GROUP* CleanupGroupReturn);

	// https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/nttp.h#L350
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

	// https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/nttp.h#L230
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

	// https://github.com/winsiderss/phnt/blob/7e097448b3a2dc3d1b43f9d0e396bbf49f2655a1/nttp.h#L49
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
	
	//https://docs.rs/phnt/latest/phnt/ffi/fn.TpSetPoolThreadBasePriority.html
	NTSYSAPI NTSTATUS NTAPI TpSetPoolThreadBasePriority(
		_In_ PTP_POOL Pool,
		_In_ ULONG BasePriority);
	
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
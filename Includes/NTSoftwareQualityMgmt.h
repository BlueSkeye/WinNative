#pragma once

#ifndef _NTSQM_
#define _NTSQM_

#include "NtCommonDefs.h"

extern "C" {

	// UNRESOLVED FUNCTIONS
	//WinSqmCheckEscalationAddToStreamEx
	//WinSqmCheckEscalationSetDWORD
	//WinSqmCheckEscalationSetDWORD64
	//WinSqmCheckEscalationSetString
	//WinSqmCommonDatapointDelete
	//WinSqmCommonDatapointSetDWORD
	//WinSqmCommonDatapointSetDWORD64
	//WinSqmCommonDatapointSetStreamEx
	//WinSqmCommonDatapointSetString
	//WinSqmEventEnabled
	//WinSqmEventWrite
	//WinSqmGetEscalationRuleStatus
	//WinSqmGetInstrumentationProperty
	//WinSqmIsOptedIn
	//WinSqmIsOptedInEx
	//WinSqmIsSessionDisabled
	//WinSqmSetEscalationInfo
	//WinSqmStartSession
	//WinSqmStartSessionForPartner
	//WinSqmStartSqmOptinListener
	// END OF UNRESOLVED FUNCTIONS

	// Reversed. Empty function always returning 0. Arguments unknown may not be VOID.
	NTSYSAPI NTSTATUS NTAPI WinSqmAddToAverageDWORD(VOID);

	// Reversed. Empty function always returning 0. Arguments unknown may not be VOID.
	NTSYSAPI NTSTATUS NTAPI WinSqmAddToStream(VOID);

	// Reversed. Empty function always returning 0. Arguments unknown may not be VOID.
	NTSYSAPI NTSTATUS NTAPI WinSqmAddToStreamEx(VOID);

	// Reversed. Empty function always returning 0. Arguments unknown may not be VOID.
	NTSYSAPI NTSTATUS NTAPI WinSqmEndSession(VOID);

	// Reversed. Empty function always returning 0. Arguments unknown may not be VOID.
	NTSYSAPI NTSTATUS NTAPI WinSqmIncrementDWORD(VOID);

	// Reversed. Empty function always returning 0. Arguments unknown may not be VOID.
	NTSYSAPI NTSTATUS NTAPI WinSqmSetDWORD(VOID);

	// Reversed. Empty function always returning 0. Arguments unknown may not be VOID.
	NTSYSAPI NTSTATUS NTAPI WinSqmSetDWORD64(VOID);

	// Reversed. Empty function always returning 0. Arguments unknown may not be VOID.
	NTSYSAPI NTSTATUS NTAPI WinSqmSetIfMaxDWORD(VOID);

	// Reversed. Empty function always returning 0. Arguments unknown may not be VOID.
	NTSYSAPI NTSTATUS NTAPI WinSqmSetIfMinDWORD(VOID);

	// Reversed. Empty function always returning 0. Arguments unknown may not be VOID.
	NTSYSAPI NTSTATUS NTAPI WinSqmSetString(VOID);

}

#endif // _NTSQM_
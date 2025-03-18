#pragma once

#ifndef _NTPEBTEB_
#define _NTPEBTEB_

#include "NtCommonDefs.h"

extern "C" {

	// The Process Environment Block (PEB) and the Thread Environment Block (TEB) are undocumented
	// and their structure differs from one Windows revision to the next.
	// Both structures live in user mode and are different from their kernel counterpart. Direct
	// modification of the PEB and TEB content don't affect the lernel structures.
	// Several source of information are used to define those structures including :
	// Process information block
	// https://learn.microsoft.com/fr-fr/windows/win32/api/winternl/ns-winternl-peb
	// https://bowtiedcrawfish.substack.com/p/understanding-the-peb-and-teb
	// Thread information block
	// https://learn.microsoft.com/fr-fr/windows/win32/api/winternl/ns-winternl-teb
	// https://en.wikipedia.org/wiki/Win32_Thread_Information_Block
	// https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/pebteb/teb/index.htm
	// https://www.nirsoft.net/kernel_struct/vista/TEB.html
	// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FThread%2FTEB.html
	// https://bowtiedcrawfish.substack.com/p/understanding-the-peb-and-teb
	// NOTE : TEB is also known as the Thead Information Block (TIB).

    typedef struct _PEB PEB, * PPEB;
    typedef struct _PEB_LDR_DATA PEB_LDR_DATA, * PPEB_LDR_DATA;
    typedef struct _RTL_USER_PROCESS_PARAMETERS RTL_USER_PROCESS_PARAMETERS,
        * PRTL_USER_PROCESS_PARAMETERS;
    typedef struct _TEB TEB, * PTEB;

    typedef VOID (NTAPI* PPS_POST_PROCESS_INIT_ROUTINE) (VOID);

    // https://learn.microsoft.com/fr-fr/windows/win32/api/winternl/ns-winternl-peb_ldr_data
    struct _PEB_LDR_DATA {
        BYTE Reserved1[8];
        PVOID Reserved2[3];
        LIST_ENTRY InMemoryOrderModuleList; // MS official
    };

    // https://learn.microsoft.com/fr-fr/windows/win32/api/winternl/ns-winternl-rtl_user_process_parameters
    struct _RTL_USER_PROCESS_PARAMETERS {
        BYTE Reserved1[16];
        PVOID Reserved2[10];
        UNICODE_STRING ImagePathName; // MS official
        UNICODE_STRING CommandLine; // MS official
    };

    // https://learn.microsoft.com/fr-fr/windows/win32/api/winternl/ns-winternl-peb
    struct _PEB {
        BYTE Reserved1[2];
        BYTE BeingDebugged; // MS official
        BYTE Reserved2[21];
        PPEB_LDR_DATA LoaderData; // MS official
        PRTL_USER_PROCESS_PARAMETERS ProcessParameters; // MS official
        BYTE Reserved3[520];
        PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;  // MS official. Definition in SDK.
        BYTE Reserved4[136];
        ULONG SessionId; // MS official
    };

    // https://learn.microsoft.com/fr-fr/windows/win32/api/winternl/ns-winternl-teb
    struct _TEB {
        PVOID Reserved1[12];
        PPEB ProcessEnvironmentBlock; // MS official
        PVOID Reserved2[399];
        BYTE Reserved3[1952];
        PVOID TlsSlots[64]; // MS official
        BYTE Reserved4[8];
        PVOID Reserved5[26];
        PVOID ReservedForOle;
        PVOID Reserved6[4];
        PVOID TlsExpansionSlots; // MS official
    };
}

#endif
#pragma once

#ifndef _NTSILOING_
#define _NTSILOING_

#include "NtCommonDefs.h"

#ifdef __cplusplus
extern "C" {
#endif

    // https://github.com/winsiderss/systeminformer/blob/fb60c2a4494de6f27ffdfefc85364d5b357a2ffa/phnt/include/ntpsapi.h#L3451
    typedef struct _SILO_USER_SHARED_DATA {
        ULONG ServiceSessionId;
        ULONG ActiveConsoleId;
        LONGLONG ConsoleSessionForegroundProcessId;
        NT_PRODUCT_TYPE NtProductType;
        ULONG SuiteMask;
        ULONG SharedUserSessionId; // since RS2
        BOOLEAN IsMultiSessionSku;
        BOOLEAN IsStateSeparationEnabled;
        WCHAR NtSystemRoot[260];
        USHORT UserModeGlobalLogger[16];
        ULONG TimeZoneId; // since 21H2
        LONG TimeZoneBiasStamp;
        KSYSTEM_TIME TimeZoneBias;
        LARGE_INTEGER TimeZoneBiasEffectiveStart;
        LARGE_INTEGER TimeZoneBiasEffectiveEnd;
    } SILO_USER_SHARED_DATA, * PSILO_USER_SHARED_DATA;

#ifdef __cplusplus
}
#endif

#endif // _NTSILOING_

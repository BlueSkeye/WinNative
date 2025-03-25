#pragma once

#ifndef _NTLANGUAGESUPPORT_
#define _NTLANGUAGESUPPORT_

#include "NtCommonDefs.h"

#ifdef __cplusplus
extern "C" {
#endif

	NTSYSAPI DWORD NlsAnsiCodePage;
	NTSYSAPI BYTE NlsMbCodePageTag;
	NTSYSAPI BYTE NlsMbOemCodePageTag;

#ifdef __cplusplus
}
#endif

#endif // _NTLANGUAGESUPPORT_
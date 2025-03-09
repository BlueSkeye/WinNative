#pragma once

#ifndef _NTLANGUAGESUPPORT_
#define _NTLANGUAGESUPPORT_

#include "NtCommonDefs.h"

extern "C" {

	NTSYSAPI DWORD NlsAnsiCodePage;
	NTSYSAPI BYTE NlsMbCodePageTag;
	NTSYSAPI BYTE NlsMbOemCodePageTag;

}

#endif // _NTLANGUAGESUPPORT_
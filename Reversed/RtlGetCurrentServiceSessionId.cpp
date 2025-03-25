#include "PebTeb.h"

NTSYSAPI DWORD NTAPI RtlGetCurrentServiceSessionId()
{
	PSERVICE_SESSION pCurrentSession = NtCurrentTeb()->ProcessEnvironmentBlock->pCurrentServiceSession;
	return (NULL == pCurrentSession) ? 0 : pCurrentSession->SessionId;
}

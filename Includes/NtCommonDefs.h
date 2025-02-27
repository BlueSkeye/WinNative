#pragma once

#ifndef _NTCOMMONDEFS_
#define _NTCOMMONDEFS_

// To be found in %SystemDrive%\Program Files (x86)\Windows Kits\10\Include\x.y.z.t\shared
#include <minwindef.h>

typedef LONG NTSTATUS;

#define NTSYSAPI     __declspec(dllimport)
#define NTSYSCALLAPI __declspec(dllimport)

#endif // _NTCOMMONDEFS_
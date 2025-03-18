# Build a native EXE program with VS 2022 C/C++

## Requirements
[Latest Windows SDK](https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/)<br/>
<br/>
## Includes and libraries
The x.y.z.t term is used below as the Windows SDK version of interest. At time of writing this is 10.0.26100.0.<br/>
"minwindef.h"  from %SystemDrive%\Program Files (x86)\Windows Kits\10\Include\x.y.z.t\shared<br/>
"winternl.h" from %SystemDrive%\Program Files (x86)\Windows Kits\10\Include\x.y.z.t<br/>
"ntdll.lib" from %SystemDrive%\Program Files (x86)\Windows Kits\10\Lib\x.y.z.t\um\x64<br/>
<br/>
## VS2022 project creation
Create a new application in VS2022 having type :<br/>
- Language : C++
- Platform : Windows
- Project type : Console (we will change this later)
<br/>
Next make sure project properties match following values :
- General properties
  - Configuration type : Application (.exe)
  - Windows SDK version : 10.0 (latest installed version)
  - Platform toolkit : Visual Studio 2022 (v143)
- Linker
  - System
    - Subsystem : Native (/SUBSYSTEM:NATIVE)
  - Input
    - Additional dependencies : ntdll.lib (uncheck inheritance checkbox)
    - Ignore default libraries : Yes (/NODEFAULTLIB)
- C/C++
  - Code generation
    - Basic runtime checks : Default
    - Enable C++ Exceptions : No
    - Runtime library : Multi-threaded (/MT)
    - Security Check : Disable Security Check (/GS-)
<br/>

## Main project file
The main project file should include <windows.h> and <winternl.h> files.<br/>
WARNING : Not all windows.h direct or indirect included content is usable by the project.<br/>
More specifically, any windows subsystem provided function (from kernel32, gdi32, user32 ...) is only<br/>
available in the Windows subsystem, not in the native context.<br/>
<br/>
The project entry function is NOT :
```
int main(int argc, char* argv[]) ...
```
A native project entry function MUST be :
```
extern "C" void NTAPI NtProcessStartup(PPEB peb) ...
```
<br/>

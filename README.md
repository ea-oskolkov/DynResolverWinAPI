# Description

Library for dynamically resolving Windows API imports using the undocumented [LdrLoadDLL](http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FLdrLoadDll.html) and [LdrGetProcedureAddress](http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FLdrGetProcedureAddress.html) functions.

# Example

```C
#include "APIResolver.h"

#define KERNEL32 L"kernel32.dll"
#define USER32   L"user32.dll"
#define NTDLL    L"user32.dll"

// Initialization 
MODULE_INF arr[] = 
{
	{KERNEL32},
	{USER32}
};
	
auto status = WinAPIRsolver::init(arr, sizeof(arr)/sizeof(arr[0]));
if (!WAPI_SUCCESS(status))
	return; // Error handling
    
// Call
WAPI(USER32, MessageBoxA)(0, "Hello world", "Message", 0);

// Or
using _NtUnmapViewOfSection = NTSTATUS(*)(IN HANDLE Proccesshandle,IN PVOID BaseAddreess); // Must be prefixed with _
_WAPI(NTDLL, NtUnmapViewOfSection)(...);

```

# LICENSE

This software is distributed under [MIT](https://opensource.org/licenses/MIT) license.

# Notice
Only x64.

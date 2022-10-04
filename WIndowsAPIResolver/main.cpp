#include "APIResolver.h"

#define KERNEL32 L"kernel32.dll"
#define USER32   L"user32.dll"

int main()
{
	// Usage example
	
	// Modules arrays
	MODULE_INF arr[] = 
	{
		{KERNEL32},
		{USER32}
	};
	
	// Init
	auto status = WinAPIResolver::init(arr, COUNT_OF(arr));
	if (!WAPI_SUCCESS(status))
		return 0;


	// Example using WAPI(...)
	WAPI(USER32, MessageBoxA)(0, "Hello world", "Hello world", 0);

	return 0;
}
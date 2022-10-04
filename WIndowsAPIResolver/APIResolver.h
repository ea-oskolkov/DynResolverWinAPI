/*
	MIT License
	Copyright (c) 2022 Evgeny Oskolkov (ea dot oskolkov at yandex.ru)
	Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
	The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#pragma once
#include <Windows.h>
#include <subauth.h>
#include <cstdint>

#ifdef _WIN64
#define MAX_LEN_MODULE_NAME 256

#define WAPI_SUCCESS(dwapiStatus) (dwapiStatus == WAPI_RSOLVER_STATUS::SUCCESS)

#define COUNT_OF(arr) (sizeof(arr)/sizeof(arr[0]))

enum class WAPI_RSOLVER_STATUS {
	SUCCESS = 0,
	ERROR_LOAD_LIB,
	ERROR_NO_LIBS,
	ERROR_INVALID_PARAM,
	ERROR_NTDLL_HANDLE,
	ERROR_FIND_LDRLOADDLL,
	ERROR_FIND_LDRGETPROCEDUREADDRESS,
};

typedef struct _MODULE_INF {
	WCHAR moduleName[MAX_LEN_MODULE_NAME];
	HMODULE hLib = 0;
} MODULE_INF, * PMODULE_INF;

namespace WinAPIResolver
{
	typedef struct _UNICODE_STRING
	{
		USHORT Length;
		USHORT MaximumLength;
		PWSTR Buffer;
	} UNICODE_STRING, * PUNICODE_STRING;

	typedef struct _STRING {
		USHORT Length;
		USHORT MaximumLength;
		PCHAR  Buffer;
	} STRING;

	typedef STRING ANSI_STRING, * PANSI_STRING;

	typedef struct _ModuleInfoNode {

		LIST_ENTRY              InLoadOrderModuleList;
		LIST_ENTRY              InMemoryOrderModuleList;
		LIST_ENTRY              InInitializationOrderModuleList;
		PVOID                   BaseAddress;
		PVOID                   EntryPoint;
		ULONG                   SizeOfImage;
		UNICODE_STRING          FullDllName;
		UNICODE_STRING          BaseDllName;
		ULONG                   Flags;
		SHORT                   LoadCount;
		SHORT                   TlsIndex;
		LIST_ENTRY              HashTableEntry;
		ULONG                   TimeDateStamp;

	} ModuleInfoNode, * pModuleInfoNode;

	typedef struct _ProcessModuleInfo {
		/*000*/  ULONG Length;
		/*004*/  BOOLEAN Initialized;
		/*008*/  PVOID SsHandle;
		/*00C*/  LIST_ENTRY ModuleListLoadOrder;
		/*014*/  LIST_ENTRY ModuleListMemoryOrder;
		/*018*/  LIST_ENTRY ModuleListInitOrder;
		/*020*/
	} ProcessModuleInfo, * pProcessModuleInfo;

	typedef struct _PEB_LDR_DATA {
		BYTE Reserved1[8];
		PVOID Reserved2[3];
		LIST_ENTRY InMemoryOrderModuleList;
	} PEB_LDR_DATA, * PPEB_LDR_DATA;

	typedef struct _RTL_USER_PROCESS_PARAMETERS {
		BYTE Reserved1[16];
		PVOID Reserved2[10];
		UNICODE_STRING ImagePathName;
		UNICODE_STRING CommandLine;
	} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

	using PPS_POST_PROCESS_INIT_ROUTINE = VOID(NTAPI*)(VOID);

	typedef struct _PEB {
		BYTE Reserved1[2];
		BYTE BeingDebugged;
		BYTE Reserved2[1];
		PVOID Reserved3[2];
		PPEB_LDR_DATA Ldr;
		PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
		PVOID Reserved4[3];
		PVOID AtlThunkSListPtr;
		PVOID Reserved5;
		ULONG Reserved6;
		PVOID Reserved7;
		ULONG Reserved8;
		ULONG AtlThunkSListPtr32;
		PVOID Reserved9[45];
		BYTE Reserved10[96];
		PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
		BYTE Reserved11[128];
		PVOID Reserved12[1];
		ULONG SessionId;
	} PEB, * PPEB;

	using PLdrLoadDll = NTSTATUS(*)(PWCHAR, ULONG, PUNICODE_STRING, HMODULE*);
	using LdrGetProcedureAddress = NTSTATUS(*)(IN HMODULE ModuleHandle, IN PANSI_STRING FunctionName OPTIONAL, WORD Oridinal OPTIONAL, PVOID* FunctionAddress);

	/**
		@brief This function gets the handle to the DLL 'ntdll.dll' from PEB.
		@return handle NTDLL.dll.
	*/
	HMODULE getHandleNtDll();

	/**
		@brief This function get address of function: LdrLoadDll, pLdrGetProcedureAddress and handle of NTDLL.
		@return operation status (WAPI_RSOLVER_STATUS).
		@param pModuleInfArr pointer to module array.
		@param count array size.
	*/
	WAPI_RSOLVER_STATUS init(const PMODULE_INF pModuleInf, const uint64_t count);

	/**
		@brief Load all DLL.
		@return operation status (WAPI_RSOLVER_STATUS).
		@param pModuleInfArr pointer to module array.
		@param count array size.
	*/
	WAPI_RSOLVER_STATUS loadModules(const PMODULE_INF pModuleInf, const uint64_t count);

	/**
		@brief Get handle DLL by name.
		@return DLL handle.
		@param dllName DLL name.
	*/
	HMODULE getHandleModuleByName(const wchar_t* const dllName);

	/**
		@brief Find the address of a function from a NTDLL
		@return address of a function.
		@param functionName name function.
	*/
	LPVOID getFuncAddrFromNtdll(const char* const functionName);

	/**
		@biref Loading DLL using native Windows-API function 'LdrLoadDll'.
		@return handle of a DLL.
		@param dllName DLL name.
	*/
	HMODULE loadLibrary(const wchar_t* const dllName);

	/**
		@brief Get procedure name with native function 'pLdrGetProcedureAddress'.
		@return function pointer.
		@param hmodule module handle from which to get the function.
		@param functionName name function.
	*/
	PVOID getProcAddress(const HMODULE hmodule, const char* const functionName);

};

#define WAPI(dll, func) ((decltype(&func))WinAPIResolver::getProcAddress(WinAPIResolver::getHandleModuleByName(##dll), (char*)#func))
#define _WAPI(dll, func) ((_##func)dynWAPI::getProcAddress(dynWAPI::getHandleModuleByName(##dll), (char*)#func))
#endif
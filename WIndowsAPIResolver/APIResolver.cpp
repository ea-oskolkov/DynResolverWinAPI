/*
	MIT License
	Copyright (c) 2022 Evgeny Oskolkov (ea dot oskolkov at yandex.ru)
	Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
	The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "APIResolver.h"
#include "APIResolverUtils.h"

static WinAPIRsolver::LdrGetProcedureAddress pLdrGetProcedureAddress = nullptr;
static WinAPIRsolver::PLdrLoadDll            pLdrLoadDll = nullptr;
static HMODULE                hNtdll = 0;
static PMODULE_INF            arrModuleInf = nullptr;
static uint64_t               countModules = 0ull;

static constexpr const auto PEB_OFFSET = 0x60;
static constexpr const auto STR_NTDLL = L"ntdll.dll";
static constexpr const auto STR_LDRLOADDLL = "LdrLoadDll";
static constexpr const auto STR_LDRGETPROCEDUREADDRESS = "LdrGetProcedureAddress";

namespace WinAPIRsolver
{

	WAPI_RSOLVER_STATUS init(const PMODULE_INF pModuleInfArr, const uint64_t count) {

		if (pModuleInfArr == nullptr || count == 0)
			return WAPI_RSOLVER_STATUS::ERROR_INVALID_PARAM;

		// Get ntdll handle
		hNtdll = getHandleNtDll();

		if (hNtdll == 0)
			return WAPI_RSOLVER_STATUS::ERROR_NTDLL_HANDLE;

		// Get LdrLoadDll func address
		pLdrLoadDll = (PLdrLoadDll)(getFuncAddrFromNtdll(STR_LDRLOADDLL));

		if (pLdrLoadDll == nullptr)
			return WAPI_RSOLVER_STATUS::ERROR_FIND_LDRLOADDLL;

		// Get LdrGetProcedureAddress func address
		pLdrGetProcedureAddress = (LdrGetProcedureAddress)
			(getFuncAddrFromNtdll(STR_LDRGETPROCEDUREADDRESS));

		if (pLdrGetProcedureAddress == nullptr)
			return WAPI_RSOLVER_STATUS::ERROR_FIND_LDRGETPROCEDUREADDRESS;

		WAPI_RSOLVER_STATUS status = loadModules(pModuleInfArr, count);
		if (WAPI_SUCCESS(status))
		{
			arrModuleInf = pModuleInfArr;
			countModules = count;
		}

		return status;
	}

	WAPI_RSOLVER_STATUS loadModules(const PMODULE_INF pModuleInfArr, const uint64_t count) {

		for (uint64_t i = 0; i < count; ++i) {
			pModuleInfArr[i].hLib = loadLibrary(pModuleInfArr[i].moduleName);

			if (!pModuleInfArr[i].hLib)
				return WAPI_RSOLVER_STATUS::ERROR_LOAD_LIB;
		}

		return WAPI_RSOLVER_STATUS::SUCCESS;
	}

	HMODULE loadLibrary(const wchar_t* const dllName) {

		if (dllName == nullptr)
			return 0;

		// Init string
		const auto dllNameSize = stringSize(dllName);
		UNICODE_STRING UnicodeDllName;
		UnicodeDllName.Buffer = (wchar_t*)(dllName);
		UnicodeDllName.Length = (USHORT)(dllNameSize);
		UnicodeDllName.MaximumLength = (USHORT)((dllNameSize)+sizeof(wchar_t));

		// Get handle of DLL
		HMODULE outHandle = 0;
		if (pLdrLoadDll(nullptr, 0, &UnicodeDllName, &outHandle) == STATUS_SUCCESS)
			return outHandle;
		return 0;
	}

	HMODULE getHandleNtDll() {

		HMODULE handleNtdll = 0;

		PPEB ptrPeb = (PPEB)(__readgsqword(PEB_OFFSET));
		if (ptrPeb) {
			pProcessModuleInfo ProcessModule = (pProcessModuleInfo)(ptrPeb->Ldr);
			pModuleInfoNode    ModuleList = (pModuleInfoNode)(ProcessModule->ModuleListLoadOrder.Flink);

			// Finding dlls trought the PEB
			while (ModuleList->BaseAddress) {

				// Find NTDLL.dll
				if (compareString((wchar_t*)ModuleList->BaseDllName.Buffer, (wchar_t*)STR_NTDLL))
				{
					handleNtdll = (HMODULE)(ModuleList->BaseAddress);
					break;
				}

				ModuleList = (pModuleInfoNode)(ModuleList->InLoadOrderModuleList.Flink);
			}
		}

		return handleNtdll;
	}

	HMODULE getHandleModuleByName(const wchar_t* const dllName) {

		for (uint64_t i = 0; i < countModules; ++i) {
			if (compareString((const wchar_t*)arrModuleInf[i].moduleName, dllName))
				return arrModuleInf[i].hLib;
		}

		return 0;
	}

	LPVOID getFuncAddrFromNtdll(const char* const functionName) {

		if (functionName == nullptr)
			return nullptr;

		PIMAGE_DOS_HEADER       imgDosHeader = nullptr;
		PIMAGE_NT_HEADERS       imgNtheader = nullptr;
		PIMAGE_EXPORT_DIRECTORY exportSection = nullptr;
		PDWORD                  nameExpFuncBaseAddr = nullptr;
		PWORD                   rvaOrdinal = nullptr;

		imgDosHeader = (PIMAGE_DOS_HEADER)(hNtdll);
		if (imgDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
			return nullptr;

		imgNtheader = (PIMAGE_NT_HEADERS)((DWORD_PTR)(imgDosHeader)+imgDosHeader->e_lfanew);
		if (imgNtheader->Signature != IMAGE_NT_SIGNATURE)
			return nullptr;

		if ((imgNtheader->FileHeader.Characteristics & IMAGE_FILE_DLL) == NULL
			|| imgNtheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == NULL
			|| imgNtheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size == NULL)
			return nullptr;

		exportSection = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)(imgDosHeader)+
			imgNtheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

		if (exportSection == nullptr)
			return nullptr;

		nameExpFuncBaseAddr = (PDWORD)((DWORD_PTR)(imgDosHeader)+
			exportSection->AddressOfNames);

		if (nameExpFuncBaseAddr == nullptr)
			return nullptr;

		rvaOrdinal = (PWORD)((DWORD_PTR)(imgDosHeader)+
			exportSection->AddressOfNameOrdinals);

		if (rvaOrdinal == nullptr)
			return nullptr;

		// Function search
		int ordinal = -1;
		for (DWORD i = 0; i < exportSection->NumberOfNames; ++i) {
			PCHAR api_name = (PCHAR)((DWORD_PTR)(imgDosHeader)+nameExpFuncBaseAddr[i]);

			if (compareString((PCHAR)api_name, (PCHAR)functionName)) {
				ordinal = (UINT)(rvaOrdinal[i]);
				break;
			}
		}

		if (ordinal != -1)
		{
			PDWORD offsetFunc = (PDWORD)((DWORD_PTR)(imgDosHeader)+
				exportSection->AddressOfFunctions);
			return (LPVOID)((DWORD_PTR)(imgDosHeader)+offsetFunc[ordinal]);
		}

		return nullptr;
	}

	PVOID getProcAddress(const HMODULE hmodule, const char* const functionName)
	{
		if (functionName == nullptr)
			return nullptr;

		// Init string
		const auto fNameSize = stringSize(functionName);
		ANSI_STRING ansiStringName;
		ansiStringName.Buffer = (char*)(functionName);
		ansiStringName.Length = (USHORT)(fNameSize);
		ansiStringName.MaximumLength = (USHORT)((fNameSize)+sizeof(char));

		// Get handle of DLL
		PVOID outAddr = nullptr;
		if (pLdrGetProcedureAddress(hmodule, &ansiStringName, 0, &outAddr) == STATUS_SUCCESS)
			return outAddr;
		return 0;
	}

}
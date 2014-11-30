#ifndef __cplusplus
#error "this file is C++ header"
#endif

#pragma once
#include <vector>

#define NT_GLOBAL_FLAG_UST 0x00001000 // user mode stack trace database enabled
#define NT_GLOBAL_FLAG_HPA 0x02000000 // page heap enabled

#define PAGE_SIZE 0x1000

#define READMEMORY(address, var) (ReadMemory(address, &var, sizeof(var), &cb) && cb == sizeof(var))

/**
*	@brief is target process 64 bit or not (32 bit)
*	@retval true 64 bit process
*	@retval false 32 bit process (include WOW64 process)
*/
bool IsTarget64();

/**
*	@brief obtain PEB address
*/
ULONG64 GetPebAddress();

/**
*	@brief get NtGlobalFlag from PEB
*/
ULONG32 GetNtGlobalFlag();

#define OS_VERSION_WIN7 (((ULONG64)6 << 32) | 1)
#define OS_VERSION_WIN8 (((ULONG64)6 << 32) | 2)
#define OS_VERSION_WIN81 (((ULONG64)6 << 32) | 3)

/**
*	@brief get OSMajorVersion and OSMinorVersion
*	@return ((OSMajorVersion << 32) | OSMinorVersion)
*/
ULONG64 GetOSVersion();

/**
*	@brief get pointer to stack trace array
*/
ULONG64 GetStackTraceArrayPtr(ULONG64 ustAddress, bool isTarget64);

/**
*	@brief get stack trace from user mode stack trace database
*/
std::vector<ULONG64> GetStackTrace(ULONG64 ustAddress, bool isTarget64, ULONG32 ntGlobalFlag);

/**
*	@brief module information from LDR_DATA_TABLE_ENTRY
*/
struct ModuleInfo
{
	ULONG64 DllBase;
	ULONG64 SizeOfImage;
	CHAR FullDllName[MAX_PATH];
};

/**
*	@brief get information of loaded modules in PEB::InMemoryOrderModuleList
*/
std::vector<ModuleInfo> GetLoadedModules();

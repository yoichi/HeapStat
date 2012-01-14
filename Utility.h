#ifndef __cplusplus
#error "this file is C++ header"
#endif

#include <vector>

#define NT_GLOBAL_FLAG_UST 0x00001000 // user mode stack trace database enabled
#define NT_GLOBAL_FLAG_HPA 0x02000000 // page heap enabled

#define PEB32_OFFSET 0x1000 // PEB64 - PEB32 offset

#define READMEMORY(address, var) (ReadMemory(address, &var, sizeof(var), &cb) && cb == sizeof(var))

/**
*	@brief is target process 64 bit or not (32 bit)
*	@retval true 64 bit process
*	@retval false 32 bit process (include WOW64 process)
*/
bool IsTarget64();

/**
*	@brief get NtGlobalFlag from PEB
*/
ULONG32 GetNtGlobalFlag();

/**
*	@brief get stack trace from user mode stack trace database
*/
std::vector<ULONG64> GetStackTrace(ULONG64 ustAddress);

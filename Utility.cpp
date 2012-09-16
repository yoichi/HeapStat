#include "common.h"
#include "Utility.h"

bool IsTarget64()
{
	ULONG64 address;
	GetTebAddress(&address);
	return (address >> 32) != 0;
}

ULONG32 GetNtGlobalFlag()
{
	ULONG64 address;
	ULONG32 ntGlobalFlag;

	GetPebAddress(NULL, &address);
	if (IsTarget64())
	{
		if (GetFieldValue(address, "ntdll!_PEB", "NtGlobalFlag", ntGlobalFlag) != 0)
		{
			dprintf("read NtGlobalFlag failed\n");
			return 0;
		}
	}
	else
	{
		if (IsPtr64())
		{
			address -= PEB32_OFFSET;
		}
		ULONG cb;
		if (!READMEMORY(address + 0x68, ntGlobalFlag))
		{
			dprintf("read NtGlobalFlag failed\n");
			return 0;
		}
	}
	return ntGlobalFlag;
}

ULONG64 GetStackTraceArrayPtr(ULONG64 ustAddress)
{
	if (IsTarget64())
	{
		return ustAddress + 0x10;
	}
	else
	{
		return ustAddress + 0xc;
	}
}

std::vector<ULONG64> GetStackTrace(ULONG64 ustAddress)
{
	std::vector<ULONG64> trace;

	ULONG cb;
	ULONG32 ntGlobalFlag;
	USHORT depth;
	ULONG64 offset;
	const bool isTarget64 = IsTarget64();

	ntGlobalFlag = GetNtGlobalFlag();
	if (ntGlobalFlag & NT_GLOBAL_FLAG_HPA)
	{
		//dprintf("hpa enabled\n");
		offset = isTarget64 ? 0xe : 0xa;
	}
	else if (ntGlobalFlag & NT_GLOBAL_FLAG_UST)
	{
		//dprintf("ust enabled\n");
		offset = isTarget64 ? 0xc : 0x8;
	}
	else
	{
		dprintf("please set ust or hpa by gflags.exe\n");
		return trace;
	}

	if (!READMEMORY(ustAddress + offset, depth))
	{
		dprintf("read depth failed\n");
		return trace;
	}

	ULONG64 address = GetStackTraceArrayPtr(ustAddress);
	if (isTarget64)
	{
		for (int i = 0; i < depth; i++)
		{
			ULONG64 sp;
			if (!READMEMORY(address, sp))
			{
				dprintf("read sp failed\n");
				return trace;
			}
			trace.push_back(sp);
			address += sizeof(sp);
		}
	}
	else
	{
		for (int i = 0; i < depth; i++)
		{
			ULONG32 sp;
			if (!READMEMORY(address, sp))
			{
				dprintf("read sp failed\n");
				return trace;
			}
			trace.push_back((ULONG64)sp);
			address += sizeof(sp);
		}
	}
	return trace;
}

std::vector<ModuleInfo> GetLoadedModules()
{
	std::vector<ModuleInfo> info;
	ULONG64 pebAddress;
	GetPebAddress(NULL, &pebAddress);
	if (!IsTarget64() && IsPtr64())
	{
		pebAddress -= PEB32_OFFSET;
	}

	ULONG cb;
	if (IsTarget64())
	{
		ULONG64 ldr;
		if (GetFieldValue(pebAddress, "ntdll!_PEB", "Ldr", ldr) != 0)
		{
			dprintf("read Ldr failed\n");
			goto ERROR_EXIT;
		}

		ULONG offset;
		if (GetFieldOffset("ntdll!_PEB_LDR_DATA", "InMemoryOrderModuleList", &offset) != 0)
		{
			dprintf("GetFieldOffset(_PEB_LDR_DATA::InMemoryOrderModuleList) failed\n");
			goto ERROR_EXIT;
		}
		ULONG64 headAddress = ldr + offset;
		LIST_ENTRY64 inMemoryOrderModuleList;
		if (GetFieldValue(ldr, "ntdll!_PEB_LDR_DATA", "InMemoryOrderModuleList", inMemoryOrderModuleList) != 0)
		{
			dprintf("read InMemoryOrderModuleList failed\n");
			goto ERROR_EXIT;
		}

		LIST_ENTRY64 entry = inMemoryOrderModuleList;
		while (entry.Flink != headAddress)
		{
			ModuleInfo moduleInfo;
			ULONG64 address = entry.Flink;
			if (!READMEMORY(address, entry))
			{
				dprintf("read entry at %p failed\n", address);
				goto ERROR_EXIT;
			}

			// LDR_DATA_TABLE_ENTRY at address - sizeof(entry)
			ULONG64 dllBase, sizeOfImage;
			if (GetFieldValue(address - sizeof(entry), "ntdll!_LDR_DATA_TABLE_ENTRY", "DllBase", dllBase) != 0)
			{
				dprintf("read DllBase around %p failed\n", address - sizeof(entry));
				goto ERROR_EXIT;
			}
			moduleInfo.DllBase = dllBase;
			if (GetFieldValue(address - sizeof(entry), "ntdll!_LDR_DATA_TABLE_ENTRY", "SizeOfImage", sizeOfImage) != 0)
			{
				dprintf("read SizeOfImage around %p failed\n", address - sizeof(entry));
				goto ERROR_EXIT;
			}
			moduleInfo.SizeOfImage = sizeOfImage;

			// UNICODE_STRING
			struct
			{
				USHORT Length;
				USHORT MaximumLength;
				ULONG64 Buffer;
			} fullDllName;
			if (GetFieldValue(address - sizeof(entry), "ntdll!_LDR_DATA_TABLE_ENTRY", "FullDllName", fullDllName) != 0)
			{
				dprintf("read FullDllName around %p failed\n", address - sizeof(entry));
				goto ERROR_EXIT;
			}
			std::vector<wchar_t> unicode;
			unicode.resize(fullDllName.Length / sizeof(wchar_t));
			if (!ReadMemory(fullDllName.Buffer, &unicode[0], fullDllName.Length, &cb) || cb != fullDllName.Length)
			{
				dprintf("read unicode at %p %d failed\n", fullDllName.Buffer, (int)fullDllName.Length);
				goto ERROR_EXIT;
			}
		
			int written = WideCharToMultiByte(CP_ACP, 0, &unicode[0], fullDllName.Length / sizeof(wchar_t),
				moduleInfo.FullDllName, sizeof(moduleInfo.FullDllName), NULL, NULL);
			if (written < 0 || written >= sizeof(moduleInfo.FullDllName))
			{
				dprintf("WideCharToMultiByte returns %d\n", written);
				goto ERROR_EXIT;
			}
			moduleInfo.FullDllName[written] = '\0';
			info.push_back(moduleInfo);
		}
		return info;
	}
	else
	{
		ULONG32 ldr;
		if (!READMEMORY(pebAddress + 0xc, ldr))
		{
			dprintf("read Ldr failed\n");
			goto ERROR_EXIT;
		}

		ULONG64 headAddress = ldr + 0x14;
		LIST_ENTRY32 inMemoryOrderModuleList;
		if (!READMEMORY(headAddress, inMemoryOrderModuleList))
		{
			dprintf("read InMemoryOrderModuleList failed\n");
			goto ERROR_EXIT;
		}

		LIST_ENTRY32 entry = inMemoryOrderModuleList;
		while (entry.Flink != headAddress)
		{
			ModuleInfo moduleInfo;
			ULONG64 address = entry.Flink;
			if (!READMEMORY(address, entry))
			{
				dprintf("read entry at %p failed\n", address);
				goto ERROR_EXIT;
			}

			// LDR_DATA_TABLE_ENTRY at address - sizeof(entry)
			ULONG32 dllBase, sizeOfImage;
			if (!READMEMORY(address - sizeof(entry) + 0x18, dllBase))
			{
				dprintf("read DllBase at %p failed\n", address - sizeof(entry) + 0x18);
				goto ERROR_EXIT;
			}
			moduleInfo.DllBase = dllBase;
			if (!READMEMORY(address - sizeof(entry) + 0x20, sizeOfImage))
			{
				dprintf("read SizeOfImage at %p failed\n", address - sizeof(entry) + 0x20);
				goto ERROR_EXIT;
			}
			moduleInfo.SizeOfImage = sizeOfImage;

			// UNICODE_STRING
			struct
			{
				USHORT Length;
				USHORT MaximumLength;
				ULONG32 Buffer;
			} fullDllName;
			if (!READMEMORY(address - sizeof(entry) + 0x24, fullDllName))
			{
				dprintf("read FullDllName at %p failed\n", address - sizeof(entry) + 0x24);
				goto ERROR_EXIT;
			}
			std::vector<wchar_t> unicode;
			unicode.resize(fullDllName.Length / sizeof(wchar_t));
			if (!ReadMemory(fullDllName.Buffer, &unicode[0], fullDllName.Length, &cb) || cb != fullDllName.Length)
			{
				dprintf("read unicode at %p %d failed\n", (ULONG64)fullDllName.Buffer, (int)fullDllName.Length);
				goto ERROR_EXIT;
			}
		
			int written = WideCharToMultiByte(CP_ACP, 0, &unicode[0], fullDllName.Length / sizeof(wchar_t),
				moduleInfo.FullDllName, sizeof(moduleInfo.FullDllName), NULL, NULL);
			if (written < 0 || written >= sizeof(moduleInfo.FullDllName))
			{
				dprintf("WideCharToMultiByte returns %d\n", written);
				goto ERROR_EXIT;
			}
			moduleInfo.FullDllName[written] = '\0';
			info.push_back(moduleInfo);
		}
		return info;
	}

ERROR_EXIT:
	info.clear();
	return info;
}

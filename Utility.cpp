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

#include "common.h"
#include <map>
#include <list>

#define NT_GLOBAL_FLAG_UST 0x00001000 // user mode stack trace database enabled
#define NT_GLOBAL_FLAG_HPA 0x02000000 // page heap enabled

#define READMEMORY(address, var) (ReadMemory(address, &var, sizeof(var), &cb) && cb == sizeof(var))

typedef struct {
	ULONG Flink;
	ULONG Blink;
} ListEntry;

typedef struct {
	USHORT Size;
	UCHAR Flags;
	UCHAR SmallTagIndex; // xor of first three bytes
	USHORT PreviousSize;
	UCHAR SegmentOffset;
	UCHAR ExtendedBlockSignature;
} HeapEntry;

typedef struct {
	HeapEntry Entry;
	ULONG SegmentSignature;
	ULONG SegmentFlags;
	ListEntry SegmentListEntry;
	ULONG Heap;
	ULONG BaseAddress;
	ULONG NumberOfPages;
	ULONG FirstEntry;
	ULONG LastValidEntry;
	ULONG NumberOfUnCommittedPages;
	ULONG NumberOfUnCommittedRanges;
	USHORT SegmentAllocatorBackTraceIndex;
	USHORT Reserved;
	ListEntry UCRSegmentList;
} HeapSegment;

typedef struct {
	ULONG64 ustAddress;
	ULONG64 count;
	ULONG64 totalSize;
	ULONG64 maxSize;
	ULONG64 largestEntry;
} UstRecord;

static BOOL DecodeHeapEntry(HeapEntry *entry, const HeapEntry *encoding)
{
	UCHAR *entry_ = (UCHAR*)entry;
	const UCHAR *encoding_ = (const UCHAR *)encoding;
	for (int i = 0; i < sizeof(HeapEntry); i++)
	{
		entry_[i] ^= encoding_[i];
	}
	return (entry_[0] ^ entry_[1] ^ entry_[2] ^ entry_[3]) == 0x00;
}

static ULONG GetNtGlobalFlag()
{
	ULONGLONG address;
    ULONG cb;
	ULONG ntGlobalFlag;

	GetPebAddress(NULL, &address);
	if (!READMEMORY(address + 0x68, ntGlobalFlag))
	{
			dprintf("read NtGlobalFlag failed\n");
			return 0;
	}
	return ntGlobalFlag;
}

static ULONG64 GetHeapAddress(ULONG index)
{
	ULONGLONG address;
	ULONG cb;
	ULONG numberOfHeaps;
	PVOID processHeaps;
	PVOID heap;

	GetPebAddress(NULL, &address);
	if (!READMEMORY(address + 0x88, numberOfHeaps))
	{
			dprintf("read NumberOfHeaps failed\n");
			return 0;
	}
	if (index >= numberOfHeaps)
	{
		return 0;
	}
	if (!READMEMORY(address + 0x90, processHeaps))
	{
		dprintf("read ProcessHeaps failed\n");
		return 0;
	}

	if (!READMEMORY((ULONG64)processHeaps + sizeof(PVOID) * index, heap))
	{
		dprintf("read heap address failed\n");
		return 0;
	}

	return (ULONG64)heap;
}

static void PrintStack(ULONG64 address, PCSTR indent = "")
{
	// Use same size as used in simplext sample extension.
	// The limit is not specified in http://msdn.microsoft.com/en-us/library/ff548447.aspx
	// In phenomenology, empty string is returned if symbol expression (including \0) exceeds 256 bytes.
	CHAR Buffer[256];
	ULONG64 displacement;

	GetSymbol(address, Buffer, &displacement);

	dprintf("%s%p %s", indent, address, Buffer);
	if (displacement)
	{
		dprintf("+0x%x", (ULONG)displacement);
	}

	dprintf("\n");
}

static void PrintStackTrace(ULONG64 ustAddress, PCSTR indent = "")
{
	ULONG cb;
	ULONG ntGlobalFlag;
	USHORT depth;
	ULONG64 offset;

	ntGlobalFlag = GetNtGlobalFlag();
	if (ntGlobalFlag & NT_GLOBAL_FLAG_HPA)
	{
		//dprintf("hpa enabled\n");
		offset = 0xa;
	}
	else if (ntGlobalFlag & NT_GLOBAL_FLAG_UST)
	{
		//dprintf("ust enabled\n");
		offset = 0x8;
	}
	else
	{
		dprintf("please set ust or hpa by gflags.exe\n");
		return;
	}

	if (!READMEMORY(ustAddress + offset, depth))
	{
		dprintf("read depth failed\n");
		return;
	}
	dprintf("%sust at %p depth: %d\n", indent, ustAddress, depth);
	ULONG64 address = ustAddress + 0xc;
	for (int i = 0; i < depth; i++)
	{
		ULONG sp;
		if (!READMEMORY(address, sp))
		{
			dprintf("read sp failed\n");
			return;
		}
		PrintStack(sp, indent);
		address += 4;
	}
}

DECLARE_API(help)
{
	UNREFERENCED_PARAMETER(args);
	UNREFERENCED_PARAMETER(dwProcessor);
	UNREFERENCED_PARAMETER(dwCurrentPc);
	UNREFERENCED_PARAMETER(hCurrentThread);
	UNREFERENCED_PARAMETER(hCurrentProcess);

	dprintf("Help for extension dll heapstat.dll\n"
			"   heapstat [-v]   - Shows statistics of heaps\n"
			"   ust <addr>      - Shows stacktrace of the ust record at <addr>\n"
			"   help            - Shows this help\n");
}

DECLARE_API(heapstat)
{
	UNREFERENCED_PARAMETER(dwProcessor);
	UNREFERENCED_PARAMETER(dwCurrentPc);
	UNREFERENCED_PARAMETER(hCurrentThread);
	UNREFERENCED_PARAMETER(hCurrentProcess);

	ULONG cb;
	ULONG64 heapAddress,address;
	HeapEntry encoding;
	HeapSegment segment;
	int index;
	ULONG ntGlobalFlag;
	BOOL verbose = FALSE;

	if (strcmp("-v", args) == 0)
	{
		dprintf("verbose mode\n");
		verbose = TRUE;
	}

	ntGlobalFlag = GetNtGlobalFlag();
	if (ntGlobalFlag & NT_GLOBAL_FLAG_HPA)
	{
		dprintf("hpa enabled\n");
	}
	else if (ntGlobalFlag & NT_GLOBAL_FLAG_UST)
	{
		dprintf("ust enabled\n");
	}
	else
	{
		dprintf("please set ust or hpa by gflags.exe\n");
		return;
	}

	std::map<ULONG64, UstRecord> records;

	for (ULONG heapIndex = 0; (heapAddress = GetHeapAddress(heapIndex)) != 0; heapIndex++)
	{
		dprintf("heap[%d] at %p\n", heapIndex, heapAddress);

		if (!READMEMORY(heapAddress + 0x50, encoding))
		{
			dprintf("read Encoding failed\n");
			return;
		}

		index = 0;
		while ((heapAddress & 0xffff) == 0)
		{
			dprintf("segment %d\n", index);
			if (!READMEMORY(heapAddress, segment))
			{
				return;
			}

			address = segment.FirstEntry;
			while (address < segment.LastValidEntry)
			{
				HeapEntry entry;
				if (!READMEMORY(address, entry))
				{
					dprintf("ReadMemory failed at %p, LastValidEntry is %p\n", address, segment.LastValidEntry);
					return;
				}
				if (!DecodeHeapEntry(&entry, &encoding))
				{
					dprintf("DecodeHeapEntry failed at %p\n", address);
					return;
				}
				if (entry.ExtendedBlockSignature == 0x03)
				{
					// uncommitted bytes follows
					break;
				}
				if (entry.ExtendedBlockSignature != 0x01)
				{
					UCHAR busy = (ntGlobalFlag & NT_GLOBAL_FLAG_HPA) ? 0x03 : 0x01;
					if (entry.Flags == busy)
					{
						if (verbose)
						{
							dprintf("addr:%p, %04x, %02x, %02x, %04x, %02x, %02x, ", address, entry.Size, entry.Flags, entry.SmallTagIndex, entry.PreviousSize, entry.SegmentOffset, entry.ExtendedBlockSignature);
						}
						if (ntGlobalFlag & (NT_GLOBAL_FLAG_UST | NT_GLOBAL_FLAG_HPA))
						{
							ULONG64 offset = (ntGlobalFlag & NT_GLOBAL_FLAG_HPA) ? 0x18 : 0;
							ULONG ustAddress;
							if (!READMEMORY(address + sizeof(entry) + offset, ustAddress))
							{
								if (verbose)
								{
									dprintf("\n");
								}
							}
							else
							{
								if (verbose)
								{
									dprintf("0x%p\n", ustAddress);
								}
								if (ustAddress != 0)
								{
									std::map<ULONG64, UstRecord>::iterator itr = records.find(ustAddress);
									if (itr == records.end())
									{
										UstRecord record;
										record.ustAddress = ustAddress;
										record.count = 1;
										record.totalSize = record.maxSize = entry.Size * 8;
										record.largestEntry = address;
										records[ustAddress] = record;
									}
									else
									{
										UstRecord record = itr->second;
										record.count++;
										record.totalSize += entry.Size * 8;
										if (record.maxSize < entry.Size * 8)
										{
											record.maxSize = entry.Size * 8;
											record.largestEntry = address;
										}
										records[ustAddress] = record;
									}
								}
							}
						}
						else
						{
							if (verbose)
							{
								dprintf("\n");
							}
						}
					}
				}
				address += entry.Size * 8;
			}
			heapAddress = segment.SegmentListEntry.Flink - 0x10;
			index++;
		}
	}

	// sort by total size
	std::list<UstRecord> sorted;
	for (std::map<ULONG64, UstRecord>::iterator itr_ = records.begin(); itr_ != records.end(); ++itr_)
	{
		std::list<UstRecord>::iterator itr = sorted.begin();
		while (itr != sorted.end())
		{
			if (itr->totalSize < itr_->second.totalSize)
			{
				break;
			}
			++itr;
		}
		sorted.insert(itr, itr_->second);
	}

	dprintf("------------------------------------------------\n");
	dprintf("     ust,    count,    total,      max,    entry\n");
	dprintf("------------------------------------------------\n");
	for (std::list<UstRecord>::iterator itr = sorted.begin(); itr != sorted.end(); ++itr)
	{
		dprintf("%p, %p, %p, %p, %p\n",
			itr->ustAddress,
			itr->count,
			itr->totalSize,
			itr->maxSize,
			itr->largestEntry);
		PrintStackTrace(itr->ustAddress, "\t");
	}
	dprintf("\n");
}

DECLARE_API(ust)
{
	UNREFERENCED_PARAMETER(dwProcessor);
	UNREFERENCED_PARAMETER(dwCurrentPc);
	UNREFERENCED_PARAMETER(hCurrentThread);
	UNREFERENCED_PARAMETER(hCurrentProcess);

	ULONG64 Address = GetExpression(args);
	PrintStackTrace(Address);
}

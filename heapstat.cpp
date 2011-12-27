#include "common.h"
#include <map>
#include <list>

#define NT_GLOBAL_FLAG_UST 0x00001000 // user mode stack trace database enabled
#define NT_GLOBAL_FLAG_HPA 0x02000000 // page heap enabled

#define PEB32_OFFSET 0x1000 // PEB64 - PEB32 offset

#define READMEMORY(address, var) (ReadMemory(address, &var, sizeof(var), &cb) && cb == sizeof(var))

typedef struct {
	USHORT Size;
	UCHAR Flags;
	UCHAR SmallTagIndex; // xor of first three bytes
	USHORT PreviousSize;
	UCHAR SegmentOffset;
	UCHAR ExtendedBlockSignature;
} HeapEntry;

typedef struct {
	ULONG64 PreviousBlockPrivateData;
	USHORT Size;
	UCHAR Flags;
	UCHAR SmallTagIndex;
	USHORT PreviousSize;
	UCHAR SegmentOffset;
	UCHAR ExtendedBlockSignature;
} Heap64Entry;

typedef struct {
	HeapEntry Entry;
	ULONG32 SegmentSignature;
	ULONG32 SegmentFlags;
	LIST_ENTRY32 SegmentListEntry;
	ULONG32 Heap;
	ULONG32 BaseAddress;
	ULONG32 NumberOfPages;
	ULONG32 FirstEntry;
	ULONG32 LastValidEntry;
	ULONG32 NumberOfUnCommittedPages;
	ULONG32 NumberOfUnCommittedRanges;
	USHORT SegmentAllocatorBackTraceIndex;
	USHORT Reserved;
	LIST_ENTRY32 UCRSegmentList;
} HeapSegment;

typedef struct {
	Heap64Entry Entry;
	ULONG32 SegmentSignature;
	ULONG32 SegmentFlags;
	LIST_ENTRY64 SegmentListEntry;
	ULONG64 Heap;
	ULONG64 BaseAddress;
	ULONG32 NumberOfPages;
	ULONG32 Padding1;
	ULONG64 FirstEntry;
	ULONG64 LastValidEntry;
	ULONG32 NumberOfUnCommittedPages;
	ULONG32 NumberOfUnCommittedRanges;
	USHORT SegmentAllocatorBackTraceIndex;
	USHORT Reserved;
	ULONG32 Padding2;
	LIST_ENTRY64 UCRSegmentList;
} Heap64Segment;

typedef struct {
	ULONG64 ustAddress;
	ULONG64 count;
	ULONG64 totalSize;
	ULONG64 maxSize;
	ULONG64 largestEntry;
} UstRecord;

static BOOL IsTarget64()
{
	ULONG64 address;
	GetTebAddress(&address);
	return (address >> 32) ? TRUE : FALSE;
}

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

static BOOL DecodeHeap64Entry(Heap64Entry *entry, const Heap64Entry *encoding)
{
	UCHAR *entry_ = (UCHAR*)entry;
	const UCHAR *encoding_ = (const UCHAR *)encoding;
	for (int i = 0; i < sizeof(Heap64Entry); i++)
	{
		entry_[i] ^= encoding_[i];
	}
	return (entry_[0x8] ^ entry_[0x9] ^ entry_[0xa] ^ entry_[0xb]) == 0x00;
}

static ULONG32 GetNtGlobalFlag()
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

static ULONG64 GetHeapAddress(ULONG index)
{
	const BOOL isTarget64 = IsTarget64();

	ULONG64 address;
	GetPebAddress(NULL, &address);
	if (!isTarget64 && IsPtr64())
	{
		address -= PEB32_OFFSET;
	}

	ULONG cb;
	ULONG32 numberOfHeaps;

	if (isTarget64)
	{
		if (GetFieldValue(address, "ntdll!_PEB", "NumberOfHeaps", numberOfHeaps) != 0)
		{
			dprintf("read NumberOfHeaps failed\n");
			return 0;
		}
	}
	else
	{
		if (!READMEMORY(address + 0x88, numberOfHeaps))
		{
			dprintf("read NumberOfHeaps failed\n");
			return 0;
		}
	}

	if (index >= numberOfHeaps)
	{
		return 0;
	}

	ULONG64 processHeaps;
	if (isTarget64)
	{
		if (GetFieldValue(address, "ntdll!_PEB", "ProcessHeaps", processHeaps) != 0)
		{
			dprintf("read ProcessHeaps failed\n");
			return 0;
		}
	}
	else
	{
		ULONG32 value;
		if (!READMEMORY(address + 0x90, value))
		{
			dprintf("read ProcessHeaps failed\n");
			return 0;
		}
		processHeaps = value;
	}

	ULONG64 heap;
	if (isTarget64)
	{
		if (!READMEMORY((ULONG64)processHeaps + 8 * index, heap))
		{
			dprintf("read heap address failed\n");
			return 0;
		}
	}
	else
	{
		ULONG32 value;
		if (!READMEMORY((ULONG64)processHeaps + 4 * index, value))
		{
			dprintf("read heap address failed\n");
			return 0;
		}
		heap = value;
	}

	return heap;
}

static void PrintStackTrace(ULONG64 ustAddress, PCSTR indent = "")
{
	ULONG cb;
	ULONG32 ntGlobalFlag;
	USHORT depth;
	ULONG64 offset;
	const BOOL isTarget64 = IsTarget64();

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
		return;
	}

	if (!READMEMORY(ustAddress + offset, depth))
	{
		dprintf("read depth failed\n");
		return;
	}
	dprintf("%sust at %p depth: %d\n", indent, ustAddress, depth);
	if (isTarget64)
	{
		ULONG64 address = ustAddress + 0x10;
		for (int i = 0; i < depth; i++)
		{
			ULONG64 sp;
			if (!READMEMORY(address, sp))
			{
				dprintf("read sp failed\n");
				return;
			}
			dprintf("%s%ly\n", indent, sp);
			address += sizeof(sp);
		}
	}
	else
	{
		ULONG64 address = ustAddress + 0xc;
		for (int i = 0; i < depth; i++)
		{
			ULONG32 sp;
			if (!READMEMORY(address, sp))
			{
				dprintf("read sp failed\n");
				return;
			}
			dprintf("%s%ly\n", indent, (ULONG64)sp);
			address += sizeof(sp);
		}
	}
}

static void Register(ULONG64 ustAddress, ULONG64 size, ULONG64 address, std::map<ULONG64, UstRecord> &records)
{
	if (ustAddress != 0)
	{
		std::map<ULONG64, UstRecord>::iterator itr = records.find(ustAddress);
		if (itr == records.end())
		{
			UstRecord record;
			record.ustAddress = ustAddress;
			record.count = 1;
			record.totalSize = record.maxSize = size;
			record.largestEntry = address;
			records[ustAddress] = record;
		}
		else
		{
			UstRecord record = itr->second;
			record.count++;
			record.totalSize += size;
			if (record.maxSize < size)
			{
				record.maxSize = size;
				record.largestEntry = address;
			}
			records[ustAddress] = record;
		}
	}
}

static BOOL AnalyzeHeap32(ULONG64 heapAddress, ULONG32 ntGlobalFlag, BOOL verbose, std::map<ULONG64, UstRecord> &records)
{
	const ULONG blockSize = 8;
	ULONG cb;
	HeapEntry encoding;
	if (!READMEMORY(heapAddress + 0x50, encoding))
	{
		dprintf("read Encoding failed\n");
		return FALSE;
	}

	int index = 0;
	while ((heapAddress & 0xffff) == 0)
	{
		dprintf("segment %d\n", index);
		HeapSegment segment;
		if (!READMEMORY(heapAddress, segment))
		{
			return FALSE;
		}

		ULONG64 address = segment.FirstEntry;
		while (address < segment.LastValidEntry)
		{
			HeapEntry entry;
			if (!READMEMORY(address, entry))
			{
				dprintf("ReadMemory failed at %p, LastValidEntry is %p\n", address, segment.LastValidEntry);
				return FALSE;
			}
			if (!DecodeHeapEntry(&entry, &encoding))
			{
				dprintf("DecodeHeapEntry failed at %p\n", address);
				return FALSE;
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
						ULONG32 ustAddress;
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
							Register(ustAddress, entry.Size * blockSize, address, records);
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
			address += entry.Size * blockSize;
		}
		heapAddress = segment.SegmentListEntry.Flink - 0x10;
		index++;
	}
	return TRUE;
}

static BOOL AnalyzeHeap64(ULONG64 heapAddress, ULONG32 ntGlobalFlag, BOOL verbose, std::map<ULONG64, UstRecord> &records)
{
	const ULONG blockSize = 16;
	ULONG cb;
	Heap64Entry encoding;
	if (GetFieldValue(heapAddress, "ntdll!_HEAP", "Encoding", encoding) != 0)
	{
		dprintf("read Encoding failed\n");
		return FALSE;
	}

	int index = 0;
	while ((heapAddress & 0xffff) == 0)
	{
		dprintf("segment %d\n", index);
		Heap64Segment segment;
		if (!READMEMORY(heapAddress, segment))
		{
			return FALSE;
		}

		ULONG64 address = segment.FirstEntry;
		while (address < segment.LastValidEntry)
		{
			Heap64Entry entry;
			if (!READMEMORY(address, entry))
			{
				dprintf("ReadMemory failed at %p, LastValidEntry is %p\n", address, segment.LastValidEntry);
				return FALSE;
			}
			if (!DecodeHeap64Entry(&entry, &encoding))
			{
				dprintf("DecodeHeapEntry failed at %p\n", address);
				return FALSE;
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
						ULONG64 offset = (ntGlobalFlag & NT_GLOBAL_FLAG_HPA) ? 0x30 : 0;
						ULONG64 ustAddress;
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
							Register(ustAddress, entry.Size * blockSize, address, records);
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
			address += entry.Size * blockSize;
		}
		heapAddress = segment.SegmentListEntry.Flink - 0x18;
		index++;
	}
	return TRUE;
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

	ULONG64 heapAddress;
	ULONG32 ntGlobalFlag;
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
		if (IsTarget64())
		{
			if (!AnalyzeHeap64(heapAddress, ntGlobalFlag, verbose, records))
			{
				return;
			}
		}
		else
		{
			if (!AnalyzeHeap32(heapAddress, ntGlobalFlag, verbose, records))
			{
				return;
			}
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

	if (IsPtr64())
	{
		dprintf("----------------------------------------------------------------------------------------\n");
		dprintf("             ust,            count,            total,              max,            entry\n");
		dprintf("----------------------------------------------------------------------------------------\n");
	}
	else
	{
		dprintf("------------------------------------------------\n");
		dprintf("     ust,    count,    total,      max,    entry\n");
		dprintf("------------------------------------------------\n");
	}
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

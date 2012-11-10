#include "common.h"
#include "Utility.h"
#include "SummaryProcessor.h"
#include "BySizeProcessor.h"
#include "UmdhProcessor.h"
#include <list>

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

// representation of heap entry
typedef struct _HeapRecord {
	ULONG64 ustAddress;
	ULONG64 size;
	ULONG64 address;
	ULONG64 userSize;
	ULONG64 userAddress;
	bool operator< (const struct _HeapRecord& rhs) const
	{
		return address < rhs.address;
	}
} HeapRecord;

// common parameter
typedef struct {
	ULONG32 ntGlobalFlag;
	ULONG64 osVersion;
	BOOL verbose;
	bool isTarget64;
} CommonParams;

#define DPRINTF(...) do { if (params.verbose) { dprintf(__VA_ARGS__); } } while (0)

/**
*	@brief walk _RTL_BALANCED_LINKS nodes
*	@param handler function to be called on each nodes
*	@retval TRUE handler returns TRUE on all nodes and complete walking
*	@retval FALSE handler returns FALSE on some node and quit walking
*/
static BOOL WalkBalancedLinks(ULONG64 address,
							  const CommonParams &params,
							   BOOL (*handler)(ULONG64 address, const CommonParams &params, void *arg),
							   void *arg)
{
	ULONG cb;

	if (!handler(address, params, arg))
	{
		return FALSE;
	}

	struct
	{
		ULONG64 Parent;
		ULONG64 LeftChild;
		ULONG64 RightChild;
	} links;
	if (params.isTarget64)
	{
		if (!READMEMORY(address, links))
		{
			return FALSE;
		}
	}
	else
	{
		struct
		{
			ULONG32 Parent;
			ULONG32 LeftChild;
			ULONG32 RightChild;
		} tmp;
		if (!READMEMORY(address, tmp))
		{
			return FALSE;
		}
		links.Parent = tmp.Parent;
		links.LeftChild = tmp.LeftChild;
		links.RightChild = tmp.RightChild;
	}

	if (links.LeftChild != 0)
	{
		if (!WalkBalancedLinks(links.LeftChild, params, handler, arg))
		{
			return FALSE;
		}
	}
	if (links.RightChild != 0)
	{
		if (!WalkBalancedLinks(links.RightChild, params, handler, arg))
		{
			return FALSE;
		}
	}
	return TRUE;
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

static ULONG64 GetHeapAddress(ULONG index)
{
	const bool isTarget64 = IsTarget64();

	ULONG64 address = GetPebAddress();

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

static BOOL ParseHeapRecord32(ULONG64 address, const HeapEntry &entry, ULONG32 ntGlobalFlag, HeapRecord &record)
{
	const ULONG blockUnit = 8;
	ULONG cb;
	if (ntGlobalFlag & NT_GLOBAL_FLAG_UST)
	{
		ULONG32 ustAddress;
		if (!READMEMORY(address + sizeof(entry), ustAddress))
		{
			dprintf("read ustAddress at %p failed", address + sizeof(entry));
			return FALSE;
		}
		else
		{
			record.ustAddress = ustAddress;
			USHORT extra;
			if (READMEMORY(address + sizeof(entry) + 0xc, extra))
			{
				if (extra < sizeof(entry) + 0x10)
				{
					return FALSE;
				}
				if (entry.Size * blockUnit < extra)
				{
					dprintf("invalid extra 0x%04x\n", extra);
					return FALSE;
				}
				record.userSize = entry.Size * blockUnit - extra;
				record.userAddress = address + sizeof(entry) + 0x10;
			}
			else
			{
				dprintf("READMEMORY for extra failed at %p\n", address + sizeof(entry) + 0xc);
				return FALSE;
			}
		}
	}
	else
	{
		record.ustAddress = 0;
		if (entry.ExtendedBlockSignature < sizeof(entry))
		{
			return FALSE;
		}
		if (entry.Size * blockUnit < entry.ExtendedBlockSignature)
		{
			dprintf("invalid extra: %02x", entry.ExtendedBlockSignature);
			return FALSE;
		}
		record.userSize = entry.Size * blockUnit - entry.ExtendedBlockSignature;
		record.userAddress = address + sizeof(entry);
	}
	record.size = entry.Size * blockUnit;
	record.address = address;
	return TRUE;
}

static BOOL ParseHeapRecord64(ULONG64 address, const Heap64Entry &entry, ULONG32 ntGlobalFlag, HeapRecord &record)
{
	const ULONG blockUnit = 16;
	ULONG cb;
	if (ntGlobalFlag & NT_GLOBAL_FLAG_UST)
	{
		ULONG64 ustAddress;
		if (!READMEMORY(address + sizeof(entry), ustAddress))
		{
			dprintf("read ustAddress at %p failed", address + sizeof(entry));
			return FALSE;
		}
		else
		{
			record.ustAddress = ustAddress;
			USHORT extra;
			if (READMEMORY(address + sizeof(entry) + 0x1c, extra))
			{
				if (extra + sizeof(entry.PreviousBlockPrivateData) < sizeof(entry) + 0x20)
				{
					return FALSE;
				}
				if (entry.Size * blockUnit < extra)
				{
					dprintf("invalid extra 0x%04x\n", extra);
					return FALSE;
				}
				record.userSize = entry.Size * blockUnit - extra;
				record.userAddress = address + sizeof(entry) + 0x20;
			}
			else
			{
				dprintf("READMEMORY for extra failed at %p\n", address + sizeof(entry) + 0xc);
				return FALSE;
			}
		}
	}
	else
	{
		record.ustAddress = 0;
		if (entry.ExtendedBlockSignature + sizeof(entry.PreviousBlockPrivateData) < sizeof(entry))
		{
			return FALSE;
		}
		if (entry.Size * blockUnit < entry.ExtendedBlockSignature)
		{
			dprintf("invalid extra: %02x", entry.ExtendedBlockSignature);
			return FALSE;
		}
		record.userSize = entry.Size * blockUnit - entry.ExtendedBlockSignature;
		record.userAddress = address + sizeof(entry);
	}
	record.size = entry.Size * blockUnit;
	record.address = address;
	return TRUE;
}

static BOOL AnalyzeLFHZone32(ULONG64 zone, const CommonParams &params, std::set<HeapRecord> &lfhRecords)
{
	DPRINTF("_LFH_BLOCK_ZONE %p\n", zone);
	ULONG cb;
	ULONG offset;
	ULONG32 freePointer;
	if (!READMEMORY(zone + 0x8, freePointer))
	{
		dprintf("read _LFH_BLOCK_ZONE::FreePointer failed\n");
		return FALSE;
	}

	ULONG64 subsegment = zone + 0x10;
	ULONG subsegmentSize = params.osVersion >= OS_VERSION_WIN8 ? 0x28 : 0x20; // sizeof(_HEAP_SUBSEGMENT)
	while (subsegment + subsegmentSize <= freePointer)
	{
		DPRINTF("_HEAP_SUBSEGMENT %p\n", subsegment);
		USHORT blockSize; // _HEAP_SUBSEGMENT::BlockSize
		USHORT blockCount; // _HEAP_SUBSEGMENT::BlockCount
		offset = params.osVersion >= OS_VERSION_WIN8 ? 0x14 : 0x10;
		if (!READMEMORY(subsegment + offset, blockSize))
		{
			dprintf("read _HEAP_SUBSEGMENT::BlockSize failed\n");
			return FALSE;
		}
		if (blockSize == 0)
		{
			// rest are unused subsegments
			break;
		}
		offset = params.osVersion >= OS_VERSION_WIN8 ? 0x18 : 0x14;
		if (!READMEMORY(subsegment + offset, blockCount))
		{
			dprintf("read _HEAP_SUBSEGMENT::BlockCount failed\n");
			return FALSE;
		}
		ULONG32 userBlocks; // _HEAP_SUBSEGMENT::UserBlocks
		if (!READMEMORY(subsegment + 0x4, userBlocks))
		{
			dprintf("read _HEAP_SUBSEGMENT::UserBlocks failed\n");
			return FALSE;
		}
		if (userBlocks != 0)
		{
			ULONG64 address;
			if (params.osVersion >= OS_VERSION_WIN8)
			{
				USHORT firstAllocationOffset; // _HEAP_USERDATA_HEADER::FirstAllocationOffset
				if (!READMEMORY(userBlocks + 0x10, firstAllocationOffset))
				{
					dprintf("read _HEAP_USERDATA_HEADER::FirstAllocationOffset failed\n");
					return FALSE;
				}
				address = userBlocks + firstAllocationOffset;
			}
			else
			{
				address = userBlocks + 0x10; // sizeof(_LFH_BLOCK_ZONE);
			}
			for (USHORT i = 0; i < blockCount; i++)
			{
				DPRINTF("entry %p\n", address);
				const ULONG blockUnit = 8;
				HeapEntry entry;
				if (!READMEMORY(address, entry))
				{
					dprintf("read LFH HeapEntry at %p failed\n", address);
					return FALSE;
				}
				entry.Size = blockSize;

				bool busy = false;
				if (params.ntGlobalFlag & NT_GLOBAL_FLAG_UST)
				{
					busy = (entry.ExtendedBlockSignature == 0xc2);
				}
				else
				{
					if (entry.ExtendedBlockSignature > 0x80)
					{
						busy = true;
						entry.ExtendedBlockSignature -= 0x80;
					}
				}
				if (busy)
				{
					HeapRecord record;
					if (ParseHeapRecord32(address, entry, params.ntGlobalFlag, record))
					{
						DPRINTF("ust:%p, userPtr:%p, userSize:%p, extra:%p\n",
							record.ustAddress, record.userAddress, record.userSize, entry.Size * blockUnit - record.userSize);
						lfhRecords.insert(record);
					}
				}

				address += blockSize * blockUnit;
			}
		}
		subsegment += subsegmentSize;
	}
	return TRUE;
}

static BOOL AnalyzeLFHZone64(ULONG64 zone, const CommonParams &params, std::set<HeapRecord> &lfhRecords)
{
	DPRINTF("_LFH_BLOCK_ZONE %p\n", zone);
	ULONG cb;
	ULONG64 freePointer;
	if (GetFieldValue(zone, "ntdll!_LFH_BLOCK_ZONE", "FreePointer", freePointer) != 0)
	{
		dprintf("read _LFH_BLOCK_ZONE::FreePointer failed\n");
		return FALSE;
	}

	ULONG64 subsegment = zone + GetTypeSize("ntdll!_LFH_BLOCK_ZONE");
	ULONG subsegmentSize = GetTypeSize("ntdll!_HEAP_SUBSEGMENT");
	while (subsegment + subsegmentSize <= freePointer)
	{
		DPRINTF("_HEAP_SUBSEGMENT %p\n", subsegment);
		USHORT blockSize; // _HEAP_SUBSEGMENT::BlockSize
		USHORT blockCount; // _HEAP_SUBSEGMENT::BlockCount
		if (GetFieldValue(subsegment, "ntdll!_HEAP_SUBSEGMENT", "BlockSize", blockSize) != 0)
		{
			dprintf("read _HEAP_SUBSEGMENT::BlockSize failed\n");
			return FALSE;
		}
		if (blockSize == 0)
		{
			// rest are unused subsegments
			break;
		}
		if (GetFieldValue(subsegment, "ntdll!_HEAP_SUBSEGMENT", "BlockCount", blockCount) != 0)
		{
			dprintf("read _HEAP_SUBSEGMENT::BlockCount failed\n");
			return FALSE;
		}
		ULONG64 userBlocks; // _HEAP_SUBSEGMENT::UserBlocks
		if (GetFieldValue(subsegment, "ntdll!_HEAP_SUBSEGMENT", "UserBlocks", userBlocks) != 0)
		{
			dprintf("read _HEAP_SUBSEGMENT::UserBlocks failed\n");
			return FALSE;
		}
		if (userBlocks != 0)
		{
			ULONG64 address;
			if (params.osVersion >= OS_VERSION_WIN8)
			{
				USHORT firstAllocationOffset;
				if (GetFieldValue(userBlocks, "ntdll!_HEAP_USERDATA_HEADER", "FirstAllocationOffset", firstAllocationOffset))
				{
					dprintf("read _HEAP_USERDATA_HEADER::FirstAllocationOffset failed\n");
					return FALSE;
				}
				address = userBlocks + firstAllocationOffset;
			}
			else
			{
				address = userBlocks + GetTypeSize("ntdll!_LFH_BLOCK_ZONE");
			}
			for (USHORT i = 0; i < blockCount; i++)
			{
				DPRINTF("entry %p\n", address);
				const ULONG blockUnit = 16;
				Heap64Entry entry;
				if (!READMEMORY(address, entry))
				{
					dprintf("read LFH HeapEntry at %p failed\n", address);
					return FALSE;
				}
				entry.Size = blockSize;

				bool busy = false;
				if (params.ntGlobalFlag & NT_GLOBAL_FLAG_UST)
				{
					busy = (entry.ExtendedBlockSignature == 0xc2);
				}
				else
				{
					if (entry.ExtendedBlockSignature > 0x80)
					{
						busy = true;
						entry.ExtendedBlockSignature -= 0x80;
					}
				}
				if (busy)
				{
					HeapRecord record;
					if (ParseHeapRecord64(address, entry, params.ntGlobalFlag, record))
					{
						DPRINTF("ust:%p, userPtr:%p, userSize:%p, extra:%p\n",
							record.ustAddress, record.userAddress, record.userSize, entry.Size * blockUnit - record.userSize);
						lfhRecords.insert(record);
					}
				}

				address += blockSize * blockUnit;
			}
		}
		subsegment += subsegmentSize;
	}
	return TRUE;
}

static BOOL AnalyzeLFH32(ULONG64 heapAddress, const CommonParams &params, std::set<HeapRecord> &lfhRecords)
{
	DPRINTF("analyze LFH for HEAP %p\n", heapAddress);
	ULONG cb;
	ULONG offset;
	UCHAR type; // _HEAP::FrontEndHeapType
	offset = params.osVersion >= OS_VERSION_WIN8 ? 0xd6: 0xda;
	if (!READMEMORY(heapAddress + offset, type))
	{
		dprintf("read FrontEndHeapType failed\n");
		return FALSE;
	}
	if (type != 0x02 /* LFH */)
	{
		return TRUE;
	}

	ULONG32 frontEndHeap;
	offset = params.osVersion >= OS_VERSION_WIN8 ? 0xd0: 0xd4;
	if (!READMEMORY(heapAddress + offset, frontEndHeap))
	{
		dprintf("read FrontEndHeap failed\n");
		return FALSE;
	}
	if (frontEndHeap == 0)
	{
		return TRUE;
	}

	DPRINTF("_LFH_HEAP %p\n", (ULONG64)frontEndHeap);
	offset = params.osVersion >= OS_VERSION_WIN8 ? 0x4 : 0x18;
	ULONG32 start = frontEndHeap + offset; // _LFH_HEAP::SubSegmentZones
	ULONG32 zone = start;
	while (true)
	{
		LIST_ENTRY32 listEntry;
		if (!READMEMORY(zone, listEntry))
		{
			dprintf("read SubsegmentZones failed\n");
			return FALSE;
		}
		zone = listEntry.Flink;
		if (zone == start)
		{
			break;
		}
		if (!AnalyzeLFHZone32(zone, params, lfhRecords))
		{
			return FALSE;
		}
	}
	return TRUE;
}

static BOOL AnalyzeLFH64(ULONG64 heapAddress, const CommonParams &params, std::set<HeapRecord> &lfhRecords)
{
	DPRINTF("analyze LFH for HEAP %p\n", heapAddress);
	ULONG cb;
	UCHAR type; // _HEAP::FrontEndHeapType
	if (GetFieldValue(heapAddress, "ntdll!_HEAP", "FrontEndHeapType", type) != 0)
	{
		dprintf("read FrontEndHeapType failed\n");
		return FALSE;
	}
	if (type != 0x02 /* LFH */)
	{
		return TRUE;
	}

	ULONG64 frontEndHeap;
	if (GetFieldValue(heapAddress, "ntdll!_HEAP", "FrontEndHeap", frontEndHeap) != 0)
	{
		dprintf("read FrontEndHeap failed\n");
		return FALSE;
	}
	if (frontEndHeap == 0)
	{
		return TRUE;
	}

	DPRINTF("_LFH_HEAP %p\n", frontEndHeap);
	ULONG offset;
	if (GetFieldOffset("ntdll!_LFH_HEAP", "SubSegmentZones", &offset) != 0)
	{
		dprintf("get SubSegmentZones offset failed\n");
		return FALSE;
	}
	ULONG64 start = frontEndHeap + offset; // _LFH_HEAP::SubSegmentZones
	ULONG64 zone = start;
	while (true)
	{
		LIST_ENTRY64 listEntry;
		if (!READMEMORY(zone, listEntry))
		{
			dprintf("read SubsegmentZones failed\n");
			return FALSE;
		}
		zone = listEntry.Flink;
		if (zone == start)
		{
			break;
		}
		if (!AnalyzeLFHZone64(zone, params, lfhRecords))
		{
			return FALSE;
		}
	}
	return TRUE;
}

static BOOL AnalyzeVirtualAllocd32(ULONG64 heapAddress, const HeapEntry &encoding, const CommonParams &params, std::set<HeapRecord> &records)
{
	DPRINTF("analyze VirtualAllocdBlocks for HEAP %p\n", heapAddress);
	ULONG cb;
	ULONG offset = params.osVersion >= OS_VERSION_WIN8 ? 0x9c : 0xa0;
	LIST_ENTRY32 listEntry;
	if (!READMEMORY(heapAddress + offset, listEntry))
	{
		dprintf("read VirtualAllocdBlocks failed\n");
		return FALSE;
	}
	while (listEntry.Flink != heapAddress + offset)
	{
		HeapRecord record;
		record.address = listEntry.Flink;

		ULONG size;
		if (!READMEMORY(record.address + 0x10, size))
		{
			dprintf("read size at %p failed\n", record.address + 0x10);
			return FALSE;
		}
		record.size = size;

		HeapEntry entry;
		if (!READMEMORY(record.address + 0x18, entry))
		{
			dprintf("read HeapEntry at %p failed\n", record.address + 0x18);
			return FALSE;
		}
		if (!DecodeHeapEntry(&entry, &encoding))
		{
			dprintf("DecodeHeapEntry failed\n");
			return FALSE;
		}
		USHORT extra = *(USHORT*)&entry;
		if (extra >= record.size)
		{
			dprintf("too large extra 0x%02x (size=%p)\n", extra, record.size);
			return FALSE;
		}

		if (params.ntGlobalFlag & NT_GLOBAL_FLAG_UST)
		{
			ULONG ustAddress;
			if (!READMEMORY(record.address + 0x20, ustAddress))
			{
				dprintf("read ustAddress at %p failed\n", record.address + 0x20);
				return FALSE;
			}
			record.ustAddress = ustAddress;
			record.userAddress = record.address + 0x30;
			record.userSize = record.size - extra;
		}
		else
		{
			record.ustAddress = 0;
			record.userAddress = record.address + 0x20;
			record.userSize = record.size - extra;
		}

		DPRINTF("ust:%p, userPtr:%p, userSize:%p, extra:%p\n",
			record.ustAddress, record.userAddress, record.userSize, record.size - record.userSize);
		records.insert(record);

		if (!READMEMORY(listEntry.Flink, listEntry))
		{
			dprintf("read ListEntry failed\n");
			return FALSE;
		}
	}
	return TRUE;
}

static BOOL AnalyzeVirtualAllocd64(ULONG64 heapAddress, const Heap64Entry &encoding, const CommonParams &params, std::set<HeapRecord> &records)
{
	DPRINTF("analyze VirtualAllocdBlocks for HEAP %p\n", heapAddress);
	ULONG cb;
	LIST_ENTRY64 listEntry;
	if (GetFieldValue(heapAddress, "ntdll!_HEAP", "VirtualAllocdBlocks", listEntry) != 0)
	{
		dprintf("read VirtualAllocdBlocks failed\n");
		return FALSE;
	}
	ULONG offset;
	GetFieldOffset("ntdll!_HEAP", "VirtualAllocdBlocks", &offset);
	while (listEntry.Flink != heapAddress + offset)
	{
		HeapRecord record;
		record.address = listEntry.Flink;

		ULONG64 size;
		if (!READMEMORY(record.address + 0x20, size))
		{
			dprintf("read size at %p failed\n", record.address + 0x20);
			return FALSE;
		}
		record.size = size;

		Heap64Entry entry;
		if (!READMEMORY(record.address + 0x30, entry))
		{
			dprintf("read Heap64Entry at %p failed\n", record.address + 0x30);
			return FALSE;
		}
		if (!DecodeHeap64Entry(&entry, &encoding))
		{
			dprintf("DecodeHeap64Entry failed\n");
			return FALSE;
		}
		USHORT extra = *(USHORT*)((UCHAR*)&entry + 8);
		if (extra >= record.size)
		{
			dprintf("too large extra 0x%02x (size=%p)\n", extra, record.size);
			return FALSE;
		}

		if (params.ntGlobalFlag & NT_GLOBAL_FLAG_UST)
		{
			ULONG64 ustAddress;
			if (!READMEMORY(record.address + 0x40, ustAddress))
			{
				dprintf("read ustAddress at %p failed\n", record.address + 0x40);
				return FALSE;
			}
			record.ustAddress = ustAddress;
			record.userAddress = record.address + 0x60;
			record.userSize = record.size - extra;
		}
		else
		{
			record.ustAddress = 0;
			record.userAddress = record.address + 0x40;
			record.userSize = record.size - extra;
		}

		DPRINTF("ust:%p, userPtr:%p, userSize:%p, extra:%p\n",
			record.ustAddress, record.userAddress, record.userSize, record.size - record.userSize);
		records.insert(record);

		if (GetFieldValue(listEntry.Flink, "ntdll!_LIST_ENTRY", "Flink", listEntry) != 0)
		{
			dprintf("read ListEntry at %p failed\n", listEntry.Flink);
			return FALSE;
		}
	}
	return TRUE;
}

static void Register(
		const HeapRecord &record,
		std::set<HeapRecord> &lfhRecords,
		IProcessor *processor)
{
	while (!lfhRecords.empty() && lfhRecords.begin()->address < record.address)
	{
		std::set<HeapRecord>::iterator itr = lfhRecords.begin();
		//dprintf("Register: insert entry %p\n", itr->address);
		processor->Register(itr->ustAddress,
			itr->size, itr->address, itr->userSize, itr->userAddress);
		lfhRecords.erase(lfhRecords.begin());
	}
	processor->Register(record.ustAddress,
		record.size, record.address, record.userSize, record.userAddress);
}

static BOOL AnalyzeHeap32(ULONG64 heapAddress, const CommonParams &params, IProcessor *processor)
{
	std::set<HeapRecord> lfhRecords;
	AnalyzeLFH32(heapAddress, params, lfhRecords);
	DPRINTF("found %d LFH records in heap %p\n", (int)lfhRecords.size(), heapAddress);

	const ULONG blockUnit = 8;
	ULONG cb;
	HeapEntry encoding;
	if (!READMEMORY(heapAddress + 0x50, encoding))
	{
		dprintf("read Encoding failed\n");
		return FALSE;
	}

	std::set<HeapRecord> vallocRecords;
	AnalyzeVirtualAllocd32(heapAddress, encoding, params, vallocRecords);
	DPRINTF("found %d valloc records in heap %p\n", (int)vallocRecords.size(), heapAddress);

	int index = 0;
	while ((heapAddress & 0xffff) == 0)
	{
		HeapSegment segment;
		if (!READMEMORY(heapAddress, segment))
		{
			dprintf("read HEAP_SEGMENT at %p failed\n", heapAddress);
			return FALSE;
		}
		DPRINTF("Segment at %p to %p\n", heapAddress, (ULONG64)segment.LastValidEntry);
		DPRINTF("NumberOfUnCommittedPages:%p, NumberOfUnCommittedRanges:%p\n", (ULONG64)segment.NumberOfUnCommittedPages, (ULONG64)segment.NumberOfUnCommittedRanges);

		std::set<HeapRecord> lfhRecordsInSegment;
		for (std::set<HeapRecord>::iterator itr = lfhRecords.begin();
			itr != lfhRecords.end();
			itr++)
		{
			if (segment.FirstEntry < itr->address && itr->address < segment.LastValidEntry)
			{
				lfhRecordsInSegment.insert(*itr);
			}
		}
		DPRINTF("%d LFH records in segment %p\n", (int)lfhRecordsInSegment.size(), heapAddress);

		ULONG64 address = segment.FirstEntry;
		while (address < segment.LastValidEntry)
		{
			HeapEntry entry;
			if (!READMEMORY(address, entry))
			{
				dprintf("ReadMemory failed at %p, LastValidEntry is %p\n", address, (ULONG64)segment.LastValidEntry);
				break;//return FALSE;
			}
			if (!DecodeHeapEntry(&entry, &encoding))
			{
				dprintf("DecodeHeapEntry failed at %p\n", address);
				return FALSE;
			}

			// skip the last entry in the segment
			if (address + entry.Size * blockUnit >= segment.LastValidEntry - segment.NumberOfUnCommittedPages * PAGE_SIZE)
			{
				DPRINTF("uncommitted bytes follows\n");
				break;
			}

			DPRINTF("addr:%p, %04x, %02x, %02x, %04x, %02x, %02x\n", address, entry.Size, entry.Flags, entry.SmallTagIndex, entry.PreviousSize, entry.SegmentOffset, entry.ExtendedBlockSignature);
			if (entry.ExtendedBlockSignature == 0x03)
			{
				break;
			}
			else
			{
				UCHAR busy = 0x01;
				if (entry.Flags == busy)
				{
					HeapRecord record;
					if (ParseHeapRecord32(address, entry, params.ntGlobalFlag, record))
					{
						DPRINTF("ust:%p, userPtr:%p, userSize:%p, extra:%p\n",
							record.ustAddress, record.userAddress, record.userSize, entry.Size * blockUnit - record.userSize);
						Register(record, lfhRecordsInSegment, processor);
					}
				}
			}
			address += entry.Size * blockUnit;
		}
		for (std::set<HeapRecord>::iterator itr = lfhRecordsInSegment.begin();
			itr != lfhRecordsInSegment.end();
			itr++)
		{
			//dprintf("insert entry %p\n", itr->address);
			processor->Register(itr->ustAddress,
				itr->size, itr->address,
				itr->userSize, itr->userAddress);
		}
		heapAddress = segment.SegmentListEntry.Flink - 0x10;
		index++;
	}
	for (std::set<HeapRecord>::iterator itr = vallocRecords.begin();
		itr != vallocRecords.end();
		itr++)
	{
		processor->Register(itr->ustAddress,
			itr->size, itr->address,
			itr->userSize, itr->userAddress);
	}
	return TRUE;
}

static BOOL AnalyzeHeap64(ULONG64 heapAddress, const CommonParams &params, IProcessor *processor)
{
	std::set<HeapRecord> lfhRecords;
	AnalyzeLFH64(heapAddress, params, lfhRecords);
	DPRINTF("found %d LFH records in heap %p\n", (int)lfhRecords.size(), heapAddress);

	const ULONG blockUnit = 16;
	ULONG cb;
	Heap64Entry encoding;
	if (GetFieldValue(heapAddress, "ntdll!_HEAP", "Encoding", encoding) != 0)
	{
		dprintf("read Encoding failed\n");
		return FALSE;
	}

	std::set<HeapRecord> vallocRecords;
	AnalyzeVirtualAllocd64(heapAddress, encoding, params, vallocRecords);
	DPRINTF("found %d valloc records in heap %p\n", (int)vallocRecords.size(), heapAddress);

	int index = 0;
	while ((heapAddress & 0xffff) == 0)
	{
		Heap64Segment segment;
		if (!READMEMORY(heapAddress, segment))
		{
			dprintf("read HEAP_SEGMENT at %p failed\n", heapAddress);
			return FALSE;
		}
		DPRINTF("Segment at %p to %p\n", heapAddress, segment.LastValidEntry);
		DPRINTF("NumberOfUnCommittedPages:%p, NumberOfUnCommittedRanges:%p\n", (ULONG64)segment.NumberOfUnCommittedPages, (ULONG64)segment.NumberOfUnCommittedRanges);

		std::set<HeapRecord> lfhRecordsInSegment;
		for (std::set<HeapRecord>::iterator itr = lfhRecords.begin();
			itr != lfhRecords.end();
			itr++)
		{
			if (segment.FirstEntry < itr->address && itr->address < segment.LastValidEntry)
			{
				lfhRecordsInSegment.insert(*itr);
			}
		}
		DPRINTF("%d LFH records in segment %p\n", (int)lfhRecordsInSegment.size(), heapAddress);

		ULONG64 address = segment.FirstEntry;
		while (address < segment.LastValidEntry)
		{
			Heap64Entry entry;
			if (!READMEMORY(address, entry))
			{
				dprintf("ReadMemory failed at %p, LastValidEntry is %p\n", address, segment.LastValidEntry);
				break;//return FALSE;
			}
			if (!DecodeHeap64Entry(&entry, &encoding))
			{
				dprintf("DecodeHeap64Entry failed at %p\n", address);
				return FALSE;
			}

			// skip the last entry in the segment
			if (address + entry.Size * blockUnit >= segment.LastValidEntry - segment.NumberOfUnCommittedPages * PAGE_SIZE)
			{
				DPRINTF("uncommitted bytes follows\n");
				break;
			}

			DPRINTF("addr:%p, %04x, %02x, %02x, %04x, %02x, %02x\n", address, entry.Size, entry.Flags, entry.SmallTagIndex, entry.PreviousSize, entry.SegmentOffset, entry.ExtendedBlockSignature);
			if (entry.ExtendedBlockSignature == 0x03)
			{
				break;
			}
			else
			{
				UCHAR busy = 0x01;
				if (entry.Flags == busy)
				{
					HeapRecord record;
					if (ParseHeapRecord64(address, entry, params.ntGlobalFlag, record))
					{
						DPRINTF("ust:%p, userPtr:%p, userSize:%p, extra:%p\n",
							record.ustAddress, record.userAddress, record.userSize, entry.Size * blockUnit - record.userSize);
						Register(record, lfhRecordsInSegment, processor);
					}
				}
			}
			address += entry.Size * blockUnit;
		}
		for (std::set<HeapRecord>::iterator itr = lfhRecordsInSegment.begin();
			itr != lfhRecordsInSegment.end();
			itr++)
		{
			//dprintf("insert entry %p\n", itr->address);
			processor->Register(itr->ustAddress,
				itr->size, itr->address,
				itr->userSize, itr->userAddress);
		}
		heapAddress = segment.SegmentListEntry.Flink - 0x18;
		index++;
	}
	for (std::set<HeapRecord>::iterator itr = vallocRecords.begin();
		itr != vallocRecords.end();
		itr++)
	{
		processor->Register(itr->ustAddress,
			itr->size, itr->address,
			itr->userSize, itr->userAddress);
	}
	return TRUE;
}

static BOOL AnalyzeDphHeapBlock32(ULONG64 address, const CommonParams &params, void *arg)
{
	ULONG cb;
	std::set<HeapRecord> *records = static_cast<std::set<HeapRecord> *>(arg);
	DPRINTF("_DPH_HEAP_BLOCK %p\n", address);
	ULONG32 pUserAllocation;
	// _DPH_HEAP_BLOCK::pUserAllocation
	if (!READMEMORY(address + 0x10, pUserAllocation))
	{
		dprintf("read pUserAllocation failed\n");
		return FALSE;
	}
	
	ULONG32 startMagic;
	if (READMEMORY(pUserAllocation - 0x20, startMagic) &&
		startMagic == 0xABCDBBBB /* allocated */)
	{
		ULONG32 pVirtualBlock, stackTrace;
		ULONG32 nVirtualBlockSize, nUserRequestedSize;

		if (!READMEMORY(address + 0x14, pVirtualBlock))
		{
			dprintf("read pVirtualBlock failed\n");
			return FALSE;
		}

		if (!READMEMORY(address + 0x18, nVirtualBlockSize))
		{
			dprintf("read nVirtualBlockSize failed\n");
			return FALSE;
		}

		if (!READMEMORY(address + 0x20, nUserRequestedSize))
		{
			dprintf("read nUserRequestedSize failed\n");
			return FALSE;
		}

		if (!READMEMORY(address + 0x30, stackTrace))
		{
			dprintf("read StackTrace failed\n");
			return FALSE;
		}

		DPRINTF("ust:%p, userPtr:%p, userSize:%p, extra:%p\n",
			(ULONG64)stackTrace, (ULONG64)pUserAllocation, (ULONG64)nUserRequestedSize, (ULONG64)(nVirtualBlockSize - nUserRequestedSize));
		HeapRecord record;
		record.ustAddress = stackTrace;
		record.size = nVirtualBlockSize;
		record.address = pVirtualBlock;
		record.userSize = nUserRequestedSize;
		record.userAddress = pUserAllocation;
		records->insert(record);
	}
	return TRUE;
}

static BOOL AnalyzeDphHeap32(ULONG64 heapList, IProcessor *processor, const CommonParams &params)
{
	std::vector<ULONG64> heapRoots;
	ULONG cb;
	LIST_ENTRY32 listEntry;
	if (!READMEMORY(heapList, listEntry))
	{
		dprintf("read LIST_ENTRY32 at %p failed\n", heapList);
		return FALSE;
	}
	while (listEntry.Flink != heapList)
	{
		ULONG64 heapRoot = listEntry.Flink - 0xa4 /* offset of _DPH_HEAP_ROOT::NextHeap */;
		DPRINTF("push heapRoot %p\n", heapRoot);
		heapRoots.push_back(heapRoot);
		if (!READMEMORY(listEntry.Flink, listEntry))
		{
			dprintf("read LIST_ENTRY32 at %p failed\n", listEntry.Flink);
			return FALSE;
		}
	}

	for (std::vector<ULONG64>::iterator itr = heapRoots.begin(); itr != heapRoots.end(); itr++)
	{
		ULONG cb;
		// _DPH_HEAP_ROOT::NormalHeap
		ULONG32 normalHeap;
		if (!READMEMORY(*itr + 0xb4, normalHeap))
		{
			dprintf("read NormalHeap at %p failed\n", *itr + 0xb4);
			return FALSE;
		}

		DPRINTF("heap at %p, _DPH_HEAP_ROOT %p\n", (ULONG64)normalHeap, *itr);
		processor->StartHeap(normalHeap);
		std::set<HeapRecord> records;

		// _DPH_HEAP_ROOT::BusyNodesTable
		if (!WalkBalancedLinks(*itr + 0x20, params, AnalyzeDphHeapBlock32, &records))
		{
			dprintf("WalkBalancedLinks failed\n");
			return FALSE;
		}

		for (std::set<HeapRecord>::iterator itr_ = records.begin();
			itr_ != records.end();
			itr_++)
		{
			processor->Register(itr_->ustAddress,
				itr_->size, itr_->address,
				itr_->userSize, itr_->userAddress);
		}
		processor->FinishHeap(normalHeap);
	}
	return TRUE;
}

static BOOL AnalyzeDphHeapBlock64(ULONG64 address, const CommonParams &params, void *arg)
{
	ULONG cb;
	const char *type = "ntdll!_DPH_HEAP_BLOCK";
	std::set<HeapRecord> *records = static_cast<std::set<HeapRecord> *>(arg);
	DPRINTF("_DPH_HEAP_BLOCK %p\n", address);
	ULONG64 pUserAllocation;
	// _DPH_HEAP_BLOCK::pUserAllocation
	if (GetFieldValue(address, type, "pUserAllocation", pUserAllocation) != 0)
	{
		dprintf("read pUserAllocation failed\n");
		return FALSE;
	}
	
	ULONG32 startMagic;
	if (READMEMORY(pUserAllocation - 0x40, startMagic) &&
		startMagic == 0xABCDBBBB /* allocated */)
	{
		ULONG64 pVirtualBlock, stackTrace;
		ULONG64 nVirtualBlockSize, nUserRequestedSize;

		if (GetFieldValue(address, type, "pVirtualBlock", pVirtualBlock) != 0)
		{
			dprintf("read pVirtualBlock failed\n");
			return FALSE;
		}

		if (GetFieldValue(address, type, "nVirtualBlockSize", nVirtualBlockSize) != 0)
		{
			dprintf("read nVirtualBlockSize failed\n");
			return FALSE;
		}

		if (GetFieldValue(address, type, "nUserRequestedSize", nUserRequestedSize) != 0)
		{
			dprintf("read nUserRequestedSize failed\n");
			return FALSE;
		}

		if (GetFieldValue(address, type, "StackTrace", stackTrace))
		{
			dprintf("read StackTrace failed\n");
			return FALSE;
		}

		DPRINTF("ust:%p, userPtr:%p, userSize:%p, extra:%p\n",
			stackTrace, pUserAllocation, nUserRequestedSize, nVirtualBlockSize - nUserRequestedSize);
		HeapRecord record;
		record.ustAddress = stackTrace;
		record.size = nVirtualBlockSize;
		record.address = pVirtualBlock;
		record.userSize = nUserRequestedSize;
		record.userAddress = pUserAllocation;
		records->insert(record);
	}
	return TRUE;
}

static BOOL AnalyzeDphHeap64(ULONG64 heapList, IProcessor *processor, const CommonParams &params)
{
	std::vector<ULONG64> heapRoots;
	ULONG cb;
	LIST_ENTRY64 listEntry;
	if (!READMEMORY(heapList, listEntry))
	{
		dprintf("read LIST_ENTRY64 at %p failed\n", heapList);
		return FALSE;
	}
	while (listEntry.Flink != heapList)
	{
		ULONG offset;
		::GetFieldOffset("ntdll!_DPH_HEAP_ROOT", "NextHeap", &offset);
		ULONG64 heapRoot = listEntry.Flink - offset;
		DPRINTF("push heapRoot %p\n", heapRoot);
		heapRoots.push_back(heapRoot);
		if (!READMEMORY(listEntry.Flink, listEntry))
		{
			dprintf("read LIST_ENTRY64 at %p failed\n", listEntry.Flink);
			return FALSE;
		}
	}

	for (std::vector<ULONG64>::iterator itr = heapRoots.begin(); itr != heapRoots.end(); itr++)
	{
		ULONG offset;

		ULONG64 normalHeap;
		if (GetFieldValue(*itr, "ntdll!_DPH_HEAP_ROOT", "NormalHeap", normalHeap))
		{
			dprintf("read NormalHeap failed\n");
			return FALSE;
		}

		DPRINTF("heap at %p, _DPH_HEAP_ROOT %p\n", normalHeap, *itr);
		processor->StartHeap(normalHeap);
		std::set<HeapRecord> records;

		GetFieldOffset("ntdll!_DPH_HEAP_ROOT", "BusyNodesTable", &offset);
		if (!WalkBalancedLinks(*itr + offset, params, AnalyzeDphHeapBlock64, &records))
		{
			dprintf("WalkBalancedLinks failed\n");
			return FALSE;
		}
		
		for (std::set<HeapRecord>::iterator itr_ = records.begin();
			itr_ != records.end();
			itr_++)
		{
			processor->Register(itr_->ustAddress,
				itr_->size, itr_->address,
				itr_->userSize, itr_->userAddress);
		}
		processor->FinishHeap(normalHeap);
	}
	return TRUE;
}

static BOOL AnalyzeDphHeap(IProcessor *processor, const CommonParams &params)
{
	ULONG64 heapList = GetExpression("verifier!AVrfpDphPageHeapList");
	DPRINTF("verifier!AVrfpDphPageHeapList: %p\n", heapList);
	if (IsTarget64())
	{
		return AnalyzeDphHeap64(heapList, processor, params);
	}
	else
	{
		return AnalyzeDphHeap32(heapList, processor, params);
	}
}

static BOOL AnalyzeHeap(IProcessor *processor, BOOL verbose)
{
	ULONG64 heapAddress;
	CommonParams params;

	params.osVersion = GetOSVersion();
	params.verbose = verbose;
	params.ntGlobalFlag = GetNtGlobalFlag();
	params.isTarget64 = IsTarget64();
	DPRINTF("target is %s\n", params.isTarget64 ? "x64" : "x86");
	if (params.ntGlobalFlag & NT_GLOBAL_FLAG_HPA)
	{
		DPRINTF("hpa enabled\n");
		return AnalyzeDphHeap(processor, params);
	}
	else if (params.ntGlobalFlag & NT_GLOBAL_FLAG_UST)
	{
		DPRINTF("ust enabled\n");
	}
	else
	{
		dprintf("set ust or hpa by gflags.exe for detailed information\n");
	}

	for (ULONG heapIndex = 0; (heapAddress = GetHeapAddress(heapIndex)) != 0; heapIndex++)
	{
		DPRINTF("heap[%d] at %p\n", heapIndex, heapAddress);
		processor->StartHeap(heapAddress);
		if (params.isTarget64)
		{
			if (!AnalyzeHeap64(heapAddress, params, processor))
			{
				return FALSE;
			}
		}
		else
		{
			if (!AnalyzeHeap32(heapAddress, params, processor))
			{
				return FALSE;
			}
		}
		processor->FinishHeap(heapAddress);
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
			"   heapstat [-v] [-k module!symbol] - Shows statistics of heaps\n"
			"   bysize [-v]                      - Shows statistics of heaps by size\n"
			"   umdh <file>                      - Generate umdh output\n"
			"   ust <addr>                       - Shows stacktrace of the ust record at <addr>\n"
			"   help                             - Shows this help\n");
}

DECLARE_API(heapstat)
{
	UNREFERENCED_PARAMETER(dwProcessor);
	UNREFERENCED_PARAMETER(dwCurrentPc);
	UNREFERENCED_PARAMETER(hCurrentThread);
	UNREFERENCED_PARAMETER(hCurrentProcess);

	BOOL verbose = FALSE;
	char *key = NULL;

	std::vector<char> buffer;
	buffer.resize(strlen(args) + 1);
	memcpy(&buffer[0], args, buffer.size());
	char *token, *nextToken;
	const char *delim = " ";
	token = strtok_s(&buffer[0], delim, &nextToken);
	while (token != NULL)
	{
		if (strcmp("-v", token) == 0)
		{
			dprintf("verbose mode\n");
			verbose = TRUE;
		}
		else if (strcmp("-k", token) == 0)
		{
			token = strtok_s(NULL, delim, &nextToken);
			if (token == NULL)
			{
				dprintf("no key specified after -k\n");
				return;
			}
			key = token;
		}
		token = strtok_s(NULL, delim, &nextToken);
	}

	SummaryProcessor processor;

	if (!AnalyzeHeap(&processor, verbose))
	{
		return;
	}

	if (key == NULL)
	{
		processor.Print();
	}
	else
	{
		processor.Print(key);
	}
}

DECLARE_API(bysize)
{
	UNREFERENCED_PARAMETER(dwProcessor);
	UNREFERENCED_PARAMETER(dwCurrentPc);
	UNREFERENCED_PARAMETER(hCurrentThread);
	UNREFERENCED_PARAMETER(hCurrentProcess);

	BOOL verbose = FALSE;

	std::vector<char> buffer;
	buffer.resize(strlen(args) + 1);
	memcpy(&buffer[0], args, buffer.size());
	char *token, *nextToken;
	const char *delim = " ";
	token = strtok_s(&buffer[0], delim, &nextToken);
	while (token != NULL)
	{
		if (strcmp("-v", token) == 0)
		{
			dprintf("verbose mode\n");
			verbose = TRUE;
		}
		token = strtok_s(NULL, delim, &nextToken);
	}

	BySizeProcessor processor;

	if (!AnalyzeHeap(&processor, verbose))
	{
		return;
	}

	processor.Print();
}

DECLARE_API(umdh)
{
	UNREFERENCED_PARAMETER(dwProcessor);
	UNREFERENCED_PARAMETER(dwCurrentPc);
	UNREFERENCED_PARAMETER(hCurrentThread);
	UNREFERENCED_PARAMETER(hCurrentProcess);

	if (!(GetNtGlobalFlag() & (NT_GLOBAL_FLAG_UST | NT_GLOBAL_FLAG_HPA)))
	{
		dprintf("please set ust or hpa by gflags.exe\n");
		return;
	}

	UmdhProcessor *processor(0);
	try
	{
		processor = new UmdhProcessor(args);
	}
	catch (...)
	{
		return;
	}

	AnalyzeHeap(processor, FALSE);
	delete processor;
}

DECLARE_API(ust)
{
	UNREFERENCED_PARAMETER(dwProcessor);
	UNREFERENCED_PARAMETER(dwCurrentPc);
	UNREFERENCED_PARAMETER(hCurrentThread);
	UNREFERENCED_PARAMETER(hCurrentProcess);

	ULONG64 Address = GetExpression(args);

	std::vector<ULONG64> trace = GetStackTrace(Address, IsTarget64(), GetNtGlobalFlag());
	dprintf("ust at %p depth: %d\n", Address, trace.size());
	for (std::vector<ULONG64>::iterator itr = trace.begin(); itr != trace.end(); itr++)
	{
		dprintf("%ly\n", *itr);
	}
}

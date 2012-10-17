#include "common.h"
#include "Utility.h"
#include "SummaryProcessor.h"
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
typedef struct {
	ULONG64 ustAddress;
	ULONG64 size;
	ULONG64 address;
	ULONG64 userSize;
	ULONG64 userAddress;
} HeapRecord;


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

static BOOL ParseHeapRecord32(ULONG64 address, const HeapEntry &entry, ULONG32 ntGlobalFlag, HeapRecord &record)
{
	const ULONG blockUnit = 8;
	ULONG cb;
	if (ntGlobalFlag & (NT_GLOBAL_FLAG_UST | NT_GLOBAL_FLAG_HPA))
	{
		ULONG64 offset = (ntGlobalFlag & NT_GLOBAL_FLAG_HPA) ? 0x18 : 0;
		ULONG32 ustAddress;
		if (!READMEMORY(address + sizeof(entry) + offset, ustAddress))
		{
			dprintf("read ustAddress at %p failed", address + sizeof(entry) + offset);
			return FALSE;
		}
		else
		{
			record.ustAddress = ustAddress;
			if (ntGlobalFlag & NT_GLOBAL_FLAG_HPA)
			{
				USHORT userSize_;
				if (READMEMORY(address + sizeof(entry) + 0x8, userSize_))
				{
					if (entry.Size * blockUnit > userSize_)
					{
						record.userSize = userSize_;
						record.userAddress = address + sizeof(entry) + 0x20;
					}
					else
					{
						dprintf("invalid userSize 0x%04x\n", userSize_);
						return FALSE;
					}
				}
				else
				{
					dprintf("READMEMORY for userSize failed at %p\n", address + sizeof(entry) + 0x8);
					return FALSE;
				}
			}
			else // NT_GLOBAL_FLAG_UST
			{
				USHORT extra;
				if (READMEMORY(address + sizeof(entry) + 0xc, extra))
				{
					if (entry.Size * blockUnit >= extra)
					{
						record.userSize = entry.Size * blockUnit - extra;
						record.userAddress = address + sizeof(entry) + 0x10;
					}
					else
					{
						dprintf("invalid extra 0x%04x\n", extra);
						return FALSE;
					}
				}
				else
				{
					dprintf("READMEMORY for extra failed at %p\n", address + sizeof(entry) + 0xc);
					return FALSE;
				}
			}
		}
	}
	else
	{
		record.ustAddress = 0;
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
	if (ntGlobalFlag & (NT_GLOBAL_FLAG_UST | NT_GLOBAL_FLAG_HPA))
	{
		ULONG64 offset = (ntGlobalFlag & NT_GLOBAL_FLAG_HPA) ? 0x30 : 0;
		ULONG64 ustAddress;
		if (!READMEMORY(address + sizeof(entry) + offset, ustAddress))
		{
			dprintf("read ustAddress at %p failed", address + sizeof(entry) + offset);
			return FALSE;
		}
		else
		{
			record.ustAddress = ustAddress;
			if (ntGlobalFlag & NT_GLOBAL_FLAG_HPA)
			{
				USHORT userSize_;
				if (READMEMORY(address + sizeof(entry) + 0x10, userSize_))
				{
					if (entry.Size * blockUnit > userSize_)
					{
						record.userSize = userSize_;
						record.userAddress = address + sizeof(entry) + 0x40;
					}
					else
					{
						dprintf("invalid userSize 0x%04x\n", userSize_);
						return FALSE;
					}
				}
				else
				{
					dprintf("READMEMORY for userSize failed at %p\n", address + sizeof(entry) + 0x10);
					return FALSE;
				}
			}
			else // NT_GLOBAL_FLAG_UST
			{
				USHORT extra;
				if (READMEMORY(address + sizeof(entry) + 0x1c, extra))
				{
					if (entry.Size * blockUnit >= extra)
					{
						record.userSize = entry.Size * blockUnit - extra;
						record.userAddress = address + sizeof(entry) + 0x20;
					}
					else
					{
						dprintf("invalid extra 0x%04x\n", extra);
						return FALSE;
					}
				}
				else
				{
					dprintf("READMEMORY for extra failed at %p\n", address + sizeof(entry) + 0xc);
					return FALSE;
				}
			}
		}
	}
	else
	{
		record.ustAddress = 0;
		record.userSize = entry.Size * blockUnit - entry.ExtendedBlockSignature;
		record.userAddress = address + sizeof(entry);
	}
	record.size = entry.Size * blockUnit;
	record.address = address;
	return TRUE;
}

static BOOL AnalyzeLFHZone32(ULONG64 zone, ULONG32 ntGlobalFlag, std::list<HeapRecord> &lfhRecords, BOOL verbose)
{
	DPRINTF("_LFH_BLOCK_ZONE %p\n", zone);
	ULONG cb;
	ULONG offset;
	ULONG32 limit;
	if (!READMEMORY(zone + 0xc, limit))
	{
		dprintf("read _LFH_BLOCK_ZONE::Limit failed\n");
		return FALSE;
	}

	ULONG64 subsegment = zone + 0x10;
	ULONG subsegmentSize = GetOSVersion() >= OS_VERSION_WIN8 ? 0x28 : 0x20; // sizeof(_HEAP_SUBSEGMENT)
	while (subsegment + subsegmentSize <= limit)
	{
		DPRINTF("_HEAP_SUBSEGMENT %p\n", subsegment);
		USHORT blockSize; // _HEAP_SUBSEGMENT::BlockSize
		USHORT blockCount; // _HEAP_SUBSEGMENT::BlockCount
		offset = GetOSVersion() >= OS_VERSION_WIN8 ? 0x14 : 0x10;
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
		offset = GetOSVersion() >= OS_VERSION_WIN8 ? 0x18 : 0x14;
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
		ULONG64 address;
		if (GetOSVersion() >= OS_VERSION_WIN8)
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

			UCHAR busy = (ntGlobalFlag & NT_GLOBAL_FLAG_UST) != 0 ? 0xc2 : 0x88;
			if (entry.ExtendedBlockSignature == busy)
			{
				HeapRecord record;
				if (ParseHeapRecord32(address, entry, ntGlobalFlag, record))
				{
					DPRINTF("ust:%p, userPtr:%p, userSize:%p, extra:%p\n",
						record.ustAddress, record.userAddress, record.userSize, entry.Size * blockUnit - record.userSize);
					lfhRecords.push_back(record);
				}
				else
				{
					return FALSE;
				}
			}

			address += blockSize * blockUnit;
		}
		subsegment += subsegmentSize;
	}
	return TRUE;
}

static BOOL AnalyzeLFHZone64(ULONG64 zone, ULONG32 ntGlobalFlag, std::list<HeapRecord> &lfhRecords, BOOL verbose)
{
	DPRINTF("_LFH_BLOCK_ZONE %p\n", zone);
	ULONG cb;
	ULONG64 limit;
	if (GetFieldValue(zone, "ntdll!_LFH_BLOCK_ZONE", "Limit", limit) != 0)
	{
		dprintf("read _LFH_BLOCK_ZONE::Limit failed\n");
		return FALSE;
	}

	ULONG64 subsegment = zone + GetTypeSize("ntdll!_LFH_BLOCK_ZONE");
	ULONG subsegmentSize = GetTypeSize("ntdll!_HEAP_SUBSEGMENT");
	while (subsegment + subsegmentSize <= limit)
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
		ULONG64 address;
		if (GetOSVersion() >= OS_VERSION_WIN8)
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

			UCHAR busy = (ntGlobalFlag & NT_GLOBAL_FLAG_UST) != 0 ? 0xc2 : 0x88;
			if (entry.ExtendedBlockSignature == busy)
			{
				HeapRecord record;
				if (ParseHeapRecord64(address, entry, ntGlobalFlag, record))
				{
					DPRINTF("ust:%p, userPtr:%p, userSize:%p, extra:%p\n",
						record.ustAddress, record.userAddress, record.userSize, entry.Size * blockUnit - record.userSize);
					lfhRecords.push_back(record);
				}
				else
				{
					return FALSE;
				}
			}

			address += blockSize * blockUnit;
		}
		subsegment += subsegmentSize;
	}
	return TRUE;
}

static BOOL AnalyzeLFH32(ULONG64 heapAddress, ULONG32 ntGlobalFlag, std::list<HeapRecord> &lfhRecords, BOOL verbose)
{
	DPRINTF("analyze LFH for HEAP %p\n", heapAddress);
	ULONG cb;
	ULONG offset;
	UCHAR type; // _HEAP::FrontEndHeapType
	offset = GetOSVersion() >= OS_VERSION_WIN8 ? 0xd6: 0xda;
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
	offset = GetOSVersion() >= OS_VERSION_WIN8 ? 0xd0: 0xd4;
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
	offset = GetOSVersion() >= OS_VERSION_WIN8 ? 0x4 : 0x18;
	ULONG32 start = frontEndHeap + offset; // _LFH_HEAP::SubSegmentZones
	ULONG32 zone = start;
	do
	{
		LIST_ENTRY32 listEntry;
		if (!READMEMORY(zone, listEntry))
		{
			dprintf("read SubsegmentZones failed\n");
			return FALSE;
		}
		zone = listEntry.Flink;
		if (!AnalyzeLFHZone32(zone, ntGlobalFlag, lfhRecords, verbose))
		{
			return FALSE;
		}
	} while (zone != start);
	return TRUE;
}

static BOOL AnalyzeLFH64(ULONG64 heapAddress, ULONG32 ntGlobalFlag, std::list<HeapRecord> &lfhRecords, BOOL verbose)
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
	do
	{
		LIST_ENTRY64 listEntry;
		if (!READMEMORY(zone, listEntry))
		{
			dprintf("read SubsegmentZones failed\n");
			return FALSE;
		}
		zone = listEntry.Flink;
		if (!AnalyzeLFHZone64(zone, ntGlobalFlag, lfhRecords, verbose))
		{
			return FALSE;
		}
	} while (zone != start);
	return TRUE;
}

static void Register(
		const HeapRecord &record,
		std::list<HeapRecord> &lfhRecords,
		IProcessor *processor)
{
	while (!lfhRecords.empty() && lfhRecords.begin()->address < record.address)
	{
		std::list<HeapRecord>::iterator itr = lfhRecords.begin();
		//dprintf("Register: insert entry %p\n", itr->address);
		processor->Register(itr->ustAddress,
			itr->size, itr->address, itr->userSize, itr->userAddress);
		lfhRecords.pop_front();
	}
	processor->Register(record.ustAddress,
		record.size, record.address, record.userSize, record.userAddress);
}

bool predicate(const HeapRecord &record1, const HeapRecord &record2)
{
	return record1.address < record2.address;
}

static BOOL AnalyzeHeap32(ULONG64 heapAddress, ULONG32 ntGlobalFlag, BOOL verbose, IProcessor *processor)
{
	std::list<HeapRecord> lfhRecords;
	AnalyzeLFH32(heapAddress, ntGlobalFlag, lfhRecords, verbose);
	lfhRecords.sort(predicate);
	dprintf("found %d LFH records in heap %p\n", (int)lfhRecords.size(), heapAddress);
	const ULONG blockUnit = 8;
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
		HeapSegment segment;
		if (!READMEMORY(heapAddress, segment))
		{
			dprintf("read HEAP_SEGMENT at %p failed\n", heapAddress);
			return FALSE;
		}
		DPRINTF("Segment at %p to %p\n", heapAddress, (ULONG64)segment.LastValidEntry);
		DPRINTF("NumberOfUnCommittedPages:%p, NumberOfUnCommittedRanges:%p\n", (ULONG64)segment.NumberOfUnCommittedPages, (ULONG64)segment.NumberOfUnCommittedRanges);
		processor->StartSegment(heapAddress, segment.LastValidEntry);

		std::list<HeapRecord> lfhRecordsInSegment;
		for (std::list<HeapRecord>::iterator itr = lfhRecords.begin();
			itr != lfhRecords.end();
			itr++)
		{
			if (segment.FirstEntry < itr->address && itr->address < segment.LastValidEntry)
			{
				lfhRecordsInSegment.push_back(*itr);
			}
		}
		DPRINTF("%d LFH records in segment %p\n", (int)lfhRecordsInSegment.size(), heapAddress);

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

			// skip the last entry in the segment
			if (address + entry.Size * blockUnit >= segment.LastValidEntry - segment.NumberOfUnCommittedPages * PAGE_SIZE)
			{
				DPRINTF("uncommitted bytes follows\n");
				break;
			}

			if (!(ntGlobalFlag & (NT_GLOBAL_FLAG_UST | NT_GLOBAL_FLAG_HPA)) || entry.ExtendedBlockSignature != 0x01)
			{
				DPRINTF("addr:%p, %04x, %02x, %02x, %04x, %02x, %02x\n", address, entry.Size, entry.Flags, entry.SmallTagIndex, entry.PreviousSize, entry.SegmentOffset, entry.ExtendedBlockSignature);
				UCHAR busy = (ntGlobalFlag & NT_GLOBAL_FLAG_HPA) ? 0x03 : 0x01;
				if (entry.Flags == busy)
				{
					HeapRecord record;
					if (ParseHeapRecord32(address, entry, ntGlobalFlag, record))
					{
						DPRINTF("ust:%p, userPtr:%p, userSize:%p, extra:%p\n",
							record.ustAddress, record.userAddress, record.userSize, entry.Size * blockUnit - record.userSize);
						Register(record, lfhRecordsInSegment, processor);
					}
				}
			}
			address += entry.Size * blockUnit;
		}
		for (std::list<HeapRecord>::iterator itr = lfhRecordsInSegment.begin();
			itr != lfhRecordsInSegment.end();
			itr++)
		{
			//dprintf("insert entry %p\n", itr->address);
			processor->Register(itr->ustAddress,
				itr->size, itr->address,
				itr->userSize, itr->userAddress);
		}
		processor->FinishSegment(heapAddress, segment.LastValidEntry);
		heapAddress = segment.SegmentListEntry.Flink - 0x10;
		index++;
	}
	return TRUE;
}

static BOOL AnalyzeHeap64(ULONG64 heapAddress, ULONG32 ntGlobalFlag, BOOL verbose, IProcessor *processor)
{
	std::list<HeapRecord> lfhRecords;
	AnalyzeLFH64(heapAddress, ntGlobalFlag, lfhRecords, verbose);
	lfhRecords.sort(predicate);
	dprintf("found %d LFH records in heap %p\n", (int)lfhRecords.size(), heapAddress);
	const ULONG blockUnit = 16;
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
		Heap64Segment segment;
		if (!READMEMORY(heapAddress, segment))
		{
			dprintf("read HEAP_SEGMENT at %p failed\n", heapAddress);
			return FALSE;
		}
		DPRINTF("Segment at %p to %p\n", heapAddress, segment.LastValidEntry);
		DPRINTF("NumberOfUnCommittedPages:%p, NumberOfUnCommittedRanges:%p\n", (ULONG64)segment.NumberOfUnCommittedPages, (ULONG64)segment.NumberOfUnCommittedRanges);
		processor->StartSegment(heapAddress, segment.LastValidEntry);

		std::list<HeapRecord> lfhRecordsInSegment;
		for (std::list<HeapRecord>::iterator itr = lfhRecords.begin();
			itr != lfhRecords.end();
			itr++)
		{
			if (segment.FirstEntry < itr->address && itr->address < segment.LastValidEntry)
			{
				lfhRecordsInSegment.push_back(*itr);
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
				return FALSE;
			}
			if (!DecodeHeap64Entry(&entry, &encoding))
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

			if (!(ntGlobalFlag & (NT_GLOBAL_FLAG_UST | NT_GLOBAL_FLAG_HPA)) || entry.ExtendedBlockSignature != 0x01)
			{
				DPRINTF("addr:%p, %04x, %02x, %02x, %04x, %02x, %02x\n", address, entry.Size, entry.Flags, entry.SmallTagIndex, entry.PreviousSize, entry.SegmentOffset, entry.ExtendedBlockSignature);
				UCHAR busy = (ntGlobalFlag & NT_GLOBAL_FLAG_HPA) ? 0x03 : 0x01;
				if (entry.Flags == busy)
				{
					HeapRecord record;
					if (ParseHeapRecord64(address, entry, ntGlobalFlag, record))
					{
						DPRINTF("ust:%p, userPtr:%p, userSize:%p, extra:%p\n",
							record.ustAddress, record.userAddress, record.userSize, entry.Size * blockUnit - record.userSize);
						Register(record, lfhRecordsInSegment, processor);
					}
				}
			}
			address += entry.Size * blockUnit;
		}
		processor->FinishSegment(heapAddress, segment.LastValidEntry);
		heapAddress = segment.SegmentListEntry.Flink - 0x18;
		index++;
	}
	return TRUE;
}

static BOOL AnalyzeHeap(IProcessor *processor, BOOL verbose)
{
	ULONG64 heapAddress;
	ULONG32 ntGlobalFlag;

	ntGlobalFlag = GetNtGlobalFlag();
	if (ntGlobalFlag & NT_GLOBAL_FLAG_HPA)
	{
		DPRINTF("hpa enabled\n");
	}
	else if (ntGlobalFlag & NT_GLOBAL_FLAG_UST)
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
		if (IsTarget64())
		{
			if (!AnalyzeHeap64(heapAddress, ntGlobalFlag, verbose, processor))
			{
				return FALSE;
			}
		}
		else
		{
			if (!AnalyzeHeap32(heapAddress, ntGlobalFlag, verbose, processor))
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
			"   heapstat [-v]   - Shows statistics of heaps\n"
			"   umdh <file>     - Generate umdh output\n"
			"   ust <addr>      - Shows stacktrace of the ust record at <addr>\n"
			"   help            - Shows this help\n");
}

DECLARE_API(heapstat)
{
	UNREFERENCED_PARAMETER(dwProcessor);
	UNREFERENCED_PARAMETER(dwCurrentPc);
	UNREFERENCED_PARAMETER(hCurrentThread);
	UNREFERENCED_PARAMETER(hCurrentProcess);

	BOOL verbose = FALSE;

	if (strcmp("-v", args) == 0)
	{
		dprintf("verbose mode\n");
		verbose = TRUE;
	}

	SummaryProcessor processor;

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

	std::vector<ULONG64> trace = GetStackTrace(Address);
	dprintf("ust at %p depth: %d\n", Address, trace.size());
	for (std::vector<ULONG64>::iterator itr = trace.begin(); itr != trace.end(); itr++)
	{
		dprintf("%ly\n", *itr);
	}
}

#include "common.h"
#include "Utility.h"
#include "SummaryProcessor.h"
#include "UmdhProcessor.h"

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
		if (!GetFieldValue(address, "ntdll!_PEB", "NumberOfHeaps", numberOfHeaps))
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
		if (!GetFieldValue(address, "ntdll!_PEB", "ProcessHeaps", processHeaps))
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

static BOOL AnalyzeHeap32(ULONG64 heapAddress, ULONG32 ntGlobalFlag, BOOL verbose, IProcessor *processor)
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
		if (verbose)
		{
			dprintf("segment %d\n", index);
		}
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
				if (verbose)
				{
					dprintf("addr:%p, %04x, %02x, %02x, %04x, %02x, %02x, ", address, entry.Size, entry.Flags, entry.SmallTagIndex, entry.PreviousSize, entry.SegmentOffset, entry.ExtendedBlockSignature);
				}
				UCHAR busy = (ntGlobalFlag & NT_GLOBAL_FLAG_HPA) ? 0x03 : 0x01;
				if (entry.Flags == busy)
				{
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
							ULONG64 userSize = 0;
							ULONG64 userPtr = 0;
							if (ntGlobalFlag & NT_GLOBAL_FLAG_HPA)
							{
								USHORT userSize_;
								if (READMEMORY(address + sizeof(entry) + 0x8, userSize_))
								{
									if (entry.Size * blockSize > userSize_)
									{
										userSize = userSize_;
										userPtr = address + sizeof(entry) + 0x20;
										if (verbose)
										{
											dprintf("userPtr:%p, userSize:%p, extra:%p\n", userPtr, userSize, entry.Size * blockSize - userSize);
										}
									}
									else
									{
										dprintf("invalid userSize 0x%04x\n", userSize);
									}
								}
								else
								{
									dprintf("READMEMORY for userSize failed at %p\n", address + sizeof(entry) + 0x8);
								}
							}
							else // NT_GLOBAL_FLAG_UST
							{
								USHORT extra;
								if (READMEMORY(address + sizeof(entry) + 0xc, extra))
								{
									if (entry.Size * blockSize > extra)
									{
										userSize = entry.Size * blockSize - extra;
										userPtr = address + sizeof(entry) + 0x10;
										if (verbose)
										{
											dprintf("userPtr:%p, userSize:%p, extra:%p\n", userPtr, userSize, (ULONG64)extra);
										}
									}
									else
									{
										dprintf("invalid extra 0x%04x\n", extra);
									}
								}
								else
								{
									dprintf("READMEMORY for extra failed at %p\n", address + sizeof(entry) + 0xc);
								}
							}
							processor->Register(ustAddress, entry.Size * blockSize, address, userSize, userPtr);
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
				else
				{
					if (verbose)
					{
						dprintf("\n");
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

static BOOL AnalyzeHeap64(ULONG64 heapAddress, ULONG32 ntGlobalFlag, BOOL verbose, IProcessor *processor)
{
	const ULONG blockSize = 16;
	ULONG cb;
	Heap64Entry encoding;
	if (!GetFieldValue(heapAddress, "ntdll!_HEAP", "Encoding", encoding))
	{
		dprintf("read Encoding failed\n");
		return FALSE;
	}

	int index = 0;
	while ((heapAddress & 0xffff) == 0)
	{
		if (verbose)
		{
			dprintf("segment %d\n", index);
		}
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
				if (verbose)
				{
					dprintf("addr:%p, %04x, %02x, %02x, %04x, %02x, %02x, ", address, entry.Size, entry.Flags, entry.SmallTagIndex, entry.PreviousSize, entry.SegmentOffset, entry.ExtendedBlockSignature);
				}
				UCHAR busy = (ntGlobalFlag & NT_GLOBAL_FLAG_HPA) ? 0x03 : 0x01;
				if (entry.Flags == busy)
				{
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
							ULONG64 userSize = 0;
							ULONG64 userPtr = 0;
							if (ntGlobalFlag & NT_GLOBAL_FLAG_HPA)
							{
								USHORT userSize_;
								if (READMEMORY(address + sizeof(entry) + 0x10, userSize_))
								{
									if (entry.Size * blockSize > userSize_)
									{
										userSize = userSize_;
										userPtr = address + sizeof(entry) + 0x40;
										dprintf("userPtr:%p, userSize:%p, extra:%p\n", userPtr, userSize, entry.Size * blockSize - userSize);
									}
									else
									{
										dprintf("invalid userSize 0x%04x\n", userSize);
									}
								}
								else
								{
									dprintf("READMEMORY for userSize failed at %p\n", address + sizeof(entry) + 0x8);
								}
							}
							else // NT_GLOBAL_FLAG_UST
							{
								USHORT extra;
								if (READMEMORY(address + sizeof(entry) + 0x1c, extra))
								{
									if (entry.Size * blockSize > extra)
									{
										userSize = entry.Size * blockSize - extra;
										userPtr = address + sizeof(entry) + 0x20;
										if (verbose)
										{
											dprintf("userPtr:%p, userSize:%p, extra:%p\n", userPtr, userSize, (ULONG64)extra);
										}
									}
									else
									{
										dprintf("invalid extra 0x%04x\n", extra);
									}
								}
								else
								{
									dprintf("READMEMORY for extra failed at %p\n", address + sizeof(entry) + 0xc);
								}
							}
							processor->Register(ustAddress, entry.Size * blockSize, address, userSize, userPtr);
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
				else
				{
					if (verbose)
					{
						dprintf("\n");
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

static BOOL AnalyzeHeap(IProcessor *processor, BOOL verbose)
{
	ULONG64 heapAddress;
	ULONG32 ntGlobalFlag;

	ntGlobalFlag = GetNtGlobalFlag();
	if (ntGlobalFlag & NT_GLOBAL_FLAG_HPA)
	{
		if (verbose)
		{
			dprintf("hpa enabled\n");
		}
	}
	else if (ntGlobalFlag & NT_GLOBAL_FLAG_UST)
	{
		if (verbose)
		{
			dprintf("ust enabled\n");
		}
	}
	else
	{
		dprintf("please set ust or hpa by gflags.exe\n");
		return FALSE;
	}

	for (ULONG heapIndex = 0; (heapAddress = GetHeapAddress(heapIndex)) != 0; heapIndex++)
	{
		if (verbose)
		{
			dprintf("heap[%d] at %p\n", heapIndex, heapAddress);
		}
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

	UmdhProcessor processor(args);

	if (!AnalyzeHeap(&processor, FALSE))
	{
		return;
	}
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

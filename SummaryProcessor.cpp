#include <list>
#include "common.h"
#include "SummaryProcessor.h"
#include "Utility.h"

void SummaryProcessor::Register(ULONG64 ustAddress,
		ULONG64 size, ULONG64 address,
		ULONG64 userSize, ULONG64 userAddress)
{
	UNREFERENCED_PARAMETER(userAddress);
	UNREFERENCED_PARAMETER(userSize);

	if (ustAddress != 0)
	{
		std::map<ULONG64, UstRecord>::iterator itr = records_.find(ustAddress);
		if (itr == records_.end())
		{
			UstRecord record;
			record.ustAddress = ustAddress;
			record.count = 1;
			record.totalSize = record.maxSize = size;
			record.largestEntry = address;
			records_[ustAddress] = record;
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
			records_[ustAddress] = record;
		}
	}
}

void SummaryProcessor::Print()
{
	// sort by total size
	std::list<UstRecord> sorted;
	for (std::map<ULONG64, UstRecord>::iterator itr_ = records_.begin(); itr_ != records_.end(); ++itr_)
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
		PrintStackTrace(itr->ustAddress);
	}
	dprintf("\n");
}

void SummaryProcessor::PrintStackTrace(ULONG64 ustAddress)
{
	PCSTR indent = "\t";
	std::vector<ULONG64> trace = GetStackTrace(ustAddress);
	dprintf("%sust at %p depth: %d\n", indent, ustAddress, trace.size());
	for (std::vector<ULONG64>::iterator itr = trace.begin(); itr != trace.end(); itr++)
	{
		dprintf("%s%ly\n", indent, *itr);
	}
}

#include <windows.h>
#include "common.h"
#include "BySizeProcessor.h"

BySizeProcessor::BySizeProcessor(ULONG64 size)
: size_(size)
{
}

void BySizeProcessor::Register(ULONG64 ustAddress,
		ULONG64 size, ULONG64 address,
		ULONG64 userSize, ULONG64 userAddress)
{
	UNREFERENCED_PARAMETER(size);
	UNREFERENCED_PARAMETER(address);
	UNREFERENCED_PARAMETER(userAddress);

	if (size_ != 0 && userSize != size_)
	{
		// ignore other size
		return;
	}

	std::map<ULONG64, SizeRecord>::iterator itr = records_.find(userSize);
	if (itr == records_.end())
	{
		SizeRecord record;
		record.userSize = userSize;
		record.count = 1;
		record.ustAddress.insert(ustAddress);
		records_[userSize] = record;
	}
	else
	{
		SizeRecord &record = itr->second;
		record.count++;
		record.ustAddress.insert(ustAddress);
	}
}

void BySizeProcessor::Print()
{
	if (size_ != 0)
	{
		SizeRecord record = records_[size_];
		for (std::set<ULONG64>::iterator itr_ = record.ustAddress.begin(); itr_ != record.ustAddress.end(); ++itr_)
		{
			dprintf("%p\n", *itr_);
		}
		return;
	}

	std::multiset<SizeRecord> sorted;
	for (std::map<ULONG64, SizeRecord>::iterator itr = records_.begin(); itr != records_.end(); ++itr)
	{
		sorted.insert(itr->second);
	}

	if (IsPtr64())
	{
		dprintf("        userSize(           count)             ust0,             ust1,...\n");
	}
	else
	{
		dprintf("userSize(   count)     ust0,     ust1,...\n");
	}
	for (std::multiset<SizeRecord>::reverse_iterator itr = sorted.rbegin(); itr != sorted.rend(); ++itr)
	{
		dprintf("%p(%p)", itr->userSize, itr->count);
		for (std::set<ULONG64>::iterator itr_ = itr->ustAddress.begin(); itr_ != itr->ustAddress.end(); ++itr_)
		{
			dprintf("%p,", *itr_);
		}
		dprintf("\n");
	}
	dprintf("\n");
}

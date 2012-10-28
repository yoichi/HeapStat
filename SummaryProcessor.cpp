#include <list>
#include "common.h"
#include "SummaryProcessor.h"

SummaryProcessor::SummaryProcessor()
: totalSize_(0)
{
}

void SummaryProcessor::StartSegment(ULONG64 start, ULONG64 end)
{
	totalSize_ += end - start;
}

void SummaryProcessor::Register(ULONG64 ustAddress,
		ULONG64 size, ULONG64 address,
		ULONG64 userSize, ULONG64 userAddress)
{
	UNREFERENCED_PARAMETER(userAddress);
	UNREFERENCED_PARAMETER(userSize);

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

void SummaryProcessor::Print()
{
	std::vector<ModuleInfo> loadedModules = GetLoadedModules();
	std::list<UstRecord> sorted;
	std::map<ULONG64, ULONG64> byCaller;
	for (std::map<ULONG64, UstRecord>::iterator itr_ = records_.begin(); itr_ != records_.end(); ++itr_)
	{
		// allocation statistics by caller
		ULONG64 module = GetCallerModule(itr_->first, loadedModules);
		if (byCaller.find(module) == byCaller.end())
		{
			byCaller[module] = itr_->second.totalSize;
		}
		else
		{
			byCaller[module] += itr_->second.totalSize;
		}

		// sort by total size
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

	dprintf("total size per caller:\n");
	std::list<std::pair<ULONG64, ULONG64>> sortedCaller;
	for (std::map<ULONG64, ULONG64>::iterator itr_ = byCaller.begin(); itr_ != byCaller.end(); itr_++)
	{
		std::list<std::pair<ULONG64, ULONG64>>::iterator itr = sortedCaller.begin();
		while (itr != sortedCaller.end())
		{
			if (itr->second <  itr_->second)
			{
				break;
			}
			++itr;
		}
		sortedCaller.insert(itr, std::pair<ULONG64, ULONG64>(itr_->first, itr_->second));
	}
	for (std::list<std::pair<ULONG64, ULONG64>>::iterator itr = sortedCaller.begin();
		itr != sortedCaller.end(); itr++)
	{
		if (itr->first == NULL)
		{
			dprintf("%p <unknown>\n", itr->second);
		}
		else
		{
			for (std::vector<ModuleInfo>::iterator itr_ = loadedModules.begin(); itr_ != loadedModules.end(); itr_++)
			{
				if (itr->first == itr_->DllBase)
				{
					dprintf("%p %s\n", itr->second, itr_->FullDllName);
				}
			}
		}
	}
	dprintf("\n");

	if (IsPtr64())
	{
		dprintf("total size: %p\n", totalSize_);
		dprintf("----------------------------------------------------------------------------------------\n");
		dprintf("             ust,            count,            total,              max,            entry\n");
		dprintf("----------------------------------------------------------------------------------------\n");
	}
	else
	{
		dprintf("total size: %p\n", totalSize_);
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

ULONG64 SummaryProcessor::GetCallerModule(ULONG64 ustAddress, std::vector<ModuleInfo> &loadedModules)
{
	std::vector<ULONG64> stackTrace = GetStackTrace(ustAddress);
	for (std::vector<ULONG64>::iterator itr = stackTrace.begin(); itr != stackTrace.end(); itr++)
	{
		static CHAR buffer[256];
		ULONG64 displacement;
		GetSymbol(*itr, buffer, &displacement);
		CHAR *ch = strchr(buffer, '!');
		if (ch == NULL)
		{
			continue;
		}
		*ch = '\0';
		const CHAR *ntdll = "ntdll";
		if (strcmp(buffer, ntdll) == 0)
		{
			continue;
		}
		const CHAR *msvcrPrefix = "msvcr";
		if (strncmp(buffer, msvcrPrefix, strlen(msvcrPrefix)) == 0)
		{
			continue;
		}
		for (std::vector<ModuleInfo>::iterator itr_ = loadedModules.begin(); itr_ != loadedModules.end(); itr_++)
		{
			if (itr_->DllBase <= *itr && *itr < itr_->DllBase + itr_->SizeOfImage)
			{
				return itr_->DllBase;
			}
		}
		return NULL;
	}
	return NULL;
}

void SummaryProcessor::PrintStackTrace(ULONG64 ustAddress)
{
	if (ustAddress == 0)
	{
		return;
	}
	PCSTR indent = "\t";
	std::vector<ULONG64> trace = GetStackTrace(ustAddress);
	dprintf("%sust at %p depth: %d\n", indent, ustAddress, trace.size());
	for (std::vector<ULONG64>::iterator itr = trace.begin(); itr != trace.end(); itr++)
	{
		dprintf("%s%ly\n", indent, *itr);
	}
}

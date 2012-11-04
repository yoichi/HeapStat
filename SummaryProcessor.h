#pragma once

#include <map>
#include <set>
#include <vector>
#include "IProcessor.h"
#include "Utility.h"

class SummaryProcessor : public IProcessor
{
private:
	/**
	*	@brief total reserved size
	*/
	ULONG64 totalSize_;

	struct UstRecord {
		ULONG64 ustAddress;
		ULONG64 count;
		ULONG64 totalSize;
		ULONG64 maxSize;
		ULONG64 largestEntry;
		bool operator< (const SummaryProcessor::UstRecord& rhs) const
		{
			return totalSize < rhs.totalSize;
		}
	};

	std::map<ULONG64, UstRecord> records_;

	/**
	*	@brief print set of UstRecord
	*/
	void PrintUstRecords(std::set<UstRecord>& records);

	/**
	*	@brief get caller module base address
	*/
	ULONG64 GetCallerModule(ULONG64 ustAddress, std::vector<ModuleInfo> &loadedModules);

	/**
	*	@brief test ust has matched frame
	*	@param key [in] prefix search key
	*/
	BOOL HasMatchedFrame(ULONG64 ustAddress, const char *key);

	/**
	*	@brief print stack trace
	*	@param ustAddress [in] address of entry in user mode stack trace database
	*/
	void PrintStackTrace(ULONG64 ustAddress);

public:
	/**
	*	@brief constructor
	*/
	SummaryProcessor();

	/**
	*	@copydoc IProcessor::StartHeap()
	*/
	void StartHeap(ULONG64 /*heapAddress*/) {}

	/**
	*	@copydoc IProcessor::StartSegment()
	*/
	void StartSegment(ULONG64 start, ULONG64 end);

	/**
	*	@copydoc IProcessor::FinishSegment()
	*/
	void FinishSegment(ULONG64 /*start*/, ULONG64 /*end*/) {}

	/**
	*	@copydoc IProcessor::Register()
	*/
	void Register(ULONG64 ustAddress,
		ULONG64 size, ULONG64 address,
		ULONG64 userSize, ULONG64 userAddress);

	/**
	*	@copydoc IProcessor::FinishHeap()
	*/
	void FinishHeap(ULONG64 /*heapAddress*/) {}

	/**
	*	@brief print summary of heap usage
	*/
	void Print();

	/**
	*	@brief print summary of matched heap usage
	*	@param key [in] prefix search key
	*/
	void Print(const char *key);
};

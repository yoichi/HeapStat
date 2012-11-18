#pragma once

#include <map>
#include <set>
#include "IProcessor.h"

class BySizeProcessor : public IProcessor
{
private:
	struct SizeRecord {
		ULONG64 userSize;
		ULONG64 count;
		std::set<ULONG64> ustAddress;
		bool operator< (const BySizeProcessor::SizeRecord& rhs) const
		{
			return count < rhs.count;
		}
	};

	/**
	*	@brief userSize to SizeRecord map
	*/
	std::map<ULONG64, SizeRecord> records_;

	/**
	*	@brief 0: show summary for entire range, !0: print ust addresses for specified size
	*/
	const ULONG64 size_;

	/**
	*	@brief operator (disabled)
	*	@note to avoid C4512 warning
	*/
	BySizeProcessor& operator=(const BySizeProcessor&);

public:
	/**
	*	@brief constructor
		@param size [in] 0: show summary for entire range, !0: print ust addresses for specified size
	*/
	BySizeProcessor(ULONG64 size);

	/**
	*	@copydoc IProcessor::StartHeap()
	*/
	void StartHeap(ULONG64 /*heapAddress*/) {}

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
};

#pragma once

#include <map>
#include "IProcessor.h"

class SummaryProcessor : public IProcessor
{
private:
	struct UstRecord {
		ULONG64 ustAddress;
		ULONG64 count;
		ULONG64 totalSize;
		ULONG64 maxSize;
		ULONG64 largestEntry;
	};

	std::map<ULONG64, UstRecord> records_;

	/**
	*	@brief print stack trace
	*	@param ustAddress [in] address of entry in user mode stack trace database
	*/
	void PrintStackTrace(ULONG64 ustAddress);

public:
	/**
	*	@copydoc IProcessor::Register()
	*/
	void Register(ULONG64 ustAddress,
		ULONG64 size, ULONG64 address,
		ULONG64 userSize, ULONG64 userAddress);

	/**
	*	@brief print summary of heap usage
	*/
	void Print();
};
